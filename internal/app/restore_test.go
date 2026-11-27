// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Every voter is lost. A new server restores the cluster backup: it is the
// only voter of the same cluster, the old members are retired by the
// restore, the backed-up state and master key are there, the administrator
// logs in again with the same key, and the cluster grows the usual way.
func TestRestoreClusterFromBackupOnNewServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	m := newManagedVoters(t, ctx, t.TempDir(), admin, 2)
	m.Change(0, "before", "create-tenant", 0, control.TenantID{ID: "before"})
	key, _ := clusterbackup.KeyFromFile(bytes.Repeat([]byte{5}, 32))
	recipient, err := clusterbackup.NewRecipient()
	if err != nil {
		t.Fatal(err)
	}
	m.Change(0, "backup-1", "cluster-backup", 0, control.ClusterBackupChange{Operation: "backup-1", Recipient: recipient.Public()})
	file, err := backupFile(t, ctx, m, 0, "backup-1", recipient, key)
	if err != nil {
		t.Fatal(err)
	}
	m.Change(0, "later", "create-tenant", 0, control.TenantID{ID: "later"})
	for i := range m.Nodes {
		if err = m.Nodes[i].Close(); err != nil {
			t.Fatal(err)
		}
		m.Nodes[i] = nil
	}

	b, err := ReadRestoreBackup(bytes.NewReader(file), key)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Clear()
	if !slices.Equal(b.Lost, []string{"node-0", "node-1"}) || b.Generation != 1 {
		t.Fatal("backup", b.Lost, b.Generation)
	}
	if _, err = ReadRestoreBackup(bytes.NewReader(file[:len(file)-1]), key); err == nil {
		t.Fatal("cut backup read")
	}
	old := slices.Clone(m.Configs)
	// The new server takes over the old genesis' address: a retired
	// server's endpoint is free.
	fresh := m.nodeConfig("node-9")
	fresh.Node.Listen = old[0].Node.Listen
	taken := fresh
	taken.Node.ID = "node-1"
	if _, err = Restore(ctx, taken, b, "restore-1", time.Now()); !errors.Is(err, cluster.ErrRestorePlan) {
		t.Fatal("restore under a backed-up name", err)
	}
	// Keep the plan and snapshot as the command writes them, to play back
	// a start that stopped after storing the restored Raft snapshot.
	record, err := bootstrap.PrepareRestore(fresh, bootstrap.Policy{Cluster: b.Manifest.Cluster, Admin: b.Manifest.Admin, TrustRoot: b.Manifest.TrustRoot, Genesis: b.Manifest.Genesis}, "restore-1")
	if err != nil {
		t.Fatal(err)
	}
	if err = planRestore(fresh, record, b, "restore-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	controlDir := filepath.Join(fresh.Node.StateDir, "control")
	kept := map[string][]byte{}
	for _, name := range []string{"restore-plan.json", "restore-snapshot.mds1"} {
		if kept[name], err = os.ReadFile(filepath.Join(controlDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	restored, err := Restore(ctx, fresh, b, "restore-1", time.Now())
	if err != nil {
		t.Fatal("restore", err)
	}
	if restored.Installation.Root.Intent != lifecycle.RestoreIntent || restored.Installation.Root.Cluster != m.Cluster || !restored.Installation.Root.Installed.Standalone("node-9") {
		t.Fatal("installation", restored.Installation)
	}
	if cluster.RestorePending(fresh.Node.StateDir) {
		t.Fatal("restore plan kept")
	}
	for name, raw := range kept {
		if err = os.WriteFile(filepath.Join(controlDir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A repeated command finds the restore done, and finishes one that
	// stopped after the restored snapshot.
	if _, err = Restore(ctx, fresh, b, "restore-1", time.Now()); err != nil || cluster.RestorePending(fresh.Node.StateDir) {
		t.Fatal("repeated restore", err)
	}

	node, err := Open(fresh)
	if err != nil {
		t.Fatal("start after restore", err)
	}
	m.Nodes[0], m.Configs[0] = node, fresh
	self := config.Peer{ID: "node-9", Key: node.Identity.Actor(), Endpoint: fresh.Node.Listen, Voter: true}
	m.addPeer(self)
	m.Peers[0] = self
	m.Peers = m.Peers[:2]
	m.client.Peers = []sfcp.Peer{m.Peer(0)}
	m.wait("restored server leads", func() bool {
		_, err := node.Engine().Read(ctx, true)
		return err == nil
	})
	if m.session, err = m.client.Login(ctx, m.Peer(0), "admin", admin.Private); err != nil {
		t.Fatal("admin login after restore", err)
	}
	m.Change(0, "after", "create-tenant", 0, control.TenantID{ID: "after"})

	d := m.directory(node)
	topology, err := d.Topology()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"node-0", "node-1"} {
		n, ok := topology.Node(id)
		if !ok || n.Phase != lifecycle.Retired || n.Restored != 1 || !d.Gone(id) {
			t.Fatal("old member not retired", id, n)
		}
	}
	if c := topology.Configuration(); len(c.Members) != 1 || c.Members[0].ID != "node-9" || topology.Generation() != 1 || !d.Restored("restore-1") {
		t.Fatal("restored configuration", c)
	}
	master, err := node.certificateMaster()
	if err != nil || !bytes.Equal(master, b.master) {
		t.Fatal("master key not resealed to the new server", err)
	}
	clear(master)
	view, err := node.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := m.Policy.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"before": true, "later": false, "after": true} {
		if _, ok := catalog.Tenant(id); ok != want {
			t.Fatal("tenant after restore", id, ok)
		}
	}

	// A lost voter comes back with its old state: it is refused and cannot
	// win an election alone, so writes keep working.
	back, err := Open(old[1])
	if err == nil {
		defer back.Close()
	}
	time.Sleep(3 * time.Second)
	m.Change(0, "with-old-back", "create-tenant", 0, control.TenantID{ID: "with-old-back"})

	// The cluster grows the usual way.
	m.AddMember("node-10", true)
	m.Change(0, "grown", "create-tenant", 0, control.TenantID{ID: "grown"})
}
