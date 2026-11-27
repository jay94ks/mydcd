// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/identity"
)

// Three voters lose two for good. The survivor plans a recovery offline,
// carries it out on the next start and is the only voter: writes work
// again, the lost voters are retired by the signed plan, and a lost voter
// that comes back is refused instead of rejoining with its old
// configuration.
func TestQuorumRecoveryAfterLosingVoterMajority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	m := newManagedVoters(t, ctx, t.TempDir(), admin, 3)
	m.Change(0, "before", "create-tenant", 0, control.TenantID{ID: "before"})
	for i := range m.Nodes {
		if err = m.Nodes[i].Close(); err != nil {
			t.Fatal(err)
		}
		m.Nodes[i] = nil
	}
	survivor := m.Configs[0]

	// A list that still holds a majority is not a recovery.
	if _, err = PreviewRecovery(survivor, []string{"node-0", "node-1"}); !errors.Is(err, cluster.ErrRecoveryPlan) {
		t.Fatal("majority list accepted", err)
	}
	if _, err = PreviewRecovery(survivor, []string{"node-1"}); !errors.Is(err, cluster.ErrRecoveryPlan) {
		t.Fatal("list without this server accepted", err)
	}
	p, err := PreviewRecovery(survivor, []string{"node-0"})
	if err != nil || !slices.Equal(p.Lost, []string{"node-1", "node-2"}) || p.LastIndex == 0 {
		t.Fatal("preview", p, err)
	}
	if _, err = PlanRecovery(survivor, []string{"node-0"}, "recover-1", p.LastIndex+1, time.Now()); !errors.Is(err, cluster.ErrRecoveryPlan) {
		t.Fatal("wrong confirmation accepted", err)
	}
	plan, err := PlanRecovery(survivor, []string{"node-0"}, "recover-1", p.LastIndex, time.Now())
	if err != nil || !plan.Valid() || plan.Index() != p.LastIndex+1 {
		t.Fatal("plan", plan, err)
	}

	controlDir := filepath.Join(survivor.Node.StateDir, "control")
	planned, err := os.ReadFile(filepath.Join(controlDir, "recovery-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Nodes[0], err = Open(survivor); err != nil {
		t.Fatal("start after recovery", err)
	}
	// A start that stopped after the recovered snapshot (plan and result
	// still there) finishes the recovery on the next start.
	if err = m.Nodes[0].Close(); err != nil {
		t.Fatal(err)
	}
	result, _ := json.Marshal(cluster.RecoveryResult{Schema: 1, Plan: plan, Lost: p.Lost})
	if os.WriteFile(filepath.Join(controlDir, "recovery-plan.json"), planned, 0o600) != nil || os.WriteFile(filepath.Join(controlDir, "recovery.json"), result, 0o600) != nil {
		t.Fatal("write interrupted recovery")
	}
	if m.Nodes[0], err = Open(survivor); err != nil {
		t.Fatal("resume an interrupted recovery", err)
	}
	if _, err = os.Stat(filepath.Join(controlDir, "recovery-plan.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plan kept after resumed recovery", err)
	}
	m.wait("survivor leads", func() bool {
		_, err := m.Nodes[0].Engine().Read(ctx, true)
		return err == nil
	})
	m.Change(0, "after", "create-tenant", 0, control.TenantID{ID: "after"})
	m.wait("lost voters retired", func() bool {
		d := m.directory(m.Nodes[0])
		topology, err := d.Topology()
		if err != nil {
			return false
		}
		for _, id := range []string{"node-1", "node-2"} {
			n, ok := topology.Node(id)
			if !ok || n.Phase != lifecycle.Retired || n.Recovery == nil || n.Recovery.RequestID != "recover-1" {
				return false
			}
		}
		c := topology.Configuration()
		return len(c.Members) == 1 && c.Members[0].ID == "node-0" && c.Index == plan.Index()
	})
	// A "recovered" report is admitted only for the configuration Raft runs.
	running := lifecycle.Configuration{Index: plan.Index(), Members: []lifecycle.Member{{ID: "node-0", Key: m.Nodes[0].Identity.Public, Voter: true}}}
	if err = m.Nodes[0].recoveredMatchesRaft(ctx, running); err != nil {
		t.Fatal("running configuration refused", err)
	}
	stale := running
	stale.Index--
	if err = m.Nodes[0].recoveredMatchesRaft(ctx, stale); err == nil {
		t.Fatal("configuration Raft does not run accepted")
	}
	m.wait("recovery result forgotten", func() bool {
		_, err := os.Stat(filepath.Join(survivor.Node.StateDir, "control", "recovery.json"))
		return errors.Is(err, os.ErrNotExist)
	})

	// A lost voter comes back with its old state. It must not take the
	// survivor's leadership or its writes.
	back, err := Open(m.Configs[1])
	if err == nil {
		m.Nodes[1] = back
	}
	m.Change(0, "with-lost-back", "create-tenant", 0, control.TenantID{ID: "with-lost-back"})
	time.Sleep(3 * time.Second)
	m.Change(0, "still-leader", "create-tenant", 0, control.TenantID{ID: "still-leader"})
	// The cluster grows again the usual way: a new server joins and
	// becomes a voter.
	m.AddMember("node-3", true)
	m.Change(0, "two-voters", "create-tenant", 0, control.TenantID{ID: "two-voters"})
	view, err := m.Nodes[0].Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := m.Policy.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"before", "after", "with-lost-back", "still-leader", "two-voters"} {
		if _, ok := catalog.Tenant(id); !ok {
			t.Fatal("tenant missing after recovery", id)
		}
	}
}
