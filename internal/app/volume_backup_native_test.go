// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func verifySharedBackupBoundary(t *testing.T, ctx context.Context, a *Runtime, owner **Runtime, cfg config.Node, root string, admin userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), ready volumes.NativeReady, marker []byte) {
	t.Helper()
	source := ready.Spec.Scope
	for _, tenant := range []string{"", source.Tenant} {
		change("backup-limit-"+tenant, "set-volume-backup-limit", 0, control.VolumeBackupLimit{Tenant: tenant, Node: ready.Owner.Node, Bytes: 128 << 10, Count: 1})
	}
	home := filepath.Join(root, "backup-client")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "backup-client.yaml")
	raw := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", admin.Cluster, a.Identity.Public, peer.Endpoint)
	if err := os.WriteFile(profile, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	selectedTenant := ""
	run := func(args ...string) any {
		t.Helper()
		args = withTenant(selectedTenant, args)
		command := nativeCLICmd(ctx, os.Getenv("SFC_TEST_CLI"), home, profile, args...)
		var output, diagnostic bytes.Buffer
		command.Stdout, command.Stderr = &output, &diagnostic
		if err := command.Run(); err != nil {
			t.Fatal("backup CLI", args, err, diagnostic.String())
		}
		if bytes.Contains(output.Bytes(), marker) {
			t.Fatal("raw data in CLI")
		}
		var reply any
		if output.Len() != 0 && json.Unmarshal(output.Bytes(), &reply) != nil {
			t.Fatal("CLI JSON")
		}
		return reply
	}
	cli := func(args ...string) { t.Helper(); run(args...) }
	list := func(args ...string) []any { t.Helper(); rows, _ := run(args...).([]any); return rows }
	cli("wallet", "init")
	cli("login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	selectedTenant = source.Tenant
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, ok := registry.Volume(source)
	if !ok {
		t.Fatal("source")
	}
	compatibility := sha256.Sum256([]byte("sfc-file-profile1/no-managed-writer"))
	request := control.VolumeBackupBegin{Scope: source, ID: "one", MaxBytes: 128 << 10, MaxEntries: 16, Compatibility: compatibility}
	document := func(name, action string, expected uint64, payload any) string {
		t.Helper()
		body, _ := json.Marshal(payload)
		raw, _ := json.Marshal(control.ChangeDocument{Schema: 1, Action: action, Expected: expected, Payload: body})
		name = filepath.Join(root, name)
		if err := os.WriteFile(name, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return name
	}
	begin := document("backup-begin.json", "begin-volume-backup", core.Revision(), request)
	cli("manage", "apply", "--request-id", "backup-begin", "--change", begin)
	selection := control.VolumeBackupSelection{Scope: source, ID: "one"}
	job := func() control.VolumeBackup {
		t.Helper()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		j, ok := v.Backup(source, "one")
		if !ok {
			t.Fatal("job")
		}
		return j
	}
	original := job()
	if original.Phase != "Reserved" || original.Binding.Origin.RequestID != "backup-begin" {
		t.Fatal("original accepted intent")
	}
	before, _ := p.Volumes(read().State)
	held, _ := before.Volume(source)
	if len(held.Consumers()) != 1 || before.Quiescent() {
		t.Fatal("atomic reader/reference reservation")
	}
	// Departure of the submit transport/session does not cancel the already
	// committed operation. A fresh login is only for subsequent user queries.
	cli("logout")
	cli("login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	selectedTenant = source.Tenant
	listed := list("volume", "backup", "list")
	if entries := listed; len(entries) != 1 {
		t.Fatal("backup metadata CLI", listed)
	}
	// Snapshot and the same owner DB preserve accepted IDs/reservations, before
	// copying. This fixture does not pretend to be an autonomous job scheduler.
	if err = a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = (*owner).Close(); err != nil {
		t.Fatal(err)
	}
	*owner = nil
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal("original owner DB reopen", err)
	}
	*owner = reopened
	for {
		_, leader := reopened.Engine().Leader()
		if leader != "" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if current := job(); current.Binding.Digest() != original.Binding.Digest() || current.Phase != "Reserved" {
		t.Fatal("same DB changed original binding")
	}
	permit := func(cleanup bool) (control.VolumeBackup, error) {
		body, _ := json.Marshal(control.VolumeBackupPermitRequest{Selection: selection, Cleanup: cleanup})
		reply, e := (*owner).appCall(ctx, "volume-backup-permit", body)
		if e != nil {
			return control.VolumeBackup{}, e
		}
		j, e := schema.Decode[control.VolumeBackup](reply.Data)
		if e != nil || j.Binding.Digest() != original.Binding.Digest() {
			return j, sfcp.ErrAdmission
		}
		return j, nil
	}
	if _, err = permit(false); err != nil {
		t.Fatal("fresh authenticated owner permit", err)
	}
	body, _ := json.Marshal(control.VolumeBackupPermitRequest{Selection: selection})
	if _, e := a.appCall(ctx, "volume-backup-permit", body); e == nil {
		t.Fatal("other node borrowed cold reader")
	}
	artifactDir := filepath.Join(root, "owned-artifacts")
	if err = os.Mkdir(artifactDir, 0700); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(artifactDir, "one.tar")
	artifact, err := os.OpenFile(artifactPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	authorize := func(_ context.Context, native volumes.NativeReady, c volumes.Consumer) error {
		j, e := permit(false)
		if e != nil {
			return e
		}
		if c != j.Binding.Consumer || native.Owner != j.Binding.Source.Owner || native.Spec != j.Binding.Source.Spec {
			return sfcp.ErrAdmission
		}
		return nil
	}
	receipt, err := (*owner).nativeVolumes.ExportCold(ctx, original.Binding.Source, original.Binding.Consumer, authorize, artifact, original.Binding.Options())
	closeErr := artifact.Close()
	if err != nil || closeErr != nil {
		t.Fatal("actual cold archive", err, closeErr)
	}
	directory, err := os.Open(artifactDir)
	if err != nil {
		t.Fatal(err)
	}
	syncErr := directory.Sync()
	closeErr = directory.Close()
	if syncErr != nil || closeErr != nil {
		t.Fatal("durable directory publication", syncErr, closeErr)
	}
	if receipt.DataBytes != uint64(len(marker)) {
		t.Fatal("actual archive content length")
	}
	report := func(kind string) control.VolumeBackupReport {
		t.Helper()
		current := job()
		view := read()
		r := control.VolumeBackupReport{Schema: 1, Scope: source, ID: "one", Epoch: view.State.ModuleEpoch(), RootRevision: view.State.Object(control.VolumesKey).Revision, Revision: current.Revision, At: time.Now().Unix(), Binding: current.Binding.Digest(), Kind: kind}
		if kind == "ready" {
			r.Receipt = receipt
			r.DirectorySynced, r.CleanShutdown, r.Compatible = true, true, true
			g := volumes.Gone{Scope: source, Consumer: current.Binding.Consumer, Stopped: true, MountsGone: true}
			g.Signature = ed25519.Sign((*owner).Identity.Private, volumes.GoneBytes(g))
			r.Closed = &g
		} else {
			r.DirectorySynced = true
			r.ArtifactGone = true
		}
		r.Signature = ed25519.Sign((*owner).Identity.Private, control.VolumeBackupReportBytes(r))
		return r
	}
	send := func(r control.VolumeBackupReport) cluster.ManagementReply {
		t.Helper()
		body, _ := json.Marshal(r)
		reply, e := (*owner).appCall(ctx, "volume-backup-report", body)
		if e != nil || reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
			t.Fatal("owner outcome commit", reply.Committed, e)
		}
		return reply
	}
	// This is a generic file source with no managed writer ever installed. All
	// fixture writes/FDs are closed before admission. It is not a MySQL shutdown
	// or database compatibility attestation; the latter remains a separate gate.
	completion := report("ready")
	first := send(completion)
	if current := job(); current.Phase != "Ready" || current.Receipt == nil || *current.Receipt != receipt {
		t.Fatal("committed original receipt")
	}
	second := send(completion)
	if second.Committed.Result.Index != first.Committed.Result.Index {
		t.Fatal("original signed outcome replay changed index")
	}
	v, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, _ = v.Volume(source)
	if len(core.Consumers()) != 0 {
		t.Fatal("owner closure did not atomically return reader")
	}
	cli("manage", "apply", "--request-id", "backup-begin", "--change", begin)
	if current := job(); current.Phase != "Ready" || current.Binding.Digest() != original.Binding.Digest() {
		t.Fatal("CLI replay resubmitted original native work")
	}
	encoded, err := state.Encode(read().State)
	if err != nil || bytes.Contains(encoded, marker) {
		t.Fatal("raw backup data in shared state", err)
	}
	current := job()
	remove := document("backup-delete.json", "delete-volume-backup", current.Revision, selection)
	cli("manage", "apply", "--request-id", "backup-delete", "--change", remove)
	if _, err = permit(false); err == nil {
		t.Fatal("deleting artifact allowed new copy")
	}
	if _, err = permit(true); err != nil {
		t.Fatal("cleanup authority", err)
	}
	if err = os.Remove(artifactPath); err != nil {
		t.Fatal(err)
	}
	directory, err = os.Open(artifactDir)
	if err != nil {
		t.Fatal(err)
	}
	syncErr = directory.Sync()
	closeErr = directory.Close()
	if syncErr != nil || closeErr != nil {
		t.Fatal(syncErr, closeErr)
	}
	send(report("gone"))
	if current := job(); current.Phase != "Deleted" || current.Completion == nil || current.Completion.Receipt != receipt {
		t.Fatal("original completion/tombstone not preserved")
	}
	listed = list("volume", "backup", "list")
	entries := listed
	if len(entries) != 1 || entries[0].(map[string]any)["Phase"] != "Deleted" {
		t.Fatal("stable metadata/tombstone CLI", listed)
	}
	if err = (*owner).nativeVolumes.DeleteDesired(volumes.NativeKey(ready.Spec), 2, ready.Generation); err != nil {
		t.Fatal(err)
	}
	if err = (*owner).nativeVolumes.Step(ctx, volumes.NativeKey(ready.Spec)); err != nil {
		t.Fatal(err)
	}
	if gone, e := (*owner).nativeVolumes.Gone(ctx, volumes.NativeKey(ready.Spec), 2, ready.Generation); e != nil || !gone {
		t.Fatal("original retained source cleanup", e)
	}
	t.Log("actual signed CLI typed backup admission/list -> one Raft/Volume root readonly consumer plus node/tenant reservation -> Snapshot/same original owner DB/binding -> authenticated fresh owner permits -> actual native archive/file+directory sync -> original signed owner report/replay -> atomic reader return -> explicit CLI delete/preserved artifact until original signed Gone -> stable tombstone/original completion; owned resource0/eight baselines. Generic no-managed-writer file fixture, not MySQL shutdown/SQL recovery, native job crash controller or complete D2.04.")
}
