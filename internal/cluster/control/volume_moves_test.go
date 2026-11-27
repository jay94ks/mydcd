// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func moveCore(t *testing.T) (*backupCoreFixture, VolumeMoveBegin) {
	t.Helper()
	f := newBackupCore(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	peer := config.Peer{ID: "node-b", Key: hex.EncodeToString(other.Public().(ed25519.PublicKey)), Endpoint: "127.0.0.1:8002"}
	d, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	d, err = d.Invite(peer, "join-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := d.Entry(peer.ID)
	d, err = d.Dispatch(peer.ID, e.Revision, e.Job.Pending.ID, 1, [32]byte(f.node.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	e, _ = d.Entry(peer.ID)
	d, err = d.Observe(peer.ID, e.Revision, e.Job.Pending.ID, 4, peer)
	if err != nil {
		t.Fatal(err)
	}
	e, _ = d.Entry(peer.ID)
	ack := membership.Ack{Schema: 1, Cluster: f.p.Cluster, Node: peer.ID, JoinID: e.JoinID, Key: [32]byte(other.Public().(ed25519.PublicKey)), ConfigurationIndex: 4, AppliedIndex: 5}
	ack.Signature = ed25519.Sign(other, membership.AckBytes(ack))
	d, err = d.Installed(ack, e.Revision)
	if err != nil {
		t.Fatal(err)
	}
	writes, code := f.p.memberCheckpoint(f.s, d)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "installed-b", Key: MembersKey, Value: "fixture"}, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	f.apply("placement", "set-nodes", tenant.Revision, NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a", "node-b"}), state.Applied)
	for _, node := range []string{"node-a", "node-b"} {
		for _, tenant := range []string{"", "tenant"} {
			f.apply("limit-"+tenant+node, "set-volume-backup-limit", 0, VolumeBackupLimit{Tenant: tenant, Node: node, Bytes: 65536, Count: 1, StagingBytes: 65536, StagingCount: 1, Original: &OriginalVolumeLimit{Bytes: 65536, Count: 2}}, map[string]state.Code{"node-a": state.ConditionFailed, "node-b": state.Applied}[node])
		}
	}
	// Map the existing source before enabling a policy: zero is unknown, not
	// an empty measured Volume. The rejected policy writes above remain receipts.
	core := f.core()
	ready := f.view().entries[volumeKey(f.scope)].Native
	f.apply("source-capacity", "set-volume-capacity", core.Revision(), VolumeCapacity{Scope: f.scope, Native: VolumeNativeDigest(ready), Bytes: 65536}, state.Applied)
	for _, tenant := range []string{"", "tenant"} {
		f.apply("source-limit-"+tenant, "set-volume-backup-limit", 0, VolumeBackupLimit{Tenant: tenant, Node: "node-a", Bytes: 65536, Count: 1, StagingBytes: 65536, StagingCount: 1, Original: &OriginalVolumeLimit{Bytes: 65536, Count: 2}}, state.Applied)
	}
	target := ready.Spec
	target.Node = "node-b"
	target.NodeKey = ack.Key
	target.Materialization = "m-move"
	_, revision := f.core().Owner()
	return f, VolumeMoveBegin{Scope: f.scope, ID: "move", OwnerRevision: revision, Target: target, Compatibility: [32]byte{7}, MaxBytes: 65536, MaxEntries: 16, CapacityBytes: 65536, ExpiresAt: 1000}
}

func moveReport(t *testing.T, f *backupCoreFixture, kind string) VolumeMoveReport {
	t.Helper()
	j, m, ok := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: "move"})
	if !ok {
		t.Fatal("move missing")
	}
	r := VolumeMoveReport{Operation: "move", Schema: 1, Selection: j.Selection(), Binding: j.Digest(), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, Revision: f.core().Revision(), At: 2, Kind: kind}
	if kind == "fenced" {
		proof := volumes.FenceProof{Binding: m.Binding, FenceThrough: m.Binding.SourceOwnerRevision, Stopped: true, MountsGone: true, StartsSettled: true, Synced: true}
		proof.Signature = ed25519.Sign(f.node, volumes.FenceBytes(proof))
		r.Fence = &proof
	}
	if kind == "reader-gone" {
		reader, ok := f.core().MoveReader(j.Binding)
		if !ok {
			t.Fatal("reader missing")
		}
		gone := volumes.Gone{Scope: f.scope, Consumer: reader, Stopped: true, MountsGone: true}
		gone.Signature = ed25519.Sign(f.node, volumes.GoneBytes(gone))
		r.Closed = &gone
	}
	r.Signature = ed25519.Sign(f.node, VolumeMoveReportBytes(r))
	return r
}
func applyMoveReport(t *testing.T, f *backupCoreFixture, r VolumeMoveReport, want state.Code) state.Command {
	t.Helper()
	raw, _ := json.Marshal(r)
	cmd, err := f.p.ResolveVolumeMoveReport(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), raw)
	if err != nil {
		t.Fatal(err)
	}
	next, out, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || out.Code != want {
		t.Fatal("move report", out.Code, want, err)
	}
	f.s = next
	return cmd
}

func TestVolumeMoveAtomicReservationsCurrentPermitAndOriginalReader(t *testing.T) {
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	j, m, ok := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	if !ok || m.Phase != volumes.Prepared {
		t.Fatal("no prepared move")
	}
	if f.view().Quiescent() {
		t.Fatal("unsettled move escaped collector")
	}
	request := VolumeMovePermitRequest{Selection: j.Selection(), Kind: "fence"}
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Source.Key, request, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Target.Key, request, 2); err == nil {
		t.Fatal("target impersonated source")
	}
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Source.Key, request, q.ExpiresAt); err == nil {
		t.Fatal("deadline was renewed")
	}
	applyMoveReport(t, f, moveReport(t, f, "fenced"), state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "reader"), state.Applied)
	read := VolumeMovePermitRequest{Selection: j.Selection(), Kind: "read"}
	permit, err := f.p.VolumeMovePermit(f.s, j.Binding.Source.Key, read, 2)
	if err != nil || permit.Reader == nil || f.core().CheckActivation(*permit.Reader) == nil {
		t.Fatal("reader bypassed activation", err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.p.VolumeMovePermit(f.s, j.Binding.Source.Key, read, 2)
	if err != nil || again.Job.Digest() != j.Digest() || *again.Reader != *permit.Reader {
		t.Fatal("snapshot lost original binding/pin", err)
	}
	copy := f.view().Moves()
	copy[0].Origin.Session.Scopes[0].Actions[0] = "foreign"
	if f.view().Moves()[0].Digest() != j.Digest() {
		t.Fatal("move view aliases private origin")
	}
	applyMoveReport(t, f, moveReport(t, f, "reader-gone"), state.Applied)
}

func TestVolumeMoveBudgetFailurePreservesSourceAndSharesBackupCapacity(t *testing.T) {
	f, q := moveCore(t)
	q.MaxBytes = 65537
	q.CapacityBytes = 65537
	before, _ := f.core().Encode()
	f.apply("over-budget", "begin-volume-move", f.core().Revision(), q, state.ConditionFailed)
	after, _ := f.core().Encode()
	if !bytes.Equal(before, after) || len(f.view().Moves()) != 0 {
		t.Fatal("failed reservation froze source")
	}
	q.MaxBytes = 65536
	q.CapacityBytes = 65536
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	limit := f.view().backupLimits[backupLimitKey("", "node-a")]
	f.apply("shrink-copy-space", "set-volume-backup-limit", limit.Revision, VolumeBackupLimit{Node: "node-a", Bytes: 65535, Count: 1, StagingBytes: 65536, StagingCount: 1, Original: limit.Original}, state.ConditionFailed)
	// A second logical source cannot obtain an independent backup allowance.
	other := f.scope
	other.ID = "other"
	f.apply("other", "create-volume", 0, volumeFact(t, other, "node-a", f.node), state.ConditionFailed)
}

func TestVolumeMoveRevokedPlacementAllowsOnlyOriginalCleanup(t *testing.T) {
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "fenced"), state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "reader"), state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	f.apply("revoke-target", "set-nodes", tenant.Revision, NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a"}), state.Applied)
	if _, err = f.p.VolumeMovePermit(f.s, j.Binding.Source.Key, VolumeMovePermitRequest{Selection: j.Selection(), Kind: "read"}, 2); err == nil {
		t.Fatal("revoked target still authorizes copy")
	}
	f.apply("cancel", "cancel-volume-move", f.core().Revision(), j.Selection(), state.Applied)
	permit, err := f.p.VolumeMovePermit(f.s, j.Binding.Source.Key, VolumeMovePermitRequest{Selection: j.Selection(), Kind: "cleanup"}, q.ExpiresAt+1)
	if err != nil || permit.Reader == nil {
		t.Fatal("lost original cleanup reference", err)
	}
	applyMoveReport(t, f, moveReport(t, f, "reader-gone"), state.Applied)
}

func TestVolumeMoveSingleNodeReservationAndPublicPhase(t *testing.T) {
	f, q := moveCore(t)
	// Leave enough copy/physical capacity for two jobs. The second move must
	// be denied by the explicit node concurrency contract, not byte exhaustion.
	for _, node := range []string{"node-a", "node-b"} {
		for _, tenant := range []string{"", "tenant"} {
			limit := f.view().backupLimits[backupLimitKey(tenant, node)]
			f.apply("larger-"+node+tenant, "set-volume-backup-limit", limit.Revision, VolumeBackupLimit{Tenant: tenant, Node: node, Bytes: 4 << 20, Count: 4, StagingBytes: 4 << 20, StagingCount: 4, Original: &OriginalVolumeLimit{Bytes: 4 << 20, Count: 4}}, state.Applied)
		}
	}
	other := f.scope
	other.ID = "second"
	ready := volumeFact(t, other, "node-a", f.node)
	f.apply("second-source", "create-volume", 0, ready, state.ConditionFailed)
	// A new source on a policy-controlled node requires its explicit capacity
	// reservation, so use the existing atomic managed creation reservation.
	// For this FSM-only test install a signed registered fixture with capacity.
	v := f.view()
	catalog, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	core, err := volumes.New(catalog, "admin", other, ready.Owner, 4)
	if err != nil {
		t.Fatal(err)
	}
	v.entries[volumeKey(other)] = registeredVolume{Native: ready, State: core, CapacityBytes: 65536}
	writes, code := f.p.volumeCheckpoint(f.s, v)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "second-capacity-fixture", Key: VolumesKey, Expected: f.s.Object(VolumesKey).Revision, Value: "fixture"}, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	q.Scope = other
	q.ID = "second"
	q.Target.Scope = other
	q.Target.Materialization = "m-second"
	f.apply("conflicting-node-move", "begin-volume-move", core.Revision(), q, state.ConditionFailed)
	if len(f.view().Moves()) != 1 {
		t.Fatal("two node transfer reservations admitted")
	}
	page, _, err := f.view().Page(catalog, "admin", "tenant", "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, view := range page {
		if view.Scope == f.scope {
			found = view.Phase == "Moving" && view.MoveID == "move" && view.MovePhase == volumes.Prepared && view.TargetNode == "node-b"
		}
	}
	if !found {
		t.Fatal("moving source falsely shown Ready")
	}
	raw, _ := json.Marshal(page)
	for _, private := range []string{"Origin", "Session", "Signature", "SourceCapacity"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private move state exposed", private)
		}
	}
}
