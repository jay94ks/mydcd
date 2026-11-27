// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Reuses the original membership/identity reducers and an explicit modeled
// installed configuration. It makes no native installation or TLS claim.
func rotateRQ9CoreOwner(t *testing.T, f *backupCoreFixture) ed25519.PrivateKey {
	t.Helper()
	for _, tenant := range []string{"", "tenant"} {
		r, err := f.p.Resources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		if limit, found := r.Quotas.Limit(tenant, "node-a"); !found || limit.Default {
			f.apply("rq9-quota-"+tenant, "set-node-quota", 0, tenancy.NodeLimit{Tenant: tenant, Node: "node-a", Owner: f.p.TrustRoot, Capacity: workload.Resources{CPU: 10_000_000_000, Memory: 1 << 30}, MaxConsumers: 128}, state.Applied)
		}
	}
	_, configuration := cleanupControlIssuer(t, f)
	d, _ := f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "configuration", Node: "node-a", Expected: d.Revision, Configuration: &configuration}, state.Applied)
	d, _ = f.p.Members(f.s)
	entry, _ := d.Entry("node-a")
	f.apply("rq9-replace-identity", "rotate-node-identity", entry.Revision, NodeIdentityChange{ID: "node-a", Operation: "rq9-replace"}, state.Applied)
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{97}, ed25519.SeedSize))
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Operation: "rq9-replace", Old: f.p.TrustRoot, New: [32]byte(next.Public().(ed25519.PublicKey)), Prepared: [32]byte{1}}
	proof.OldSignature = ed25519.Sign(f.node, lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(proof))
	d, _ = f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "identity-prepared", Node: "node-a", Operation: "rq9-replace", Expected: d.Revision, Identity: &proof}, state.Applied)
	d, _ = f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "identity-activate", Node: "node-a", Operation: "rq9-replace", Expected: d.Revision}, state.Applied)
	return next
}

func TestNodeIdentityKeepsRQ9OriginalFileWriterAndCurrentKeySettlement(t *testing.T) {
	f := newBackupCore(t)
	q := VolumeFileChange{Scope: f.scope, Path: "backups/original.bin", Size: 1, MaxBytes: 1024, Digest: sha256.Sum256([]byte{1})}
	f.apply("rq9-original-file", "volume-file-put", f.core().Revision(), q, state.Applied)
	job := f.view().VolumeFiles()[0]
	before, err := f.p.NodeActivity(f.s, f.p.TrustRoot)
	if err != nil || before.Resources == 0 || before.Writers == 0 {
		t.Fatal("pending file original omitted from node blockers", before, err)
	}
	next := rotateRQ9CoreOwner(t, f)
	current := [32]byte(next.Public().(ed25519.PublicKey))
	if _, err := f.p.VolumeFileWork(f.s, current, f.session, job.ID, 3); err != nil {
		t.Fatal("current key cannot consume exact original file job", err)
	}
	if _, err := f.p.VolumeFileWork(f.s, f.p.TrustRoot, f.session, job.ID, 3); err == nil {
		t.Fatal("historical key authorized current file I/O")
	}
	after, err := f.p.NodeActivity(f.s, current)
	retained, found := f.view().VolumeFile(job.ID)
	if err != nil || after.Resources == 0 || after.Writers == 0 || !found || retained.Consumer != job.Consumer || !bytes.Equal(OperationBytes(retained.Origin), OperationBytes(job.Origin)) {
		t.Fatal("identity activation cleared original file work/pins", err)
	}
	gone := volumes.Gone{Scope: q.Scope, Consumer: job.Consumer, Stopped: true, MountsGone: true}
	gone.Signature = ed25519.Sign(f.node, volumes.GoneBytes(gone))
	report := VolumeFileReport{Schema: 1, Operation: "file", ID: job.ID, Code: "ok", Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, At: 3, Result: &volumes.FileResult{Path: q.Path, Size: q.Size, Digest: q.Digest}, Gone: gone}
	report.Signature = ed25519.Sign(next, VolumeFileReportBytes(report))
	raw, _ := json.Marshal(report)
	if _, err := f.p.ResolveVolumeFileReport(f.s, f.p.TrustRoot, raw); err == nil {
		t.Fatal("old key minted a current close report")
	}
	cmd, err := f.p.ResolveVolumeFileReport(f.s, current, raw)
	if err != nil {
		t.Fatal("current report rejected original historic Gone proof", err)
	}
	applyRestartCore(t, f, cmd, state.Applied)
	closed, _ := f.view().VolumeFile(job.ID)
	if closed.Phase != "Completed" || closed.Native.Owner != job.Native.Owner || closed.Consumer != job.Consumer || closed.Gone == nil || !bytes.Equal(closed.Gone.Signature, gone.Signature) || len(f.core().Consumers()) != 0 {
		t.Fatal("positive close rewrote source history or retained writer")
	}
}

func TestNodeIdentityStandalonePolicyUsesCurrentReporterAndOriginalTaskOwner(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	before, _ := f.p.Apps(f.s)
	inventory, _ := before.Inventory("tenant", scope)
	original, _ := inventory.Encode()
	next := rotateRQ9CoreOwner(t, f)
	q := standaloneReportCore(t, f, scope, "expire", "ttl", 3602)
	if f.p.CheckStandalonePolicy(f.s, q) {
		t.Fatal("retired reporter minted a current standalone policy command")
	}
	owner := q.Reporter
	q.Reporter, q.ResourceOwner = [32]byte(next.Public().(ed25519.PublicKey)), &owner
	q.Signature = ed25519.Sign(next, StandalonePolicyBytes(q))
	if !f.p.CheckStandalonePolicy(f.s, q) {
		t.Fatal("current reporter could not settle exact retained standalone")
	}
	wrong := [32]byte{99}
	bad := q
	bad.ResourceOwner = &wrong
	bad.Signature = ed25519.Sign(next, StandalonePolicyBytes(bad))
	if f.p.CheckStandalonePolicy(f.s, bad) {
		t.Fatal("current key adopted another physical owner's standalone")
	}
	after, _ := f.p.Apps(f.s)
	kept, _ := after.Inventory("tenant", scope)
	encoded, _ := kept.Encode()
	if !bytes.Equal(original, encoded) {
		t.Fatal("identity activation replaced standalone Task/writable history")
	}
	cmd, err := q.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, cmd, state.Applied)
	apps, err := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", scope)]
	if err != nil || entry.Standalone.Cleanup == nil || entry.Standalone.Cleanup.resourceOwner() != owner || entry.Standalone.Cleanup.Reporter != q.Reporter {
		t.Fatal("original standalone cleanup lost current/history distinction", err)
	}
}
