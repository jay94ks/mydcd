// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/reconcile"
)

func private(n byte) ed25519.PrivateKey    { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
func public(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }

type fixture struct {
	t              *testing.T
	c              access.Catalog
	s              State
	a, b           ed25519.PrivateKey
	source, target Owner
}

func makeFixture(t *testing.T) *fixture {
	t.Helper()
	root := public(private(1))
	c, e := access.New(root)
	if e != nil {
		t.Fatal(e)
	}
	c, e = c.Enroll(root, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: root, Enabled: true}}})
	if e != nil {
		t.Fatal(e)
	}
	c, e = c.CreateTenant("admin", "tenant", 0)
	if e != nil {
		t.Fatal(e)
	}
	tenant, _ := c.Tenant("tenant")
	c, e = c.SetNodes("admin", "tenant", tenant.Revision, []string{"node-a", "node-b"})
	if e != nil {
		t.Fatal(e)
	}
	a, b := private(10), private(11)
	source := Owner{"node-a", public(a), "sfc-source"}
	target := Owner{"node-b", public(b), "sfc-stage"}
	s, e := New(c, "admin", Scope{Cluster: [32]byte{9}, Tenant: "tenant", App: "app", ID: "mysql", Generation: 1}, source, 3)
	if e != nil {
		t.Fatal(e)
	}
	return &fixture{t, c, s, a, b, source, target}
}
func (f *fixture) set(s State, e error) {
	f.t.Helper()
	if e != nil {
		f.t.Fatal(e)
	}
	// An in-memory fake publication uses the product codec, so every accepted
	// transition also has to restore its original references and evidence.
	b, e := s.Encode()
	if e != nil {
		f.t.Fatal("candidate", e, s.d)
	}
	q, e := Decode(b)
	if e != nil {
		f.t.Fatal("restore", e)
	}
	f.s = q
}
func (f *fixture) acquire(id string, generation uint64, writer bool) Consumer {
	f.t.Helper()
	s, p, e := f.s.Acquire(f.c, "admin", f.s.Revision(), id, generation, writer)
	f.set(s, e)
	return p
}
func (f *fixture) gone(p Consumer) Gone {
	g := Gone{Scope: f.s.Scope(), Consumer: p, Stopped: true, MountsGone: true}
	k := f.a
	if p.Owner.Key == public(f.b) {
		k = f.b
	}
	g.Signature = ed25519.Sign(k, GoneBytes(g))
	return g
}
func (f *fixture) prepare(id string, target Owner) Move {
	f.t.Helper()
	_, r := f.s.Owner()
	f.set(f.s.Prepare(f.c, "admin", f.s.Revision(), r, id, target, [32]byte{22}, 1<<20))
	m, _ := f.s.Move(id)
	return m
}
func (f *fixture) fence(m Move) FenceProof {
	p := FenceProof{Binding: m.Binding, FenceThrough: m.Binding.SourceOwnerRevision, Stopped: true, MountsGone: true, StartsSettled: true, Synced: true}
	k := f.a
	if m.Binding.Source.Key == public(f.b) {
		k = f.b
	}
	p.Signature = ed25519.Sign(k, FenceBytes(p))
	return p
}
func (f *fixture) manifest(m Move, artifact [32]byte) Manifest {
	p := Manifest{Binding: m.Binding, Artifact: artifact, Bytes: 4096, Files: 3, ReadOnly: true}
	k := f.a
	if m.Binding.Source.Key == public(f.b) {
		k = f.b
	}
	p.Signature = ed25519.Sign(k, ManifestBytes(p))
	return p
}
func (f *fixture) copy(m Move, manifest Manifest) CopyProof {
	p := CopyProof{Binding: m.Binding, Artifact: manifest.Artifact, Bytes: manifest.Bytes, DigestVerified: true, Synced: true, NoWriters: true}
	k := f.b
	if m.Binding.Target.Key == public(f.a) {
		k = f.a
	}
	p.Signature = ed25519.Sign(k, CopyBytes(p))
	return p
}
func (f *fixture) verified(m Move, artifact [32]byte) {
	f.t.Helper()
	f.set(f.s.RecordFence(f.fence(m)))
	manifest := f.manifest(m, artifact)
	f.set(f.s.BeginCopy(manifest))
	f.set(f.s.VerifyCopy(f.copy(m, manifest)))
}
func (f *fixture) activate(m Move, p Consumer) {
	f.t.Helper()
	proof := ActiveProof{Binding: m.Binding, Consumer: p, Running: true}
	k := f.b
	if p.Owner.Key == public(f.a) {
		k = f.a
	}
	proof.Signature = ed25519.Sign(k, ActiveBytes(proof))
	f.set(f.s.RecordActive(proof))
}
func (f *fixture) cleanup(m Move) {
	f.t.Helper()
	for _, owner := range []Owner{m.Binding.Target, m.Binding.Source} {
		p := CleanupProof{Binding: m.Binding, Owner: owner, TransferClosed: true, RetainedFenced: owner == m.Binding.Source}
		k := f.a
		if owner.Key == public(f.b) {
			k = f.b
		}
		p.Signature = ed25519.Sign(k, CleanupBytes(p))
		f.set(f.s.RecordCleanup(p))
	}
}
func (f *fixture) cancelProof(m Move) CancelProof {
	p := CancelProof{Binding: m.Binding, StagingGone: true, StartsSettled: true, MountsGone: true, TransferClosed: true}
	k := f.b
	if m.Binding.Target.Key == public(f.a) {
		k = f.a
	}
	p.Signature = ed25519.Sign(k, CancelBytes(p))
	return p
}
func expectDenied(t *testing.T, e error) {
	t.Helper()
	if e == nil {
		t.Fatal("unsafe transition accepted")
	}
}
func gateRequest(t *testing.T, g Gate, p Consumer, nonce byte) (Gate, StartRequest) {
	t.Helper()
	n, r, e := g.Request(p, [32]byte{nonce})
	if e != nil {
		t.Fatal(e)
	}
	return n, r
}
func gateAccept(t *testing.T, g Gate, p Permit) Gate {
	t.Helper()
	n, e := g.Accept(p)
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func gateSettle(t *testing.T, g Gate, p Consumer, outcome reconcile.Outcome) Gate {
	t.Helper()
	n, e := g.SettleStart(p, outcome)
	if e != nil {
		t.Fatal(e)
	}
	return n
}

func TestVolumeWriterReaderExclusionOriginalClosureAndRetain(t *testing.T) {
	f := makeFixture(t)
	before, _ := f.s.Encode()
	writer := f.acquire("db", 1, true)
	_, _, e := f.s.Acquire(f.c, "admin", f.s.Revision(), "db-two", 1, true)
	expectDenied(t, e)
	_, _, e = f.s.Acquire(f.c, "admin", f.s.Revision(), "backup", 1, false)
	expectDenied(t, e)
	_, same, e := f.s.Acquire(f.c, "admin", 0, "db", 1, true)
	if e != nil || same != writer {
		t.Fatal("lost original idempotent pin")
	}
	bad := f.gone(writer)
	bad.Stopped = false
	bad.Signature = ed25519.Sign(f.a, GoneBytes(bad))
	_, e = f.s.Release(bad)
	expectDenied(t, e)
	bad = f.gone(writer)
	bad.Signature = ed25519.Sign(f.b, GoneBytes(bad))
	_, e = f.s.Release(bad)
	expectDenied(t, e)
	f.set(f.s.Release(f.gone(writer)))
	_, _, e = f.s.Acquire(f.c, "admin", f.s.Revision(), "db", 1, true)
	expectDenied(t, e)
	r1 := f.acquire("backup", 1, false)
	r2 := f.acquire("inspect", 1, false)
	_, _, e = f.s.Acquire(f.c, "admin", f.s.Revision(), "db", 2, true)
	expectDenied(t, e)
	f.set(f.s.Release(f.gone(r1)))
	f.set(f.s.Release(f.gone(r2)))
	next := f.acquire("db", 2, true)
	if next.Lease.Token <= r2.Lease.Token || !f.s.RetainsData() || len(f.s.Retained()) != 0 {
		t.Fatal("token floor or retain lost")
	}
	if len(before) == 0 {
		t.Fatal("missing original snapshot")
	}
	_, e = New(f.c, "nobody", f.s.Scope(), f.source, 3)
	expectDenied(t, e)
}

func TestVolumeFenceRequiresOriginalOwnerAndPositiveClosure(t *testing.T) {
	f := makeFixture(t)
	p := f.acquire("db", 1, true)
	m := f.prepare("move", f.target)
	proof := f.fence(m)
	_, e := f.s.RecordFence(proof)
	expectDenied(t, e) // the pin survives even a claimed native absence
	f.set(f.s.Release(f.gone(p)))
	for _, change := range []func(*FenceProof){
		func(p *FenceProof) { p.Stopped = false }, func(p *FenceProof) { p.MountsGone = false }, func(p *FenceProof) { p.StartsSettled = false }, func(p *FenceProof) { p.Synced = false }, func(p *FenceProof) { p.FenceThrough++ }, func(p *FenceProof) { p.Binding.Scope.Generation++ },
	} {
		bad := proof
		change(&bad)
		bad.Signature = ed25519.Sign(f.a, FenceBytes(bad))
		_, e = f.s.RecordFence(bad)
		expectDenied(t, e)
	}
	bad := proof
	bad.Signature = ed25519.Sign(f.b, FenceBytes(bad))
	_, e = f.s.RecordFence(bad)
	expectDenied(t, e)
	_, e = f.s.CommitOwner(f.c, "admin", "move", f.s.Revision(), m.Binding.SourceOwnerRevision)
	expectDenied(t, e)
	f.set(f.s.RecordFence(proof))
	rev := f.s.Revision()
	f.set(f.s.RecordFence(proof))
	if f.s.Revision() != rev {
		t.Fatal("duplicate fence changed state")
	}
	manifest := f.manifest(m, [32]byte{1})
	f.set(f.s.BeginCopy(manifest))
	copy := f.copy(m, manifest)
	copy.Synced = false
	copy.Signature = ed25519.Sign(f.b, CopyBytes(copy))
	_, e = f.s.VerifyCopy(copy)
	expectDenied(t, e)
	copy = f.copy(m, manifest)
	copy.Artifact[0]++
	copy.Signature = ed25519.Sign(f.b, CopyBytes(copy))
	_, e = f.s.VerifyCopy(copy)
	expectDenied(t, e)
	_, _, e = f.s.Acquire(f.c, "admin", f.s.Revision(), "db", 2, true)
	expectDenied(t, e)
}

func TestVolumeColdMoveArmsBeforeTargetAndRetainsSource(t *testing.T) {
	f := makeFixture(t)
	old := f.acquire("db", 1, true)
	f.set(f.s.Release(f.gone(old)))
	m := f.prepare("move", f.target)
	f.verified(m, [32]byte{2})
	_, _, e := f.s.Acquire(f.c, "admin", f.s.Revision(), "db", 2, true)
	expectDenied(t, e)
	f.set(f.s.CommitOwner(f.c, "admin", "move", f.s.Revision(), m.Binding.SourceOwnerRevision))
	_, _, e = f.s.Acquire(f.c, "admin", f.s.Revision(), "db", 2, true)
	expectDenied(t, e)
	f.set(f.s.Arm(f.c, "admin", "move", f.s.Revision()))
	target := f.acquire("db", 2, true)
	g, e := NewGate(f.s.Scope(), f.target, [32]byte{1})
	if e != nil {
		t.Fatal(e)
	}
	g, r := gateRequest(t, g, target, 1)
	permit, e := f.s.PermitStart(f.c, "admin", r)
	if e != nil {
		t.Fatal(e)
	}
	g = gateAccept(t, g, permit)
	g = gateSettle(t, g, target, reconcile.EffectApplied)
	f.activate(m, target)
	f.cleanup(m)
	done, _ := f.s.Move("move")
	if done.Phase != Completed || !done.Irreversible || f.s.d.Active != "" || len(f.s.Retained()) != 1 || f.s.Retained()[0].Owner != f.source || target.Lease.Token <= old.Lease.Token {
		t.Fatal("incomplete ownership/retention")
	}
	_, e = f.s.Cancel(f.c, "admin", "move", f.s.Revision())
	expectDenied(t, e)
	retained := f.s.Retained()
	retained[0].Owner.Native = "tampered"
	if f.s.Retained()[0].Owner.Native == "tampered" {
		t.Fatal("view alias")
	}
}

func TestVolumeCancellationWaitsForBothSidesAndUsesFreshGeneration(t *testing.T) {
	f := makeFixture(t)
	old := f.acquire("db", 1, true)
	g, e := NewGate(f.s.Scope(), f.source, [32]byte{1})
	if e != nil {
		t.Fatal(e)
	}
	g, r := gateRequest(t, g, old, 1)
	stale, e := f.s.PermitStart(f.c, "admin", r)
	if e != nil {
		t.Fatal(e)
	}
	m := f.prepare("move", f.target)
	f.set(f.s.Cancel(f.c, "admin", "move", f.s.Revision()))
	_, e = f.s.FinishCancel(f.c, "admin", "move", f.s.Revision(), m.Binding.SourceOwnerRevision)
	expectDenied(t, e)
	bad := f.cancelProof(m)
	bad.StartsSettled = false
	bad.Signature = ed25519.Sign(f.b, CancelBytes(bad))
	_, e = f.s.RecordCancelTarget(bad)
	expectDenied(t, e)
	f.set(f.s.RecordCancelTarget(f.cancelProof(m)))
	f.set(f.s.Release(f.gone(old)))
	g, e = g.Fence(m.Binding.SourceOwnerRevision)
	if e != nil {
		t.Fatal(e)
	}
	_, e = g.Accept(stale)
	expectDenied(t, e)
	f.set(f.s.RecordFence(f.fence(m)))
	sourceClosed := CleanupProof{Binding: m.Binding, Owner: m.Binding.Source, TransferClosed: true, RetainedFenced: true}
	sourceClosed.Signature = ed25519.Sign(f.a, CleanupBytes(sourceClosed))
	f.set(f.s.RecordCleanup(sourceClosed))
	f.set(f.s.FinishCancel(f.c, "admin", "move", f.s.Revision(), m.Binding.SourceOwnerRevision))
	_, e = f.s.BeginCopy(f.manifest(m, [32]byte{1}))
	expectDenied(t, e)
	_, _, e = f.s.Acquire(f.c, "admin", f.s.Revision(), "db", 1, true)
	expectDenied(t, e)
	p := f.acquire("db", 2, true)
	if p.Owner != f.source || p.OwnerRevision <= m.Binding.SourceOwnerRevision {
		t.Fatal("no fresh source authority")
	}
	g, r = gateRequest(t, g, p, 2)
	permit, e := f.s.PermitStart(f.c, "admin", r)
	if e != nil {
		t.Fatal(e)
	}
	gateAccept(t, g, permit)
	f.set(f.s.RecordFence(f.fence(m))) // late identical receipt cannot roll back the new owner revision
	_, e = f.s.Prepare(f.c, "admin", f.s.Revision(), p.OwnerRevision, "move", f.target, [32]byte{22}, 1<<20)
	expectDenied(t, e)
}

func TestVolumeCommitAckLossCannotUndoNewWritesAndReverseUsesFreshCopy(t *testing.T) {
	f := makeFixture(t)
	m := f.prepare("move", f.target)
	f.verified(m, [32]byte{3})
	before := f.s
	candidate, e := before.CommitOwner(f.c, "admin", "move", before.Revision(), m.Binding.SourceOwnerRevision)
	if e != nil {
		t.Fatal(e)
	}
	// Fake store rejects publication: no new owner/start is visible.
	if owner, _ := before.Owner(); owner != f.source {
		t.Fatal("candidate mutated published state")
	}
	f.set(candidate, nil)
	committed := f.s.Revision()
	f.set(f.s.CommitOwner(f.c, "admin", "move", 0, m.Binding.SourceOwnerRevision))
	if f.s.Revision() != committed {
		t.Fatal("ACK loss re-committed")
	}
	_, e = f.s.Cancel(f.c, "admin", "move", f.s.Revision())
	expectDenied(t, e)
	f.set(f.s.Arm(f.c, "admin", "move", f.s.Revision()))
	p := f.acquire("db", 1, true)
	g, e := NewGate(f.s.Scope(), f.target, [32]byte{7})
	if e != nil {
		t.Fatal(e)
	}
	g, r := gateRequest(t, g, p, 1)
	permit, e := f.s.PermitStart(f.c, "admin", r)
	if e != nil {
		t.Fatal(e)
	}
	g = gateAccept(t, g, permit)
	// A native start already wrote recovery/data although its response is lost.
	g = gateSettle(t, g, p, reconcile.EffectUnknown)
	_, e = g.Fence(p.OwnerRevision)
	expectDenied(t, e)
	_, e = f.s.Cancel(f.c, "admin", "move", f.s.Revision())
	expectDenied(t, e)
	g = gateSettle(t, g, p, reconcile.EffectApplied)
	f.activate(m, p)
	f.cleanup(m)
	f.set(f.s.Release(f.gone(p)))
	_, e = f.s.Prepare(f.c, "admin", f.s.Revision(), p.OwnerRevision, "reverse-old", f.source, [32]byte{22}, 1<<20)
	expectDenied(t, e)
	fresh := f.source
	fresh.Native = "sfc-reverse-fresh"
	reverse := f.prepare("reverse", fresh)
	f.verified(reverse, [32]byte{99})
	f.set(f.s.CommitOwner(f.c, "admin", "reverse", f.s.Revision(), reverse.Binding.SourceOwnerRevision))
	f.set(f.s.Arm(f.c, "admin", "reverse", f.s.Revision()))
	newPin := f.acquire("db", 2, true)
	if newPin.Owner != fresh || len(f.s.Retained()) != 2 {
		t.Fatal("reverse adopted old data")
	}
	proof, _ := f.s.Move("reverse")
	if proof.Manifest.Artifact == ([32]byte{3}) {
		t.Fatal("reused pre-write artifact")
	}
}

func TestVolumeGateRejectsOldBootReplayedChallengeAndUnknownStartReset(t *testing.T) {
	f := makeFixture(t)
	p := f.acquire("db", 1, true)
	cached := f.s
	g, e := NewGate(f.s.Scope(), f.source, [32]byte{1})
	if e != nil {
		t.Fatal(e)
	}
	g, r := gateRequest(t, g, p, 1)
	permit, e := f.s.PermitStart(f.c, "admin", r)
	if e != nil {
		t.Fatal(e)
	}
	g = gateAccept(t, g, permit)
	g = gateSettle(t, g, p, reconcile.EffectUnknown)
	reboot, e := RestoreGate(g.Checkpoint(), [32]byte{2})
	if e != nil {
		t.Fatal(e)
	}
	_, e = reboot.Fence(p.OwnerRevision)
	expectDenied(t, e)
	_, _, e = reboot.Request(p, [32]byte{2})
	expectDenied(t, e)
	_, e = RestoreGate(g.Checkpoint(), [32]byte{1})
	expectDenied(t, e)
	reboot = gateSettle(t, reboot, p, reconcile.EffectApplied)
	reboot, r = gateRequest(t, reboot, p, 1)
	_, e = reboot.Accept(permit)
	expectDenied(t, e)
	newPermit, e := f.s.PermitStart(f.c, "admin", r)
	if e != nil {
		t.Fatal(e)
	}
	reboot = gateAccept(t, reboot, newPermit)
	reboot = gateSettle(t, reboot, p, reconcile.EffectNotApplied)
	reboot, r = gateRequest(t, reboot, p, 1)
	_, e = reboot.Accept(newPermit)
	expectDenied(t, e) // same nonce, different sequence
	latest, e := f.s.PermitStart(f.c, "admin", r)
	if e != nil {
		t.Fatal(e)
	}
	f.set(f.s.Release(f.gone(p)))
	m := f.prepare("move", f.target)
	reboot, e = reboot.Fence(m.Binding.SourceOwnerRevision)
	if e != nil {
		t.Fatal(e)
	}
	f.verified(m, [32]byte{5})
	f.set(f.s.CommitOwner(f.c, "admin", "move", f.s.Revision(), m.Binding.SourceOwnerRevision))
	_, e = f.s.PermitStart(f.c, "admin", r)
	expectDenied(t, e) // fresh quorum owner refuses restored stale local view
	if _, e = cached.PermitStart(f.c, "admin", r); e != nil {
		t.Fatal("fixture lost the stale-view counterexample")
	}
	_, e = reboot.Accept(latest)
	expectDenied(t, e) // local fence still rejects an in-flight old permit
	restored, e := RestoreGate(reboot.Checkpoint(), [32]byte{3})
	if e != nil {
		t.Fatal(e)
	}
	_, e = restored.Accept(latest)
	expectDenied(t, e)
}

func TestVolumeCancelCannotReleaseUnknownCopyAndEmptyArtifactIsValid(t *testing.T) {
	f := makeFixture(t)
	m := f.prepare("move", f.target)
	f.set(f.s.RecordFence(f.fence(m)))
	empty := f.manifest(m, [32]byte{45})
	empty.Bytes = 0
	empty.Files = 0
	empty.Signature = ed25519.Sign(f.a, ManifestBytes(empty))
	f.set(f.s.BeginCopy(empty))
	f.set(f.s.VerifyCopy(f.copy(m, empty)))
	f.set(f.s.Cancel(f.c, "admin", "move", f.s.Revision()))
	bad := f.cancelProof(m)
	bad.TransferClosed = false
	bad.Signature = ed25519.Sign(f.b, CancelBytes(bad))
	_, e := f.s.RecordCancelTarget(bad)
	expectDenied(t, e)
	f.set(f.s.RecordCancelTarget(f.cancelProof(m)))
	_, e = f.s.FinishCancel(f.c, "admin", "move", f.s.Revision(), m.Binding.SourceOwnerRevision)
	expectDenied(t, e)
	p := CleanupProof{Binding: m.Binding, Owner: m.Binding.Source, RetainedFenced: true}
	p.Signature = ed25519.Sign(f.a, CleanupBytes(p))
	_, e = f.s.RecordCleanup(p)
	expectDenied(t, e)
	p.TransferClosed = true
	p.Signature = ed25519.Sign(f.a, CleanupBytes(p))
	f.set(f.s.RecordCleanup(p))
	f.set(f.s.FinishCancel(f.c, "admin", "move", f.s.Revision(), m.Binding.SourceOwnerRevision))
	d := ownSnapshot(f.s.d)
	d.Moves[0].SourceCleanup = nil
	raw, _ := json.Marshal(d)
	_, e = Decode(raw)
	expectDenied(t, e)
	_, e = f.s.VerifyCopy(f.copy(m, empty))
	if e != nil {
		t.Fatal("original duplicate observation should return original result", e)
	}
}

func TestVolumeSnapshotsRejectErasedPinsForgedFencesAndEarlyOwner(t *testing.T) {
	f := makeFixture(t)
	p := f.acquire("db", 1, true)
	good, _ := f.s.Encode()
	for _, change := range []func(*snapshot){
		func(d *snapshot) { d.Pins.Active = nil }, func(d *snapshot) { d.Floors = nil }, func(d *snapshot) { d.Consumers[0].Writable = false; d.Consumers = append(d.Consumers, d.Consumers[0]) }, func(d *snapshot) { d.Owner = f.target }, func(d *snapshot) { d.Schema = 2 },
	} {
		d := ownSnapshot(f.s.d)
		change(&d)
		raw, _ := json.Marshal(d)
		_, e := Decode(raw)
		expectDenied(t, e)
	}
	if now, _ := f.s.Encode(); !bytes.Equal(good, now) {
		t.Fatal("snapshot mutation alias")
	}
	f.set(f.s.Release(f.gone(p)))
	m := f.prepare("move", f.target)
	f.verified(m, [32]byte{5})
	f.set(f.s.CommitOwner(f.c, "admin", "move", f.s.Revision(), m.Binding.SourceOwnerRevision))
	for _, change := range []func(*snapshot){
		func(d *snapshot) { d.Moves[0].Fence = nil }, func(d *snapshot) { d.Moves[0].Verified.Signature[0] ^= 1 }, func(d *snapshot) { d.Retained = nil }, func(d *snapshot) { d.Moves[0].Phase = Activating }, func(d *snapshot) { d.OwnerRevision-- }, func(d *snapshot) { d.Active = "" },
	} {
		d := ownSnapshot(f.s.d)
		change(&d)
		raw, _ := json.Marshal(d)
		_, e := Decode(raw)
		expectDenied(t, e)
	}
	view, _ := f.s.Move("move")
	view.Fence.Signature[0] ^= 1
	if _, e := f.s.Encode(); e != nil {
		t.Fatal("move view aliases state", e)
	}
}
