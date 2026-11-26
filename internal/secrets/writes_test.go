// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func writable(t *testing.T) fixture {
	t.Helper()
	f := makeFixture(t)
	for _, p := range []WriteProfile{{ID: "vault", Node: "node-a", Key: public(f.na), Enabled: true, Values: true}, {ID: "auth", Node: "node-b", Key: public(f.nb), Enabled: true, Verifiers: true}} {
		n, err := f.t.SetWriteProfile(f.c, "admin", f.t.Revision(), p)
		f.t = mustTree(t, n, err)
	}
	return f
}
func valueRequest(f fixture, id, object string) WriteRequest {
	o, _ := f.t.Object(object)
	return WriteRequest{ID: id, Object: object, Profile: o.Reference.Profile, ProviderObject: o.Reference.Object, Epoch: f.t.WriteEpoch(), ExpectedProviderRevision: o.Reference.Revision, Kind: ValueWrite, Keys: o.Reference.Keys}
}
func prepare(t *testing.T, f fixture, r WriteRequest) fixture {
	t.Helper()
	n, err := f.t.PrepareWrite(f.c, "alice", f.t.Revision(), r)
	f.t = mustTree(t, n, err)
	return f
}
func dispatch(t *testing.T, f fixture, id string) fixture {
	t.Helper()
	n, err := f.t.DispatchWrite(f.c, "alice", id, f.t.WriteEpoch(), f.t.Revision())
	f.t = mustTree(t, n, err)
	return f
}
func observation(f fixture, id string, outcome reconcile.Outcome) WriteObservation {
	w, _ := f.t.Write(id)
	p := WriteObservation{Cluster: f.t.cluster, Tenant: f.t.tenant, Request: w.Request, Generation: w.Generation, ExpectedObjectRevision: w.ExpectedObjectRevision, Writer: w.Writer, Operation: w.Journal.LastID, Outcome: outcome}
	if outcome == reconcile.EffectApplied {
		p.ProviderRevision = w.Request.ExpectedProviderRevision + 1
		if w.Request.Kind == VerifierWrite && w.Request.Protected {
			p.VerifierRef = "new-immutable-verifier"
		}
	}
	return signObservation(f, p)
}
func signObservation(f fixture, p WriteObservation) WriteObservation {
	k := f.na
	signer := p.Writer.Key
	if p.Observer != (WriteProfile{}) {
		signer = p.Observer.Key
	}
	if signer == public(f.nb) {
		k = f.nb
	}
	p.Signature = ed25519.Sign(k, WriteObservationBytes(p))
	return p
}
func observe(t *testing.T, f fixture, p WriteObservation) fixture {
	t.Helper()
	n, err := f.t.ObserveWrite(p)
	f.t = mustTree(t, n, err)
	return f
}
func abandon(t *testing.T, f fixture, id string) fixture {
	t.Helper()
	n, err := f.t.AbandonWrite(f.c, "admin", id, f.t.WriteEpoch(), f.t.Revision())
	f.t = mustTree(t, n, err)
	return f
}

func TestSecretOriginalWriteUnknownReceiptAndExplicitCASPublication(t *testing.T) {
	f := writable(t)
	request := valueRequest(f, "write-runtime", "runtime")
	f = prepare(t, f, request)
	f = dispatch(t, f, request.ID)
	f = observe(t, f, observation(f, request.ID, reconcile.EffectUnknown))
	w, _ := f.t.Write(request.ID)
	if w.Status() != "Unknown" || w.Journal.Pending == nil || w.Journal.Pending.ID != 1 {
		t.Fatal("unknown original intent lost")
	}
	if _, err := f.t.AbandonWrite(f.c, "admin", request.ID, request.Epoch, f.t.Revision()); err != reconcile.ErrPending {
		t.Fatal("unknown write abandoned", err)
	}
	if _, err := f.t.RotateWrites(f.c, "alice", f.t.Revision(), f.t.WriteEpoch()); err != reconcile.ErrPending {
		t.Fatal("unknown window discarded", err)
	}
	other := request
	other.ID = "another-write"
	if _, err := f.t.PrepareWrite(f.c, "alice", f.t.Revision(), other); err == nil {
		t.Fatal("new ID replaced unresolved effect")
	}
	n, err := DecodeTree(encodedTree(t, f.t))
	f.t = mustTree(t, n, err)
	f = observe(t, f, observation(f, request.ID, reconcile.EffectApplied))
	w, _ = f.t.Write(request.ID)
	o, _ := f.t.Object("runtime")
	if w.Status() != "StoredUnreferenced" || o.Reference.Revision != 1 {
		t.Fatal("provider stored falsely published metadata")
	}
	n, err = f.t.SetACL(f.c, "alice", o.ID, o.Revision, ACL{Users: []string{"alice"}})
	f.t = mustTree(t, n, err)
	before := encodedTree(t, f.t)
	n, err = f.t.PublishStored(f.c, "alice", request.ID, request.Epoch, w.ExpectedObjectRevision, f.t.Revision())
	if err != access.ErrConflict || !bytes.Equal(before, encodedTree(t, n)) {
		t.Fatal("CAS conflict discarded receipt", err)
	}
	o, _ = f.t.Object("runtime")
	n, err = f.t.PublishStored(f.c, "alice", request.ID, request.Epoch, o.Revision, f.t.Revision())
	f.t = mustTree(t, n, err)
	w, _ = f.t.Write(request.ID)
	o, _ = f.t.Object("runtime")
	if w.Status() != "Published" || o.Reference.Revision != 2 || o.PendingWrite != "" {
		t.Fatal("original receipt not atomically published")
	}
	if _, err = DecodeTree(encodedTree(t, f.t)); err != nil {
		t.Fatal(err)
	}
}
func TestSecretReadbackAfterWriterReplacementKeepsOriginalIntent(t *testing.T) {
	f := writable(t)
	request := valueRequest(f, "original-write", "runtime")
	f = prepare(t, f, request)
	f = dispatch(t, f, request.ID)
	f = observe(t, f, observation(f, request.ID, reconcile.EffectUnknown))
	original, _ := f.t.Write(request.ID)
	p := f.t.profiles["vault"]
	p.Node = "node-b"
	p.Key = public(f.nb)
	p.Revision = 0
	n, err := f.t.SetWriteProfile(f.c, "admin", f.t.Revision(), p)
	f.t = mustTree(t, n, err)
	proof := observation(f, request.ID, reconcile.EffectApplied)
	proof.Observer = f.t.profiles["vault"]
	proof = signObservation(f, proof)
	bad := proof
	bad.Outcome = reconcile.EffectNotApplied
	bad.ProviderRevision = 0
	bad = signObservation(f, bad)
	if _, err = f.t.ObserveWrite(bad); err == nil {
		t.Fatal("new observer's absence declared non-execution")
	}
	unknown := proof
	unknown.Outcome = reconcile.EffectUnknown
	unknown.ProviderRevision = 0
	unknown = signObservation(f, unknown)
	f = observe(t, f, unknown)
	w, _ := f.t.Write(request.ID)
	if w.Status() != "Unknown" {
		t.Fatal("readback absence lost unknown")
	}
	f = observe(t, f, proof)
	w, _ = f.t.Write(request.ID)
	if w.Status() != "StoredUnreferenced" || w.Writer != original.Writer || !sameRequest(w.Request, original.Request) || w.Observation.Observer.Key != public(f.nb) {
		t.Fatal("recovery replaced original operation")
	}
	o, _ := f.t.Object("runtime")
	n, err = f.t.PublishStored(f.c, "alice", request.ID, request.Epoch, o.Revision, f.t.Revision())
	f.t = mustTree(t, n, err)
	p = f.t.profiles["vault"]
	p.Enabled = false
	p.Revision = 0
	n, err = f.t.SetWriteProfile(f.c, "admin", f.t.Revision(), p)
	f.t = mustTree(t, n, err)
	if _, err = DecodeTree(encodedTree(t, f.t)); err != nil {
		t.Fatal("settled historical observer invalidated by new policy", err)
	}
}

func TestSecretInitialValueRemainsPendingUntilStoredReceipt(t *testing.T) {
	f := writable(t)
	n, err := f.t.Create(f.c, "alice", f.t.Revision(), Object{ID: "initial", Parent: "root", Kind: Secret, Reference: Reference{Profile: "vault", Object: "tenant/initial", Keys: []string{"KEY"}}})
	f.t = mustTree(t, n, err)
	u := web(f)
	u.Sources = []string{"initial"}
	if _, err = f.t.Plan(f.c, []Use{u}); err != access.ErrDenied {
		t.Fatal("missing first value selected")
	}
	request := valueRequest(f, "first-write", "initial")
	f = prepare(t, f, request)
	o, _ := f.t.Object("initial")
	if _, err = f.t.PublishReference(f.c, "alice", o.ID, o.Revision, Reference{Profile: "vault", Object: "tenant/initial", Revision: 1, Keys: []string{"KEY"}}); err == nil {
		t.Fatal("raw reference bypassed pending write")
	}
	f = dispatch(t, f, request.ID)
	proof := observation(f, request.ID, reconcile.EffectApplied)
	for _, mutate := range []func(*WriteObservation){func(p *WriteObservation) { p.Cluster[0]++ }, func(p *WriteObservation) { p.Request.ProviderObject = "other/path" }, func(p *WriteObservation) { p.Request.ID = "other-write" }, func(p *WriteObservation) { p.Operation++ }, func(p *WriteObservation) { p.ProviderRevision = 0 }} {
		bad := proof
		bad.Request = ownRequest(bad.Request)
		mutate(&bad)
		bad = signObservation(f, bad)
		if _, err = f.t.ObserveWrite(bad); err == nil {
			t.Fatal("wrong original effect accepted")
		}
	}
	f = observe(t, f, proof)
	o, _ = f.t.Object("initial")
	n, err = f.t.PublishStored(f.c, "alice", request.ID, request.Epoch, o.Revision, f.t.Revision())
	f.t = mustTree(t, n, err)
	if _, err = f.t.Plan(f.c, []Use{u}); err != nil {
		t.Fatal(err)
	}
}
func TestSecretVerifierRevokeSettlesOriginalEffectAndRejectsOldEpoch(t *testing.T) {
	f := writable(t)
	o, _ := f.t.Object("common")
	request := WriteRequest{ID: "change-common", Object: o.ID, Profile: "auth", ProviderObject: verifierObject(f.t.tenant, o.ID, o.Generation), Epoch: f.t.WriteEpoch(), Kind: VerifierWrite, Protected: true}
	f = prepare(t, f, request)
	o, _ = f.t.Object("common")
	if _, err := f.t.ActivatePassword(f.c, "alice", o.ID, request.ID, "guessed-verifier", true, o.Revision); err == nil {
		t.Fatal("unknown verifier activated")
	}
	f = dispatch(t, f, request.ID)
	f = observe(t, f, observation(f, request.ID, reconcile.EffectUnknown))
	o, _ = f.t.Object("common")
	n, err := f.t.Revoke(f.c, "alice", o.ID, o.Revision)
	f.t = mustTree(t, n, err)
	o, _ = f.t.Object("common")
	if o.PasswordChange != request.ID || o.PendingWrite != request.ID {
		t.Fatal("revoke erased original verifier write")
	}
	profile := f.t.profiles["auth"]
	profile.Enabled = false
	profile.Revision = 0
	n, err = f.t.SetWriteProfile(f.c, "admin", f.t.Revision(), profile)
	f.t = mustTree(t, n, err)
	proof := observation(f, request.ID, reconcile.EffectApplied)
	f = observe(t, f, proof)
	if _, err = f.t.PublishStored(f.c, "alice", request.ID, request.Epoch, o.Revision, f.t.Revision()); err == nil {
		t.Fatal("revoked verifier published")
	}
	f = abandon(t, f, request.ID)
	o, _ = f.t.Object("common")
	if o.Status != Revoking || o.PendingWrite != "" || o.PasswordChange != "" || o.VerifierRef != "credential-common" {
		t.Fatal("abandonment revived or changed old policy")
	}
	n, err = DecodeTree(encodedTree(t, f.t))
	f.t = mustTree(t, n, err)
	n, err = f.t.RotateWrites(f.c, "alice", f.t.Revision(), request.Epoch)
	f.t = mustTree(t, n, err)
	if _, err = f.t.ObserveWrite(proof); err == nil {
		t.Fatal("old epoch replayed")
	}
	if _, err = f.t.PrepareWrite(f.c, "alice", f.t.Revision(), request); err == nil {
		t.Fatal("old epoch opened new write")
	}
}
func TestSecretUnsentAndTerminalRejectionPreserveOriginalReference(t *testing.T) {
	f := writable(t)
	r := valueRequest(f, "never-sent", "runtime")
	f = prepare(t, f, r)
	f = abandon(t, f, r.ID)
	w, _ := f.t.Write(r.ID)
	if w.Journal.Applied.Present || w.Journal.Pending != nil || w.Status() != "Abandoned" {
		t.Fatal("never dispatched effect fabricated")
	}
	r = valueRequest(f, "rejected", "runtime")
	f = prepare(t, f, r)
	f = dispatch(t, f, r.ID)
	m, _ := f.c.Membership("tenant", "alice")
	expected := m.Revision
	m.Revision = 0
	m.Enabled = false
	c, err := f.c.SetMembership("admin", expected, m)
	if err != nil {
		t.Fatal(err)
	}
	f.c = c
	f = observe(t, f, observation(f, r.ID, reconcile.EffectNotApplied))
	w, _ = f.t.Write(r.ID)
	if w.Status() != "NotApplied" {
		t.Fatal("terminal rejection not retained")
	}
	if _, err = f.t.PublishStored(f.c, "alice", r.ID, r.Epoch, w.ExpectedObjectRevision, f.t.Revision()); err != access.ErrDenied {
		t.Fatal("revoked actor published", err)
	}
	f = abandon(t, f, r.ID)
	o, _ := f.t.Object("runtime")
	if o.Reference.Revision != 1 {
		t.Fatal("rejection changed old reference")
	}
	if _, err = DecodeTree(encodedTree(t, f.t)); err != nil {
		t.Fatal(err)
	}
}
func useGone(f fixture, g Grant) UseGone {
	p := UseGone{Cluster: f.t.cluster, Realm: g.Realm, Tenant: g.Use.Tenant, App: g.Use.App, Deployment: g.Use.Deployment, Consumer: g.Consumer, Generation: g.Generation, NodeKey: g.Use.NodeKey, Selection: g.Selection, Lifetime: g.Lifetime, Stopped: true, MountsGone: true}
	key := f.na
	if p.NodeKey == public(f.nb) {
		key = f.nb
	}
	p.Signature = ed25519.Sign(key, UseGoneBytes(p))
	return p
}
func TestSecretUnprotectedMovedUseBlocksDeletionUntilOriginalClosure(t *testing.T) {
	f := makeFixture(t)
	n, err := f.t.Create(f.c, "alice", f.t.Revision(), Object{ID: "loose", Parent: "root", Kind: Group})
	f.t = mustTree(t, n, err)
	n, err = f.t.Create(f.c, "alice", f.t.Revision(), Object{ID: "leaf", Parent: "loose", Kind: Secret, Reference: Reference{Profile: "vault", Object: "tenant/leaf", Revision: 1, Keys: []string{"KEY"}}})
	f.t = mustTree(t, n, err)
	u := web(f)
	u.Sources = []string{"leaf"}
	var grant Grant
	f, grant = acquire(t, f, u, "unprotected-instance", 1)
	if len(grant.Pins) != 0 || grant.Lifetime.Token == 0 {
		t.Fatal("unprotected use lost lifetime pin")
	}
	o, _ := f.t.Object("leaf")
	n, err = f.t.Move(f.c, "alice", o.ID, "root", o.Revision)
	f.t = mustTree(t, n, err)
	if _, err = f.a.ReadSet(f.c, f.t, grant, 110); err == nil {
		t.Fatal("old metadata plan reused moved authorization")
	}
	o, _ = f.t.Object("loose")
	n, err = f.t.Revoke(f.c, "alice", o.ID, o.Revision)
	f.t = mustTree(t, n, err)
	o, _ = f.t.Object("loose")
	if _, err = f.t.Retire(f.c, "alice", o.ID, o.Revision, f.a); err == nil {
		t.Fatal("move erased original group dependency")
	}
	book, err := DecodeApprovals(encodedBook(t, f.a))
	f.a = mustBook(t, book, err)
	p := useGone(f, grant)
	bad := p
	bad.MountsGone = false
	bad.Signature = ed25519.Sign(f.na, UseGoneBytes(bad))
	if _, err = f.a.ReleaseUse(bad); err == nil {
		t.Fatal("live mount released usage")
	}
	book, err = f.a.ReleaseUse(p)
	f.a = mustBook(t, book, err)
	if _, err = f.a.ReleaseUse(p); err == nil {
		t.Fatal("old lifetime released another usage")
	}
	n, err = f.t.Retire(f.c, "alice", o.ID, o.Revision, f.a)
	f.t = mustTree(t, n, err)
	o, _ = f.t.Object("loose")
	if o.Status != Retired {
		t.Fatal("tombstone missing")
	}
	if _, err = f.t.Create(f.c, "alice", f.t.Revision(), Object{ID: "loose", Parent: "root", Kind: Group}); err != access.ErrConflict {
		t.Fatal("retired ID reused", err)
	}
	if _, err = DecodeTree(encodedTree(t, f.t)); err != nil {
		t.Fatal(err)
	}
}
func TestSecretWriteAndUsageSnapshotsRejectForgedPendingOrMissingPins(t *testing.T) {
	f := writable(t)
	f = prepare(t, f, valueRequest(f, "pending-write", "runtime"))
	var tr treeRecord
	json.Unmarshal(encodedTree(t, f.t), &tr)
	tr.Writes[0].Journal.Pending.Target.Spec = "another operation"
	bad, _ := json.Marshal(tr)
	if _, err := DecodeTree(bad); err == nil {
		t.Fatal("altered journal target accepted")
	}
	f = approved(t)
	var grant Grant
	f, grant = acquire(t, f, web(f), "instance", 1)
	var ar approvalsRecord
	json.Unmarshal(encodedBook(t, f.a), &ar)
	ar.Usages = nil
	bad, _ = json.Marshal(ar)
	if _, err := DecodeApprovals(bad); err == nil {
		t.Fatal("missing lifetime usage accepted")
	}
	p := useGone(f, grant)
	p.NodeKey = public(f.nb)
	p.Signature = ed25519.Sign(f.nb, UseGoneBytes(p))
	if _, err := f.a.ReleaseUse(p); err == nil {
		t.Fatal("other node returned usage")
	}
	book, err := f.a.ReleaseUse(useGone(f, grant))
	f.a = mustBook(t, book, err)
	if _, err = DecodeApprovals(encodedBook(t, f.a)); err != nil {
		t.Fatal("atomic all-pin release snapshot", err)
	}
}
