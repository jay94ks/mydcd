// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
)

func builtinObservation(f fixture, id string, reporter ed25519.PrivateKey, holders ...ed25519.PrivateKey) WriteObservation {
	w, _ := f.t.Write(id)
	p := WriteObservation{Cluster: f.t.cluster, Tenant: f.t.tenant, Request: w.Request, Generation: w.Generation, ExpectedObjectRevision: w.ExpectedObjectRevision, Writer: w.Writer, Operation: w.Journal.LastID, Outcome: reconcile.EffectApplied, ProviderRevision: w.Request.ExpectedProviderRevision + 1, Reporter: public(reporter), Digest: [32]byte{7}}
	for _, h := range holders {
		p.Holders = append(p.Holders, HolderReceipt{Voter: public(h), Signature: ed25519.Sign(h, HolderBytes(p, public(h)))})
	}
	p.Signature = ed25519.Sign(reporter, WriteObservationBytes(p))
	return p
}

func TestBuiltinProfileIsReservedAndNeedsSignedHolders(t *testing.T) {
	f := writable(t)
	if _, err := f.t.SetWriteProfile(f.c, "admin", f.t.Revision(), WriteProfile{ID: BuiltinProfile, Node: "node-a", Key: public(f.na), Enabled: true, Values: true}); err == nil {
		t.Fatal("installed profile took the builtin name")
	}
	if p, ok := f.t.WriteProfile(BuiltinProfile); !ok || !p.Builtin() {
		t.Fatal("tree has no builtin profile")
	}
	if _, err := f.t.Create(f.c, "alice", f.t.Revision(), Object{ID: "token", Parent: "common", Kind: Secret, Reference: Reference{Profile: BuiltinProfile, Object: "elsewhere", Keys: []string{"TOKEN"}}}); err == nil {
		t.Fatal("builtin secret chose a provider path")
	}
	n, err := f.t.Create(f.c, "alice", f.t.Revision(), Object{ID: "token", Parent: "common", Kind: Secret, Reference: Reference{Profile: BuiltinProfile, Object: "token", Keys: []string{"TOKEN"}}})
	f.t = mustTree(t, n, err)
	request := valueRequest(f, "write-token", "token")
	f = prepare(t, f, request)
	f = dispatch(t, f, request.ID)

	// A holder receipt for other bytes, a reporter that holds nothing, and
	// an unsigned holder are refused.
	bad := builtinObservation(f, request.ID, f.na, f.na)
	bad.Digest = [32]byte{8}
	bad.Signature = ed25519.Sign(f.na, WriteObservationBytes(bad))
	if _, err = f.t.ObserveWrite(bad); err == nil {
		t.Fatal("holder signed other bytes")
	}
	if _, err = f.t.ObserveWrite(builtinObservation(f, request.ID, f.na, f.nb)); err == nil {
		t.Fatal("reporter is not a holder")
	}
	unsorted := builtinObservation(f, request.ID, f.na, f.na, f.nb)
	if public(f.na)[0] < public(f.nb)[0] {
		unsorted = builtinObservation(f, request.ID, f.na, f.nb, f.na)
	}
	if _, err = f.t.ObserveWrite(unsorted); err == nil {
		t.Fatal("unsorted holders accepted")
	}
	first, second := f.na, f.nb
	if public(f.nb)[0] < public(f.na)[0] {
		first, second = f.nb, f.na
	}
	f = observe(t, f, builtinObservation(f, request.ID, f.na, first, second))
	o, _ := f.t.Object("token")
	n, err = f.t.PublishStored(f.c, "alice", request.ID, request.Epoch, o.Revision, f.t.Revision())
	f.t = mustTree(t, n, err)
	if o, _ = f.t.Object("token"); o.Reference.Revision != 1 || o.Status != Active {
		t.Fatal("builtin value not published", o.Reference, o.Status)
	}
	h, ok := f.t.BuiltinHolding(ValueWrite, "token", 1)
	if !ok || h.Digest != ([32]byte{7}) || len(h.Holders) != 2 || h.Holders[0] != public(first) {
		t.Fatal("published holding", h)
	}
	if _, ok = f.t.BuiltinHolding(ValueWrite, "token", 2); ok {
		t.Fatal("holding for an unpublished revision")
	}
	decoded, err := DecodeTree(encodedTree(t, f.t))
	if err != nil {
		t.Fatal("snapshot", err)
	}
	if again, ok := decoded.BuiltinHolding(ValueWrite, "token", 1); !ok || again.Digest != h.Digest {
		t.Fatal("holding lost in snapshot")
	}

	// An installed profile's observation cannot carry builtin fields.
	plain := valueRequest(f, "write-runtime", "runtime")
	f = prepare(t, f, plain)
	f = dispatch(t, f, plain.ID)
	p := observation(f, plain.ID, reconcile.EffectApplied)
	p.Digest = [32]byte{1}
	p = signObservation(f, p)
	if _, err = f.t.ObserveWrite(p); err == nil {
		t.Fatal("builtin fields on a Vault write")
	}
}

func TestDefaultProfileIsBuiltinWithoutAnInstalledOne(t *testing.T) {
	f := writable(t)
	if f.t.DefaultProfile(ValueWrite) != "vault" || f.t.DefaultProfile(VerifierWrite) != "auth" {
		t.Fatal("the only installed value profile is the default")
	}
	tree, err := NewTree(f.t.cluster, "tenant", "root")
	if err != nil {
		t.Fatal(err)
	}
	if tree.DefaultProfile(ValueWrite) != BuiltinProfile || tree.DefaultProfile(VerifierWrite) != BuiltinProfile {
		t.Fatal("builtin is the default without installed profiles")
	}
	n, err := f.t.Create(f.c, "alice", f.t.Revision(), Object{ID: "named", Parent: "common", Kind: Secret, Reference: Reference{Object: "tenant/named", Keys: []string{"K"}}})
	f.t = mustTree(t, n, err)
	if o, _ := f.t.Object("named"); o.Reference.Profile != f.t.DefaultProfile(ValueWrite) {
		t.Fatal("create took the default profile", o.Reference)
	}
}
