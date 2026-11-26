// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"testing"
)

func changeTarget(f fixture, tenant, id, cidr string) Network {
	return definition(tenant, id, "node-b", cidr, f.b)
}
func candidateClose(n Networks, ch NetworkChange, k ed25519.PrivateKey) ChangeCandidateClose {
	p := ChangeCandidateClose{Cluster: n.cluster, Change: ch.ID, Generation: ch.Generation, TargetRevision: ch.TargetRevision, Target: ChangeTargetHash(ch.Target), Owner: ch.Target.Owner, Boot: [32]byte{9}, Native: CandidateNativeID(ch), Fenced: true, Gone: true, NoPending: true}
	p.Signature = ed25519.Sign(k, ChangeCandidateBytes(p))
	return p
}
func changeSourceClose(n Networks, ch NetworkChange, k ed25519.PrivateKey) NetworkClosure {
	v, _ := n.Network(ch.Original.Tenant, ch.Original.ID)
	p := NetworkClosure{Cluster: n.cluster, Tenant: v.Tenant, Network: v.ID, Node: v.Node, Owner: v.Owner, Generation: v.Generation, Revision: v.Revision, NativeGone: true}
	p.Signature = ed25519.Sign(k, NetworkClosureBytes(p))
	return p
}
func changePlan(t *testing.T, f fixture, target Network) fixture {
	t.Helper()
	v, _ := f.n.Network("first", "lan")
	var e error
	f.n, e = f.n.PlanChange(f.c, "admin", "first", "lan", "move", v.Revision, target)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func TestNetworkChangeReservesCandidateAgainstBothLiveAndPlannedCIDRs(t *testing.T) {
	f := two(t)
	v, _ := f.n.Network("first", "lan")
	target := changeTarget(f, "first", "lan", "10.9.0.0/24")
	f = changePlan(t, f, target)
	current, _ := f.n.Network("first", "lan")
	if current.PendingChange == 0 {
		t.Fatal("network lost active plan marker")
	}
	current.PendingChange = 0
	if !sameNetwork(v, current) {
		t.Fatal("reservation changed original serving policy")
	}
	raw := snapshotBytes(t, f.n)
	again, e := f.n.PlanChange(f.c, "admin", "first", "lan", "move", v.Revision, target)
	if e != nil || !bytes.Equal(raw, snapshotBytes(t, again)) {
		t.Fatal("same request changed plan", e)
	}
	bad := ownNetwork(target)
	bad.Pools[0].MTU--
	if _, e = f.n.PlanChange(f.c, "admin", "first", "lan", "move", v.Revision, bad); e == nil {
		t.Fatal("same original request rewritten")
	}
	if _, e = f.n.Create(f.c, "admin", f.n.Revision(), definition("third", "stolen", "node-a", "10.9.0.128/25", f.a)); e == nil {
		t.Fatal("another network stole reserved candidate CIDR")
	}
	second, _ := f.n.Network("second", "lan")
	if _, e = f.n.PlanChange(f.c, "admin", "second", "lan", "other", second.Revision, changeTarget(f, "second", "lan", "10.9.0.0/24")); e == nil {
		t.Fatal("two pending changes reserved same CIDR")
	}
	if _, e = f.n.PlanChange(f.c, "admin", "second", "lan", "other", second.Revision, changeTarget(f, "second", "lan", "10.1.0.0/24")); e == nil {
		t.Fatal("target overlapped another live network")
	}
	restored, e := Decode(raw)
	if e != nil || !bytes.Equal(raw, snapshotBytes(t, restored)) {
		t.Fatal(e)
	}
}
func TestNetworkChangeCancellationRequiresOriginalCandidateNoPendingProof(t *testing.T) {
	f := changePlan(t, two(t), changeTarget(two(t), "first", "lan", "10.9.0.0/24"))
	ch, _ := f.n.Change("first", "lan")
	p := candidateClose(f.n, ch, f.b)
	bad := p
	bad.NoPending = false
	bad.Signature = ed25519.Sign(f.b, ChangeCandidateBytes(bad))
	if _, e := f.n.CancelChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, bad); e == nil {
		t.Fatal("unknown candidate work freed reservation")
	}
	var e error
	f.n, e = f.n.CancelChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, p)
	if e != nil {
		t.Fatal(e)
	}
	v, _ := f.n.Network("first", "lan")
	if v.Draining || v.Generation != ch.Original.Generation {
		t.Fatal("pre-switch rollback disturbed original")
	}
	f.n, e = f.n.Create(f.c, "admin", f.n.Revision(), definition("third", "released", "node-a", "10.9.0.0/24", f.a))
	if e != nil {
		t.Fatal("candidate reservation not freed after positive closure", e)
	}
	if _, e = Decode(snapshotBytes(t, f.n)); e != nil {
		t.Fatal(e)
	}
}
func TestNetworkChangeIrreversibleRecoveryUsesFreshTargetAndNeverUndrainsOriginal(t *testing.T) {
	f := two(t)
	f = changePlan(t, f, changeTarget(f, "first", "lan", "10.9.0.0/24"))
	ch, _ := f.n.Change("first", "lan")
	var e error
	f.n, e = f.n.BeginChangeDrain(f.c, "admin", "first", "lan", ch.Generation, ch.Revision)
	if e != nil {
		t.Fatal(e)
	}
	ch, _ = f.n.Change("first", "lan")
	if _, e = f.n.CancelChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, candidateClose(f.n, ch, f.b)); e == nil {
		t.Fatal("Drain reversed original generation")
	}
	f.n, e = f.n.FenceChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, changeSourceClose(f.n, ch, f.a))
	if e != nil {
		t.Fatal(e)
	}
	ch, _ = f.n.Change("first", "lan")
	first := candidateClose(f.n, ch, f.b)
	target := ownNetwork(ch.Original)
	target.Generation = 0
	target.Revision = 0
	target.Draining = false
	f.n, e = f.n.RecoverChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, target, first)
	if e != nil {
		t.Fatal(e)
	}
	ch, _ = f.n.Change("first", "lan")
	raw := snapshotBytes(t, f.n)
	f.n, e = Decode(raw)
	if e != nil {
		t.Fatal("recovery snapshot", e)
	}
	if _, e = f.n.RecoverChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, target, first); e == nil {
		t.Fatal("old candidate closure applied to new target revision")
	}
	// A second explicit recovery can skip unrelated catalog revisions and still
	// preserve each exact prior target, rather than assuming contiguous epochs.
	second := candidateClose(f.n, ch, f.a)
	other := changeTarget(f, "first", "lan", "10.10.0.0/24")
	f.n, e = f.n.RecoverChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, other, second)
	if e != nil {
		t.Fatal(e)
	}
	ch, _ = f.n.Change("first", "lan")
	f.n, e = Decode(snapshotBytes(t, f.n))
	if e != nil {
		t.Fatal("second recovery snapshot", e)
	}
	f.n, e = f.n.CommitChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision)
	if e != nil {
		t.Fatal(e)
	}
	now, _ := f.n.Network("first", "lan")
	if now.Generation <= ch.Original.Generation || now.Draining || now.Node != "node-b" || now.Pools[0].Prefix != netip.MustParsePrefix("10.10.0.0/24") {
		t.Fatal("recovery restored old generation")
	}
	if _, e = Decode(snapshotBytes(t, f.n)); e != nil {
		t.Fatal(e)
	}
}
func TestNetworkChangeSnapshotRejectsMissingFenceCandidateIdentityAndRecoveryHistory(t *testing.T) {
	f := two(t)
	f = changePlan(t, f, changeTarget(f, "first", "lan", "10.9.0.0/24"))
	ch, _ := f.n.Change("first", "lan")
	var e error
	f.n, e = f.n.BeginChangeDrain(f.c, "admin", "first", "lan", ch.Generation, ch.Revision)
	if e != nil {
		t.Fatal(e)
	}
	ch, _ = f.n.Change("first", "lan")
	f.n, e = f.n.FenceChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, changeSourceClose(f.n, ch, f.a))
	if e != nil {
		t.Fatal(e)
	}
	ch, _ = f.n.Change("first", "lan")
	f.n, e = f.n.RecoverChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, changeTarget(f, "first", "lan", "10.10.0.0/24"), candidateClose(f.n, ch, f.b))
	if e != nil {
		t.Fatal(e)
	}
	raw := snapshotBytes(t, f.n)
	for _, mutate := range []func(*snapshot){func(s *snapshot) { s.Changes[0].SourceClosed = nil }, func(s *snapshot) { s.Changes[0].Previous = nil }, func(s *snapshot) { s.Changes[0].Previous[0].Closed.Signature = nil }, func(s *snapshot) { s.Changes[0].TargetRevision++ }, func(s *snapshot) { s.Changes[0].Phase = ChangeReserved }, func(s *snapshot) { s.Changes[0].Target.Pools[0].Prefix = netip.MustParsePrefix("10.2.0.0/24") }} {
		var s snapshot
		json.Unmarshal(raw, &s)
		mutate(&s)
		bad, _ := json.Marshal(s)
		if _, e = Decode(bad); e == nil {
			t.Fatal("missing/foreign original transition restored")
		}
	}
}

func TestNetworkChangeSnapshotCannotEraseActivePlanOrItsNetworkMarker(t *testing.T) {
	f := two(t)
	f = changePlan(t, f, changeTarget(f, "first", "lan", "10.9.0.0/24"))
	raw := snapshotBytes(t, f.n)
	for _, change := range []func(*snapshot){func(s *snapshot) { s.Changes = nil }, func(s *snapshot) {
		for i := range s.Networks {
			s.Networks[i].PendingChange = 0
		}
	}, func(s *snapshot) {
		for i := range s.Networks {
			if s.Networks[i].PendingChange != 0 {
				s.Networks[i].PendingChange++
			}
		}
	}} {
		var s snapshot
		json.Unmarshal(raw, &s)
		change(&s)
		bad, _ := json.Marshal(s)
		if _, e := Decode(bad); e == nil {
			t.Fatal("active plan/reservation could be independently erased")
		}
	}
}
