// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
)

type routeFixture struct {
	f     networkFixture
	a, b  RouteRuntime
	keyB  ed25519.PrivateKey
	tuple RouteTuple
}

func routeCoreFixture(t *testing.T) routeFixture {
	t.Helper()
	return routeCoreFixtureProtocol(t, 6)
}
func routeCoreFixtureProtocol(t *testing.T, protocol uint8) routeFixture {
	t.Helper()
	f := fixture(t)
	kb := private(32)
	var e error
	f.c, e = f.c.CreateTenant("admin", "second", 0)
	if e != nil {
		t.Fatal(e)
	}
	v, _ := f.c.Tenant("second")
	f.c, e = f.c.SetNodes("admin", "second", v.Revision, []string{"node-b"})
	if e != nil {
		t.Fatal(e)
	}
	f.n, e = f.n.Create(f.c, "admin", f.n.Revision(), tenancy.Network{Tenant: "second", ID: "lan", Node: "node-b", Owner: pub(kb), Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.43.0.0/24"), Gateway: addr("10.43.0.1"), MTU: 1500}}})
	if e != nil {
		t.Fatal(e)
	}
	f.a, e = f.a.SyncPools(f.n)
	if e != nil {
		t.Fatal(e)
	}
	var src, dst network.Allocation
	f.a, src, e = f.a.ReserveStatic("php", poolOwner(Source{Owner: pub(f.key)}), "first/lan", "first/lan/pool", 1, addr("10.42.0.10"))
	if e != nil {
		t.Fatal(e)
	}
	f.a, dst, e = f.a.ReserveStatic("sql", poolOwner(Source{Owner: pub(kb)}), "second/lan", "second/lan/pool", 1, addr("10.43.0.10"))
	if e != nil {
		t.Fatal(e)
	}
	sb, _ := f.n.Bind("first", "lan", netip.MustParsePrefix("10.42.0.0/24"))
	db, _ := f.n.Bind("second", "lan", netip.MustParsePrefix("10.43.0.0/24"))
	f.n, e = f.n.Propose(f.c, "admin", f.n.Revision(), tenancy.Route{ID: "sql", Source: sb, Destination: db, Protocol: protocol, Ports: []tenancy.Ports{{First: 3306, Last: 3306}}})
	if e != nil {
		t.Fatal(e)
	}
	for _, side := range []string{"first", "second"} {
		r, _ := f.n.Route("first", "sql")
		f.n, e = f.n.Approve(f.c, "admin", "first", "sql", side, r.Revision)
		if e != nil {
			t.Fatal(e)
		}
	}
	var ca, cb ReferenceConsumer
	f.a, ca, e = f.a.GrantRouteInstance(f.c, f.n, "admin", "first", "sql", "first", 0)
	if e != nil {
		t.Fatal(e)
	}
	f.a, cb, e = f.a.GrantRouteInstance(f.c, f.n, "admin", "first", "sql", "second", 0)
	if e != nil {
		t.Fatal(e)
	}
	a, e := NewRouteRuntime(f.c, f.n, f.a, ca.ID, f.boot, 2)
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewRouteRuntime(f.c, f.n, f.a, cb.ID, [32]byte{9}, 2)
	if e != nil {
		t.Fatal(e)
	}
	return routeFixture{f, a, b, kb, RouteTuple{Source: src, Destination: dst, SourcePort: 41000, DestinationPort: 3306, Protocol: protocol}}
}
func routeRaw(t *testing.T, m RouteRuntime) []byte {
	t.Helper()
	raw, e := m.Encode()
	if e != nil {
		t.Fatal("invalid runtime candidate", e)
	}
	return raw
}
func routeNative(t *testing.T, m RouteRuntime, key ed25519.PrivateKey) RouteNativeProof {
	t.Helper()
	op := m.state.Pending
	if op == nil {
		t.Fatal("no original pending native operation")
	}
	p := RouteNativeProof{Cluster: m.consumer.Local.Cluster, Reference: referenceNeed(m.consumer), Boot: m.boot, Native: routeNativeKey(m.consumer), Spec: op.Target.Spec, Operation: op.ID, Kind: op.Kind, Outcome: reconcile.EffectApplied, JournalSynced: true, Installed: op.Kind == reconcile.Apply, Gone: op.Kind == reconcile.Remove}
	p.Signature = ed25519.Sign(key, RouteNativeBytes(p))
	return p
}
func routeInstall(t *testing.T, m RouteRuntime, key ed25519.PrivateKey) RouteRuntime {
	t.Helper()
	var e error
	var op *reconcile.Operation
	m, op, e = m.Plan()
	if e != nil || op == nil {
		t.Fatal(op, e)
	}
	m, e = m.Dispatch(op.ID)
	if e != nil {
		t.Fatal(e)
	}
	m, e = m.ObserveNative(routeNative(t, m, key))
	if e != nil {
		t.Fatal(e)
	}
	routeRaw(t, m)
	return m
}
func routeBoth(t *testing.T) routeFixture {
	t.Helper()
	r := routeCoreFixture(t)
	r.a = routeInstall(t, r.a, r.f.key)
	r.b = routeInstall(t, r.b, r.keyB)
	return r
}
func routeClock(m RouteRuntime, at int64) Clock {
	return Clock{Boot: m.boot, Wall: at, Mono: at, Certain: true}
}
func routeBorrow(t *testing.T, r routeFixture) (routeFixture, RouteFlow, RouteFlow) {
	t.Helper()
	pb, e := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	if e != nil {
		t.Fatal(e)
	}
	pa, e := r.a.AppliedProof(r.f.c, r.f.n, r.f.a)
	if e != nil {
		t.Fatal(e)
	}
	var a, b RouteFlow
	r.a, a, e = r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, pb, r.b.boot, r.tuple, routeClock(r.a, 150))
	if e != nil {
		t.Fatal(e)
	}
	r.b, b, e = r.b.BorrowFlow(r.f.c, r.f.n, r.f.a, pa, r.a.boot, r.tuple, routeClock(r.b, 150))
	if e != nil {
		t.Fatal(e)
	}
	return r, a, b
}
func routeFlowProof(m RouteRuntime, h RouteFlow, key ed25519.PrivateKey) RouteFlowClose {
	p := RouteFlowClose{Cluster: m.consumer.Local.Cluster, Reference: referenceNeed(m.consumer), Boot: m.boot, Pin: h.pin, Tuple: tupleHash(h.tuple), Native: routeNativeKey(m.consumer) + "/flow/" + generationText(h.pin.Token), JournalSynced: true, Stopped: true, NoPending: true}
	p.Signature = ed25519.Sign(key, RouteFlowCloseBytes(p))
	return p
}
func routeWithdraw(t *testing.T, r routeFixture) routeFixture {
	t.Helper()
	p, _ := r.f.n.Route("first", "sql")
	var e error
	r.f.n, e = r.f.n.Withdraw(r.f.c, "admin", "first", "sql", "first", p.Revision)
	if e != nil {
		t.Fatal(e)
	}
	r.a, e = r.a.Sync(r.f.c, r.f.n, r.f.a)
	if e != nil {
		t.Fatal(e)
	}
	r.b, e = r.b.Sync(r.f.c, r.f.n, r.f.a)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func routeRefProof(t *testing.T, m RouteRuntime, a Authority, target [32]byte, key ed25519.PrivateKey, at int64) ReferenceClose {
	t.Helper()
	p, e := m.ReferenceFacts(a, target, routeClock(m, at))
	if e != nil {
		t.Fatal(e)
	}
	if p.Settled {
		t.Fatal("metadata claimed native work stopped")
	}
	// Fake native collector establishes original fence/worker/conntrack/journal facts.
	p.Settled = true
	p.Signature = ed25519.Sign(key, ReferenceCloseBytes(p))
	return p
}
func routeGoneProof(t *testing.T, m RouteRuntime, n tenancy.Networks, key ed25519.PrivateKey) tenancy.RouteClosure {
	t.Helper()
	p, e := m.RouteClosureFacts(n)
	if e != nil {
		t.Fatal(e)
	}
	if p.NativeGone {
		t.Fatal("metadata claimed native completion")
	}
	p.NativeGone = true
	p.Signature = ed25519.Sign(key, tenancy.RouteClosureBytes(p))
	return p
}

func TestRouteRuntimeNeedsBothNativeOwnersAndCurrentPeerBoot(t *testing.T) {
	r := routeCoreFixture(t)
	before := routeRaw(t, r.a)
	if _, e := r.a.AppliedProof(r.f.c, r.f.n, r.f.a); e == nil {
		t.Fatal("policy approval became native Ready")
	}
	r.a = routeInstall(t, r.a, r.f.key)
	if bytes.Equal(before, routeRaw(t, r.a)) {
		t.Fatal("native journal unchanged")
	}
	if _, _, e := r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, RouteNativeProof{}, r.b.boot, r.tuple, routeClock(r.a, 150)); e == nil {
		t.Fatal("one native owner admitted flow")
	}
	r.b = routeInstall(t, r.b, r.keyB)
	p, e := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, p, [32]byte{99}, r.tuple, routeClock(r.a, 150)); e == nil {
		t.Fatal("old boot proof admitted on new authenticated peer")
	}
	r, h, k := routeBorrow(t, r)
	for _, v := range []struct {
		m    RouteRuntime
		h    RouteFlow
		boot [32]byte
	}{{r.a, h, r.b.boot}, {r.b, k, r.a.boot}} {
		if !v.m.AllowsPacket(r.f.c, r.f.n, r.f.a, v.h, r.tuple, v.boot, routeClock(v.m, 151)) || !v.m.AllowsPacket(r.f.c, r.f.n, r.f.a, v.h, reverseTuple(r.tuple), v.boot, routeClock(v.m, 151)) {
			t.Fatal("original forward/return flow rejected")
		}
	}
	if _, _, e = r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, p, r.b.boot, reverseTuple(r.tuple), routeClock(r.a, 151)); e == nil {
		t.Fatal("return direction created new policy")
	}
}
func TestRouteRuntimeRejectsForgedNativeScopeAndCurrentEndpointMismatch(t *testing.T) {
	r := routeBoth(t)
	p, _ := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	cases := []func(*RouteNativeProof){func(p *RouteNativeProof) { p.Reference.Lifetime.Token++ }, func(p *RouteNativeProof) { p.Operation++ }, func(p *RouteNativeProof) { p.Reference.Owner = pub(r.f.key) }, func(p *RouteNativeProof) { p.Gone = true }, func(p *RouteNativeProof) { p.JournalSynced = false }, func(p *RouteNativeProof) { p.Spec = "other" }}
	for _, change := range cases {
		bad := ownRouteNative(p)
		change(&bad)
		if _, _, e := r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, bad, r.b.boot, r.tuple, routeClock(r.a, 150)); e == nil {
			t.Fatal("forged/incorrect native proof accepted")
		}
	}
	for _, change := range []func(*RouteTuple){func(t *RouteTuple) { t.Destination.Generation++ }, func(t *RouteTuple) { t.DestinationPort = 443 }, func(t *RouteTuple) { t.Protocol = 17 }, func(t *RouteTuple) { t.Source.Owner = t.Destination.Owner }, func(t *RouteTuple) { t.SourcePort = 0 }} {
		tuple := r.tuple
		change(&tuple)
		if _, _, e := r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, p, r.b.boot, tuple, routeClock(r.a, 150)); e == nil {
			t.Fatal("foreign endpoint/direction/protocol/port admitted")
		}
	}
}
func TestRouteRuntimeWithdrawPreservesDispatchedApplyAndOriginalUnknown(t *testing.T) {
	r := routeCoreFixture(t)
	var e error
	var op *reconcile.Operation
	r.a, op, e = r.a.Plan()
	if e != nil {
		t.Fatal(e)
	}
	r.a, e = r.a.Dispatch(op.ID)
	if e != nil {
		t.Fatal(e)
	}
	proof := routeNative(t, r.a, r.f.key)
	r.a, e = r.a.Unknown(op.ID)
	if e != nil {
		t.Fatal(e)
	}
	r = routeWithdraw(t, r)
	if r.a.state.Pending == nil || r.a.state.Pending.ID != op.ID || r.a.state.Pending.Phase != reconcile.RecoveryRequired {
		t.Fatal("withdraw erased original apply")
	}
	if _, _, e = r.a.Plan(); e == nil {
		t.Fatal("reissued while original unknown")
	}
	if _, e = r.a.ReferenceFacts(r.f.a, [32]byte{}, routeClock(r.a, 200)); e == nil {
		t.Fatal("unknown apply became native Gone")
	}
	restored, e := DecodeRouteRuntime(routeRaw(t, r.a))
	if e != nil {
		t.Fatal(e)
	}
	r.a = restored
	r.a, e = r.a.ObserveNative(proof)
	if e != nil {
		t.Fatal(e)
	}
	if !r.a.state.Applied.Present || r.a.state.Desired.Present {
		t.Fatal("late apply was rewritten as current desired")
	}
	r.a, op, e = r.a.Plan()
	if e != nil || op == nil || op.Kind != reconcile.Remove || op.ID == proof.Operation {
		t.Fatal("original native not removed", op, e)
	}
	r.a, e = r.a.Dispatch(op.ID)
	if e != nil {
		t.Fatal(e)
	}
	gone := routeNative(t, r.a, r.f.key)
	r.a, e = r.a.Unknown(op.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.a.RouteClosureFacts(r.f.n); e == nil {
		t.Fatal("unknown remove became closure")
	}
	r.a, e = r.a.ObserveNative(gone)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.a.ReferenceFacts(r.f.a, [32]byte{}, routeClock(r.a, 201)); e != nil {
		t.Fatal(e)
	}
	routeRaw(t, r.a)
}
func TestRouteRuntimeWithdrawalWaitsForEachFlowAndBilateralNativeClosure(t *testing.T) {
	r, h, k := routeBorrow(t, routeBoth(t))
	old := r.f.n
	r = routeWithdraw(t, r)
	var e error
	if r.a.AllowsPacket(r.f.c, r.f.n, r.f.a, h, r.tuple, r.b.boot, routeClock(r.a, 200)) || r.a.AllowsPacket(r.f.c, old, r.f.a, h, r.tuple, r.b.boot, routeClock(r.a, 200)) {
		t.Fatal("withdraw/old root admitted packet")
	}
	if _, _, e = r.a.Plan(); e == nil {
		t.Fatal("remove started with original flows")
	}
	p := routeFlowProof(r.a, h, r.f.key)
	p.NoPending = false
	p.Signature = ed25519.Sign(r.f.key, RouteFlowCloseBytes(p))
	if _, e = r.a.ReleaseFlow(h, p); e == nil {
		t.Fatal("unknown native flow returned pin")
	}
	r.a, e = r.a.ReleaseFlow(h, routeFlowProof(r.a, h, r.f.key))
	if e != nil {
		t.Fatal(e)
	}
	r.a = routeInstall(t, r.a, r.f.key)
	closed := routeRefProof(t, r.a, r.f.a, [32]byte{}, r.f.key, 201)
	policy := routeGoneProof(t, r.a, r.f.n, r.f.key)
	r.f.a, r.f.n, e = r.f.a.ObserveRouteRetired(r.f.n, closed, policy, 201)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := r.f.n.Route("first", "sql"); !ok {
		t.Fatal("single owner erased bilateral policy")
	}
	r.b, e = r.b.ReleaseFlow(k, routeFlowProof(r.b, k, r.keyB))
	if e != nil {
		t.Fatal(e)
	}
	r.b = routeInstall(t, r.b, r.keyB)
	closed = routeRefProof(t, r.b, r.f.a, [32]byte{}, r.keyB, 202)
	policy = routeGoneProof(t, r.b, r.f.n, r.keyB)
	r.f.a, r.f.n, e = r.f.a.ObserveRouteRetired(r.f.n, closed, policy, 202)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := r.f.n.Route("first", "sql"); ok {
		t.Fatal("both original closures retained policy")
	}
	encode(t, r.f.a)
}
func TestRouteRuntimeAddressRetirementJoinsBothInstanceConsumers(t *testing.T) {
	r, h, k := routeBorrow(t, routeBoth(t))
	var e error
	old := r.f.a
	r.f.a, e = r.f.a.BeginStaticRetirement(r.f.c, r.f.n, "admin", r.f.a.Revision(), r.tuple.Source, 200)
	if e != nil {
		t.Fatal(e)
	}
	f, _ := r.f.a.AddressRetirement(r.tuple.Source)
	if len(f.Required) != 2 {
		t.Fatal("route potential consumer missing", len(f.Required))
	}
	r.a, e = r.a.SyncReferenceFence(r.f.a, f.ID)
	if e != nil {
		t.Fatal(e)
	}
	r.b, e = r.b.SyncReferenceFence(r.f.a, f.ID)
	if e != nil {
		t.Fatal(e)
	}
	if r.a.AllowsPacket(r.f.c, r.f.n, old, h, r.tuple, r.b.boot, routeClock(r.a, 201)) {
		t.Fatal("old shared root bypassed local fence")
	}
	if _, e = r.a.ReferenceFacts(r.f.a, f.ID, routeClock(r.a, 201)); e == nil {
		t.Fatal("flow still holds original address")
	}
	r.a, e = r.a.ReleaseFlow(h, routeFlowProof(r.a, h, r.f.key))
	if e != nil {
		t.Fatal(e)
	}
	p := routeRefProof(t, r.a, r.f.a, f.ID, r.f.key, 201)
	r.f.a, e = r.f.a.ObserveReferenceClose(p, 201)
	if e != nil {
		t.Fatal(e)
	}
	owner := AddressOwnerClose{Cluster: r.f.a.cluster, Target: f.ID, Epoch: f.Epoch, Owner: f.Target.Source.Owner, Boot: r.f.boot, At: 201, Native: "php-original", Fenced: true, Stopped: true}
	owner.Signature = ed25519.Sign(r.f.key, AddressOwnerCloseBytes(owner))
	if _, e = r.f.a.ReleaseStatic(r.tuple.Source, owner, 201); e == nil {
		t.Fatal("one route owner freed shared address")
	}
	r.b, e = r.b.ReleaseFlow(k, routeFlowProof(r.b, k, r.keyB))
	if e != nil {
		t.Fatal(e)
	}
	p = routeRefProof(t, r.b, r.f.a, f.ID, r.keyB, 202)
	r.f.a, e = r.f.a.ObserveReferenceClose(p, 202)
	if e != nil {
		t.Fatal(e)
	}
	r.f.a, e = r.f.a.ReleaseStatic(r.tuple.Source, owner, 202)
	if e != nil {
		t.Fatal(e)
	}
	r.f.a, e = r.f.a.CompactReferences()
	if e != nil {
		t.Fatal(e)
	}
	r.a, e = r.a.CompactReferenceFences(r.f.a)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := DecodeRouteRuntime(routeRaw(t, r.a))
	if e != nil {
		t.Fatal(e)
	}
	if restored.AllowsPacket(r.f.c, r.f.n, old, h, r.tuple, r.b.boot, routeClock(restored, 203)) {
		t.Fatal("compacted fence replayed old root")
	}
	encode(t, r.f.a)
}
func TestRouteRuntimeCanonicalRecoveryRetainsPinsAndOriginalPeerProof(t *testing.T) {
	r, h, _ := routeBorrow(t, routeBoth(t))
	raw := routeRaw(t, r.a)
	restored, e := DecodeRouteRuntime(raw)
	if e != nil || !bytes.Equal(raw, routeRaw(t, restored)) {
		t.Fatal(e)
	}
	if !restored.AllowsPacket(r.f.c, r.f.n, r.f.a, h, r.tuple, r.b.boot, routeClock(restored, 151)) {
		t.Fatal("original flow was not restored")
	}
	changes := []func(*routeRuntimeSnapshot){func(s *routeRuntimeSnapshot) { s.Flows = nil }, func(s *routeRuntimeSnapshot) { s.Pins.Active = nil }, func(s *routeRuntimeSnapshot) { s.Flows[0].Pin.Token++ }, func(s *routeRuntimeSnapshot) { s.Flows[0].Peer.Signature = nil }, func(s *routeRuntimeSnapshot) { s.Consumer.Route.Side = "second" }, func(s *routeRuntimeSnapshot) { s.State.Applied.Spec = "changed" }, func(s *routeRuntimeSnapshot) { s.ReferenceFloor = 0 }}
	for _, change := range changes {
		var s routeRuntimeSnapshot
		if json.Unmarshal(raw, &s) != nil {
			t.Fatal("decode fixture")
		}
		change(&s)
		bad, _ := json.Marshal(s)
		if _, e = DecodeRouteRuntime(bad); e == nil {
			t.Fatal("corrupt/missing original state restored")
		}
	}
}
func TestRouteRuntimeRestartRevalidatesNativeWithoutErasingOriginalFlows(t *testing.T) {
	r, h, _ := routeBorrow(t, routeBoth(t))
	var e error
	original := *r.a.native
	r.a = r.a.Pause()
	r.a, e = r.a.ResumeBoot([32]byte{50})
	if e != nil {
		t.Fatal(e)
	}
	r.a, e = DecodeRouteRuntime(routeRaw(t, r.a))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.a.AppliedProof(r.f.c, r.f.n, r.f.a); e == nil {
		t.Fatal("old boot published Ready")
	}
	if _, e = r.a.RevalidateNative(original); e == nil {
		t.Fatal("old boot accepted native readback")
	}
	proof := ownRouteNative(original)
	proof.Boot = r.a.boot
	proof.Signature = ed25519.Sign(r.f.key, RouteNativeBytes(proof))
	r.a, e = r.a.RevalidateNative(proof)
	if e != nil {
		t.Fatal(e)
	}
	if !r.a.AllowsPacket(r.f.c, r.f.n, r.f.a, h, r.tuple, r.b.boot, routeClock(r.a, 151)) {
		t.Fatal("same original native flow lost despite positive recovery")
	}
	if r.a.AllowsPacket(r.f.c, r.f.n, r.f.a, h, r.tuple, [32]byte{99}, routeClock(r.a, 151)) {
		t.Fatal("original flow silently adopted new peer boot")
	}
	if len(r.a.flows) != 1 || r.a.pins.Active[0] != h.pin {
		t.Fatal("boot reset original references")
	}
}
func TestRouteRuntimeShrinkKeepsOriginalPinsAndCannotReuseOldReturn(t *testing.T) {
	r, h, _ := routeBorrow(t, routeBoth(t))
	var e error
	p, _ := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	second := r.tuple
	second.SourcePort++
	var next RouteFlow
	r.a, next, e = r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, p, r.b.boot, second, routeClock(r.a, 151))
	if e != nil {
		t.Fatal(e)
	}
	r.a, e = r.a.Resize(1)
	if e != nil {
		t.Fatal(e)
	}
	third := second
	third.SourcePort++
	if _, _, e = r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, p, r.b.boot, third, routeClock(r.a, 152)); e == nil {
		t.Fatal("shrink evicted old refs or admitted over budget")
	}
	old := routeFlowProof(r.a, h, r.f.key)
	r.a, e = r.a.ReleaseFlow(h, old)
	if e != nil {
		t.Fatal(e)
	}
	r.a, e = r.a.ReleaseFlow(next, routeFlowProof(r.a, next, r.f.key))
	if e != nil {
		t.Fatal(e)
	}
	var newer RouteFlow
	r.a, newer, e = r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, p, r.b.boot, r.tuple, routeClock(r.a, 153))
	if e != nil {
		t.Fatal(e)
	}
	if newer.pin.Token <= next.pin.Token {
		t.Fatal("token reused")
	}
	if _, e = r.a.ReleaseFlow(newer, old); e == nil {
		t.Fatal("old native receipt freed new flow")
	}
	routeRaw(t, r.a)
}
func TestRouteRuntimePausedWithdrawalAbortsOnlyUnsentApply(t *testing.T) {
	r := routeCoreFixture(t)
	var e error
	var op *reconcile.Operation
	r.a, op, e = r.a.Plan()
	if e != nil || op == nil {
		t.Fatal(e)
	}
	r.a = r.a.Pause()
	r = routeWithdraw(t, r)
	if !r.a.fenced || r.a.state.Pending != nil || r.a.state.Desired.Present {
		t.Fatal("paused owner ignored committed withdrawal or dispatched unsent work")
	}
	r.a, e = r.a.ResumeBoot(r.a.boot)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.a.Dispatch(op.ID); e == nil {
		t.Fatal("original unsent work dispatched after fence")
	}
	if _, e = r.a.ReferenceFacts(r.f.a, [32]byte{}, routeClock(r.a, 201)); e != nil {
		t.Fatal(e)
	}
	routeRaw(t, r.a)
}
func TestRouteRuntimeSharedSnapshotCannotEraseOrRetagRouteCoverage(t *testing.T) {
	r := routeBoth(t)
	raw := encode(t, r.f.a)
	restored, e := DecodeAuthority(raw)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(raw, encode(t, restored)) {
		t.Fatal("noncanonical shared root")
	}
	for _, change := range []func(*authoritySnapshot){func(s *authoritySnapshot) { s.References.Consumers[0].Route = nil }, func(s *authoritySnapshot) { s.References.Consumers[0].Members = s.References.Consumers[0].Members[:1] }, func(s *authoritySnapshot) { s.References.Consumers[0].Route.Side = "third" }, func(s *authoritySnapshot) { s.References.Consumers[0].Members[0].Since++ }} {
		var s authoritySnapshot
		json.Unmarshal(raw, &s)
		change(&s)
		bad, _ := json.Marshal(s)
		if _, e = DecodeAuthority(bad); e == nil {
			t.Fatal("incomplete/retagged shared route reference restored")
		}
	}
}
func TestRouteRuntimeAtomicPolicyAndInstanceRetirementPreservesOriginalRootOnFailure(t *testing.T) {
	r := routeWithdraw(t, routeBoth(t))
	r.a = routeInstall(t, r.a, r.f.key)
	closed := routeRefProof(t, r.a, r.f.a, [32]byte{}, r.f.key, 201)
	p := routeGoneProof(t, r.a, r.f.n, r.f.key)
	before := encode(t, r.f.a)
	p.Revision++
	p.Signature = ed25519.Sign(r.f.key, tenancy.RouteClosureBytes(p))
	a, _, e := r.f.a.ObserveRouteRetired(r.f.n, closed, p, 201)
	if e == nil || !bytes.Equal(before, encode(t, a)) || !bytes.Equal(before, encode(t, r.f.a)) {
		t.Fatal("policy failure partially published instance closure")
	}
}

func TestRouteRuntimeMixedDNSAndRouteConsumersMustAllClose(t *testing.T) {
	r := routeBoth(t)
	m, e := NewDNSManager(r.f.a.cluster, pub(r.f.key), []string{"sfc.test."}, 8, 8)
	if e != nil {
		t.Fatal(e)
	}
	cfg := DNSConfig{Tenant: "first", ID: "dns", Network: "lan", Pool: "pool", Source: 100, Serial: 1, Enabled: true, Zone: "app.sfc.test.", ClientZone: "clients.app.sfc.test.", TTL: 30, NegativeTTL: 5, QuerySeconds: 2, MaxQueries: 2, MaxCacheEntries: 2, MaxResponseBytes: 4096, Names: []DNSName{{"php", "php", 1}}}
	d := publishDNS(t, dnsFixture{f: r.f, m: m, cfg: cfg, origin: r.tuple.Source}, cfg, 190)
	r.f = d.f
	dnsRef := dnsConsumer(t, d)
	foreign := ownDNSConfig(cfg)
	foreign.Source++
	foreign.Serial++
	foreign.Names = []DNSName{{"sql", "sql", 1}}
	if _, _, e = r.f.a.GrantDNSInstance(r.f.c, r.f.n, "admin", dnsRef.Generation, foreign); e == nil {
		t.Fatal("route granted cross-tenant DNS visibility")
	}
	r.f.a, e = r.f.a.BeginStaticRetirement(r.f.c, r.f.n, "admin", r.f.a.Revision(), r.tuple.Source, 200)
	if e != nil {
		t.Fatal(e)
	}
	f, _ := r.f.a.AddressRetirement(r.tuple.Source)
	if len(f.Required) != 3 {
		t.Fatal("mixed required set incomplete", len(f.Required))
	}
	for i := 0; i < 2; i++ {
		local, key := r.a, r.f.key
		if i == 1 {
			local, key = r.b, r.keyB
		}
		local, e = local.SyncReferenceFence(r.f.a, f.ID)
		if e != nil {
			t.Fatal(e)
		}
		p := routeRefProof(t, local, r.f.a, f.ID, key, 201)
		r.f.a, e = r.f.a.ObserveReferenceClose(p, 201)
		if e != nil {
			t.Fatal(e)
		}
	}
	owner := AddressOwnerClose{Cluster: r.f.a.cluster, Target: f.ID, Epoch: f.Epoch, Owner: pub(r.f.key), Boot: r.f.boot, At: 201, Native: "php-original", Fenced: true, Stopped: true}
	owner.Signature = ed25519.Sign(r.f.key, AddressOwnerCloseBytes(owner))
	if _, e = r.f.a.ReleaseStatic(r.tuple.Source, owner, 201); e == nil {
		t.Fatal("both routes bypassed remaining DNS view/TTL")
	}
	d.f.a = r.f.a
	consumer := dnsConsumer(t, d)
	d.m, e = d.m.SyncReferenceFence(d.f.a, consumer.ID, f.ID)
	if e != nil {
		t.Fatal(e)
	}
	old := d.m.current["first/dns"]
	cfg.Source++
	cfg.Serial++
	cfg.Names = nil
	d = publishDNS(t, d, cfg, 201)
	if _, e = d.m.ReferenceFacts(d.f.a, consumer.ID, f.ID, d.clock(230)); e == nil {
		t.Fatal("DNS TTL bypassed")
	}
	d.m, e = d.m.Collect(old, d.clock(231))
	if e != nil {
		t.Fatal(e)
	}
	p := nativeReferenceProof(t, d, consumer, f.ID, 231)
	d.f.a, e = d.f.a.ObserveReferenceClose(p, 231)
	if e != nil {
		t.Fatal(e)
	}
	d.f.a, e = d.f.a.ReleaseStatic(r.tuple.Source, owner, 231)
	if e != nil {
		t.Fatal(e)
	}
	encode(t, d.f.a)
}

func TestRouteRuntimePolicyRevocationRequiresExplicitFreshLifetime(t *testing.T) {
	r := routeBoth(t)
	oldCatalog := r.f.c
	tenant, _ := r.f.c.Tenant("first")
	var e error
	r.f.c, e = r.f.c.SetNodes("admin", "first", tenant.Revision, nil)
	if e != nil {
		t.Fatal(e)
	}
	r.a, e = r.a.Sync(r.f.c, r.f.n, r.f.a)
	if e != nil {
		t.Fatal(e)
	}
	if !r.a.fenced || r.a.state.Desired.Present {
		t.Fatal("node grant revocation failed to fence")
	}
	if _, e = r.a.AppliedProof(oldCatalog, r.f.n, r.f.a); e == nil {
		t.Fatal("old catalog restored admission")
	}
	tenant, _ = r.f.c.Tenant("first")
	r.f.c, e = r.f.c.SetNodes("admin", "first", tenant.Revision, []string{"node-a"})
	if e != nil {
		t.Fatal(e)
	}
	r.a, e = r.a.Sync(r.f.c, r.f.n, r.f.a)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.a.AppliedProof(r.f.c, r.f.n, r.f.a); e == nil {
		t.Fatal("grant restoration resurrected permanently fenced native instance")
	}
	r.a = routeInstall(t, r.a, r.f.key)
	closed := routeRefProof(t, r.a, r.f.a, [32]byte{}, r.f.key, 201)
	r.f.a, e = r.f.a.ObserveReferenceClose(closed, 201)
	if e != nil {
		t.Fatal(e)
	}
	previous := r.a.consumer
	var ref ReferenceConsumer
	r.f.a, ref, e = r.f.a.GrantRouteInstance(r.f.c, r.f.n, "admin", "first", "sql", "first", previous.Generation)
	if e != nil {
		t.Fatal(e)
	}
	if ref.ID == previous.ID || ref.Lifetime.Token <= previous.Lifetime.Token {
		t.Fatal("explicit reactivation reused original instance")
	}
	r.a, e = NewRouteRuntime(r.f.c, r.f.n, r.f.a, ref.ID, r.f.boot, 2)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.a.AppliedProof(r.f.c, r.f.n, r.f.a); e == nil {
		t.Fatal("fresh instance falsely inherited native Applied")
	}
	routeRaw(t, r.a)
	encode(t, r.f.a)
}

func TestRouteRuntimePositiveNotAppliedOnlySettlesExactDispatchedOperation(t *testing.T) {
	r := routeCoreFixture(t)
	var e error
	var op *reconcile.Operation
	r.a, op, e = r.a.Plan()
	if e != nil {
		t.Fatal(e)
	}
	p := routeNative(t, r.a, r.f.key)
	p.Outcome = reconcile.EffectNotApplied
	p.Installed = false
	p.NotApplied = true
	p.Signature = ed25519.Sign(r.f.key, RouteNativeBytes(p))
	if _, e = r.a.ObserveNative(p); e == nil {
		t.Fatal("unsent native operation accepted completion")
	}
	r.a, e = r.a.Dispatch(op.ID)
	if e != nil {
		t.Fatal(e)
	}
	r.a, e = r.a.Unknown(op.ID)
	if e != nil {
		t.Fatal(e)
	}
	raw := routeRaw(t, r.a)
	r.a, e = DecodeRouteRuntime(raw)
	if e != nil {
		t.Fatal(e)
	}
	r.a, e = r.a.ObserveNative(p)
	if e != nil {
		t.Fatal(e)
	}
	if r.a.state.Applied.Present || r.a.state.Pending != nil {
		t.Fatal("positive no-effect not settled")
	}
	r.a, op, e = r.a.Plan()
	if e != nil || op.ID <= p.Operation {
		t.Fatal("explicit retry reused old native operation", e)
	}
	r.a, e = r.a.Dispatch(op.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.a.ObserveNative(p); e == nil {
		t.Fatal("old result settled new dispatched operation")
	}
	routeRaw(t, r.a)
}
