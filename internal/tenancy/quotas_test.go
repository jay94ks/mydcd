// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/workload"
)

func quotaFixture(t *testing.T) (fixture, Quotas) {
	t.Helper()
	f := newFixture(t)
	q, err := NewQuotas(f.n.Cluster())
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"", "first", "second"} {
		cpu, mem, nets := uint64(8), uint64(80), uint64(2)
		if tenant != "" {
			cpu, mem, nets = 4, 40, 1
		}
		q, err = q.Set(f.c, "admin", 0, NodeLimit{Tenant: tenant, Node: "node-a", Owner: public(f.a), Capacity: workload.Resources{CPU: cpu, Memory: mem}, Networks: nets}, f.n)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f, q
}
func request(tenant, id string, owner [32]byte, cpu, mem uint64) Reservation {
	return Reservation{Key: "workload/task/" + tenant + "/app/" + id, Tenant: tenant, Node: "node-a", Owner: owner, Need: workload.Resources{CPU: cpu, Memory: mem}}
}

func TestRegistryBudgetOwnershipIsExplicit(t *testing.T) {
	f, q := quotaFixture(t)
	// Reserve takes only Task slots; registry slots go through ReserveRegistry.
	plain := request("first", "server", public(f.a), 1, 10)
	plain.Key = "workload/registry/first/plain/server"
	if _, err := q.Reserve(f.c, "admin", q.Revision(), plain); err == nil {
		t.Fatal("registry slot reserved without registry ownership")
	}
	newRequest := plain
	newRequest.Key = "workload/registry/first/new/server"
	q, err := q.ReserveRegistry(f.c, "admin", q.Revision(), newRequest)
	if err != nil {
		t.Fatal(err)
	}
	managed, _ := q.Reservation(newRequest.Key)
	if !managed.ManagedRegistry {
		t.Fatal("missing managed parent marker")
	}
	snapshot, err := q.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeQuotas(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restored.DrainRegistryOwner(managed.Key, managed.Owner, managed.Generation); err != nil {
		t.Fatal(err)
	}
	newRequest.ManagedRegistry = true
	newRequest.Key = "workload/registry/first/forged/server"
	if _, err = q.ReserveRegistry(f.c, "admin", q.Revision(), newRequest); err == nil {
		t.Fatal("caller forged managed registry ownership")
	}
}
func mustQuota(t *testing.T, q Quotas, err error) Quotas {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := q.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeQuotas(raw); err != nil {
		t.Fatal("invalid candidate", err)
	}
	return q
}
func TestQuotaReservationCompetesWithinGlobalAndTenantLimits(t *testing.T) {
	f, q := quotaFixture(t)
	r := request("first", "php", public(f.a), 4, 40)
	next, err := q.Reserve(f.c, "alice", q.Revision(), r)
	q = mustQuota(t, next, err)
	if _, err = q.Reserve(f.c, "alice", q.Revision(), request("first", "another", public(f.a), 1, 1)); err == nil {
		t.Fatal("tenant budget bypass")
	}
	next, err = q.Reserve(f.c, "bob", q.Revision(), request("second", "db", public(f.a), 4, 40))
	q = mustQuota(t, next, err)
	used, _ := q.Usage("", "node-a")
	if used != (workload.Resources{CPU: 8, Memory: 80}) {
		t.Fatal("global usage", used)
	}
	if _, err = q.Reserve(f.c, "admin", q.Revision(), request("second", "overflow", public(f.a), ^uint64(0), 1)); err == nil {
		t.Fatal("overflow/global budget bypass")
	}
	if _, err = q.Reserve(f.c, "alice", q.Revision()-1, r); err != access.ErrConflict {
		t.Fatal("stale quota CAS", err)
	}
	if _, err = q.Reserve(f.c, "bob", q.Revision(), request("first", "foreign", public(f.a), 1, 1)); err != access.ErrDenied {
		t.Fatal("tenant boundary", err)
	}
	limit, _ := q.Limit("", "node-a")
	limit.Revision = 0
	limit.Capacity.CPU = 7
	if _, err = q.Set(f.c, "admin", q.limits[quotaKey("", "node-a")].Revision, limit, f.n); err == nil {
		t.Fatal("shrink below current reservation")
	}
}
func TestQuotaDrainAndGrantRevocationNeverReturnReservation(t *testing.T) {
	f, q := quotaFixture(t)
	next, err := q.Reserve(f.c, "alice", q.Revision(), request("first", "php", public(f.a), 4, 40))
	q = mustQuota(t, next, err)
	original, _ := q.Reservation("workload/task/first/app/php")
	tenant, _ := f.c.Tenant("first")
	f.c, err = f.c.SetNodes("admin", "first", tenant.Revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Reserve(f.c, "alice", q.Revision(), request("first", "new", public(f.a), 1, 1)); err != access.ErrDenied {
		t.Fatal("node grant revocation", err)
	}
	next, err = q.Drain(f.c, "alice", original.Key, original.Revision)
	q = mustQuota(t, next, err)
	held, _ := q.Usage("first", "node-a")
	if held.CPU != 4 {
		t.Fatal("Drain returned capacity")
	}
	draining, _ := q.Reservation(original.Key)
	proof := ReservationClosure{Schema: 1, Cluster: f.n.Cluster(), Key: draining.Key, Node: draining.Node, Owner: draining.Owner, Generation: draining.Generation, DrainRevision: draining.Revision, NativeGone: true}
	for _, mutate := range []func(*ReservationClosure){func(p *ReservationClosure) { p.Cluster[0]++ }, func(p *ReservationClosure) { p.Generation++ }, func(p *ReservationClosure) { p.DrainRevision++ }, func(p *ReservationClosure) { p.PendingNative = 1 }, func(p *ReservationClosure) { p.PendingRefs = 1 }, func(p *ReservationClosure) { p.PendingWriters = 1 }, func(p *ReservationClosure) { p.NativeGone = false }} {
		bad := proof
		mutate(&bad)
		bad.Signature = ed25519.Sign(f.a, ReservationClosureBytes(bad))
		if _, err = q.Release(f.c, "alice", bad); err == nil {
			t.Fatal("foreign/nonterminal closure returned capacity")
		}
	}
	proof.Signature = ed25519.Sign(f.b, ReservationClosureBytes(proof))
	if _, err = q.Release(f.c, "alice", proof); err == nil {
		t.Fatal("wrong owner key returned capacity")
	}
	proof.Signature = ed25519.Sign(f.a, ReservationClosureBytes(proof))
	next, err = q.Release(f.c, "alice", proof)
	q = mustQuota(t, next, err)
	held, _ = q.Usage("first", "node-a")
	if held != (workload.Resources{}) {
		t.Fatal("verified closure did not return")
	}
	tenant, _ = f.c.Tenant("first")
	f.c, err = f.c.SetNodes("admin", "first", tenant.Revision, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	next, err = q.Reserve(f.c, "alice", q.Revision(), request("first", "php", public(f.a), 4, 40))
	q = mustQuota(t, next, err)
	replacement, _ := q.Reservation(original.Key)
	if replacement.Generation <= original.Generation {
		t.Fatal("recreated budget slot reused generation")
	}
	if _, err = q.Release(f.c, "alice", proof); err == nil {
		t.Fatal("old closure released replacement")
	}
}
func TestQuotaNetworksIncludeDrainingAndStagedOwners(t *testing.T) {
	f, q := quotaFixture(t)
	nw := Network{Tenant: "first", ID: "private", Node: "node-a", Owner: public(f.a), Pools: []Subnet{{ID: "v4", Prefix: netip.MustParsePrefix("10.70.0.0/24"), Gateway: netip.MustParseAddr("10.70.0.1"), MTU: 1400}}}
	if err := q.AdmitNetwork(f.c, "alice", nw.Tenant, nw.Node, nw.Owner, f.n); err != nil {
		t.Fatal(err)
	}
	var err error
	f.n, err = f.n.Create(f.c, "alice", f.n.Revision(), nw)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.AdmitNetwork(f.c, "alice", nw.Tenant, nw.Node, nw.Owner, f.n); err == nil {
		t.Fatal("occupied network quota ignored")
	}
	current, _ := f.n.Network("first", "private")
	target := nw
	target.Pools = []Subnet{{ID: "v4", Prefix: netip.MustParsePrefix("10.80.0.0/24"), Gateway: netip.MustParseAddr("10.80.0.1"), MTU: 1400}}
	candidate, err := f.n.PlanChange(f.c, "alice", "first", "private", "replace", current.Revision, target)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.ReservedCount("first", "node-a") != 2 || q.ValidateNetworks(candidate) == nil {
		t.Fatal("staged target reservation was ignored")
	}
	limit, _ := q.Limit("first", "node-a")
	revision := limit.Revision
	limit.Revision = 0
	limit.Networks = 2
	next, err := q.Set(f.c, "admin", revision, limit, f.n)
	q = mustQuota(t, next, err)
	if err = q.ValidateNetworks(candidate); err != nil {
		t.Fatal("explicit staged capacity rejected", err)
	}
	global, _ := q.Limit("", "node-a")
	revision = global.Revision
	global.Revision = 0
	global.Networks = 1
	if _, err = q.Set(f.c, "admin", revision, global, candidate); err == nil {
		t.Fatal("shrink ignored staged source/target")
	}
}
func TestQuotaRestoreRejectsMissingOwnerOverspendAndNoncanonicalData(t *testing.T) {
	f, q := quotaFixture(t)
	next, err := q.Reserve(f.c, "alice", q.Revision(), request("first", "php", public(f.a), 4, 40))
	q = mustQuota(t, next, err)
	raw, _ := q.Encode()
	for _, change := range []func(*quotaSnapshot){func(s *quotaSnapshot) { s.Reservations[0].Need.CPU = 9 }, func(s *quotaSnapshot) { s.Reservations[0].Owner = public(f.b) }, func(s *quotaSnapshot) { s.Limits = s.Limits[1:] }, func(s *quotaSnapshot) { s.Reservations = append(s.Reservations, s.Reservations[0]) }} {
		var view quotaSnapshot
		_ = json.Unmarshal(raw, &view)
		change(&view)
		bad, _ := json.Marshal(view)
		if _, err = DecodeQuotas(bad); err == nil {
			t.Fatal("invalid restored quota accepted")
		}
	}
	if _, err = DecodeQuotas(append(bytes.Clone(raw), ' ')); err == nil {
		t.Fatal("noncanonical restored quota")
	}
	var view quotaSnapshot
	_ = json.Unmarshal(raw, &view)
	view.Limits[0].Owner = public(f.b)
	// An ownership switch with existing reservations cannot bypass Set's fence.
	bad, _ := json.Marshal(view)
	if _, err = DecodeQuotas(bad); err == nil {
		t.Fatal("restored foreign global owner accepted")
	}
}

func TestIngressQuotasRequireExplicitGlobalAndTenantCeilings(t *testing.T) {
	f, q := quotaFixture(t)
	v, _ := q.Limit("", "node-a")
	rev := v.Revision
	v.Revision = 0
	v.MaxIngressInstances = 2
	v.MaxIngressListeners = 4
	v.MaxIngressRequests = 8
	v.MaxIngressConnections = 32
	v.IngressBufferBytes = 1 << 20
	next, err := q.Set(f.c, "admin", rev, v, f.n)
	q = mustQuota(t, next, err)
	v, _ = q.Limit("first", "node-a")
	rev = v.Revision
	v.Revision = 0
	v.MaxIngressInstances = 1
	v.MaxIngressListeners = 3
	v.MaxIngressRequests = 4
	v.MaxIngressConnections = 16
	v.IngressBufferBytes = 512 << 10
	next, err = q.Set(f.c, "admin", rev, v, f.n)
	q = mustQuota(t, next, err)
	for _, change := range []func(*NodeLimit){func(v *NodeLimit) { v.MaxIngressInstances = 3 }, func(v *NodeLimit) { v.MaxIngressListeners = 5 }, func(v *NodeLimit) { v.MaxIngressRequests = 9 }, func(v *NodeLimit) { v.MaxIngressConnections = 33 }, func(v *NodeLimit) { v.IngressBufferBytes = (1 << 20) + 1 }, func(v *NodeLimit) { v.MaxIngressInstances = -1 }} {
		bad := v
		bad.Revision = 0
		change(&bad)
		if _, err := q.Set(f.c, "admin", q.limits[quotaKey("first", "node-a")].Revision, bad, f.n); err == nil {
			t.Fatal("ingress quota bypass")
		}
	}
}
