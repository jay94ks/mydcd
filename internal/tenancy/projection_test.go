// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/jay94ks/mydcd/internal/workload"
)

func TestCommittedBuildReservationSharesBudgetWithoutPublicTaskReserve(t *testing.T) {
	for _, kind := range []string{"imagebuild", "imagebuild-cache-prune"} {
		t.Run(kind, func(t *testing.T) {
			f, q := quotaFixture(t)
			r := Reservation{Key: "workload/" + kind + "/first/build-one/builder", Tenant: "first", Node: "node-a", Owner: public(f.a), Generation: 1, Revision: 2, Need: workload.Resources{CPU: 3, Memory: 30}, Draining: true}
			projected, err := q.WithCommittedReservation(r)
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := projected.Usage("first", "node-a"); got != r.Need {
				t.Fatal("cancelled build budget not held", got)
			}
			if _, err := projected.WithCommittedReservation(r); err == nil {
				t.Fatal("duplicate authority")
			}
			request := r
			request.Generation, request.Revision = 0, 0
			request.Draining = false
			if _, err := q.Reserve(f.c, "admin", q.Revision(), request); err == nil {
				t.Fatal("manual Task API minted build reservation")
			}
			for _, edit := range []func(*Reservation){
				func(v *Reservation) { v.Key = "workload/" + kind + "/first/build-one/arbitrary" },
				func(v *Reservation) { v.ManagedRegistry = true },
				func(v *Reservation) { v.Tenant = "second" },
				func(v *Reservation) { v.Need.CPU = 5 },
			} {
				bad := r
				edit(&bad)
				if _, err := q.WithCommittedReservation(bad); err == nil {
					t.Fatal("foreign/over-budget source accepted", bad.Key)
				}
			}
		})
	}
}

func TestCommittedResourceProjectionPreservesSourcesAndSharedBudgets(t *testing.T) {
	f, q := quotaFixture(t)
	baseQ, _ := q.Encode()
	baseN, _ := f.n.Encode()
	n := Network{Tenant: "first", ID: "owned", Node: "node-a", Owner: public(f.a), Generation: 70, Revision: 80, Draining: true, Pools: []Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.91.0.0/24"), Gateway: netip.MustParseAddr("10.91.0.1"), MTU: 1280}}}
	projected, err := f.n.WithCommittedNetwork(n)
	if err != nil {
		t.Fatal(err)
	}
	n.Pools[0].Gateway = netip.MustParseAddr("10.91.0.2")
	source, _ := projected.Network("first", "owned")
	if source.Generation != 70 || source.Revision != 80 || source.Pools[0].Gateway.String() != "10.91.0.1" || !source.Draining {
		t.Fatal("source changed", source)
	}
	if _, err = f.n.WithCommittedNetwork(source); err != nil {
		t.Fatal(err)
	}
	if _, err = f.n.WithCommittedNetworks([]Network{source, source}); err == nil {
		t.Fatal("batch duplicate authority")
	}
	if _, err = projected.WithCommittedNetwork(source); err == nil {
		t.Fatal("second authority with same ID adopted")
	}
	conflict := source
	conflict.Tenant, conflict.ID = "second", "other"
	if _, err = projected.WithCommittedNetwork(conflict); err == nil {
		t.Fatal("cross tenant overlap")
	}
	reservation := request("first", "web", public(f.a), 2, 20)
	reservation.Generation, reservation.Revision, reservation.Draining = 90, 95, true
	withTask, err := q.WithCommittedReservation(reservation)
	if err != nil {
		t.Fatal(err)
	}
	registry := reservation
	registry.Key = "workload/registry/first/app/private"
	registry.Generation, registry.Revision = 96, 96
	withRegistry, err := withTask.WithCommittedReservation(registry)
	if err != nil {
		t.Fatal(err)
	}
	batched, err := q.WithCommittedReservations([]Reservation{reservation, registry})
	if err != nil {
		t.Fatal(err)
	}
	batchBytes, _ := batched.Encode()
	sequentialBytes, _ := withRegistry.Encode()
	if !bytes.Equal(batchBytes, sequentialBytes) {
		t.Fatal("batch changed source revisions or quantities")
	}
	if used, _ := withRegistry.Usage("first", "node-a"); used != (workload.Resources{CPU: 4, Memory: 40}) {
		t.Fatal("shared task/registry budget", used)
	}
	if _, err = withTask.WithCommittedReservation(reservation); err == nil {
		t.Fatal("duplicate reservation authority")
	}
	overflow := reservation
	overflow.Key = "workload/task/first/app/overflow"
	overflow.Need = workload.Resources{CPU: 1, Memory: 1}
	if _, err = withRegistry.WithCommittedReservation(overflow); err == nil {
		t.Fatal("global/tenant budget bypass")
	}
	if err = withRegistry.ValidateNetworks(projected); err != nil {
		t.Fatal(err)
	}
	extra := source
	extra.ID = "second"
	extra.Pools = []Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.91.1.0/24"), Gateway: netip.MustParseAddr("10.91.1.1"), MTU: 1280}}
	withExtra, err := projected.WithCommittedNetwork(extra)
	if err != nil {
		t.Fatal(err)
	}
	if withRegistry.ValidateNetworks(withExtra) == nil {
		t.Fatal("network slot limit bypass")
	}
	if got, _ := q.Encode(); !bytes.Equal(baseQ, got) {
		t.Fatal("base quota modified")
	}
	if got, _ := f.n.Encode(); !bytes.Equal(baseN, got) {
		t.Fatal("base network registry modified")
	}
	if r, _ := withRegistry.Reservation(reservation.Key); r != reservation {
		t.Fatal("original reservation rewritten")
	}
	// The public Reserve API remains for task requests, not a registry bypass.
	registry.Generation, registry.Revision, registry.Draining = 0, 0, false
	if _, err = q.Reserve(f.c, "alice", q.Revision(), registry); err == nil {
		t.Fatal("manual reserve-task widened")
	}
}

func TestNodeConsumerPolicyIsBoundedAndBackwardCompatible(t *testing.T) {
	f, q := quotaFixture(t)
	old, _ := q.Encode()
	if bytes.Contains(old, []byte("MaxConsumers")) {
		t.Fatal("zero optional field changed old canonical rows")
	}
	global, _ := q.Limit("", "node-a")
	revision := global.Revision
	global.Revision = 0
	global.MaxConsumers = 8
	var err error
	q, err = q.Set(f.c, "admin", revision, global, f.n)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := q.Limit("first", "node-a")
	revision = tenant.Revision
	tenant.Revision = 0
	tenant.MaxConsumers = 9
	if _, err = q.Set(f.c, "admin", revision, tenant, f.n); err == nil {
		t.Fatal("tenant expanded node consumer limit")
	}
	tenant.MaxConsumers = 4
	q, err = q.Set(f.c, "admin", revision, tenant, f.n)
	if err != nil {
		t.Fatal(err)
	}
	global, _ = q.Limit("", "node-a")
	revision = global.Revision
	global.Revision = 0
	global.MaxConsumers = 1
	q, err = q.Set(f.c, "admin", revision, global, f.n)
	if err != nil {
		t.Fatal(err)
	}
	scoped, _ := q.Limit("first", "node-a")
	if min(global.MaxConsumers, scoped.MaxConsumers) != 1 {
		t.Fatal("effective node shrink")
	}
	encoded, err := q.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeQuotas(encoded); err != nil {
		t.Fatal(err)
	}
	global, _ = q.Limit("", "node-a")
	revision = global.Revision
	global.Revision = 0
	global.MaxConsumers = 65537
	if _, err = q.Set(f.c, "admin", revision, global, f.n); err == nil {
		t.Fatal("unbounded consumer policy")
	}
}
