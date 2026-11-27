// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network"
)

// These are deterministic Book/projection inputs, not native readiness facts.
func TestMoveAddressesRetainOriginalSlotButDenyForeignOrOrphanHolds(t *testing.T) {
	owner := [32]byte{71}
	scope := deployment.AppScope{Cluster: [32]byte{72}, Actor: "manager", Tenant: "tenant", App: "app", Deployment: "deploy"}
	key := deployment.ResourceKey("task", scope.Tenant, scope.App, "web")
	address := netip.MustParseAddr("10.90.0.10")
	book, err := network.NewBook(4)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.AddPool(network.Pool{ID: "pool", Network: "tenant/shared", Owner: hex.EncodeToString(owner[:]), Prefix: netip.MustParsePrefix("10.90.0.0/24"), Gateway: netip.MustParseAddr("10.90.0.1"), MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	book, _, err = book.Reserve(key+"/lan/0", hex.EncodeToString(owner[:]), "tenant/shared", "pool", 7, address)
	if err != nil {
		t.Fatal(err)
	}
	goal := deployment.GoalResources{Goal: deployment.GoalCommand{Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment, Node: "node-a", Owner: owner}}
	base := ResourceProjection{Addresses: book, AddressSources: map[string]deployment.ObjectRef{address.String(): {Key: key, Generation: 7, Revision: 9}}, Goals: map[string]deployment.GoalResources{key: goal}}
	demand := deployment.ResourceDemand{Key: key, Kind: "task", Node: "node-a", Owner: owner, Addresses: []deployment.StaticAddressDemand{{Endpoint: key + "/lan/0", Network: "tenant/shared", Address: address}}}
	if err = admitMoveAddresses(base, scope, demand, nil); err != nil {
		t.Fatal("same app attachment cannot survive cold replacement", err)
	}
	for _, mutate := range []func(*deployment.ResourceDemand){
		func(d *deployment.ResourceDemand) { d.Key += "-other" },
		func(d *deployment.ResourceDemand) { d.Node = "node-b" },
		func(d *deployment.ResourceDemand) { d.Owner[0]++ },
		func(d *deployment.ResourceDemand) {
			d.Addresses = append([]deployment.StaticAddressDemand(nil), d.Addresses...)
			d.Addresses[0].Endpoint += "-other"
		},
		func(d *deployment.ResourceDemand) {
			d.Addresses = append([]deployment.StaticAddressDemand(nil), d.Addresses...)
			d.Addresses[0].Network = "tenant/other"
		},
	} {
		bad := demand
		mutate(&bad)
		if admitMoveAddresses(base, scope, bad, nil) == nil {
			t.Fatal("foreign pending demand borrowed committed address", bad)
		}
	}
	orphan := base
	orphan.AddressSources = map[string]deployment.ObjectRef{}
	if admitMoveAddresses(orphan, scope, demand, nil) == nil {
		t.Fatal("unclosed orphan was inferred reusable")
	}
	stale := base
	stale.AddressSources = map[string]deployment.ObjectRef{address.String(): {Key: key, Generation: 8, Revision: 9}}
	if admitMoveAddresses(stale, scope, demand, nil) == nil {
		t.Fatal("another generation borrowed original address")
	}
	other := scope
	other.Deployment = "other"
	if admitMoveAddresses(base, other, demand, nil) == nil {
		t.Fatal("another deployment borrowed original address")
	}
	competing := base
	competing.MoveHolds = []deployment.PlannedResource{{Origin: [32]byte{3}, Scope: scope, Demand: demand}}
	if admitMoveAddresses(competing, scope, demand, nil) == nil {
		t.Fatal("second accepted intent reused a desired address")
	}
}
