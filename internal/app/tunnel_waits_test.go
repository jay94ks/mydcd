// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"testing"
)

func TestTunnelWaitsNameTheNetworkAndMTU(t *testing.T) {
	if tenant, name, ok := managedTunnelName("tenant/shop/network/shop-net"); !ok || tenant != "shop" || name != "shop-net" {
		t.Fatal(tenant, name, ok)
	}
	if _, _, ok := managedTunnelName("route/shop/x"); ok {
		t.Fatal("non-network name accepted")
	}
	rt := &tunnelRuntime{instances: map[[16]byte]*tunnelInstance{
		{1}: {network: "tenant/shop/network/shop-net", lastError: fmt.Errorf("%w: underlay MTU=1500 cannot carry TUN MTU=1500", errTunnelPending)},
		{2}: {network: "tenant/shop/network/ok"},
		{3}: {network: "tenant/shop/network/other", lastError: fmt.Errorf("unrelated")},
	}}
	waits := rt.Waits()
	if len(waits) != 1 || waits[0].Tenant != "shop" || waits[0].Network != "shop-net" || waits[0].Reason != "underlay MTU=1500 cannot carry TUN MTU=1500" {
		t.Fatalf("%+v", waits)
	}
}
