// SPDX-License-Identifier: Apache-2.0

package tenancy

import "testing"

func TestManagedSourceIdentityPreservesCommittedNames(t *testing.T) {
	for _, kind := range []string{"bridge", "tun"} {
		want := "control/network-sources/" + kind + "/tenant/shared-services/node-a"
		identity := SourceIdentity{Kind: kind, Tenant: "tenant", Network: "shared-services", Node: "node-a"}
		got, err := ParseSourceIdentity(want)
		if err != nil || got != identity || identity.Key() != want {
			t.Fatal("committed source identity changed", err)
		}
	}
	if PacketNamespace("tenant", "shared-services") != "tenant/tenant/network/shared-services" {
		t.Fatal("committed packet namespace changed")
	}
	for _, key := range []string{
		"control/network-sources/bridge/tenant/shared-services/node-a/extra",
		"control/network-sources/bridge/tenant/shared-services/node-a/",
		"control/network-sources/bridge/tenant/shared-services",
		"control/network-sources/bridge/tenant//node-a",
		"control/network-sources/bridge/other/path/shared-services/node-a",
		"control/network-sources/dns/tenant/shared-services/node-a",
		"control/network-sources/tun/tenant/shared_services/node-a",
		"control/network-sources/tun/Tenant/shared-services/node-a",
		"network/tun/tenant/app/shared-services/node-a",
	} {
		if _, err := ParseSourceIdentity(key); err == nil {
			t.Fatal("accepted another identity boundary", key)
		}
	}
	if (SourceIdentity{Kind: "bridge", Tenant: "tenant", Network: "../outside", Node: "node-a"}).Key() != "" || PacketNamespace("", "shared-services") != "" {
		t.Fatal("invalid identity rendered as a native selector")
	}
}
