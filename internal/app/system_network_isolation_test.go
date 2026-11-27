// SPDX-License-Identifier: Apache-2.0

package app

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// The system network takes part in tenant isolation under its own scope:
// isolation needs a tenant name, and the system network has none.
func TestSystemNetworkHasItsOwnIsolationScope(t *testing.T) {
	member := tenancy.Network{Logical: tenancy.SystemNetwork, System: true}
	if member.Scope() != tenancy.SystemScope || (tenancy.Network{Tenant: "shop"}).Scope() != "shop" {
		t.Fatal("scope", member.Scope())
	}
	spec := network.IsolationSpec{Schema: 1, Owner: strings.Repeat("01", 32) + "/" + strings.Repeat("02", 32), Prefixes: []network.TenantPrefix{
		{Tenant: member.Scope(), Prefix: netip.MustParsePrefix("10.254.1.0/24")},
		{Tenant: "shop", Prefix: netip.MustParsePrefix("10.71.1.0/24")},
	}}
	if _, err := network.NormalizeIsolation(spec); err != nil {
		t.Fatal("isolation refused the system scope:", err)
	}
}

// Since every TUN network on a server uses the server's own address, the
// system network and a tenant network on the same server share it, and both
// route to their peers' server addresses. Isolation must accept that (lab
// 2026-11-27: a second TUN network on jay3 failed every owner pass with
// "network ownership, allocation or capacity conflict").
func TestTwoTUNNetworksShareTheServerAddressInIsolation(t *testing.T) {
	self, peer := netip.MustParsePrefix("10.254.240.2/32"), netip.MustParsePrefix("10.254.240.3/32")
	system := network.TunnelSpec{Addresses: []netip.Prefix{self}, Routes: []netip.Prefix{netip.MustParsePrefix("10.254.0.2/32"), netip.MustParsePrefix("10.254.2.0/24"), peer}}
	tenant := network.TunnelSpec{Addresses: []netip.Prefix{self}, Routes: []netip.Prefix{netip.MustParsePrefix("198.19.91.0/28"), peer}}
	spec := network.IsolationSpec{Schema: 1, Owner: strings.Repeat("01", 32) + "/" + strings.Repeat("02", 32), Prefixes: []network.TenantPrefix{
		{Tenant: tenancy.SystemScope, Prefix: netip.MustParsePrefix("10.254.1.0/24")},
		{Tenant: "regtest", Prefix: netip.MustParsePrefix("198.19.90.0/28")},
	}}
	spec.Prefixes = append(spec.Prefixes, tunnelTenantPrefixes(tenancy.SystemScope, system)...)
	spec.Prefixes = append(spec.Prefixes, tunnelTenantPrefixes("regtest", tenant)...)
	spec.Tunnels = []network.IsolationTunnel{
		{Tenant: tenancy.SystemScope, Device: "mt0655a57ea39f", Prefixes: system.Routes},
		{Tenant: "regtest", Device: "mt0000000000aa", Prefixes: tenant.Routes},
	}
	got, err := network.NormalizeIsolation(spec)
	if err != nil {
		t.Fatal("isolation refused the shared server address:", err)
	}
	for _, p := range got.Prefixes {
		if network.SharedServerPrefix(p.Prefix) {
			t.Fatal("server address became a tenant's prefix", p)
		}
	}
	for _, tun := range got.Tunnels {
		if !slicesContains(tun.Prefixes, peer) {
			t.Fatal("TUN lost its route to the peer server address", tun)
		}
	}
}

func slicesContains(list []netip.Prefix, p netip.Prefix) bool {
	for _, q := range list {
		if q == p {
			return true
		}
	}
	return false
}
