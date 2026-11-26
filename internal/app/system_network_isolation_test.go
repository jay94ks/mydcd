// SPDX-License-Identifier: Apache-2.0

package app

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/tenancy"
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
