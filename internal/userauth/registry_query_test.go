// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"strings"
	"testing"
)

// The registry page queries name their tenant and carry nothing else; who may
// read them is checked on the actual wire in registry_wire_test.go.
func TestRegistryPageQueriesNameTheirTenant(t *testing.T) {
	for _, q := range []TenantPageQuery{{Tenant: "tenant"}, {Tenant: "tenant", After: "tenant/private"}} {
		if !q.Valid() {
			t.Fatal("valid page query rejected", q)
		}
	}
	for _, q := range []TenantPageQuery{{}, {After: "tenant/private"}, {Tenant: "../tenant"}, {Tenant: "tenant", After: strings.Repeat("a", 513)}} {
		if q.Valid() {
			t.Fatal("invalid page query accepted", q)
		}
	}
	for _, raw := range []string{`{"Tenant":"tenant","Node":"node-a"}`, `{"Tenant":"tenant","ImageResolve":{"Ref":"busybox"}}`} {
		if strict([]byte(raw), &TenantPageQuery{}) == nil {
			t.Fatal("foreign field accepted", raw)
		}
	}
	for _, q := range []RegistryCredentialQuery{{ID: "private", Actions: []string{"pull"}}, {Tenant: "tenant", Actions: []string{"pull"}}, {Tenant: "tenant", ID: "private"}, {Tenant: "tenant", ID: "private", Actions: []string{"pull", "login"}}} {
		if q.Valid() {
			t.Fatal("invalid credential query accepted", q)
		}
	}
	if !(RegistryCredentialQuery{Tenant: "tenant", ID: "private", Repository: "team/app", Actions: []string{"pull", "push"}}).Valid() {
		t.Fatal("valid credential query rejected")
	}
}
