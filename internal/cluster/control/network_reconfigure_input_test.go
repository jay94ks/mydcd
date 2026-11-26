// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/tenancy"
)

func TestNetworkMembershipInputRequiresExplicitTargetMembers(t *testing.T) {
	q := NetworkReconfigure{Target: tenancy.TUNDefinition{Tenant: "tenant", Name: "services", Members: []tenancy.TUNNode{}}, Members: []tenancy.NetworkChangeVersion{{Tenant: "tenant", ID: "member", Generation: 2, Revision: 4}}}
	if _, err := InputChange(changeInput("reconfigure-tun-network", 9, q), "admin"); err != nil {
		t.Fatal("explicit empty target rejected", err)
	}
	q.Target.Members = nil
	if _, err := InputChange(changeInput("reconfigure-tun-network", 9, q), "admin"); err == nil {
		t.Fatal("null target silently became group retirement")
	}
	if _, err := InputChange([]byte(`{"schema":1,"action":"reconfigure-tun-network","expected":9,"payload":{"Target":{"Tenant":"tenant","Name":"services"},"Members":[]}}`), "admin"); err == nil {
		t.Fatal("omitted Members became a destructive replacement")
	}
}
