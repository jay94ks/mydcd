// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"testing"
)

func TestIngressReadFieldsCannotSmuggleOtherMethodOrTenant(t *testing.T) {
	r := Request{Schema: 1, Method: "ingresses", Tenant: "tenant", Ingress: &control.IngressQuery{Tenant: "tenant", Node: "node-a", Part: "mappings"}}
	if !r.validMethodFields() || !r.validQuerySelectors() {
		t.Fatal("valid ingress query")
	}
	for _, bad := range []Request{{Schema: 1, Method: "ingresses", Tenant: "other", Ingress: r.Ingress}, {Schema: 1, Method: "whoami", Ingress: r.Ingress}, {Schema: 1, Method: "ingresses", Tenant: "tenant", Ingress: r.Ingress, App: "other"}, {Schema: 1, Method: "ingresses", Tenant: "tenant", Ingress: r.Ingress, Secret: []byte("private")}} {
		if bad.validMethodFields() && bad.validQuerySelectors() {
			t.Fatal("mixed ingress query accepted")
		}
	}
}
