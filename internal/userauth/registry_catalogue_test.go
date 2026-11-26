// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"testing"
)

func TestRegistryCatalogueRequestRequiresExactReadSelection(t *testing.T) {
	valid := Request{Method: "registry-catalog", Tenant: "tenant", RegistryCatalog: &control.RegistryCatalogueQuery{Kind: "external", ID: "source", Repository: "team/app"}}
	if !valid.validMethodFields() || !valid.validQuerySelectors() {
		t.Fatal("valid catalogue query")
	}
	for _, change := range []func(*Request){
		func(r *Request) { r.Tenant = "" }, func(r *Request) { r.Node = "node-a" }, func(r *Request) { r.After = "invalid" }, func(r *Request) { r.RegistryCatalog = nil }, func(r *Request) { r.App = "app" }, func(r *Request) {
			r.RegistryCatalog = &control.RegistryCatalogueQuery{Kind: "external", ID: "source", Repository: "../escape"}
		},
	} {
		copy := valid
		change(&copy)
		if copy.validMethodFields() && copy.validQuerySelectors() {
			t.Fatal("foreign/invalid catalogue fields", copy)
		}
	}
}
