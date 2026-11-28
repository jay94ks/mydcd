// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestRegistryCatalogueRequestRequiresExactReadSelection(t *testing.T) {
	valid := RegistryCatalogQuery{Tenant: "tenant", Query: control.RegistryCatalogueQuery{Kind: "external", ID: "source", Repository: "team/app"}}
	if !valid.Valid() {
		t.Fatal("valid catalogue query")
	}
	for _, change := range []func(*RegistryCatalogQuery){
		func(q *RegistryCatalogQuery) { q.Tenant = "" }, func(q *RegistryCatalogQuery) { q.After = "invalid" },
		func(q *RegistryCatalogQuery) {
			q.Query = control.RegistryCatalogueQuery{Kind: "external", ID: "source", Repository: "../escape"}
		},
	} {
		copy := valid
		change(&copy)
		if copy.Valid() {
			t.Fatal("invalid catalogue fields", copy)
		}
	}
	if strict([]byte(`{"Tenant":"tenant","Query":{"Kind":"external","ID":"source"},"Node":"node-a"}`), &RegistryCatalogQuery{}) == nil {
		t.Fatal("foreign catalogue field accepted")
	}
}
