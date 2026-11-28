// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestRegistryActionPlanCannotCarryOtherFields(t *testing.T) {
	q := control.RegistryActionQuery{Action: "stop-registry", ID: "private"}
	if !(RegistryActionQuery{Tenant: "tenant", Query: q}).Valid() {
		t.Fatal("typed registry plan rejected")
	}
	if (RegistryActionQuery{Query: q}).Valid() || (RegistryActionQuery{Tenant: "tenant", Query: control.RegistryActionQuery{Action: "delete-registry", ID: "private"}}).Valid() {
		t.Fatal("registry plan without tenant or with a foreign action accepted")
	}
	for _, raw := range []string{
		`{"Tenant":"tenant","Query":{"Action":"stop-registry","ID":"private"},"Node":"node-a"}`,
		`{"Tenant":"tenant","Query":{"Action":"stop-registry","ID":"private"},"After":"cursor"}`,
	} {
		if strict([]byte(raw), &RegistryActionQuery{}) == nil {
			t.Fatal("mixed registry action request accepted", raw)
		}
	}
}
