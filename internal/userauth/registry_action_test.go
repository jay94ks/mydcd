// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestRegistryActionPlanCannotMixScopeAndMethodFields(t *testing.T) {
	q := control.RegistryActionQuery{Action: "stop-registry", ID: "private"}
	base := Request{Method: "registry-action-plan", Tenant: "tenant", RegistryAction: &q}
	if !base.validQuerySelectors() {
		t.Fatal("typed registry plan rejected")
	}
	for _, edit := range []func(*Request){func(r *Request) { r.Tenant = "" }, func(r *Request) { r.Node = "node-a" }, func(r *Request) { r.After = "cursor" }, func(r *Request) { r.Method = "whoami" }, func(r *Request) { r.RegistryAction = nil }} {
		bad := base
		edit(&bad)
		if bad.validQuerySelectors() {
			t.Fatal("mixed registry action request accepted")
		}
	}
}
