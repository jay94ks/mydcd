// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"testing"
)

func TestNodeObservationSelectorsAndRaftStatusCannotAcquireWriteInputs(t *testing.T) {
	for _, r := range []Request{{Method: "raft-status", After: "cursor"}} {
		if !r.validMethodFields() || !r.validQuerySelectors() {
			t.Fatal("valid observation selector", r.Method)
		}
	}
	for _, r := range []Request{{Method: "raft-status", Tenant: "tenant"}, {Method: "raft-status", Node: "node-a"}} {
		if r.validMethodFields() && r.validQuerySelectors() {
			t.Fatal("cross-method/private selector accepted", r.Method)
		}
	}
}

// Observation pages are typed methods: each carries only its own selector.
func TestNodeObservationMethodsAreTyped(t *testing.T) {
	valid := map[string]string{
		"node-summary":      `{"Tenant":"tenant","Node":"node-a"}`,
		"node-disks":        `{"After":"cursor"}`,
		"mesh-links":        `{"Tenant":"tenant"}`,
		"node-tenant-usage": `{"Node":"node-a"}`,
	}
	for method, params := range valid {
		r := Request{Schema: 1, Method: method, Params: json.RawMessage(params)}
		if _, typed, ok := r.typedMethod(); !typed || !ok || !r.validMethodFields() {
			t.Fatal("valid observation request refused", method, params)
		}
	}
	for name, r := range map[string]Request{
		"usage without node": {Schema: 1, Method: "node-tenant-usage", Params: json.RawMessage(`{}`)},
		"usage with tenant":  {Schema: 1, Method: "node-tenant-usage", Params: json.RawMessage(`{"Tenant":"tenant","Node":"node-a"}`)},
		"bad node":           {Schema: 1, Method: "node-summary", Params: json.RawMessage(`{"Node":"../node"}`)},
		"foreign field":      {Schema: 1, Method: "node-disks", Params: json.RawMessage(`{"App":"app"}`)},
		"old field":          {Schema: 1, Method: "mesh-links", After: "other", Params: json.RawMessage(`{}`)},
		"old shape":          {Schema: 1, Method: "node-summary", Tenant: "tenant"},
	} {
		if r.validMethodFields() {
			t.Fatal(name, "accepted")
		}
	}
}
