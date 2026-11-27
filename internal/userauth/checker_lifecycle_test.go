// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"strings"
	"testing"
)

// lifecycles is typed: its tenant and cursor live only in Params, and any
// other field or an oversized cursor fails decoding before the handler.
func TestCheckerLifecycleMetadataQueryRequiresExplicitTenant(t *testing.T) {
	for _, test := range []struct {
		params string
		ok     bool
	}{
		{`{"Tenant":"tenant"}`, true},
		{`{"Tenant":"tenant","After":"script/ready/00000000000000000001"}`, true},
		{`{}`, false},
		{`{"Tenant":"tenant","Node":"node-a"}`, false},
		{`{"Tenant":"tenant","After":"` + strings.Repeat("a", 513) + `"}`, false},
	} {
		if _, typed, ok := (Request{Method: "lifecycles", Params: json.RawMessage(test.params)}).typedMethod(); !typed || ok != test.ok {
			t.Fatal(test.params, typed, ok)
		}
	}
	if _, typed, ok := (Request{Method: "lifecycles", Tenant: "tenant", Params: json.RawMessage(`{"Tenant":"tenant"}`)}).typedMethod(); !typed || ok {
		t.Fatal("legacy selector beside Params admitted")
	}
}
