// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"testing"
)

// network-dns-names takes exactly {Tenant, Network}: both valid IDs, nothing
// else.
func TestNetworkDNSNamesParams(t *testing.T) {
	rule := methodRules["network-dns-names"]
	for raw, ok := range map[string]bool{
		`{"Tenant":"shop","Network":"services"}`:             true,
		`{"Tenant":"","Network":"services"}`:                 false,
		`{"Tenant":"shop","Network":""}`:                     false,
		`{"Tenant":"shop","Network":"Bad Name"}`:             false,
		`{"Tenant":"shop","Network":"services","After":"x"}`: false,
	} {
		if _, got := rule.decode(json.RawMessage(raw)); got != ok {
			t.Errorf("%s: decoded=%v", raw, got)
		}
	}
}

// resources takes an optional tenant and a bounded cursor.
func TestResourcesParams(t *testing.T) {
	rule := methodRules["resources"]
	for raw, ok := range map[string]bool{
		`{}`:                            true,
		`{"Tenant":"shop","After":"x"}`: true,
		`{"Tenant":"Bad Tenant"}`:       false,
		`{"Tenant":"shop","Node":"a"}`:  false,
	} {
		if _, got := rule.decode(json.RawMessage(raw)); got != ok {
			t.Errorf("%s: decoded=%v", raw, got)
		}
	}
	if (ResourcesQuery{After: string(make([]byte, 513))}).Valid() {
		t.Fatal("oversized cursor accepted")
	}
}
