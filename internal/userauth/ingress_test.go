// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"testing"
)

// ingresses carries its query only in Params: no Request field can widen
// its tenant, add a target user or smuggle a secret.
func TestIngressesRequestCarriesOnlyItsQuery(t *testing.T) {
	params, err := json.Marshal(control.IngressQuery{Tenant: "tenant", Node: "node-a", Part: "mappings"})
	if err != nil {
		t.Fatal(err)
	}
	ok := Request{Schema: 1, Method: "ingresses", Params: params}
	if _, typed, valid := ok.typedMethod(); !typed || !valid || !ok.validMethodFields() {
		t.Fatal("valid ingress query refused")
	}
	for name, r := range map[string]Request{
		"tenant field":  {Schema: 1, Method: "ingresses", Tenant: "other", Params: params},
		"target user":   {Schema: 1, Method: "ingresses", After: "other", Params: params},
		"secret":        {Schema: 1, Method: "ingresses", Secret: []byte("private"), Params: params},
		"bad part":      {Schema: 1, Method: "ingresses", Params: json.RawMessage(`{"Part":"everything"}`)},
		"unknown field": {Schema: 1, Method: "ingresses", Params: json.RawMessage(`{"Part":"mappings","Admin":true}`)},
	} {
		if r.validMethodFields() {
			t.Fatal(name, "accepted")
		}
	}
}
