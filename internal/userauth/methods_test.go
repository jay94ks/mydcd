// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"testing"
)

// A typed method's Request carries only its header and Params, and Params
// decodes strictly into the method's own type.
func TestTypedMethodRequestShape(t *testing.T) {
	ok := Request{Schema: 1, Method: "certificates", Params: json.RawMessage(`{}`)}
	if _, typed, valid := ok.typedMethod(); !typed || !valid || !ok.validMethodFields() {
		t.Fatal("valid typed request refused")
	}
	for name, r := range map[string]Request{
		"no params":      {Schema: 1, Method: "certificates"},
		"unknown field":  {Schema: 1, Method: "certificates", Params: json.RawMessage(`{"Nope":1}`)},
		"other spelling": {Schema: 1, Method: "certificates", Params: json.RawMessage(`{ }`)},
		"extra field":    {Schema: 1, Method: "certificates", Tenant: "tenant", Params: json.RawMessage(`{}`)},
		"untyped":        {Schema: 1, Method: "apps", Params: json.RawMessage(`{}`)},
	} {
		if r.validMethodFields() {
			t.Fatal(name, "accepted")
		}
	}
}
