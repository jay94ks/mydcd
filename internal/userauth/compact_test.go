// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestCompactUserRequestShapeCannotMixTenantOrOtherMethodSelectors(t *testing.T) {
	params, _ := json.Marshal(CompactPlanQuery{Selection: control.CompactSelection{Mode: "keep"}})
	base := Request{Schema: 1, Method: "raft-compact-plan", Params: params}
	if !base.validMethodFields() {
		t.Fatal("typed compact plan rejected", string(params))
	}
	for _, edit := range []func(*Request){
		func(r *Request) { r.Tenant = "tenant" },
		func(r *Request) { r.Node = "a" },
		func(r *Request) { r.After = "cursor" },
		func(r *Request) { r.Params = nil },
		func(r *Request) { r.Method = "raft-compact-status" },
	} {
		bad := base
		edit(&bad)
		if bad.validMethodFields() {
			t.Fatal("mixed compact authority selector accepted")
		}
	}
	status := Request{Schema: 1, Method: "raft-compact-status", Params: json.RawMessage(`{"Operation":"maint-1"}`)}
	if !status.validMethodFields() {
		t.Fatal("original status rejected")
	}
	if bad := (Request{Schema: 1, Method: "raft-compact-status", Params: json.RawMessage(`{"Operation":"../maint"}`)}); bad.validMethodFields() {
		t.Fatal("malformed original accepted")
	}
}

// A typed refusal may carry one symbolic input code.
func TestTypedRefusalCarriesInputCode(t *testing.T) {
	code, input, _ := cutRefusal(refuse("conflict", "COMPACT_VIEW_CHANGED"))
	if code != "conflict" || input != "COMPACT_VIEW_CHANGED" {
		t.Fatal(code, input)
	}
	if code, input, _ = cutRefusal("denied"); code != "denied" || input != "" {
		t.Fatal(code, input)
	}
	if code, input, _ = cutRefusal("conflict not/symbolic"); code != "conflict" || input != "" {
		t.Fatal(code, input)
	}
}
