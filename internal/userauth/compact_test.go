// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"testing"
)

func TestCompactUserRequestShapeCannotMixTenantOrOtherMethodSelectors(t *testing.T) {
	base := Request{Method: "raft-compact-plan", Compact: &control.CompactQuery{Selection: &control.CompactSelection{Mode: "keep"}}}
	if !base.validQuerySelectors() {
		t.Fatal("typed compact plan rejected")
	}
	for _, edit := range []func(*Request){func(r *Request) { r.Tenant = "tenant" }, func(r *Request) { r.Method = "whoami" }, func(r *Request) { r.Node = "a" }, func(r *Request) { r.After = "cursor" }, func(r *Request) { r.Compact = nil }} {
		bad := base
		edit(&bad)
		if bad.validQuerySelectors() {
			t.Fatal("mixed compact authority selector accepted")
		}
	}
	status := Request{Method: "raft-compact-status", Compact: &control.CompactQuery{Operation: "maint-1"}}
	if !status.validQuerySelectors() {
		t.Fatal("original status rejected")
	}
}
