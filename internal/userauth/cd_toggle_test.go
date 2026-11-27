// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"github.com/jay94ks/seafield/internal/cluster/control"
	"testing"
)

func TestCDTogglePlanCannotMixSelectors(t *testing.T) {
	q := control.CDToggleQuery{App: "shop", Action: "pause-app-cd"}
	base := Request{Method: "app-cd-toggle-plan", Tenant: "team", CDToggle: &q}
	if !base.validQuerySelectors() {
		t.Fatal("CD toggle query rejected")
	}
	for _, edit := range []func(*Request){func(r *Request) { r.Tenant = "" }, func(r *Request) { r.Node = "node-a" }, func(r *Request) { r.After = "x" }, func(r *Request) { r.Method = "whoami" }, func(r *Request) { r.CDToggle = nil }} {
		bad := base
		edit(&bad)
		if bad.validQuerySelectors() {
			t.Fatal("mixed CD toggle selectors accepted")
		}
	}
}
