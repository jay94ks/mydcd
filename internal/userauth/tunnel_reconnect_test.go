// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"testing"
)

func TestTunnelQueryCannotMixTenantAndOtherAuthoritySelectors(t *testing.T) {
	q := control.TunnelQuery{Node: "a", Peer: "b"}
	base := Request{Method: "tunnel-reconnect-plan", Tunnel: &q}
	if !base.validQuerySelectors() {
		t.Fatal("tunnel plan shape rejected")
	}
	for _, edit := range []func(*Request){func(r *Request) { r.Tenant = "team" }, func(r *Request) { r.Node = "a" }, func(r *Request) { r.After = "cursor" }, func(r *Request) { r.Tunnel = nil }, func(r *Request) { r.Method = "whoami" }} {
		bad := base
		edit(&bad)
		if bad.validQuerySelectors() {
			t.Fatal("mixed tunnel query accepted")
		}
	}
	if !(Request{Method: "tunnel-reconnect-status", Tunnel: &control.TunnelQuery{Operation: "repair-42"}}).validQuerySelectors() {
		t.Fatal("original status shape rejected")
	}
}
