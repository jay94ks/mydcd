// SPDX-License-Identifier: Apache-2.0

package app

import (
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/schema"
)

// A member leaving the network must not hold every other member's TUN: the
// members that stay open no path to it and keep applying.
func TestLivePeersLeaveOutDrainingMembers(t *testing.T) {
	tunnels := map[string]network.TunnelSpec{
		"a": {Owner: "c/a"},
		"b": {Owner: "c/b", Lifecycle: schema.Lifecycle{Drain: true}},
		"d": {Owner: "c/d"},
	}
	owners := []string{"c/b", "c/d", "c/e"}
	got := livePeers(tunnels, owners)
	if !slices.Equal(got, []string{"c/d"}) {
		t.Fatalf("live peers = %v", got)
	}
	if !slices.Equal(owners, []string{"c/b", "c/d", "c/e"}) {
		t.Fatalf("livePeers changed its input: %v", owners)
	}
}

func TestShortOwnerKeepsTheEnd(t *testing.T) {
	if got := shortOwner("cluster/0123456789abcdef"); got != "89abcdef" {
		t.Fatal(got)
	}
	if got := shortOwner("abc"); got != "abc" {
		t.Fatal(got)
	}
}
