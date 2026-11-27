// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
)

func TestVPSStillMemberFollowsMembershipNotPhase(t *testing.T) {
	entry := func(phase membership.Phase) membership.Entry {
		return membership.Entry{Peer: config.Peer{ID: "edge-1"}, Phase: phase}
	}
	view := func(phase lifecycle.Phase) membership.NodeView {
		return membership.NodeView{Node: lifecycle.Node{Member: lifecycle.Member{ID: "edge-1"}, Phase: phase}}
	}
	for _, c := range []struct {
		name  string
		nodes nodeDirectory
		want  bool
	}{
		{"no entry", nodeDirectory{}, false},
		{"only invited", nodeDirectory{Members: []membership.Entry{entry(membership.Invited)}}, false},
		{"joined, no runtime yet", nodeDirectory{Members: []membership.Entry{entry(membership.Ready)}}, true},
		{"joined", nodeDirectory{Members: []membership.Entry{entry(membership.Ready)}, Nodes: []membership.NodeView{view(lifecycle.Active)}}, true},
		{"removed with node remove", nodeDirectory{Members: []membership.Entry{entry(membership.Ready)}, Nodes: []membership.NodeView{view(lifecycle.Removed)}}, false},
		{"force removed", nodeDirectory{Members: []membership.Entry{entry(membership.Active)}, Nodes: []membership.NodeView{view(lifecycle.Retired)}}, false},
	} {
		if got := vpsStillMember(c.nodes, "edge-1"); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
