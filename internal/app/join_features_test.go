// SPDX-License-Identifier: Apache-2.0

package app

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// A joining server that did not announce a feature the cluster's entries
// used is refused; a cluster that used none takes any joiner.
func TestJoinRefusesServerLackingUsedFeatures(t *testing.T) {
	s, err := state.New("admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := joinFeatures(cluster.View{State: s}, &sfcp.Session{}, nil, sfcp.Identity{}, false); err != nil {
		t.Fatal("baseline cluster", err)
	}
	c := state.Command{Actor: "admin", Epoch: 1, RequestID: "1", Key: "workload/a", Value: "x", Features: buildinfo.MustFeatures(buildinfo.NetworkTransitV1)}
	if s, _, err = state.Apply(s, 1, c); err != nil {
		t.Fatal(err)
	}
	err = joinFeatures(cluster.View{State: s}, &sfcp.Session{}, nil, sfcp.Identity{}, false)
	if err == nil || !strings.Contains(err.Error(), "this cluster uses network-transit-v1, which the joining server does not have") {
		t.Fatal(err)
	}
}
