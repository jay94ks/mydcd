// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/jay94ks/seafield/internal/userauth"
)

func TestMixedVersions(t *testing.T) {
	n := func(v string) userauth.RaftNodeStatus { return userauth.RaftNodeStatus{Version: v} }
	if got := mixedVersions([]userauth.RaftNodeStatus{n("0.1.1"), n("0.1.0"), n(""), n("0.1.1"), n("0.1.0")}); got != "0.1.0 ×2, 0.1.1 ×2" {
		t.Fatal(got)
	}
	if got := mixedVersions([]userauth.RaftNodeStatus{n("0.1.1"), n(""), n("0.1.1")}); got != "" {
		t.Fatal("one version is not mixed", got)
	}
}

func TestNewUpgradeStatus(t *testing.T) {
	st := &userauth.RaftStatus{ObservedBy: "jay2", Nodes: []userauth.RaftNodeStatus{
		{Node: "jay2", Version: "0.1.1", Features: []string{"network-transit-v1", "network-transit-v2"}},
		{Node: "jay3", Version: "0.1.0", Features: []string{"network-transit-v1"}},
		{Node: "vps1"},
	}}
	v := newUpgradeStatus(st, userauth.ServerVersion{Version: "0.1.1", ClusterFeatures: []string{"network-transit-v1"}})
	if v.Server != "jay2" || v.Version != "0.1.1" || len(v.Nodes) != 3 || len(v.ClusterFeatures) != 1 {
		t.Fatalf("%+v", v)
	}
	if len(v.Nodes[0].Lacks) != 0 || len(v.Nodes[1].Lacks) != 1 || v.Nodes[1].Lacks[0] != "network-transit-v2" {
		t.Fatalf("lacks %+v", v.Nodes)
	}
	if v.Nodes[2].Lacks == nil || len(v.Nodes[2].Lacks) != 0 || v.Nodes[2].Features == nil {
		t.Fatal("unknown server is not lacking", v.Nodes[2])
	}
}
