// SPDX-License-Identifier: Apache-2.0

package server

import (
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// The cluster's set is the intersection over every server: a stale server
// counts with its last report, one that never reported has none, names this
// build cannot read never count, and the table is grouped by group and set.
func TestClusterFeaturesIntersection(t *testing.T) {
	v1 := buildinfo.NetworkTransitV1.String()
	host := func(version string, names ...string) *control.NodeAdminView {
		return &control.NodeAdminView{Host: &observability.Host{Version: version, Features: names}}
	}
	both := []sfc.NodeSummaryView{
		{Node: "a", Admin: host("0.1.5", v1, "network-transit-v2-preview", "network-future-v1")},
		{Node: "b", Stale: true, ObservedAt: 1_700_000_000_500, Admin: host("0.1.4", v1)},
	}
	v := newClusterFeaturesView(both)
	if v.Major != buildinfo.Major || !slices.Equal(v.Cluster, []string{v1}) {
		t.Fatalf("stale server's last report: %+v", v)
	}
	if a := v.Nodes[0]; !a.Seen || a.Build != "0.1.5" || a.Major == nil || *a.Major != 0 || !slices.Equal(a.Features, []string{v1, "network-transit-v2-preview"}) {
		t.Fatalf("node row: %+v", a)
	}
	if v.Nodes[1].Seen || v.Nodes[1].ReportedAt != 1_700_000_000 {
		t.Fatal("stale server shown as connected")
	}
	if len(v.Groups) != 1 || v.Groups[0].Name != "network" || len(v.Groups[0].Sets) != 1 {
		t.Fatalf("groups: %+v", v.Groups)
	}
	set := v.Groups[0].Sets[0]
	if set.Name != "network-transit" || set.Cluster != 1 || len(set.Behind) != 0 || len(set.Versions) != 1 || set.Versions[0] != (featureView{Name: v1, Version: 1, Postfix: "mainline", Desc: buildinfo.NetworkTransitV1.Description()}) {
		t.Fatalf("set: %+v", set)
	}
	never := append(both, sfc.NodeSummaryView{Node: "c", Stale: true})
	v = newClusterFeaturesView(never)
	if len(v.Cluster) != 0 || v.Nodes[2].Features == nil || v.Nodes[2].Major != nil || v.Nodes[2].ReportedAt != 0 {
		t.Fatalf("never-reported server: %+v", v)
	}
	if set := v.Groups[0].Sets[0]; set.Cluster != 0 || !slices.Equal(set.Behind, []string{"c"}) {
		t.Fatalf("never-reported server holds the set back: %+v", set)
	}
	if v := newClusterFeaturesView(nil); v.Cluster == nil || len(v.Cluster) != 0 || v.Nodes == nil || v.Groups == nil {
		t.Fatalf("no servers: %+v", v)
	}
}

func TestClusterFeaturesRoute(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	code, out := f.do("GET", "/api/v1/cluster/features", nil)
	if code != 200 || out["nodes"] == nil || out["groups"] == nil || out["cluster"] == nil {
		t.Fatalf("features: %d %v", code, out)
	}
}
