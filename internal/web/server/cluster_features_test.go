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
// counts with its last report, one that never reported has none, and names
// this build does not know never count.
func TestClusterFeaturesIntersection(t *testing.T) {
	transit := int(buildinfo.FeatureTransit)
	host := func(version string, names ...string) *control.NodeAdminView {
		return &control.NodeAdminView{Host: &observability.Host{Version: version, Features: names}}
	}
	both := []sfc.NodeSummaryView{
		{Node: "a", Admin: host("0.1.5", "transit", "from-the-future")},
		{Node: "b", Stale: true, Admin: host("0.1.4", "transit")},
	}
	v := newClusterFeaturesView(both)
	if v.Major != buildinfo.Major || !slices.Equal(v.Cluster, []int{transit}) {
		t.Fatalf("stale server's last report: %+v", v)
	}
	if a := v.Nodes[0]; !a.Seen || a.Build != "0.1.5" || a.Major == nil || *a.Major != 0 || !slices.Equal(a.Features, []int{transit}) {
		t.Fatalf("node row: %+v", a)
	}
	if v.Nodes[1].Seen {
		t.Fatal("stale server shown as connected")
	}
	if i := slices.IndexFunc(v.Features, func(f featureView) bool { return f.ID == transit }); i < 0 || v.Features[i].Name != "transit" || v.Features[i].Desc == "" {
		t.Fatalf("table: %+v", v.Features)
	}
	never := append(both, sfc.NodeSummaryView{Node: "c", Stale: true})
	if v := newClusterFeaturesView(never); len(v.Cluster) != 0 || v.Nodes[2].Features == nil || v.Nodes[2].Major != nil {
		t.Fatalf("never-reported server: %+v", v)
	}
	if v := newClusterFeaturesView(nil); v.Cluster == nil || len(v.Cluster) != 0 || v.Nodes == nil {
		t.Fatalf("no servers: %+v", v)
	}
}

func TestClusterFeaturesRoute(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	code, out := f.do("GET", "/api/v1/cluster/features", nil)
	if code != 200 || out["nodes"] == nil || out["features"] == nil || out["cluster"] == nil {
		t.Fatalf("features: %d %v", code, out)
	}
}
