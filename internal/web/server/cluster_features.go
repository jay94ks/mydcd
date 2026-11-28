// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Feature sets (canvas 서버 › 합의 상태 '기능 집합' card): this major's
// feature table grouped by group and set, each server's reported features
// and the cluster's set. No sfcd method of its own: servers report
// Host.Features (written names such as network-transit-v1) in the admin
// node-summary, and the table is this module's buildinfo. The cluster's set
// is the intersection over every server, as sfcd's Transport.ClusterFeatures
// computes it: a stale server counts with its last report, a server that
// never reported counts as having none.

type featureView struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	// Postfix is "mainline" for a version inside the compatibility promise.
	Postfix string `json:"postfix"`
	Desc    string `json:"desc"`
}

type featureSetView struct {
	// Name is the written set name, such as "network-transit".
	Name     string        `json:"name"`
	Versions []featureView `json:"versions"`
	// Cluster is the highest mainline version every server has, 0 for none.
	Cluster int `json:"cluster"`
	// Behind are the servers whose highest mainline version of the set is
	// below the table's newest, which keep the cluster from using it.
	Behind []string `json:"behind"`

	group, set uint8
	newest     uint16
}

type featureGroupView struct {
	Name string           `json:"name"`
	Sets []featureSetView `json:"sets"`
}

type nodeFeaturesView struct {
	Node  string `json:"node"`
	Major *int   `json:"major,omitempty"`
	Build string `json:"build,omitempty"`
	// ReportedAt is when the server last reported (Unix seconds, the
	// node-summary observation); absent for a server that never reported.
	ReportedAt int64    `json:"reportedAt,omitempty"`
	Features   []string `json:"features"`
	Seen       bool     `json:"seen"`
}

type clusterFeaturesView struct {
	Major   int                `json:"major"`
	Groups  []featureGroupView `json:"groups"`
	Cluster []string           `json:"cluster"`
	Nodes   []nodeFeaturesView `json:"nodes"`
}

// parseFeatures reads reported names; names this build cannot read (a set
// a newer build named) are left out, since this build's table has no row
// for them.
func parseFeatures(names []string) buildinfo.Features {
	var list []buildinfo.Feature
	for _, n := range names {
		if f, ok := buildinfo.ParseFeature(n); ok {
			list = append(list, f)
		}
	}
	s, _ := buildinfo.NewFeatures(list...)
	return s
}

func featureNames(s buildinfo.Features) []string {
	if n := s.Names(); n != nil {
		return n
	}
	return []string{}
}

// versionMajor reads the major of "major.minor.build[-dev]".
func versionMajor(v string) *int {
	head, _, ok := strings.Cut(v, ".")
	if !ok {
		return nil
	}
	n, err := strconv.Atoi(head)
	if err != nil {
		return nil
	}
	return &n
}

func newClusterFeaturesView(nodes []sfc.NodeSummaryView) clusterFeaturesView {
	v := clusterFeaturesView{Major: buildinfo.Major, Groups: []featureGroupView{}, Cluster: []string{}, Nodes: []nodeFeaturesView{}}
	var all buildinfo.Features
	have := make([]buildinfo.Features, len(nodes))
	for i, n := range nodes {
		row := nodeFeaturesView{Node: n.Node, Features: []string{}, Seen: !n.Stale, ReportedAt: int64(n.ObservedAt / 1000)}
		if n.Admin != nil && n.Admin.Host != nil {
			h := n.Admin.Host
			have[i] = parseFeatures(h.Features)
			row.Build, row.Major, row.Features = h.Version, versionMajor(h.Version), featureNames(have[i])
		}
		if i == 0 {
			all = have[i]
		} else {
			all = all.And(have[i])
		}
		v.Nodes = append(v.Nodes, row)
	}
	v.Cluster = featureNames(all)
	for _, f := range buildinfo.Table() {
		if len(v.Groups) == 0 || v.Groups[len(v.Groups)-1].Name != buildinfo.GroupName(f.Group) {
			v.Groups = append(v.Groups, featureGroupView{Name: buildinfo.GroupName(f.Group), Sets: []featureSetView{}})
		}
		g := &v.Groups[len(v.Groups)-1]
		name := buildinfo.SetName(f.Group, f.Set)
		if len(g.Sets) == 0 || g.Sets[len(g.Sets)-1].Name != name {
			g.Sets = append(g.Sets, featureSetView{Name: name, Versions: []featureView{}, Cluster: int(all.Best(f.Group, f.Set)), Behind: []string{}, group: f.Group, set: f.Set})
		}
		set := &g.Sets[len(g.Sets)-1]
		if f.Stable() && f.Version > set.newest {
			set.newest = f.Version
		}
		set.Versions = append(set.Versions, featureView{Name: f.String(), Version: int(f.Version), Postfix: f.PostfixName(), Desc: f.Description()})
	}
	for gi := range v.Groups {
		for si := range v.Groups[gi].Sets {
			set := &v.Groups[gi].Sets[si]
			for i, n := range nodes {
				if have[i].Best(set.group, set.set) < set.newest {
					set.Behind = append(set.Behind, n.Node)
				}
			}
		}
	}
	return v
}

// GET /cluster/features → {major, groups:[{name, sets:[{name, versions:[{name,
// version, postfix, desc}], cluster, behind:[node]}]}], cluster:[name],
// nodes:[{node, major?, build?, reportedAt?, features:[name], seen}]}. Reads
// the admin node-summary, so who may see it is sfcd's (system administrator,
// as for GET /raft).
func (s *Server) handleClusterFeatures(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (clusterFeaturesView, error) {
		var nodes []sfc.NodeSummaryView
		after := ""
		for i := 0; i < incidentMaxPages; i++ {
			p, err := c.NodeSummary(ctx, "", "", after)
			if err != nil {
				return clusterFeaturesView{}, err
			}
			nodes = append(nodes, p.Nodes...)
			if after = p.Next; after == "" {
				break
			}
		}
		return newClusterFeaturesView(nodes), nil
	})
}
