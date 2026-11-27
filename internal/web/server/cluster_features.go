// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// SFCP feature sets (canvas v268 Consensus 'SFCP 기능' card): this major's
// feature table, each server's reported features and the cluster's set. No
// sfcd method of its own: servers report Host.Features (names) in the admin
// node-summary, and the table is this module's buildinfo. The cluster's set
// is the intersection over every server, as sfcd's Transport.ClusterFeatures
// computes it: a stale server counts with its last report, a server that
// never reported counts as having none.

type featureView struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type nodeFeaturesView struct {
	Node     string `json:"node"`
	Major    *int   `json:"major,omitempty"`
	Build    string `json:"build,omitempty"`
	Features []int  `json:"features"`
	Seen     bool   `json:"seen"`
}

type clusterFeaturesView struct {
	Major    int                `json:"major"`
	Features []featureView      `json:"features"`
	Cluster  []int              `json:"cluster"`
	Nodes    []nodeFeaturesView `json:"nodes"`
}

// featureIDs maps names to this build's feature numbers; names this build
// does not know are left out (a newer build's feature is never in the
// cluster's set as seen from here).
func featureIDs(names []string) buildinfo.Features {
	var s buildinfo.Features
	for f := buildinfo.Feature(0); f < 64; f++ {
		if n := f.Name(); n != "" && slices.Contains(names, n) {
			s = s.With(f)
		}
	}
	return s
}

func featureList(s buildinfo.Features) []int {
	out := []int{}
	for f := buildinfo.Feature(0); f < 64; f++ {
		if s.Has(f) {
			out = append(out, int(f))
		}
	}
	return out
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
	v := clusterFeaturesView{Major: buildinfo.Major, Features: []featureView{}, Cluster: []int{}, Nodes: []nodeFeaturesView{}}
	for f := buildinfo.Feature(0); f < 64; f++ {
		if n := f.Name(); n != "" {
			v.Features = append(v.Features, featureView{ID: int(f), Name: n, Desc: f.Description()})
		}
	}
	all := ^buildinfo.Features(0)
	for _, n := range nodes {
		row := nodeFeaturesView{Node: n.Node, Features: []int{}, Seen: !n.Stale}
		var have buildinfo.Features
		if n.Admin != nil && n.Admin.Host != nil {
			h := n.Admin.Host
			have = featureIDs(h.Features)
			row.Build, row.Major, row.Features = h.Version, versionMajor(h.Version), featureList(have)
		}
		all = all.And(have)
		v.Nodes = append(v.Nodes, row)
	}
	if len(nodes) > 0 {
		v.Cluster = featureList(all)
	}
	return v
}

// GET /cluster/features → {major, features:[{id, name, desc}], cluster:[id],
// nodes:[{node, major?, build?, features:[id], seen}]}. Reads the admin
// node-summary, so who may see it is sfcd's (system administrator, as for
// GET /raft).
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
