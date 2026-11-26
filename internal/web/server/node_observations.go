// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// diskView: one node-disks row for the screen. The real row may group
// several purposes and storage roots on one filesystem; purpose and
// storageRootID keep the first of each for the existing screens, purposes
// and storageRoots carry all. Sizes are absent while unobserved; times
// are Unix seconds.
type diskView struct {
	Node          string   `json:"node"`
	ID            string   `json:"id,omitempty"`
	Mount         string   `json:"mount"`
	Device        string   `json:"device,omitempty"`
	FSType        string   `json:"fsType,omitempty"`
	State         string   `json:"state"`
	Purpose       string   `json:"purpose"`
	Purposes      []string `json:"purposes"`
	StorageRootID string   `json:"storageRootID,omitempty"`
	StorageRoots  []string `json:"storageRoots"`
	Total         *uint64  `json:"total,omitempty"`
	Used          *uint64  `json:"used,omitempty"`
	Free          *uint64  `json:"free,omitempty"`
	Available     *uint64  `json:"available,omitempty"`
	InodesFree    *uint64  `json:"inodesFree,omitempty"`
	ObservedAt    int64    `json:"observedAt"`
	Stale         bool     `json:"stale"`
}

func newDiskView(d mydc.NodeDiskView) diskView {
	v := diskView{Node: d.Node, ID: d.ID, Mount: d.Mount, Device: d.Device, FSType: d.Filesystem, State: d.State,
		Purposes: append([]string{}, d.Purposes...), StorageRoots: append([]string{}, d.StorageRoots...),
		Total: d.Total, Used: d.Used, Free: d.Free, Available: d.Available, InodesFree: d.InodesFree,
		ObservedAt: int64(d.ObservedAt / 1000), Stale: d.Stale}
	if len(d.Purposes) > 0 {
		v.Purpose = d.Purposes[0]
	}
	if len(d.StorageRoots) > 0 {
		v.StorageRootID = d.StorageRoots[0]
	}
	return v
}

// meshView: one mesh-links row. rttMillis/lossPercent/lastHandshakeAt/
// lastChangeAt/observedBy come from the sides' observations, which mydcd
// gives only in the cluster-wide admin view (the worst side wins). Times
// are Unix seconds.
type meshView struct {
	ID              string   `json:"id"`
	NodeA           string   `json:"nodeA"`
	NodeB           string   `json:"nodeB"`
	State           string   `json:"state"`
	RTTMillis       *float64 `json:"rttMillis,omitempty"`
	LossPercent     *float64 `json:"lossPercent,omitempty"`
	LastHandshakeAt int64    `json:"lastHandshakeAt,omitempty"`
	LastChangeAt    int64    `json:"lastChangeAt,omitempty"`
	ObservedBy      string   `json:"observedBy,omitempty"`
	ObservedAt      int64    `json:"observedAt"`
	Stale           bool     `json:"stale"`
}

func newMeshView(l mydc.MeshLinkView) meshView {
	v := meshView{ID: l.ID, NodeA: l.NodeA, NodeB: l.NodeB, State: l.State, ObservedAt: int64(l.ObservedAt / 1000), Stale: l.Stale}
	var handshake, change uint64
	for _, e := range l.Ends {
		o := e.Observation
		if o.RTTMillis != nil && (v.RTTMillis == nil || *o.RTTMillis > *v.RTTMillis) {
			x := *o.RTTMillis
			v.RTTMillis = &x
		}
		if o.LossPct != nil && (v.LossPercent == nil || *o.LossPct > *v.LossPercent) {
			x := *o.LossPct
			v.LossPercent = &x
		}
		// The oldest handshake a side reports; a side with none (0) is
		// skipped so the row keeps the reported one (state shows down).
		if o.LastHandshakeAt != 0 && (handshake == 0 || o.LastHandshakeAt < handshake) {
			handshake = o.LastHandshakeAt
		}
		change = max(change, o.LastChangeAt)
		if v.ObservedBy == "" {
			v.ObservedBy = e.ObservedBy
		}
	}
	v.LastHandshakeAt, v.LastChangeAt = int64(handshake/1000), int64(change/1000)
	return v
}

// GET /disks?tenant=&node=&after= and GET /nodes/{node}/disks?tenant=&after=
// → node-disks. No tenant = the cluster-wide admin view.
func (s *Server) handleNodeDisks(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	node := r.PathValue("node")
	if node == "" {
		node = q.Get("node")
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (listPage, error) {
		p, err := c.NodeDisks(ctx, q.Get("tenant"), node, q.Get("after"))
		if err != nil {
			return listPage{}, err
		}
		rows := make([]diskView, 0, len(p.Disks))
		for _, d := range p.Disks {
			rows = append(rows, newDiskView(d))
		}
		return s.page(rows, p.Next, p.RootRevision), nil
	})
}

// GET /mesh?tenant=&node=&after= → mesh-links. No tenant = the
// cluster-wide admin view.
func (s *Server) handleMeshLinks(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (listPage, error) {
		p, err := c.MeshLinks(ctx, q.Get("tenant"), q.Get("node"), q.Get("after"))
		if err != nil {
			return listPage{}, err
		}
		rows := make([]meshView, 0, len(p.Links))
		for _, l := range p.Links {
			rows = append(rows, newMeshView(l))
		}
		return s.page(rows, p.Next, p.RootRevision), nil
	})
}

// summaryView: one node-summary row for the screen (Unix seconds). status
// keeps the screens' words: ready, degraded (mydcd unready), unreachable,
// or mydcd's state as is (pending, draining, removed, …). role, cpuPercent
// and memory/disk totals come from the cluster-wide admin view; a tenant
// view carries that tenant's memUsed (when reported) and containers.
type summaryView struct {
	Node                string                `json:"node"`
	Status              string                `json:"status"`
	State               string                `json:"state"`
	Ready               bool                  `json:"ready"`
	Stale               bool                  `json:"stale"`
	Role                string                `json:"role,omitempty"`
	CPUPercent          *float64              `json:"cpuPercent,omitempty"`
	MemUsed             *uint64               `json:"memUsed,omitempty"`
	MemTotal            *uint64               `json:"memTotal,omitempty"`
	DiskUsed            *uint64               `json:"diskUsed,omitempty"`
	DiskTotal           *uint64               `json:"diskTotal,omitempty"`
	Containers          uint64                `json:"containers"`
	ObservedAt          int64                 `json:"observedAt"`
	ObserveLimitSeconds uint64                `json:"observeLimitSeconds"`
	CordonedBy          string                `json:"cordonedBy,omitempty"`
	CordonedAt          string                `json:"cordonedAt,omitempty"`
	Scheduling          membership.CordonView `json:"scheduling"`
}

func newSummaryView(n mydc.NodeSummaryView) summaryView {
	v := summaryView{Node: n.Node, Status: n.State, State: n.State, Ready: n.Ready, Stale: n.Stale, ObservedAt: int64(n.ObservedAt / 1000),
		ObserveLimitSeconds: n.ObserveLimitSeconds, CordonedBy: n.CordonedBy, CordonedAt: n.CordonedAt, Scheduling: n.Scheduling}
	if n.State == "unready" {
		v.Status = "degraded"
	}
	if u := n.Usage; u != nil {
		v.MemUsed = u.MemoryUsed
		if u.Containers != nil {
			v.Containers = *u.Containers
		}
	}
	if a := n.Admin; a != nil {
		v.Role, v.DiskUsed, v.DiskTotal = a.Role, a.DiskUsed, a.DiskTotal
		if h := a.Host; h != nil {
			v.MemUsed, v.MemTotal = h.MemoryUsed, h.MemoryTotal
			if h.CPUUsed != nil && h.CPUCapacity > 0 {
				p := float64(*h.CPUUsed) * 100 / float64(h.CPUCapacity)
				v.CPUPercent = &p
			}
		}
		for _, t := range a.Tenants {
			if t.Containers != nil {
				v.Containers += *t.Containers
			}
		}
	}
	return v
}

// nodeSummaries reads every node-summary page (bounded) as screen rows.
func nodeSummaries(ctx context.Context, c mydc.Conn, tenant string) ([]summaryView, error) {
	out := []summaryView{}
	after := ""
	for i := 0; i < incidentMaxPages; i++ {
		p, err := c.NodeSummary(ctx, tenant, "", after)
		if err != nil {
			return nil, err
		}
		for _, n := range p.Nodes {
			out = append(out, newSummaryView(n))
		}
		if after = p.Next; after == "" {
			break
		}
	}
	return out, nil
}

// GET /nodes/summary?tenant=&node=&after= → node-summary rows. No tenant =
// the cluster-wide admin view.
func (s *Server) handleNodeSummary(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (listPage, error) {
		p, err := c.NodeSummary(ctx, q.Get("tenant"), q.Get("node"), q.Get("after"))
		if err != nil {
			return listPage{}, err
		}
		rows := make([]summaryView, 0, len(p.Nodes))
		for _, n := range p.Nodes {
			rows = append(rows, newSummaryView(n))
		}
		return s.page(rows, p.Next, p.RootRevision), nil
	})
}
