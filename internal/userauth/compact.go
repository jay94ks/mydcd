// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"time"
)

func (s Service) compactQuery(view cluster.View, q Request, session access.Session) Reply {
	out := Reply{Schema: 1, Code: "unavailable", RootRevision: view.State.Object(control.CatalogKey).Revision, CompactRootRevision: view.State.Object(control.CompactKey).Revision, ModuleEpoch: view.State.ModuleEpoch()}
	var err error
	if q.Method == "raft-compact-plan" {
		var page control.CompactPlanPage
		page, err = s.Policy.CompactPlanPage(view.State, session, time.Now().Unix(), *q.Compact)
		if err == nil {
			out.CompactPlan = &page
		}
	} else {
		var page control.CompactStatusPage
		page, err = s.Policy.CompactStatusPage(view.State, session, time.Now().Unix(), *q.Compact)
		if err == nil {
			out.CompactStatus = &page
		}
	}
	if err == nil {
		out.Code = "ok"
	} else if errors.Is(err, access.ErrDenied) {
		out.Code = "denied"
	} else if errors.Is(err, access.ErrConflict) {
		out.Code = "conflict"
		out.InputCode = "COMPACT_VIEW_CHANGED"
	}
	return out
}
func (c Client) CompactPlan(ctx context.Context, peer mydcp.Peer, session access.Session, selection control.CompactSelection) (control.CompactPlan, error) {
	plan := control.CompactPlan{Schema: 1, Cluster: c.Cluster, Selection: selection}
	q := control.CompactQuery{Selection: &selection}
	total := 0
	for pages := 0; pages < 16; pages++ {
		reply, err := c.query(ctx, peer, session, Request{Method: "raft-compact-plan", Compact: &q})
		if err != nil {
			return control.CompactPlan{}, err
		}
		page := reply.CompactPlan
		if page == nil || page.Schema != 1 || page.Cluster != c.Cluster || page.Total < 1 || page.Total > 1024 || len(page.Nodes) == 0 || len(page.Nodes) > 64 || total != 0 && page.Total != total || plan.Target != ([32]byte{}) && plan.Target != page.Target {
			return control.CompactPlan{}, mydcp.ErrFrame
		}
		total = page.Total
		plan.Target = page.Target
		plan.Nodes = append(plan.Nodes, page.Nodes...)
		if page.Next == "" {
			if len(plan.Nodes) != total || !plan.Valid() {
				return control.CompactPlan{}, mydcp.ErrFrame
			}
			return plan, nil
		}
		if page.Next == q.After {
			return control.CompactPlan{}, mydcp.ErrFrame
		}
		q.After = page.Next
	}
	return control.CompactPlan{}, mydcp.ErrFrame
}
func (c Client) CompactStatus(ctx context.Context, peer mydcp.Peer, session access.Session, q control.CompactQuery) (Reply, error) {
	if !q.Valid(false) {
		return Reply{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "raft-compact-status", Compact: &q})
	if err != nil {
		return reply, err
	}
	page := reply.CompactStatus
	if page == nil || page.Schema != 1 || page.Cluster != c.Cluster || page.Summary.Operation != q.Operation || len(page.Nodes) > 4 || page.Summary.Total < 1 || page.Summary.Total > 1024 {
		return Reply{}, mydcp.ErrFrame
	}
	return reply, nil
}
