// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// CompactPlanQuery asks for one page of a manual Raft compaction preview.
type CompactPlanQuery struct {
	Selection control.CompactSelection
	After     string `json:",omitempty"`
}

func (q CompactPlanQuery) Valid() bool { return q.query().Valid(true) }

func (q CompactPlanQuery) query() control.CompactQuery {
	return control.CompactQuery{Selection: &q.Selection, After: q.After}
}

// CompactStatusQuery asks for one page of an original compaction job.
type CompactStatusQuery struct {
	Operation string
	After     string `json:",omitempty"`
}

func (q CompactStatusQuery) Valid() bool { return q.query().Valid(false) }

func (q CompactStatusQuery) query() control.CompactQuery {
	return control.CompactQuery{Operation: q.Operation, After: q.After}
}

var (
	CompactPlanMethod = define(Method[CompactPlanQuery, control.CompactPlanPage]{Name: "raft-compact-plan"}, false, func(_ context.Context, s Service, view cluster.View, session access.Session, q CompactPlanQuery) (control.CompactPlanPage, string) {
		if !s.manageCluster(view, session) {
			return control.CompactPlanPage{}, "denied"
		}
		page, err := s.Policy.CompactPlanPage(view.State, session, time.Now().Unix(), q.query())
		return page, compactCode(err)
	})
	CompactStatusMethod = define(Method[CompactStatusQuery, control.CompactStatusPage]{Name: "raft-compact-status"}, false, func(_ context.Context, s Service, view cluster.View, session access.Session, q CompactStatusQuery) (control.CompactStatusPage, string) {
		if !s.manageCluster(view, session) {
			return control.CompactStatusPage{}, "denied"
		}
		page, err := s.Policy.CompactStatusPage(view.State, session, time.Now().Unix(), q.query())
		return page, compactCode(err)
	})
)

func compactCode(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, access.ErrDenied):
		return "denied"
	case errors.Is(err, access.ErrConflict):
		return refuse("conflict", "COMPACT_VIEW_CHANGED")
	}
	return "unavailable"
}

func (c Client) CompactPlan(ctx context.Context, peer sfcp.Peer, session access.Session, selection control.CompactSelection) (control.CompactPlan, error) {
	plan := control.CompactPlan{Schema: 1, Cluster: c.Cluster, Selection: selection}
	q := CompactPlanQuery{Selection: selection}
	total := 0
	for pages := 0; pages < 16; pages++ {
		page, err := c.CompactPlanPage(ctx, peer, session, q)
		if err != nil {
			return control.CompactPlan{}, err
		}
		if page.Schema != 1 || page.Cluster != c.Cluster || page.Total < 1 || page.Total > 1024 || len(page.Nodes) == 0 || len(page.Nodes) > 64 || total != 0 && page.Total != total || plan.Target != ([32]byte{}) && plan.Target != page.Target {
			return control.CompactPlan{}, sfcp.ErrFrame
		}
		total = page.Total
		plan.Target = page.Target
		plan.Nodes = append(plan.Nodes, page.Nodes...)
		if page.Next == "" {
			if len(plan.Nodes) != total || !plan.Valid() {
				return control.CompactPlan{}, sfcp.ErrFrame
			}
			return plan, nil
		}
		if page.Next == q.After {
			return control.CompactPlan{}, sfcp.ErrFrame
		}
		q.After = page.Next
	}
	return control.CompactPlan{}, sfcp.ErrFrame
}

// CompactPlanPage reads one preview page; CompactPlan collects and checks all.
func (c Client) CompactPlanPage(ctx context.Context, peer sfcp.Peer, session access.Session, q CompactPlanQuery) (control.CompactPlanPage, error) {
	return call(ctx, c, peer, session, CompactPlanMethod, q)
}

func (c Client) CompactStatus(ctx context.Context, peer sfcp.Peer, session access.Session, q CompactStatusQuery) (control.CompactStatusPage, error) {
	if !q.Valid() {
		return control.CompactStatusPage{}, sfcp.ErrAdmission
	}
	page, err := call(ctx, c, peer, session, CompactStatusMethod, q)
	if err != nil {
		return control.CompactStatusPage{}, err
	}
	if page.Schema != 1 || page.Cluster != c.Cluster || page.Summary.Operation != q.Operation || len(page.Nodes) > 4 || page.Summary.Total < 1 || page.Summary.Total > 1024 {
		return control.CompactStatusPage{}, sfcp.ErrFrame
	}
	return page, nil
}
