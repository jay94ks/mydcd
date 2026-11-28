// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// NodeObservationQuery selects one page of node-summary, node-disks or
// mesh-links. An empty Tenant asks for the whole cluster (administrators);
// Node narrows the page to one server.
type NodeObservationQuery struct {
	Tenant string `json:",omitempty"`
	Node   string `json:",omitempty"`
	After  string `json:",omitempty"`
}

func (q NodeObservationQuery) Valid() bool {
	return validObservationSelector(q.Tenant, q.Node, q.After)
}

// NodeTenantUsageQuery selects one page of a server's per-tenant usage.
type NodeTenantUsageQuery struct {
	Node  string
	After string `json:",omitempty"`
}

func (q NodeTenantUsageQuery) Valid() bool {
	return q.Node != "" && validObservationSelector("", q.Node, q.After)
}

func validObservationSelector(tenant, node, after string) bool {
	return (tenant == "" || lifecycle.ValidID(tenant)) && (node == "" || lifecycle.ValidID(node)) && len(after) <= 512
}

func (c Client) NodeSummary(ctx context.Context, peer sfcp.Peer, session access.Session, q NodeObservationQuery) (control.NodeSummaryPage, error) {
	return call(ctx, c, peer, session, NodeSummaryMethod, q)
}

func (c Client) NodeDisks(ctx context.Context, peer sfcp.Peer, session access.Session, q NodeObservationQuery) (control.NodeDisksPage, error) {
	return call(ctx, c, peer, session, NodeDisksMethod, q)
}

func (c Client) NodeTenantUsage(ctx context.Context, peer sfcp.Peer, session access.Session, q NodeTenantUsageQuery) (control.NodeTenantPage, error) {
	return call(ctx, c, peer, session, NodeTenantUsageMethod, q)
}

func (c Client) MeshLinks(ctx context.Context, peer sfcp.Peer, session access.Session, q NodeObservationQuery) (control.MeshLinksPage, error) {
	return call(ctx, c, peer, session, MeshLinksMethod, q)
}

// Each observation page is authorized by its control.Policy reader: the whole
// cluster needs ManageCluster, a tenant page Read (node-disks ManageVolumes)
// on each server it shows.
var (
	NodeSummaryMethod = define(Method[NodeObservationQuery, control.NodeSummaryPage]{Name: "node-summary"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q NodeObservationQuery) (control.NodeSummaryPage, string) {
		return observe(ctx, s, view, func(now int64, reports []observability.Report, waiting []string) (control.NodeSummaryPage, error) {
			page, err := s.Policy.NodeSummary(view.State, session, now, q.Tenant, q.Node, q.After, reports, !view.Local)
			for i := range page.Nodes {
				page.Nodes[i].Waiting = slices.Contains(waiting, page.Nodes[i].Node)
			}
			return page, err
		})
	})
	NodeDisksMethod = define(Method[NodeObservationQuery, control.NodeDisksPage]{Name: "node-disks"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q NodeObservationQuery) (control.NodeDisksPage, string) {
		return observe(ctx, s, view, func(now int64, reports []observability.Report, waiting []string) (control.NodeDisksPage, error) {
			return s.Policy.NodeDisks(view.State, session, now, q.Tenant, q.Node, q.After, reports)
		})
	})
	NodeTenantUsageMethod = define(Method[NodeTenantUsageQuery, control.NodeTenantPage]{Name: "node-tenant-usage"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q NodeTenantUsageQuery) (control.NodeTenantPage, string) {
		return observe(ctx, s, view, func(now int64, reports []observability.Report, waiting []string) (control.NodeTenantPage, error) {
			return s.Policy.NodeTenantUsage(view.State, session, now, q.Node, q.After, reports)
		})
	})
	MeshLinksMethod = define(Method[NodeObservationQuery, control.MeshLinksPage]{Name: "mesh-links"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q NodeObservationQuery) (control.MeshLinksPage, string) {
		return observe(ctx, s, view, func(now int64, reports []observability.Report, waiting []string) (control.MeshLinksPage, error) {
			return s.Policy.MeshLinks(view.State, session, now, q.Tenant, q.Node, q.After, reports)
		})
	})
)

// observe loads the local authenticated measurements and runs one page reader.
func observe[R any](ctx context.Context, s Service, view cluster.View, read func(int64, []observability.Report, []string) (R, error)) (R, string) {
	var zero R
	if s.NodeObservations == nil {
		return zero, "unavailable"
	}
	reports, waiting, err := s.NodeObservations(ctx, view)
	if err != nil {
		return zero, "unavailable"
	}
	page, err := read(time.Now().Unix(), reports, waiting)
	switch {
	case err == nil:
		return page, "ok"
	case errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid):
		return zero, "denied"
	case errors.Is(err, access.ErrConflict):
		return zero, "conflict"
	}
	return zero, "unavailable"
}

// Keep the callback typed at the ownership boundary: Runtime loads local
// authenticated measurements, control owns authorization/public projections.
// The second result names the servers that did not answer in time; their
// reports may be missing or old, and views show them as waiting ("대기 중").
type NodeObservations func(context.Context, cluster.View) ([]observability.Report, []string, error)

// tunnelWaits lists, for a deploy that waits, the tenant's own TUN networks a
// server reports it cannot open yet. Other tenants' rows are never included.
func (s Service) tunnelWaits(ctx context.Context, view cluster.View, tenant string) []string {
	if s.NodeObservations == nil || tenant == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	reports, _, err := s.NodeObservations(ctx, view)
	if err != nil {
		return nil
	}
	now := uint64(time.Now().UnixMilli())
	var out []string
	for _, r := range reports {
		if r.Host == nil || r.At > now || now-r.At > observability.MaxAge {
			continue
		}
		for _, w := range r.Host.TunnelWaits {
			if w.Tenant == tenant && len(out) < 8 {
				out = append(out, fmt.Sprintf("server %s cannot open TUN network %s: %s", r.Node, w.Network, w.Reason))
			}
		}
	}
	return out
}
