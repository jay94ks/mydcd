// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/observability"
)

func (c Client) NodeObservationPage(ctx context.Context, peer mydcp.Peer, session access.Session, method, tenant, node, after string) (Reply, error) {
	if method != "node-summary" && method != "node-disks" && method != "node-tenant-usage" && method != "mesh-links" {
		return Reply{}, access.ErrInvalid
	}
	return c.query(ctx, peer, session, Request{Method: method, Tenant: tenant, Node: node, After: after})
}

func (s Service) nodeObservationQueryReply(ctx context.Context, view cluster.View, session access.Session, request Request) Reply {
	if s.NodeObservations == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	reports, err := s.NodeObservations(ctx, view)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	now := time.Now().Unix()
	var reply Reply
	switch request.Method {
	case "node-summary":
		var page control.NodeSummaryPage
		page, err = s.Policy.NodeSummary(view.State, session, now, request.Tenant, request.Node, request.After, reports, !view.Local)
		if err == nil {
			reply = Reply{Schema: 1, Code: "ok", NodeSummary: &page}
		}
	case "node-disks":
		var page control.NodeDisksPage
		page, err = s.Policy.NodeDisks(view.State, session, now, request.Tenant, request.Node, request.After, reports)
		if err == nil {
			reply = Reply{Schema: 1, Code: "ok", NodeDisks: &page}
		}
	case "node-tenant-usage":
		var page control.NodeTenantPage
		page, err = s.Policy.NodeTenantUsage(view.State, session, now, request.Node, request.After, reports)
		if err == nil {
			reply = Reply{Schema: 1, Code: "ok", NodeTenantUsage: &page}
		}
	case "mesh-links":
		var page control.MeshLinksPage
		page, err = s.Policy.MeshLinks(view.State, session, now, request.Tenant, request.Node, request.After, reports)
		if err == nil {
			reply = Reply{Schema: 1, Code: "ok", MeshLinks: &page}
		}
	}
	if err == nil {
		return reply
	}
	code := "unavailable"
	if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
		code = "denied"
	} else if errors.Is(err, access.ErrConflict) {
		code = "conflict"
	}
	return Reply{Schema: 1, Code: code}
}

// Keep the callback typed at the ownership boundary: Runtime loads local
// authenticated measurements, control owns authorization/public projections.
type NodeObservations func(context.Context, cluster.View) ([]observability.Report, error)

// tunnelWaits lists, for a deploy that waits, the tenant's own TUN networks a
// server reports it cannot open yet. Other tenants' rows are never included.
func (s Service) tunnelWaits(ctx context.Context, view cluster.View, tenant string) []string {
	if s.NodeObservations == nil || tenant == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	reports, err := s.NodeObservations(ctx, view)
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
