// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (s Service) imageResolve(ctx context.Context, view cluster.View, q Request, session access.Session) Reply {
	if s.ImageResolver == nil || s.Self == nil || q.ImageResolve == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	read, err := s.Policy.PlanImageResolve(view.State, session, time.Now().Unix(), q.Tenant, *q.ImageResolve, s.Self.Public)
	if err != nil {
		return Reply{Schema: 1, Code: "denied"}
	}
	result, err := s.ImageResolver(ctx, read)
	if err != nil || !result.Valid(read) {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	current, err := s.Policy.CurrentImageResolve(latest.State, read, time.Now().Unix())
	if err != nil || !result.Valid(current) {
		return Reply{Schema: 1, Code: "denied"}
	}
	return Reply{Schema: 1, Code: "ok", Tenant: q.Tenant, ImageResolve: &result}
}

func (c Client) ResolveImage(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q control.ImageResolveQuery) (control.ImageResolveResult, error) {
	if tenant == "" || !q.Valid() {
		return control.ImageResolveResult{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "image-resolve", Tenant: tenant, ImageResolve: &q})
	if err != nil {
		return control.ImageResolveResult{}, err
	}
	r := reply.ImageResolve
	if r == nil || reply.Tenant != tenant {
		return control.ImageResolveResult{}, mydcp.ErrFrame
	}
	if !r.ValidQuery(q) {
		return control.ImageResolveResult{}, mydcp.ErrFrame
	}
	return *r, nil
}
