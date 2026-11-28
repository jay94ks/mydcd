// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// ImageResolveQuery resolves one image reference for the tenant.
type ImageResolveQuery struct {
	Tenant string
	Query  control.ImageResolveQuery
}

func (q ImageResolveQuery) Valid() bool { return lifecycle.ValidID(q.Tenant) && q.Query.Valid() }

// ImageResolveMethod needs the tenant's Read or ManageRegistry; the source
// read can take a while, so the tenant's authority is checked again on a
// fresh view after it.
var ImageResolveMethod = define(Method[ImageResolveQuery, control.ImageResolveResult]{Name: "image-resolve"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q ImageResolveQuery) (control.ImageResolveResult, string) {
	if !s.mayAny(view, session, q.Tenant, access.Read, access.ManageRegistry) {
		return control.ImageResolveResult{}, "denied"
	}
	if s.ImageResolver == nil || s.Self == nil {
		return control.ImageResolveResult{}, "unavailable"
	}
	read, err := s.Policy.PlanImageResolve(view.State, session, time.Now().Unix(), q.Tenant, q.Query, s.Self.Public)
	if err != nil {
		return control.ImageResolveResult{}, "denied"
	}
	result, err := s.ImageResolver(ctx, read)
	if err != nil || !result.Valid(read) {
		return control.ImageResolveResult{}, "unavailable"
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return control.ImageResolveResult{}, "unavailable"
	}
	current, err := s.Policy.CurrentImageResolve(latest.State, read, time.Now().Unix())
	if err != nil || !result.Valid(current) {
		return control.ImageResolveResult{}, "denied"
	}
	return result, "ok"
})

func (c Client) ResolveImage(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.ImageResolveQuery) (control.ImageResolveResult, error) {
	r, err := call(ctx, c, peer, session, ImageResolveMethod, ImageResolveQuery{Tenant: tenant, Query: q})
	if err != nil {
		return control.ImageResolveResult{}, err
	}
	if !r.ValidQuery(q) {
		return control.ImageResolveResult{}, sfcp.ErrFrame
	}
	return r, nil
}
