// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// RegistryPruneQuery selects one page of a prune preview or of a prune's
// results.
type RegistryPruneQuery struct {
	Tenant string
	Query  control.RegistryPruneQuery
	After  string `json:",omitempty"`
}

func (q RegistryPruneQuery) valid(results bool) bool {
	_, _, err := registryclient.CatalogueCursor(q.After)
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid(results) && err == nil
}

// RegistryPrunePreviewQuery and RegistryPruneResultsQuery differ only in
// what Query must name.
type (
	RegistryPrunePreviewQuery struct{ RegistryPruneQuery }
	RegistryPruneResultsQuery struct{ RegistryPruneQuery }
)

func (q RegistryPrunePreviewQuery) Valid() bool { return q.valid(false) }
func (q RegistryPruneResultsQuery) Valid() bool { return q.valid(true) }

var (
	RegistryPrunePreviewMethod = define(Method[RegistryPrunePreviewQuery, control.RegistryPruneView]{Name: "registry-prune-preview"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q RegistryPrunePreviewQuery) (control.RegistryPruneView, string) {
		if !s.mayAny(view, session, q.Tenant, access.ManageRegistry) {
			return control.RegistryPruneView{}, "denied"
		}
		return s.registryPrune(ctx, view, session, q.RegistryPruneQuery, false)
	})
	RegistryPruneResultsMethod = define(Method[RegistryPruneResultsQuery, control.RegistryPruneView]{Name: "registry-prune-results"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q RegistryPruneResultsQuery) (control.RegistryPruneView, string) {
		if !s.mayAny(view, session, q.Tenant, access.ManageRegistry, access.Read) {
			return control.RegistryPruneView{}, "denied"
		}
		return s.registryPrune(ctx, view, session, q.RegistryPruneQuery, true)
	})
)

// registryPrune reads the registry, then checks the read again on a fresh
// view before it answers.
func (s Service) registryPrune(ctx context.Context, view cluster.View, session access.Session, q RegistryPruneQuery, results bool) (control.RegistryPruneView, string) {
	var zero control.RegistryPruneView
	if s.RegistryPrune == nil {
		return zero, "unavailable"
	}
	read, err := s.Policy.RegistryPruneRead(view.State, session, time.Now().Unix(), q.Tenant, q.Query, q.After, results)
	if err != nil {
		return zero, registryPruneCode(err)
	}
	out, err := s.RegistryPrune(ctx, read, results)
	if err != nil {
		return zero, registryPruneCode(err)
	}
	if !out.Valid(read, results) {
		return zero, "unavailable"
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return zero, "unavailable"
	}
	current, err := s.Policy.CurrentRegistryPruneRead(latest.State, read, time.Now().Unix(), results)
	if err != nil {
		return zero, registryPruneCode(err)
	}
	if !out.Valid(current, results) {
		return zero, "denied"
	}
	return out, "ok"
}

func registryPruneCode(err error) string {
	if errors.Is(err, registryclient.ErrCatalogueChanged) {
		return "conflict"
	}
	return errorCode(err)
}

func (c Client) RegistryPrune(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.RegistryPruneQuery, after string, results bool) (control.RegistryPruneView, error) {
	query := RegistryPruneQuery{Tenant: tenant, Query: q, After: after}
	var view control.RegistryPruneView
	var err error
	if results {
		view, err = call(ctx, c, peer, session, RegistryPruneResultsMethod, RegistryPruneResultsQuery{query})
	} else {
		view, err = call(ctx, c, peer, session, RegistryPrunePreviewMethod, RegistryPrunePreviewQuery{query})
	}
	if err == nil && !view.ValidQuery(c.Cluster, tenant, q, after, results) {
		return control.RegistryPruneView{}, sfcp.ErrFrame
	}
	return view, err
}
