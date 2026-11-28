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

// RegistryCatalogQuery selects one page of a registry's repositories or tags.
type RegistryCatalogQuery struct {
	Tenant string
	Query  control.RegistryCatalogueQuery
	After  string `json:",omitempty"`
}

func (q RegistryCatalogQuery) Valid() bool {
	_, _, err := registryclient.CatalogueCursor(q.After)
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid() && err == nil
}

// RegistryCatalogMethod reads the registry itself, then checks the session's
// authority again on a fresh view before it answers.
var RegistryCatalogMethod = define(Method[RegistryCatalogQuery, control.RegistryCatalogueResult]{Name: "registry-catalog"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q RegistryCatalogQuery) (control.RegistryCatalogueResult, string) {
	var zero control.RegistryCatalogueResult
	if !s.mayAny(view, session, q.Tenant, access.Read, access.ManageRegistry) {
		return zero, "denied"
	}
	if s.RegistryCatalog == nil {
		return zero, "unavailable"
	}
	read, err := s.Policy.PlanRegistryCatalogue(view.State, session, time.Now().Unix(), q.Tenant, q.Query, q.After)
	if err != nil {
		if errors.Is(err, access.ErrConflict) {
			return zero, "conflict"
		}
		return zero, "denied"
	}
	result, err := s.RegistryCatalog(ctx, read)
	if err != nil || !result.Valid(read) {
		return zero, "unavailable"
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return zero, "unavailable"
	}
	current, err := s.Policy.CurrentRegistryCatalogue(latest.State, read, time.Now().Unix())
	if err != nil || !result.Valid(current) {
		return zero, "denied"
	}
	if result.Page.Code == "CATALOGUE_CHANGED" {
		return zero, "conflict"
	}
	return result, "ok"
})

func (c Client) RegistryCatalogue(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.RegistryCatalogueQuery, after string) (control.RegistryCatalogueResult, error) {
	result, err := call(ctx, c, peer, session, RegistryCatalogMethod, RegistryCatalogQuery{Tenant: tenant, Query: q, After: after})
	if err == nil && !result.ValidQuery(q, after) {
		return control.RegistryCatalogueResult{}, sfcp.ErrFrame
	}
	return result, err
}
