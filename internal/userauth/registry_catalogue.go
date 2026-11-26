// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

func (s Service) registryCatalog(ctx context.Context, view cluster.View, q Request, session access.Session) Reply {
	if s.RegistryCatalog == nil || q.RegistryCatalog == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	read, err := s.Policy.PlanRegistryCatalogue(view.State, session, time.Now().Unix(), q.Tenant, *q.RegistryCatalog, q.After)
	if err != nil {
		code := "denied"
		if errors.Is(err, access.ErrConflict) {
			code = "conflict"
		}
		return Reply{Schema: 1, Code: code}
	}
	result, err := s.RegistryCatalog(ctx, read)
	if err != nil || !result.Valid(read) {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	current, err := s.Policy.CurrentRegistryCatalogue(latest.State, read, time.Now().Unix())
	if err != nil || !result.Valid(current) {
		return Reply{Schema: 1, Code: "denied"}
	}
	if result.Page.Code == "CATALOGUE_CHANGED" {
		return Reply{Schema: 1, Code: "conflict"}
	}
	return Reply{Schema: 1, Code: "ok", Tenant: q.Tenant, RegistryCatalog: &result}
}
func (c Client) RegistryCatalogue(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q control.RegistryCatalogueQuery, after string) (control.RegistryCatalogueResult, error) {
	if _, _, err := registryclient.CatalogueCursor(after); err != nil || !q.Valid() || tenant == "" {
		return control.RegistryCatalogueResult{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "registry-catalog", Tenant: tenant, RegistryCatalog: &q, After: after})
	if err != nil {
		return control.RegistryCatalogueResult{}, err
	}
	result := reply.RegistryCatalog
	if result == nil || reply.Tenant != tenant || !result.ValidQuery(q, after) {
		return control.RegistryCatalogueResult{}, mydcp.ErrFrame
	}
	return *result, nil
}
