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

func (s Service) registryPruneQuery(ctx context.Context, view cluster.View, q Request, session access.Session) Reply {
	if s.RegistryPrune == nil || q.RegistryPrune == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	results := q.Method == "registry-prune-results"
	read, err := s.Policy.RegistryPruneRead(view.State, session, time.Now().Unix(), q.Tenant, *q.RegistryPrune, q.After, results)
	if err != nil {
		return registryPruneError(err)
	}
	out, err := s.RegistryPrune(ctx, read, results)
	if err != nil {
		return registryPruneError(err)
	}
	if !out.Valid(read, results) {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	current, err := s.Policy.CurrentRegistryPruneRead(latest.State, read, time.Now().Unix(), results)
	if err != nil {
		return registryPruneError(err)
	}
	if !out.Valid(current, results) {
		return Reply{Schema: 1, Code: "denied"}
	}
	return Reply{Schema: 1, Code: "ok", Tenant: q.Tenant, RegistryPrune: &out}
}
func registryPruneError(err error) Reply {
	code := "unavailable"
	if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
		code = "denied"
	}
	if errors.Is(err, access.ErrConflict) || errors.Is(err, registryclient.ErrCatalogueChanged) {
		code = "conflict"
	}
	return Reply{Schema: 1, Code: code}
}
func (c Client) RegistryPrune(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q control.RegistryPruneQuery, after string, results bool) (control.RegistryPruneView, error) {
	if tenant == "" || !q.Valid(results) {
		return control.RegistryPruneView{}, mydcp.ErrAdmission
	}
	if _, _, err := registryclient.CatalogueCursor(after); err != nil {
		return control.RegistryPruneView{}, err
	}
	method := "registry-prune-preview"
	if results {
		method = "registry-prune-results"
	}
	reply, err := c.query(ctx, peer, session, Request{Method: method, Tenant: tenant, After: after, RegistryPrune: &q})
	if err != nil {
		return control.RegistryPruneView{}, err
	}
	if reply.Tenant != tenant || reply.RegistryPrune == nil || !reply.RegistryPrune.ValidQuery(c.Cluster, tenant, q, after, results) {
		return control.RegistryPruneView{}, mydcp.ErrFrame
	}
	return *reply.RegistryPrune, nil
}
