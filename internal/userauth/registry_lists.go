// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// RegistriesPage is one page of a tenant's managed registries. A reader that
// joins pages, or that combines them with maintenance summaries, needs the
// same RootRevision, Revision and MaintenanceRootRevision on every page.
type RegistriesPage struct {
	RootRevision, Revision, MaintenanceRootRevision uint64
	Items                                           []control.RegistryView `json:",omitempty"`
	Next                                            string                 `json:",omitempty"`
}

// ExternalRegistriesPage is one page of a tenant's external sources; joined
// pages need the same RootRevision.
type ExternalRegistriesPage struct {
	RootRevision uint64
	Items        []control.ExternalRegistryView `json:",omitempty"`
	Next         string                         `json:",omitempty"`
}

var (
	RegistriesMethod = define(Method[TenantPageQuery, RegistriesPage]{Name: "registries"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q TenantPageQuery) (RegistriesPage, string) {
		book, err := s.Policy.Registries(view.State)
		if err != nil {
			return RegistriesPage{}, "unavailable"
		}
		if !s.mayAny(view, session, q.Tenant, access.Read, access.ManageRegistry) {
			return RegistriesPage{}, "denied"
		}
		out := RegistriesPage{RootRevision: view.State.Object(control.RegistriesKey).Revision, Revision: book.Revision, MaintenanceRootRevision: view.State.Object(control.RegistryMaintenanceKey).Revision}
		if out.Items, out.Next, err = s.Policy.RegistryPage(view.State, session, time.Now().Unix(), q.Tenant, q.After); err != nil {
			return RegistriesPage{}, "denied"
		}
		return out, "ok"
	})
	ExternalRegistriesMethod = define(Method[TenantPageQuery, ExternalRegistriesPage]{Name: "external-registries"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q TenantPageQuery) (ExternalRegistriesPage, string) {
		if !s.mayAny(view, session, q.Tenant, access.Read, access.ManageRegistry) {
			return ExternalRegistriesPage{}, "denied"
		}
		out := ExternalRegistriesPage{RootRevision: view.State.Object(control.ExternalRegistriesKey).Revision}
		var err error
		if out.Items, out.Next, err = s.Policy.ExternalRegistryPage(view.State, session, time.Now().Unix(), q.Tenant, q.After); err != nil {
			return ExternalRegistriesPage{}, "denied"
		}
		return out, "ok"
	})
)

func (c Client) RegistryPage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (RegistriesPage, error) {
	return call(ctx, c, target, session, RegistriesMethod, TenantPageQuery{Tenant: tenant, After: after})
}

func (c Client) ExternalRegistryPage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (ExternalRegistriesPage, error) {
	return call(ctx, c, target, session, ExternalRegistriesMethod, TenantPageQuery{Tenant: tenant, After: after})
}
