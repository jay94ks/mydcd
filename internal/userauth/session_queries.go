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

// NoParams is the request of a method that takes nothing; it is exactly {}.
type NoParams struct{}

// WhoamiReply is the signed-in account and the CAS window a new operation
// starts from: the current module epoch and the root revision of each book.
type WhoamiReply struct {
	User        UserView
	ModuleEpoch uint64
	Roots       map[string]uint64
}

// Root is the root revision an operation on key's book compares against.
// A book without its own root uses the catalog's.
func (r WhoamiReply) Root(key string) uint64 {
	if v, ok := r.Roots[key]; ok {
		return v
	}
	return r.Roots[control.CatalogKey]
}

// whoamiRoots are the books whose root revision whoami reports.
var whoamiRoots = []string{
	control.CatalogKey, control.AppsKey, control.ResourcesKey, control.VolumesKey, control.VaultKey,
	control.LifecycleKey, control.RegistriesKey, control.ExternalRegistriesKey, control.RegistryMaintenanceKey,
	control.ImageBuildKey, control.ImageCacheKey, control.NodeStorageKey, control.StorageKey,
	control.CertificatesKey, control.VPSKey, control.IngressManagementKey, control.CompactKey,
	control.ClusterBackupKey, control.TunnelReconnectKey,
}

// rootsOf reads each book's root revision from the one committed view; it
// never loads or decodes a book.
func rootsOf(view cluster.View) map[string]uint64 {
	roots := make(map[string]uint64, len(whoamiRoots))
	for _, key := range whoamiRoots {
		roots[key] = view.State.Object(key).Revision
	}
	return roots
}

// TenantsReply lists the tenants the session may read.
type TenantsReply struct {
	User    UserView
	Tenants []TenantView
}

// SelectTenantQuery names the tenant to work in.
type SelectTenantQuery struct{ Tenant string }

func (q SelectTenantQuery) Valid() bool { return lifecycle.ValidID(q.Tenant) }

// SelectTenantReply is the selected tenant's revision and the servers in it
// the session may read.
type SelectTenantReply struct {
	User         UserView
	Tenant       string
	Revision     uint64
	AllowedNodes []string
}

func (c Client) Whoami(ctx context.Context, target sfcp.Peer, session access.Session) (WhoamiReply, error) {
	r, _, err := c.WhoamiRoute(ctx, target, session)
	return r, err
}

// WhoamiRoute is Whoami that also says which server answered.
func (c Client) WhoamiRoute(ctx context.Context, target sfcp.Peer, session access.Session) (WhoamiReply, Route, error) {
	r, route, err := callRoute(ctx, c, target, session, WhoamiMethod, NoParams{})
	if err == nil && (r.User.ID != session.User || r.ModuleEpoch == 0) {
		return WhoamiReply{}, Route{}, sfcp.ErrFrame
	}
	return r, route, err
}

func (c Client) Tenants(ctx context.Context, target sfcp.Peer, session access.Session) (TenantsReply, error) {
	r, err := call(ctx, c, target, session, TenantsMethod, NoParams{})
	if err == nil && r.User.ID != session.User {
		return TenantsReply{}, sfcp.ErrFrame
	}
	return r, err
}

func (c Client) SelectTenant(ctx context.Context, target sfcp.Peer, session access.Session, tenant string) (SelectTenantReply, error) {
	r, err := call(ctx, c, target, session, SelectTenantMethod, SelectTenantQuery{Tenant: tenant})
	if err == nil && (r.User.ID != session.User || r.Tenant != tenant) {
		return SelectTenantReply{}, sfcp.ErrFrame
	}
	return r, err
}

// sessionUser reads the session's account from the current catalog.
func (s Service) sessionUser(view cluster.View, session access.Session) (access.Catalog, UserView, bool) {
	c, err := s.Policy.Catalog(view.State)
	if err != nil {
		return access.Catalog{}, UserView{}, false
	}
	u, ok := c.User(session.User)
	return c, UserView{u.ID, u.Username, u.Revision, u.SystemAdmin}, ok
}

var (
	WhoamiMethod = define(Method[NoParams, WhoamiReply]{Name: "whoami"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, _ NoParams) (WhoamiReply, string) {
		_, user, ok := s.sessionUser(view, session)
		if !ok {
			return WhoamiReply{}, "denied"
		}
		return WhoamiReply{User: user, ModuleEpoch: max(view.State.ModuleEpoch(), 1), Roots: rootsOf(view)}, "ok"
	})
	TenantsMethod = define(Method[NoParams, TenantsReply]{Name: "tenants"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, _ NoParams) (TenantsReply, string) {
		c, user, ok := s.sessionUser(view, session)
		if !ok {
			return TenantsReply{}, "denied"
		}
		return s.tenantsOf(c, user, session, time.Now().Unix()), "ok"
	})
	SelectTenantMethod = define(Method[SelectTenantQuery, SelectTenantReply]{Name: "select-tenant"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q SelectTenantQuery) (SelectTenantReply, string) {
		c, user, ok := s.sessionUser(view, session)
		if !ok {
			return SelectTenantReply{}, "denied"
		}
		return s.selectTenantOf(c, user, session, time.Now().Unix(), q.Tenant)
	})
)

// tenantsOf lists the tenants the session may read now, with the servers in
// each it may read. A system administrator manages every tenant.
func (s Service) tenantsOf(c access.Catalog, user UserView, session access.Session, now int64) TenantsReply {
	policy := s.Policy.Issuer(session.Issuer)
	out := TenantsReply{User: user, Tenants: []TenantView{}}
	for _, tenant := range c.VisibleTenants(user.ID) {
		if c.AuthorizeSession(session, s.Policy.Cluster, policy, now, tenant.ID, access.Read, "") != nil {
			continue
		}
		membership, _ := c.Membership(tenant.ID, user.ID)
		if user.SystemAdmin {
			membership.Role = access.Manager
		}
		out.Tenants = append(out.Tenants, TenantView{ID: tenant.ID, Revision: tenant.Revision, Role: membership.Role, AllowedNodes: s.readableNodes(c, session, now, tenant)})
	}
	return out
}

func (s Service) selectTenantOf(c access.Catalog, user UserView, session access.Session, now int64, id string) (SelectTenantReply, string) {
	if c.AuthorizeSession(session, s.Policy.Cluster, s.Policy.Issuer(session.Issuer), now, id, access.Read, "") != nil {
		return SelectTenantReply{}, "denied"
	}
	tenant, _ := c.Tenant(id)
	return SelectTenantReply{User: user, Tenant: id, Revision: tenant.Revision, AllowedNodes: s.readableNodes(c, session, now, tenant)}, "ok"
}

func (s Service) readableNodes(c access.Catalog, session access.Session, now int64, tenant access.Tenant) []string {
	nodes := []string{}
	for _, node := range tenant.AllowedNodes {
		if c.AuthorizeSession(session, s.Policy.Cluster, s.Policy.Issuer(session.Issuer), now, tenant.ID, access.Read, node) == nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}
