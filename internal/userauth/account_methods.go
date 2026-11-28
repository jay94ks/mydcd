// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Users, tenant members and account records (R09 batch 4). The CAS root
// an operation starts from is whoami's Roots, so these replies carry no
// root revisions of other books.

// PageQuery is a cursor; empty reads the first page.
type PageQuery struct {
	After string `json:",omitempty"`
}

func (q PageQuery) Valid() bool { return len(q.After) <= 512 }

// UsersReply is one page of public account records. Revision is the
// catalog's; a cursor from another revision is refused with "conflict".
type UsersReply struct {
	Users    []access.PublicUser
	Next     string `json:",omitempty"`
	Revision uint64
}

// TenantMembersReply is one page of a tenant's members, the servers in the
// tenant, the tenant's revision and the catalog's (Revision).
type TenantMembersReply struct {
	Tenant         string
	Members        []access.TenantMember
	AllowedNodes   []string
	Next           string `json:",omitempty"`
	TenantRevision uint64
	Revision       uint64
}

// UserCredentialsQuery names the account a system administrator reads.
type UserCredentialsQuery struct{ Username string }

func (q UserCredentialsQuery) Valid() bool { return cliprofile.ValidUsername(q.Username) }

// accountCatalog is the catalog and the session's issuer policy, or false.
func (s Service) accountCatalog(view cluster.View, session access.Session) (access.Catalog, access.Issuer, bool) {
	c, err := s.Policy.Catalog(view.State)
	if err != nil {
		return access.Catalog{}, access.Issuer{}, false
	}
	return c, s.Policy.Issuer(session.Issuer), true
}

// systemAdmin is the catalog when the session may manage the cluster now.
func (s Service) systemAdmin(view cluster.View, session access.Session) (access.Catalog, bool) {
	c, issuer, ok := s.accountCatalog(view, session)
	if !ok || c.AuthorizeSession(session, s.Policy.Cluster, issuer, time.Now().Unix(), "", access.ManageCluster, "") != nil {
		return access.Catalog{}, false
	}
	return c, true
}

func pageRefusal(err error) string {
	if errors.Is(err, access.ErrConflict) {
		return "conflict"
	}
	return "denied"
}

var (
	UsersMethod = define(Method[PageQuery, UsersReply]{Name: "users"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q PageQuery) (UsersReply, string) {
		c, ok := s.systemAdmin(view, session)
		if !ok {
			return UsersReply{}, "denied"
		}
		users, next, err := c.UsersPage(session.User, q.After)
		if err != nil {
			return UsersReply{}, pageRefusal(err)
		}
		return UsersReply{Users: users, Next: next, Revision: c.Revision()}, "ok"
	})
	TenantMembersMethod = define(Method[TenantPageQuery, TenantMembersReply]{Name: "tenant-members"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q TenantPageQuery) (TenantMembersReply, string) {
		c, issuer, ok := s.accountCatalog(view, session)
		if !ok || c.AuthorizeSession(session, s.Policy.Cluster, issuer, time.Now().Unix(), q.Tenant, access.ManageMembers, "") != nil {
			return TenantMembersReply{}, "denied"
		}
		members, allowed, next, err := c.TenantMembersPage(session.User, q.Tenant, q.After)
		if err != nil {
			return TenantMembersReply{}, pageRefusal(err)
		}
		tenant, _ := c.Tenant(q.Tenant)
		return TenantMembersReply{Tenant: q.Tenant, Members: members, AllowedNodes: allowed, Next: next, TenantRevision: tenant.Revision, Revision: c.Revision()}, "ok"
	})
	MyCredentialsMethod = define(Method[NoParams, access.PublicUser]{Name: "my-credentials"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, _ NoParams) (access.PublicUser, string) {
		c, _, ok := s.accountCatalog(view, session)
		if !ok {
			return access.PublicUser{}, "denied"
		}
		u, ok := c.User(session.User)
		if !ok {
			return access.PublicUser{}, "denied"
		}
		return access.PublicUserOf(u), "ok"
	})
	UserCredentialsMethod = define(Method[UserCredentialsQuery, access.User]{Name: "user-credentials"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q UserCredentialsQuery) (access.User, string) {
		c, ok := s.systemAdmin(view, session)
		if !ok {
			return access.User{}, "denied"
		}
		u, exists := c.Username(q.Username)
		if !exists {
			return access.User{}, "denied"
		}
		return u, "ok"
	})
	NodeCLIPolicyMethod = define(Method[NoParams, access.NodeCLIPolicy]{Name: "node-cli-policy"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, _ NoParams) (access.NodeCLIPolicy, string) {
		c, ok := s.systemAdmin(view, session)
		if !ok {
			return access.NodeCLIPolicy{}, "denied"
		}
		return c.NodeCLI(), "ok"
	})
	TenantRetirementMethod = define(Method[TenantPageQuery, control.TenantRetirementStatus]{Name: "tenant-retirement"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q TenantPageQuery) (control.TenantRetirementStatus, string) {
		if _, ok := s.systemAdmin(view, session); !ok {
			return control.TenantRetirementStatus{}, "denied"
		}
		status, err := s.Policy.TenantRetirementStatus(view.State, q.Tenant, q.After)
		if err != nil {
			return control.TenantRetirementStatus{}, "unavailable"
		}
		return status, "ok"
	})
)

// Users reads one page of public account records (system administrator).
func (c Client) Users(ctx context.Context, peer sfcp.Peer, session access.Session, after string) (UsersReply, error) {
	return call(ctx, c, peer, session, UsersMethod, PageQuery{After: after})
}

// TenantMembers reads one page of a tenant's members (ManageMembers).
func (c Client) TenantMembers(ctx context.Context, peer sfcp.Peer, session access.Session, tenant, after string) (TenantMembersReply, error) {
	r, err := call(ctx, c, peer, session, TenantMembersMethod, TenantPageQuery{Tenant: tenant, After: after})
	if err == nil && r.Tenant != tenant {
		return TenantMembersReply{}, sfcp.ErrFrame
	}
	return r, err
}

// MyCredentials reads the session's own public account record.
func (c Client) MyCredentials(ctx context.Context, peer sfcp.Peer, session access.Session) (access.PublicUser, error) {
	u, err := call(ctx, c, peer, session, MyCredentialsMethod, NoParams{})
	if err == nil && u.ID != session.User {
		return access.PublicUser{}, sfcp.ErrFrame
	}
	return u, err
}

// UserCredentials reads a single owned public account record for a system
// administrator. Username selects the target, not the current actor/session.
func (c Client) UserCredentials(ctx context.Context, peer sfcp.Peer, session access.Session, username string) (access.User, error) {
	u, err := call(ctx, c, peer, session, UserCredentialsMethod, UserCredentialsQuery{Username: username})
	if err == nil && u.Username != username {
		return access.User{}, sfcp.ErrFrame
	}
	return u, err
}

// NodeCLIPolicy reads whether node-local CLI operation is blocked.
func (c Client) NodeCLIPolicy(ctx context.Context, peer sfcp.Peer, session access.Session) (access.NodeCLIPolicy, error) {
	return call(ctx, c, peer, session, NodeCLIPolicyMethod, NoParams{})
}

// TenantRetirement is an authenticated system-admin observation, including
// a Deleted tombstone. It never creates or resumes a deletion.
func (c Client) TenantRetirement(ctx context.Context, peer sfcp.Peer, session access.Session, tenant, after string) (control.TenantRetirementStatus, error) {
	return call(ctx, c, peer, session, TenantRetirementMethod, TenantPageQuery{Tenant: tenant, After: after})
}
