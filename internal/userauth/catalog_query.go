// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (c Client) UsersPage(ctx context.Context, peer mydcp.Peer, session access.Session, after string) (Reply, error) {
	return c.query(ctx, peer, session, Request{Method: "users", After: after})
}

func (c Client) TenantMembersPage(ctx context.Context, peer mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, peer, session, Request{Method: "tenant-members", Tenant: tenant, After: after})
}

func (s Service) catalogQueryReply(c access.Catalog, session access.Session, issuer access.Issuer, now int64, r Request) Reply {
	reply := Reply{Schema: 1, Code: "denied"}
	var err error
	if r.Method == "users" {
		if r.Tenant != "" || c.AuthorizeSession(session, s.Policy.Cluster, issuer, now, "", access.ManageCluster, "") != nil {
			return reply
		}
		reply.Users, reply.UsersNext, err = c.UsersPage(session.User, r.After)
		reply.UsersRevision = c.Revision()
	} else {
		if r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, issuer, now, r.Tenant, access.ManageMembers, "") != nil {
			return reply
		}
		reply.TenantMembers, reply.TenantAllowedNodes, reply.TenantMembersNext, err = c.TenantMembersPage(session.User, r.Tenant, r.After)
		tenant, _ := c.Tenant(r.Tenant)
		reply.Tenant, reply.TenantRevision, reply.TenantMembersRevision = r.Tenant, tenant.Revision, c.Revision()
	}
	if err != nil {
		code := "denied"
		if errors.Is(err, access.ErrConflict) {
			code = "conflict"
		}
		return Reply{Schema: 1, Code: code}
	}
	reply.Code = "ok"
	return reply
}
