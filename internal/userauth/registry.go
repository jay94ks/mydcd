// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// RegistryCredentialQuery asks for a derived, short-lived registry login. It
// is not a registry definition change, Raft command or raw SFCP session
// bearer.
type RegistryCredentialQuery struct {
	Tenant, ID, Repository string
	Actions                []string
}

func (q RegistryCredentialQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && lifecycle.ValidID(q.ID) && len(q.Repository) <= 255 && len(q.Actions) > 0 && len(q.Actions) <= 8 && !slices.Contains(q.Actions, "login")
}

// RegistryCredential is the login a registry accepts as a password. It is a
// secret; callers clear it after use.
type RegistryCredential struct {
	Credential []byte
	Authority  string
	ExpiresAt  int64
}

// RegistryCredentialMethod issues a login for one registry. It is served only
// by servers that run workloads, since registries live there.
var RegistryCredentialMethod = define(Method[RegistryCredentialQuery, RegistryCredential]{Name: "registry-credential"}, false, func(ctx context.Context, s Service, view cluster.View, session access.Session, q RegistryCredentialQuery) (RegistryCredential, string) {
	return s.registryCredential(ctx, view, session, q)
})

func (s Service) registryCredential(ctx context.Context, view cluster.View, session access.Session, q RegistryCredentialQuery) (RegistryCredential, string) {
	tenant := q.Tenant
	p, err := s.Policy.Current(view.State)
	if err != nil {
		return RegistryCredential{}, "denied"
	}
	book, err := p.Registries(view.State)
	if err != nil {
		return RegistryCredential{}, "denied"
	}
	entry, known := book.Entry(tenant, q.ID)
	if !known || entry.Deleted || !entry.Spec.Enabled || entry.Active == nil || entry.Active.Draining || entry.Active.SpecRevision != entry.Revision || entry.Active.Spec != entry.Spec {
		return RegistryCredential{}, "denied"
	}
	c, err := p.Catalog(view.State)
	if err != nil {
		return RegistryCredential{}, "denied"
	}
	now := time.Now().Unix()
	for _, action := range q.Actions {
		if action == "push" && p.RegistryPushAvailable(view.State, entry.Spec) != nil {
			return RegistryCredential{}, "conflict"
		}
		if action == "push" && c.OperationAllowed(session, "registry-push") != nil {
			return RegistryCredential{}, "denied"
		}
		permission := access.ManageRegistry
		node := entry.Spec.Node
		if action == "pull" {
			permission = access.Deploy
			node = ""
		}
		err = c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), now, tenant, permission, node)
		if action == "pull" && err != nil {
			err = c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), now, tenant, access.ManageRegistry, entry.Spec.Node)
		}
		if err != nil {
			return RegistryCredential{}, "denied"
		}
	}
	grant := registry.Grant{Cluster: p.Cluster, Tenant: tenant, Registry: q.ID, Authority: entry.Spec.Authority, Repository: q.Repository, Actions: slices.Clone(q.Actions), Subject: registry.Subject{Session: &session}, IssuedAt: now, ExpiresAt: min(session.ExpiresAt, now+int64(entry.Spec.TokenSeconds))}
	credential, err := registry.IssueLogin(grant, s.Self.Private)
	if err != nil {
		return RegistryCredential{}, "denied"
	}
	if ctx.Err() != nil {
		return RegistryCredential{}, "unavailable"
	}
	return RegistryCredential{Credential: credential.Bytes(), Authority: entry.Spec.Authority, ExpiresAt: grant.ExpiresAt}, "ok"
}

func (c Client) RegistryCredential(ctx context.Context, target sfcp.Peer, session access.Session, q RegistryCredentialQuery) (RegistryCredential, error) {
	cred, err := call(ctx, c, target, session, RegistryCredentialMethod, q)
	if err == nil && (len(cred.Credential) == 0 || cred.Authority == "" || cred.ExpiresAt <= 0) {
		clear(cred.Credential)
		return RegistryCredential{}, sfcp.ErrFrame
	}
	return cred, err
}
