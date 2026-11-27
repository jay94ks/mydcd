// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// This is a protected request for a derived, short-lived credential, not a
// registry definition change, Raft command or raw SFCP session bearer.
type RegistryCredentialRequest struct {
	ID, Repository string
	Actions        []string
}

func (s Service) registryCredential(ctx context.Context, view cluster.View, session access.Session, tenant string, q RegistryCredentialRequest) Reply {
	denied := Reply{Schema: 1, Code: "denied"}
	if tenant == "" || slices.Contains(q.Actions, "login") {
		return denied
	}
	p, err := s.Policy.Current(view.State)
	if err != nil {
		return denied
	}
	book, err := p.Registries(view.State)
	if err != nil {
		return denied
	}
	entry, known := book.Entry(tenant, q.ID)
	if !known || entry.Deleted || !entry.Spec.Enabled || entry.Active == nil || entry.Active.Draining || entry.Active.SpecRevision != entry.Revision || entry.Active.Spec != entry.Spec {
		return denied
	}
	c, err := p.Catalog(view.State)
	if err != nil {
		return denied
	}
	now := time.Now().Unix()
	for _, action := range q.Actions {
		if action == "push" && p.RegistryPushAvailable(view.State, entry.Spec) != nil {
			return Reply{Schema: 1, Code: "conflict"}
		}
		if action == "push" && c.OperationAllowed(session, "registry-push") != nil {
			return denied
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
			return denied
		}
	}
	grant := registry.Grant{Cluster: p.Cluster, Tenant: tenant, Registry: q.ID, Authority: entry.Spec.Authority, Repository: q.Repository, Actions: slices.Clone(q.Actions), Subject: registry.Subject{Session: &session}, IssuedAt: now, ExpiresAt: min(session.ExpiresAt, now+int64(entry.Spec.TokenSeconds))}
	credential, err := registry.IssueLogin(grant, s.Self.Private)
	if err != nil {
		return denied
	}
	if ctx.Err() != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	return Reply{Schema: 1, Code: "ok", RegistryCredential: credential.Bytes(), RegistryAuthority: entry.Spec.Authority, RegistryCredentialExpires: grant.ExpiresAt}
}

func (c Client) RegistryCredential(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, q RegistryCredentialRequest) (Reply, error) {
	if c.Verify(session) != nil {
		return Reply{}, sfcp.ErrAdmission
	}
	body, err := requestBody(Request{Method: "registry-credential", Tenant: tenant, Registry: &q})
	if err != nil {
		return Reply{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *sfcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, true)
	return reply, err
}
