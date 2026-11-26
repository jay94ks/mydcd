// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/credentials"
)

// InitialCredentialAllowed is reused before private provider effects and at
// public activation. Stage/observe is not a substitute for the final user CAS.
func (p Policy) InitialCredentialAllowed(s state.State, session access.Session, at int64, request credentials.InitialRequest) error {
	p, err := p.Current(s)
	if err != nil || !request.Valid() || request.Cluster != p.Cluster || request.At > at || request.Method == access.Token && at >= request.At+86400 {
		return access.ErrDenied
	}
	users, err := p.Catalog(s)
	if err != nil {
		return err
	}
	if users.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil || users.OperationAllowed(session, "issue-initial-credential") != nil {
		return access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(request.Owner) {
		return access.ErrDenied
	}
	u, ok := users.User(request.User)
	if !ok || u.Username != request.Username || u.Revision != request.ExpectedUserRevision {
		return access.ErrConflict
	}
	_, err = users.InstallInitialCredential(session.User, u.ID, u.Revision, request.CredentialRecord())
	return err
}

func (p Policy) installInitialCredential(s state.State, c access.Catalog, change Change) (access.Catalog, error) {
	var fact credentials.InitialFact
	if canonical(change.Payload, &fact) != nil || !fact.Verify() || fact.Request.Cluster != p.Cluster || fact.Request.ExpectedUserRevision != change.Expected {
		return c, access.ErrInvalid
	}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(fact.Request.Owner) {
		return c, access.ErrDenied
	}
	u, known := c.User(fact.Request.User)
	if !known || u.Username != fact.Request.Username {
		return c, access.ErrConflict
	}
	return c.InstallInitialCredential(change.Principal, u.ID, change.Expected, fact.Request.CredentialRecord())
}
