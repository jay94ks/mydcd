// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/secrets"
)

type VaultWritePermitRequest struct {
	Session         access.Session
	Realm, ID, Mode string
	At              int64
}
type VaultWritePermit struct {
	Cluster  [32]byte
	Realm    string
	Record   secrets.WriteRecord
	Observer secrets.WriteProfile
}

func (p Policy) VaultWritePermit(s state.State, caller [32]byte, q VaultWritePermitRequest) (VaultWritePermit, error) {
	if q.Mode != "execute" && q.Mode != "recover" {
		return VaultWritePermit{}, ErrCatalog
	}
	p, err := p.Current(s)
	if err != nil {
		return VaultWritePermit{}, err
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) || q.Mode == "execute" && !members.WorkKey(caller) {
		return VaultWritePermit{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return VaultWritePermit{}, err
	}
	action := access.ManageSecrets
	if q.Realm == "" {
		action = access.ManageCluster
	}
	if c.AuthorizeSession(q.Session, p.Cluster, p.Issuer(q.Session.Issuer), q.At, q.Realm, action, "") != nil {
		return VaultWritePermit{}, access.ErrDenied
	}
	v, err := p.Vault(s)
	if err != nil {
		return VaultWritePermit{}, err
	}
	tree, ok := v.Trees[q.Realm]
	if !ok {
		return VaultWritePermit{}, ErrCatalog
	}
	w, ok := tree.Write(q.ID)
	if !ok || q.Session.User != w.Actor && !c.SystemAllowed(q.Session.User) {
		return VaultWritePermit{}, access.ErrDenied
	}
	observer, ok := tree.WriteProfile(w.Request.Profile)
	if !ok || !observer.Enabled || observer.Mode == "local-file" || observer.Key != caller || w.Request.Kind == secrets.ValueWrite && !observer.Values || w.Request.Kind == secrets.VerifierWrite && !observer.Verifiers {
		return VaultWritePermit{}, access.ErrDenied
	}
	key, err := p.nodeOwner(s, observer.Node)
	if err != nil || key != caller {
		return VaultWritePermit{}, access.ErrDenied
	}
	if q.Mode == "execute" {
		if c.OperationAllowed(q.Session, "vault-dispatch-write") != nil {
			return VaultWritePermit{}, access.ErrDenied
		}
		o, exists := tree.Object(w.Request.Object)
		if !exists || w.Status() != "Dispatched" || observer != w.Writer || o.Generation != w.Generation || o.Revision != w.ExpectedObjectRevision || o.PendingWrite != w.Request.ID || o.Status != secrets.Active && o.Status != secrets.ReferencePending && o.Status != secrets.PasswordPending {
			return VaultWritePermit{}, access.ErrDenied
		}
	} else if w.Status() != "Dispatched" && w.Status() != "Unknown" && w.Status() != "StoredUnreferenced" && w.Status() != "Published" {
		return VaultWritePermit{}, access.ErrDenied
	}
	return VaultWritePermit{p.Cluster, q.Realm, w, observer}, nil
}
