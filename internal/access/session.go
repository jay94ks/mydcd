// SPDX-License-Identifier: Apache-2.0

package access

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
)

const ManageCluster Action = "cluster"
const MaxSessionSeconds int64 = 3600

type Revocation struct {
	User, Session             string
	AccountRevision, Revision uint64
}

// RevokeSession is applied for the authenticated owner or a system admin. Its
// tombstone is persisted with the command result; a client deleting a file is
// never a substitute for this shared revocation.
func (c Catalog) RevokeSession(actor, user, id string, expectedAccount uint64) (Catalog, error) {
	a, known := c.users[actor]
	u, exists := c.users[user]
	if !known || !a.Enabled || !exists || actor != user && !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	if u.Revision != expectedAccount {
		return c, ErrConflict
	}
	if !identifier(id) {
		return c, ErrInvalid
	}
	k := memberKey(user, id)
	if _, revoked := c.revocations[k]; revoked {
		return c, nil
	}
	if len(c.revocations) >= maxRecords {
		return c, ErrInvalid
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	n.revocations[k] = Revocation{User: user, Session: id, AccountRevision: u.Revision, Revision: n.revision}
	return n, nil
}

type KeyProof struct {
	Schema                     uint8
	Cluster                    [32]byte
	User, Username, Credential string
	Challenge, SessionKey      [32]byte
	Deadline                   int64
	Signature                  []byte
}

func KeyProofBytes(p KeyProof) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("mydc-user-key-proof-1\x00"), b...)
}

// VerifyKeyProof consumes a fresh challenge supplied by the connection owner.
// It proves the registered USER key; it grants no node/member permissions.
func (c Catalog) VerifyKeyProof(p KeyProof, cluster, challenge [32]byte, now int64) error {
	u, ok := c.users[p.User]
	if !ok || !u.Enabled || p.Schema != 1 || p.Username != u.Username || p.Cluster != cluster || cluster == ([32]byte{}) || p.Challenge != challenge || challenge == ([32]byte{}) || p.SessionKey == ([32]byte{}) || now < 0 || p.Deadline <= now || p.Deadline-now > 300 {
		return ErrDenied
	}
	for _, credential := range u.Credentials {
		if credential.ID == p.Credential && credential.Enabled && credential.Method == PrivateKey && ed25519.Verify(ed25519.PublicKey(credential.PublicKey[:]), KeyProofBytes(p), p.Signature) {
			return nil
		}
	}
	return ErrDenied
}

type Scope struct {
	Tenant  string
	Actions []Action
}
type Issuer struct {
	Key     [32]byte
	Epoch   uint64
	Enabled bool
}
type Session struct {
	Schema              uint8
	ID                  string
	Cluster             [32]byte
	User, Credential    string
	AccountRevision     uint64
	Key                 [32]byte
	Issuer              [32]byte
	IssuerEpoch         uint64
	IssuedAt, ExpiresAt int64
	Scopes              []Scope
	Signature           []byte
	Approval            *SessionApproval `json:",omitempty"`
}

func SessionBytes(s Session) []byte {
	s.Signature = nil
	// Approval is added by the USER after the issuer returns this grant. It
	// has its own signature over the complete issued session, including the
	// issuer signature. Excluding it here avoids circular signing and keeps
	// old schema-1 issuer signatures byte-for-byte unchanged.
	s.Approval = nil
	b, _ := json.Marshal(s)
	return append([]byte("mydc-user-session-1\x00"), b...)
}
func allowedScopeAction(a Action) bool {
	switch a {
	case Read, CallService, ManageNetwork, Deploy, ManageSecrets, ManageVolumes, ManageRoutes, ManageServices, ManageCD, ManageRegistry, ManageTrust, ManageMembers, ManageCluster, ManageCredentials, NodeShell:
		return true
	}
	return false
}
func validScopes(scopes []Scope) bool {
	if len(scopes) == 0 || len(scopes) > 256 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range scopes {
		if s.Tenant != "*" && !identifier(s.Tenant) || seen[s.Tenant] || len(s.Actions) == 0 {
			return false
		}
		seen[s.Tenant] = true
		// Recognized, unique actions are bounded by the vocabulary itself.
		actions := map[Action]bool{}
		for _, a := range s.Actions {
			if !allowedScopeAction(a) || actions[a] || (a == ManageCluster || a == ManageCredentials || a == NodeShell) && s.Tenant != "*" {
				return false
			}
			actions[a] = true
		}
	}
	return true
}

// ValidateScopes shares the session contract with protected token backends.
// It validates syntax and bounds; current membership is checked separately.
func ValidateScopes(scopes []Scope) bool { return validScopes(scopes) }

// VerifySession checks a CURRENT authorized issuer and CURRENT credential. The
// authenticated issuer constructs scopes from the verified password/key/token
// backend policy; clients cannot widen them by changing a signed grant.
func (c Catalog) VerifySession(s Session, cluster [32]byte, issuer Issuer, now int64) error {
	return c.verifySession(s, cluster, issuer, now, false, true)
}

// VerifyAuthenticationSession is for returning a newly issued login grant,
// before the client has attached its independent user approval. It grants no
// request/operation permission. All subsequent requests use VerifySession.
func (c Catalog) VerifyAuthenticationSession(s Session, cluster [32]byte, issuer Issuer, now int64) error {
	return c.verifySession(s, cluster, issuer, now, false, false)
}

// VerifyLogoutReceipt checks the original identity of a self-revocation. It is
// only for reading that exact retained result, never for executing or resuming
// an operation. Callers must bind the supplied session to its own logout.
func (c Catalog) VerifyLogoutReceipt(s Session, cluster [32]byte, issuer Issuer, admittedAt int64) error {
	return c.verifySession(s, cluster, issuer, admittedAt, true, false)
}

func (c Catalog) verifySession(s Session, cluster [32]byte, issuer Issuer, now int64, logoutReceipt, currentRequest bool) error {
	u, ok := c.users[s.User]
	if _, revoked := c.revocations[memberKey(s.User, s.ID)]; revoked && !logoutReceipt {
		return ErrDenied
	}
	if !ok || !u.Enabled || u.Revision != s.AccountRevision || s.Schema != 1 || !identifier(s.ID) || s.Cluster != cluster || cluster == ([32]byte{}) || s.Key == ([32]byte{}) || !issuer.Enabled || issuer.Key == ([32]byte{}) || s.Issuer != issuer.Key || issuer.Epoch == 0 || s.IssuerEpoch != issuer.Epoch || now < 0 || s.IssuedAt < 0 || s.IssuedAt > now || s.ExpiresAt <= now || s.ExpiresAt <= s.IssuedAt || s.ExpiresAt-s.IssuedAt > MaxSessionSeconds || !validScopes(s.Scopes) || !ed25519.Verify(ed25519.PublicKey(issuer.Key[:]), SessionBytes(s), s.Signature) {
		return ErrDenied
	}
	for _, v := range u.Credentials {
		if v.ID == s.Credential && v.Enabled {
			if currentRequest && c.nodeCLI.DisableNodeCLIOperation && c.VerifyManagementApproval(s) != nil {
				return ErrDenied
			}
			if !(currentRequest && c.nodeCLI.DisableNodeCLIOperation) && s.Approval != nil && c.VerifySessionApproval(s) != nil {
				return ErrDenied
			}
			return nil
		}
	}
	return ErrDenied
}

// AuthorizeSession intersects signed credential scopes with current tenant roles
// and node allocation. A system administrator's explicitly limited token remains
// limited, even though the underlying account manages every tenant implicitly.
func (c Catalog) AuthorizeSession(s Session, cluster [32]byte, issuer Issuer, now int64, tenant string, action Action, node string) error {
	return c.authorizeSession(s, cluster, issuer, now, tenant, action, node, false)
}

// AuthorizeSessionCleanup preserves the same signature/current credential and
// scope checks while settling existing resources of a retiring tenant. The
// consumer must bind the operation to its original resource, never a new create.
func (c Catalog) AuthorizeSessionCleanup(s Session, cluster [32]byte, issuer Issuer, now int64, tenant string, action Action) error {
	return c.authorizeSession(s, cluster, issuer, now, tenant, action, "", true)
}
func (c Catalog) authorizeSession(s Session, cluster [32]byte, issuer Issuer, now int64, tenant string, action Action, node string, cleanup bool) error {
	if c.VerifySession(s, cluster, issuer, now) != nil {
		return ErrDenied
	}
	if c.nodeCLI.DisableNodeCLIOperation && tenant != "" && !c.SystemAllowed(s.User) && !c.manager(s.User, tenant) {
		return ErrDenied
	}
	return c.authorizeScope(s, tenant, action, node, cleanup)
}

// AuthorizeAccepted consumes ONLY a grant already retained in an authenticated
// committed operation. Its original time/signature/scopes remain fixed. Session
// logout/expiry and departure of the issuing control do not cancel an accepted
// application. Current account/credential revision, roles and node placement do.
// This is not a login/request admission API and cannot prove prior acceptance.
func (c Catalog) AuthorizeAccepted(s Session, cluster [32]byte, acceptedAt int64, tenant string, action Action, node string) error {
	issuer := Issuer{Key: s.Issuer, Epoch: s.IssuerEpoch, Enabled: true}
	if c.VerifyLogoutReceipt(s, cluster, issuer, acceptedAt) != nil {
		return ErrDenied
	}
	return c.authorizeScope(s, tenant, action, node, false)
}

// AuthorizeAcceptedCleanup consumes a retained cleanup grant, preserving its
// original scope and current account/credential/role checks. It authorizes no
// new placement and therefore does not require the revoked node assignment.
func (c Catalog) AuthorizeAcceptedCleanup(s Session, cluster [32]byte, acceptedAt int64, tenant string, action Action) error {
	issuer := Issuer{Key: s.Issuer, Epoch: s.IssuerEpoch, Enabled: true}
	if c.VerifyLogoutReceipt(s, cluster, issuer, acceptedAt) != nil {
		return ErrDenied
	}
	return c.authorizeScope(s, tenant, action, "", true)
}

func (c Catalog) authorizeScope(s Session, tenant string, action Action, node string, cleanup bool) error {
	allowed := false
	for _, scope := range s.Scopes {
		if scope.Tenant == "*" || scope.Tenant == tenant {
			for _, a := range scope.Actions {
				if a == action {
					allowed = true
				}
			}
		}
	}
	if !allowed {
		return ErrDenied
	}
	if action == ManageCluster {
		if cleanup || tenant != "" || node != "" || !c.SystemAllowed(s.User) {
			return ErrDenied
		}
		return nil
	}
	if cleanup {
		return c.AuthorizeCleanup(s.User, tenant, action)
	}
	return c.Authorize(s.User, tenant, action, node)
}
func RequestBytes(session Session, challenge [32]byte, body []byte) []byte {
	b := append([]byte("mydc-user-request-1\x00"), session.Cluster[:]...)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(session.ID)))
	b = append(b, session.ID...)
	b = append(b, challenge[:]...)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(body)))
	return append(b, body...)
}

// VerifyRequest binds the complete request (including tenant in the adapter's
// canonical body) to the session proof key and current connection challenge.
func VerifyRequest(session Session, challenge [32]byte, body, signature []byte) error {
	if session.Key == ([32]byte{}) || challenge == ([32]byte{}) || len(body) == 0 || len(body) > 128<<10 || !ed25519.Verify(ed25519.PublicKey(session.Key[:]), RequestBytes(session, challenge, body), signature) {
		return ErrDenied
	}
	return nil
}
