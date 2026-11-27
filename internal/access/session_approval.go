// SPDX-License-Identifier: Apache-2.0

package access

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
)

// SessionApproval delegates only this exact issued session's proof key and
// scope ceiling. The key is a registered USER credential, not an issuer key.
// Possession of a password/token login alone cannot produce this signature.
type SessionApproval struct {
	Schema    uint8
	PublicKey [32]byte
	Session   [32]byte
	Signature []byte
}

// IssuedSessionDigest includes the issuer signature, ID, cluster, account and
// authentication credential, account revision, proof key, issuer, scopes and
// lifetime. Only the separate user approval is omitted.
func IssuedSessionDigest(s Session) [32]byte {
	s.Approval = nil
	b, _ := json.Marshal(s)
	return sha256.Sum256(append([]byte("sfc-issued-user-session-1\x00"), b...))
}

func SessionApprovalBytes(a SessionApproval) []byte {
	a.Signature = nil
	b, _ := json.Marshal(a)
	return append([]byte("sfc-user-session-approval-1\x00"), b...)
}

// VerifyBinding is safe for a client without a catalog. It verifies the
// immutable delegation, but only the cluster can verify current registration,
// role and separation from installed node keys.
func (a SessionApproval) VerifyBinding(s Session) error {
	if a.Schema != 1 || a.PublicKey == ([32]byte{}) || a.Session != IssuedSessionDigest(s) ||
		!ed25519.Verify(ed25519.PublicKey(a.PublicKey[:]), SessionApprovalBytes(a), a.Signature) {
		return ErrDenied
	}
	return nil
}

// ApproveSession signs an already authenticated issuer grant. The client must
// first verify the issuer pin, its requested account and its own proof key.
// Registration/current authority is checked by Catalog, never by this signer.
func ApproveSession(s Session, private ed25519.PrivateKey) (Session, error) {
	if len(private) != ed25519.PrivateKeySize || s.Schema != 1 || !identifier(s.ID) ||
		s.Cluster == ([32]byte{}) || !identifier(s.User) || !identifier(s.Credential) ||
		s.AccountRevision == 0 || s.Key == ([32]byte{}) || s.Issuer == ([32]byte{}) ||
		s.IssuerEpoch == 0 || s.IssuedAt < 0 || s.ExpiresAt <= s.IssuedAt ||
		s.ExpiresAt-s.IssuedAt > MaxSessionSeconds || !validScopes(s.Scopes) ||
		!ed25519.Verify(ed25519.PublicKey(s.Issuer[:]), SessionBytes(s), s.Signature) {
		return Session{}, ErrDenied
	}
	key := [32]byte(private.Public().(ed25519.PublicKey))
	a := SessionApproval{Schema: 1, PublicKey: key, Session: IssuedSessionDigest(s)}
	a.Signature = ed25519.Sign(private, SessionApprovalBytes(a))
	s.Approval = &a
	return s, nil
}

// VerifySessionApproval verifies ONLY the independent user signature and its
// current account/key registration. It does not authenticate a session, grant
// roles, or prove prior Raft acceptance. Current requests must also verify the
// session/issuer/time/revocations and authorize their specific action. Retained
// operations use their fixed accepted-time boundary instead of a new request.
func (c Catalog) VerifySessionApproval(s Session) error {
	a := s.Approval
	u, ok := c.users[s.User]
	if a == nil || !ok || !u.Enabled || u.Revision != s.AccountRevision || a.VerifyBinding(s) != nil {
		return ErrDenied
	}
	for _, credential := range u.Credentials {
		if credential.Enabled && credential.Method == PrivateKey && credential.PublicKey == a.PublicKey {
			return nil
		}
	}
	return ErrDenied
}

// AttachSessionApproval adds an approval signed elsewhere (for example by a
// browser that holds the user key) to an issued session. The approval must be
// for exactly this session; registration is still checked by the Catalog.
func AttachSessionApproval(s Session, a SessionApproval) (Session, error) {
	if s.Approval != nil || a.VerifyBinding(s) != nil {
		return Session{}, ErrDenied
	}
	s.Approval = &a
	return s, nil
}
