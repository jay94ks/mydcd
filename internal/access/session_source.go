// SPDX-License-Identifier: Apache-2.0

package access

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
)

// ExactSessionDigest includes the independent approval as well as the issuer
// grant. Unlike IssuedSessionDigest it identifies one complete accepted input.
func ExactSessionDigest(s Session) [32]byte {
	b, _ := json.Marshal(s)
	return sha256.Sum256(append([]byte("sfc-exact-user-session-1\x00"), b...))
}

// VerifyOriginalSession checks historical signature/time binding only. It is
// not current authentication and grants no permission. Retained owner records
// use it together with a separately authorized current caller.
func VerifyOriginalSession(s Session, cluster [32]byte, at int64) error {
	if s.Schema != 1 || cluster == ([32]byte{}) || s.Cluster != cluster || !identifier(s.ID) || !identifier(s.User) || !identifier(s.Credential) || s.AccountRevision == 0 || s.Key == ([32]byte{}) || s.Issuer == ([32]byte{}) || s.IssuerEpoch == 0 || s.IssuedAt < 0 || s.IssuedAt > at || s.ExpiresAt <= at || s.ExpiresAt-s.IssuedAt > MaxSessionSeconds || !validScopes(s.Scopes) || !ed25519.Verify(ed25519.PublicKey(s.Issuer[:]), SessionBytes(s), s.Signature) {
		return ErrDenied
	}
	if s.Approval != nil && s.Approval.VerifyBinding(s) != nil {
		return ErrDenied
	}
	return nil
}
