// SPDX-License-Identifier: Apache-2.0

package access

import (
	"crypto/ed25519"
	"encoding/binary"
	"slices"
	"strings"
	"unicode/utf8"
)

const ManageCredentials Action = "credentials"

type CredentialKey struct {
	ID        string
	Method    Method
	PublicKey [32]byte
}

// CredentialAddition adds a private key to an account. The account itself
// proves it holds the key (Challenge, Proof). A system administrator adds a
// key to any account, its own too, without a proof, and may give it an action
// ceiling (Operations) and a volume-file ceiling (VolumeFiles); the account's
// own addition takes neither. A key's ceilings are fixed once it is added.
type CredentialAddition struct {
	User        string
	Credential  CredentialKey
	Label       string            `json:",omitempty"`
	Operations  []string          `json:",omitempty"`
	VolumeFiles []VolumeFileGrant `json:",omitempty"`
	Challenge   [32]byte
	Proof       []byte
}

// CredentialDisable turns off one login method. The account itself may turn
// off its own private keys; a system administrator any method of any account.
type CredentialDisable struct{ User, Credential string }

// CredentialAdditionBytes binds the prospective key to ONE account revision
// and exact public input. The challenge comes from the client CSPRNG; account
// CAS prevents replay after any accepted change. Nothing reads a clock in FSM.
func CredentialAdditionBytes(cluster [32]byte, revision uint64, change CredentialAddition) []byte {
	raw := append([]byte("sfc-self-credential-addition-1\x00"), cluster[:]...)
	raw = binary.LittleEndian.AppendUint64(raw, revision)
	for _, value := range []string{change.User, change.Credential.ID, string(change.Credential.Method), change.Label} {
		raw = binary.LittleEndian.AppendUint64(raw, uint64(len(value)))
		raw = append(raw, value...)
	}
	raw = append(raw, change.Credential.PublicKey[:]...)
	return append(raw, change.Challenge[:]...)
}

func validCredentialLabel(label string) bool {
	return len(label) <= 128 && utf8.ValidString(label) && !strings.ContainsAny(label, "\x00\r\n\t")
}

// AuthorizeCredentialManagement permits only the authenticated account, with
// an explicit unscoped credential-management ceiling. Tenant read/deploy and
// cluster roles cannot turn a restricted token into a full-login key.
func (c Catalog) AuthorizeCredentialManagement(s Session, cluster [32]byte, issuer Issuer, now int64, user string) error {
	if s.User != user || c.VerifySession(s, cluster, issuer, now) != nil {
		return ErrDenied
	}
	for _, scope := range s.Scopes {
		if scope.Tenant == "*" {
			for _, action := range scope.Actions {
				if action == ManageCredentials {
					return nil
				}
			}
		}
	}
	return ErrDenied
}

// AddCredential/DisableCredential are the same deterministic core used by
// the typed reducer. Actor authentication and scope are checked by the reducer;
// these methods additionally enforce ownership and preserve all other fields.
func (c Catalog) AddCredential(actor string, cluster [32]byte, expected uint64, change CredentialAddition) (Catalog, error) {
	admin := actor != change.User || change.Proof == nil && change.Challenge == [32]byte{} && c.SystemAllowed(actor)
	if admin && !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	u, found := c.User(change.User)
	if !found || !admin && !u.Enabled {
		return c, ErrDenied
	}
	if u.Revision != expected {
		return c, ErrConflict
	}
	v := change.Credential
	if v.Method != PrivateKey || !identifier(v.ID) || v.PublicKey == ([32]byte{}) || !validCredentialLabel(change.Label) {
		return c, ErrInvalid
	}
	if admin {
		if change.Challenge != ([32]byte{}) || change.Proof != nil || !ValidCredentialOperations(change.Operations) {
			return c, ErrInvalid
		}
	} else if cluster == ([32]byte{}) || change.Challenge == ([32]byte{}) || change.Operations != nil || change.VolumeFiles != nil ||
		!ed25519.Verify(ed25519.PublicKey(v.PublicKey[:]), CredentialAdditionBytes(cluster, expected, change), change.Proof) {
		return c, ErrInvalid
	}
	if slices.ContainsFunc(u.Credentials, func(o Credential) bool { return o.ID == v.ID || o.Method == PrivateKey && o.PublicKey == v.PublicKey }) {
		return c, ErrConflict
	}
	u.Credentials = append(ownCredentials(u.Credentials), Credential{ID: v.ID, Method: PrivateKey, PublicKey: v.PublicKey, Enabled: true, Label: change.Label, Operations: slices.Clone(change.Operations), VolumeFiles: slices.Clone(change.VolumeFiles)})
	u.Revision = 0
	return c.replaceUser(expected, u)
}

func (c Catalog) DisableCredential(actor string, expected uint64, change CredentialDisable) (Catalog, error) {
	admin := actor != change.User || c.SystemAllowed(actor)
	if admin && !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	u, found := c.User(change.User)
	if !found || !admin && !u.Enabled {
		return c, ErrDenied
	}
	if u.Revision != expected {
		return c, ErrConflict
	}
	var candidate User
	var err error
	if admin {
		candidate, err = u.WithCredentialDisabled(change.Credential)
	} else {
		candidate, err = u.WithPrivateKeyDisabled(change.Credential)
	}
	if err != nil {
		return c, err
	}
	return c.replaceUser(expected, candidate)
}
