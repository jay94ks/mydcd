// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// NewCredentialAddition prepares the public, immutable input for ordinary
// Prepare/Operation. It never uploads the prospective private key. Browser
// clients sign access.CredentialAdditionBytes with their local WebCrypto key.
func (c Client) NewCredentialAddition(session access.Session, id, label string, private ed25519.PrivateKey) (access.CredentialAddition, error) {
	if c.Verify(session) != nil || len(private) != ed25519.PrivateKeySize {
		return access.CredentialAddition{}, mydcp.ErrAdmission
	}
	addition := access.CredentialAddition{User: session.User, Label: label, Credential: access.CredentialKey{ID: id, Method: access.PrivateKey, PublicKey: [32]byte(private.Public().(ed25519.PublicKey))}}
	if _, err := rand.Read(addition.Challenge[:]); err != nil {
		return access.CredentialAddition{}, err
	}
	addition.Proof = ed25519.Sign(private, access.CredentialAdditionBytes(c.Cluster, session.AccountRevision, addition))
	return addition, nil
}
