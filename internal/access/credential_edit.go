// SPDX-License-Identifier: Apache-2.0

package access

import "slices"

// WithPrivateKey prepares a full PutUser candidate, preserving every other
// credential/account field. It is not a partial-update authorization boundary.
// The caller must submit the old revision via the existing signed PutUser CAS.
func (u User) WithPrivateKey(id string, key [32]byte) (User, error) {
	return u.WithPrivateKeyOperations(id, key, nil)
}

func (u User) WithPrivateKeyOperations(id string, key [32]byte, operations []string) (User, error) {
	if !ValidCredentialOperations(operations) {
		return User{}, ErrInvalid
	}
	u.Credentials = append(ownCredentials(u.Credentials), Credential{ID: id, Method: PrivateKey, PublicKey: key, Enabled: true, Operations: slices.Clone(operations)})
	u.Revision = 0
	if !validUser(u) {
		return User{}, ErrInvalid
	}
	return u, nil
}

func (u User) WithPrivateKeyDisabled(id string) (User, error) {
	u.Credentials = ownCredentials(u.Credentials)
	for i, credential := range u.Credentials {
		if credential.ID != id {
			continue
		}
		if credential.Method != PrivateKey || !credential.Enabled {
			return User{}, ErrInvalid
		}
		u.Credentials[i].Enabled = false
		u.Revision = 0
		if !validUser(u) {
			return User{}, ErrInvalid
		}
		return u, nil
	}
	return User{}, ErrInvalid
}
