// SPDX-License-Identifier: Apache-2.0

package mydc

// RegistryCredentialRequest: `registry-credential` (userauth): registry ID,
// repository and actions (pull, push, or both sorted).
type RegistryCredentialRequest struct {
	ID, Repository string
	Actions        []string
}

// RegistryCredential: a short-lived login for `docker login` against a
// built-in registry: the account's username with Token as the password.
// Token is secret: never store or log it, and clear it after use.
type RegistryCredential struct {
	Token     []byte
	Authority string
	ExpiresAt int64 // Unix seconds
}
