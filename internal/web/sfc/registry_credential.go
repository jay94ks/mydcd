// SPDX-License-Identifier: Apache-2.0

package sfc

// RegistryCredentialRequest: `registry-credential` (userauth): registry ID,
// repository and actions (pull, push, or both sorted).
type RegistryCredentialRequest struct {
	ID, Repository string
	Actions        []string
}
