// SPDX-License-Identifier: Apache-2.0

package sfc

import "github.com/jay94ks/seafield/internal/cluster/control"

// REQ-42 (mock) `vault-approvals`: the Group approvals already committed
// (Vault.Approvals) and their revocation. Names follow REQUEST.md REQ-42 and
// may change when sfcd publishes them.

const ActionVaultRevokeApproval = "vault-revoke-approval"

// VaultApprovalSelection is the vault-revoke-approval payload ({ID});
// Change.Expected = VaultApprovalPage.Collection (Approvals revision).
type VaultApprovalSelection = control.VaultApprovalSelection

// VaultApprovalRow is one committed approval. ExpiresAt is ApprovedAt +
// the Group's vault-approval-age (0 = no age set). Revoked rows stay
// listed with RevokedAt.
type VaultApprovalRow struct {
	ID, Realm, Group string
	User             string // who approved (the deploying user)
	App, Deployment  string
	Services         []string
	Nodes            []string // permitted servers
	ApprovedAt       int64
	ExpiresAt        int64  `json:",omitempty"`
	Issuer           string // the server that checked the password
	Revoked          bool
	RevokedAt        int64 `json:",omitempty"`
}

// VaultApprovalPage: Collection is vault-revoke-approval's Expected.
type VaultApprovalPage = Page[VaultApprovalRow]
