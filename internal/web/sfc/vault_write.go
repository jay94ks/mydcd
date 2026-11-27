// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/secrets"
)

// Vault provider writes (real sfcd actions). A Secret value or a Group
// password verifier is written in five steps, as the CLI's `sfcli secret put`
// and `secret group password` do:
//
//	vault-write-plan (query) → vault-prepare-write → vault-dispatch-write →
//	SecretInput to the plan's receiver (values, never in an original) →
//	vault-observe-write (the receiver's signed observation) → vault-publish-write
const (
	ActionVaultPrepareWrite  = "vault-prepare-write"
	ActionVaultDispatchWrite = "vault-dispatch-write"
	ActionVaultObserveWrite  = "vault-observe-write"
	ActionVaultPublishWrite  = "vault-publish-write"
)

type (
	VaultWritePlanRequest = control.VaultWritePlanRequest
	VaultWritePlan        = control.VaultWritePlan
	VaultWriteView        = control.VaultWriteView
)

// SecretWrite is the private input of one dispatched write, sent only over
// sfcd's SecretInput purpose to the plan's receiver. Mode "execute" carries
// Values (a Secret's keys, or "verifier" for a Group password hash); mode
// "recover" carries none and asks for the outcome of an earlier attempt. It
// must never be stored, logged or put in an original operation.
type SecretWrite struct {
	Realm, ID, Mode string
	Values          map[string][]byte
}

// SecretWriteReply is the receiver's answer: Code ok/unknown/denied and, once
// the receiver ran or settled the write, its signed public observation.
type SecretWriteReply struct {
	Code        string
	Observation *secrets.WriteObservation
}

// VaultWriter is the part of Conn for provider writes.
type VaultWriter interface {
	// PlanVaultWrite: `vault-write-plan` (Deploy on the realm's tenant).
	PlanVaultWrite(ctx context.Context, tenant string, q VaultWritePlanRequest) (VaultWritePlan, error)
	// WriteVault sends q over SecretInput to receiver (plan.Receiver).
	WriteVault(ctx context.Context, tenant string, receiver config.Peer, q SecretWrite) (SecretWriteReply, error)
}
