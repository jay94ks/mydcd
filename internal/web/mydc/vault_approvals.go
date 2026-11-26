// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// Protected Group approvals (real mydcd), as the CLI's `compose up` and
// `cd approve` do: before begin-app is sent, the requester plans each realm
// the app's blueprint uses with the signed begin-app original as Origin
// (`vault-approval-plan`), then sends each required Group's password over
// SecretInput mode "approve" to the plan's approver node, which checks it
// and commits vault-commit-approval. The password is never stored, logged
// or put in an original operation.
type (
	VaultApprovalPlanRequest = control.VaultApprovalPlanRequest
	VaultApprovalPlan        = control.VaultApprovalPlan
	VaultApprovalTarget      = control.VaultApprovalTarget
	AppApprovalSelection     = control.AppApprovalSelection
	AppCDRegistration        = control.AppCDApprovalRegistration
)

// VaultApprove is the private input of one Group approval.
type VaultApprove struct {
	Target    secrets.Target
	Password  []byte
	Origin    *UserOperation
	Selection *AppApprovalSelection
}

// VaultApprover is the part of Conn for Group approvals.
type VaultApprover interface {
	// PlanVaultApprovals: `vault-approval-plan` (all parts joined).
	PlanVaultApprovals(ctx context.Context, tenant string, q VaultApprovalPlanRequest) (VaultApprovalPlan, error)
	// ApproveVault sends q over SecretInput (mode approve) to approver
	// (VaultApprovalTarget.Approver). Code: ok / denied / unknown.
	ApproveVault(ctx context.Context, tenant string, approver config.Peer, q VaultApprove) (string, error)
	// AppDeliveryRegistration: `app-cd-registration`, the registered
	// begin-app original of an app's CD and the realms a selected candidate
	// (or pending CD operation) reads. Only the registrant may approve: plan
	// with Origin = Registration.Origin and Selection, as `mydc cd approve`.
	AppDeliveryRegistration(ctx context.Context, tenant, app string, sel AppApprovalSelection) (AppCDRegistration, error)
}
