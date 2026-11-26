// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// PlanVaultApprovals retrieves a single canonical public plan. A changing
// policy/approval digest aborts the read instead of mixing snapshot parts.
func (c Client) PlanVaultApprovals(ctx context.Context, target mydcp.Peer, session access.Session, tenant string, q control.VaultApprovalPlanRequest) (control.VaultApprovalPlan, error) {
	q.Part = 0
	q.Digest = [32]byte{}
	var raw []byte
	var root uint64
	length := 0
	for {
		reply, err := c.query(ctx, target, session, Request{Method: "vault-approval-plan", Tenant: tenant, VaultPlan: &q})
		if err != nil {
			return control.VaultApprovalPlan{}, err
		}
		part := reply.VaultPlan
		if part == nil || part.Part != q.Part || part.Length < 1 || part.Length > 4<<20 || len(part.Data) == 0 || len(part.Data) > 24<<10 {
			return control.VaultApprovalPlan{}, mydcp.ErrFrame
		}
		if q.Part == 0 {
			root, length, q.Digest = part.RootRevision, part.Length, part.Digest
		} else if part.RootRevision != root || part.Length != length || part.Digest != q.Digest {
			return control.VaultApprovalPlan{}, mydcp.ErrFrame
		}
		if len(part.Data) != min(24<<10, length-len(raw)) {
			return control.VaultApprovalPlan{}, mydcp.ErrFrame
		}
		raw = append(raw, part.Data...)
		if len(raw) == length {
			break
		}
		q.Part++
	}
	if sha256.Sum256(raw) != q.Digest {
		return control.VaultApprovalPlan{}, mydcp.ErrFrame
	}
	var plan control.VaultApprovalPlan
	if strict(raw, &plan) != nil || plan.Realm != q.Realm {
		return plan, mydcp.ErrFrame
	}
	canonical, _ := json.Marshal(plan)
	if len(canonical) != length {
		return plan, mydcp.ErrFrame
	}
	return plan, nil
}
