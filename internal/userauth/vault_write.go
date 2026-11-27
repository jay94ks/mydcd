// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// PlanVaultWrite returns public metadata from one authenticated quorum view.
// Private input never traverses the query/relay path.
func (c Client) PlanVaultWrite(ctx context.Context, target sfcp.Peer, session access.Session, q control.VaultWritePlanRequest) (control.VaultWritePlan, error) {
	reply, err := c.query(ctx, target, session, Request{Method: "vault-write-plan", Tenant: q.Realm, VaultWritePlan: &q})
	if err != nil {
		return control.VaultWritePlan{}, err
	}
	p := reply.VaultWritePlan
	if p == nil || p.Schema != 1 || p.Realm != q.Realm || p.Request.ID != q.ID {
		return control.VaultWritePlan{}, sfcp.ErrFrame
	}
	return *p, nil
}

func (c Client) QueryVault(ctx context.Context, target sfcp.Peer, session access.Session, realm, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "vault", Tenant: realm, After: after})
}
