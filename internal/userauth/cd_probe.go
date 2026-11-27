// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (c Client) ProbeCD(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q deployment.GitProbeRequest) (deployment.GitProbeResult, error) {
	if tenant == "" || !q.Valid() {
		return deployment.GitProbeResult{}, sfcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "cd-probe", Tenant: tenant, CDProbe: &q})
	if err != nil {
		return deployment.GitProbeResult{}, err
	}
	if reply.CDProbe == nil || !reply.CDProbe.Valid() {
		return deployment.GitProbeResult{}, sfcp.ErrFrame
	}
	return *reply.CDProbe, nil
}
