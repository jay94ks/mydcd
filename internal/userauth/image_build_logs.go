// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (c Client) ImageBuildLogs(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, q imagebuild.LogQuery, after string) (control.ImageBuildLogPage, error) {
	if tenant == "" || !q.Valid() || q.Tail && after != "" {
		return control.ImageBuildLogPage{}, sfcp.ErrAdmission
	}
	_, _, err := control.ImageBuildLogOffset(after)
	if err != nil {
		return control.ImageBuildLogPage{}, sfcp.ErrAdmission
	}
	page, err := call(ctx, c, target, session, ImageBuildLogsMethod, ImageBuildLogsQuery{Tenant: tenant, Query: q, After: after})
	if err != nil {
		return control.ImageBuildLogPage{}, err
	}
	if !page.ValidQuery(c.Cluster, tenant, q, after) {
		return control.ImageBuildLogPage{}, sfcp.ErrFrame
	}
	return page, nil
}
