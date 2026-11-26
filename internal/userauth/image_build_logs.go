// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (c Client) ImageBuildLogs(ctx context.Context, target mydcp.Peer, session access.Session, tenant string, q imagebuild.LogQuery, after string) (control.ImageBuildLogPage, error) {
	if tenant == "" || !q.Valid() || q.Tail && after != "" {
		return control.ImageBuildLogPage{}, mydcp.ErrAdmission
	}
	_, _, err := control.ImageBuildLogOffset(after)
	if err != nil {
		return control.ImageBuildLogPage{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, target, session, Request{Method: "image-build-logs", Tenant: tenant, ImageBuildLog: &q, After: after})
	if err != nil {
		return control.ImageBuildLogPage{}, err
	}
	page := reply.ImageBuildLog
	if page == nil || !page.ValidQuery(c.Cluster, tenant, q, after) {
		return control.ImageBuildLogPage{}, mydcp.ErrFrame
	}
	return *page, nil
}
