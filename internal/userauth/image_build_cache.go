// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (c Client) ImageBuildCacheUsage(ctx context.Context, target mydcp.Peer, session access.Session, tenant string, q imagebuild.CacheQuery, after string) (control.ImageBuildCachePage, error) {
	if tenant == "" || !q.Valid() {
		return control.ImageBuildCachePage{}, mydcp.ErrAdmission
	}
	if _, _, _, _, err := control.ImageBuildCacheOffset(after); err != nil {
		return control.ImageBuildCachePage{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, target, session, Request{Method: "image-build-cache", Tenant: tenant, ImageBuildCache: &q, After: after})
	if err != nil {
		return control.ImageBuildCachePage{}, err
	}
	page := reply.ImageBuildCache
	if page == nil || !page.ValidQuery(tenant, q, after) {
		return control.ImageBuildCachePage{}, mydcp.ErrFrame
	}
	return *page, nil
}
