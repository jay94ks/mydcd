// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
)

// Resources is one sfcd resources page as it is (the screen form is built
// by internal/web/server, which joins the pages under one revision as the
// CLI does).
func (c *realConn) Resources(ctx context.Context, tenant, after string) (Page[control.ResourceEntry], error) {
	p, err := realCall(ctx, c, "resources", func(u userauth.Client, s access.Session) (userauth.ResourcesPage, error) {
		return u.Resources(ctx, c.peer, s, userauth.ResourcesQuery{Tenant: tenant, After: after})
	})
	if err != nil {
		return Page[control.ResourceEntry]{}, err
	}
	return Page[control.ResourceEntry]{Items: p.Items, Next: p.Next, Revision: p.RootRevision,
		Collection: p.NetworkRevision, QuotaRevision: p.QuotaRevision}, nil
}
