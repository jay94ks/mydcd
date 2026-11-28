// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// ImageUsagesQuery pages the tenant's workloads that use the selected
// images.
type ImageUsagesQuery struct {
	Tenant string
	Query  control.ImageUsageQuery
	After  string `json:",omitempty"`
}

func (q ImageUsagesQuery) Valid() bool {
	if q.After != "" {
		if _, _, err := control.ImageUsagesCursor(q.After); err != nil {
			return false
		}
	}
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid()
}

// ImageUsagesMethod needs the tenant's Read or ManageRegistry.
var ImageUsagesMethod = define(Method[ImageUsagesQuery, control.ImageUsagesPage]{Name: "image-usages"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q ImageUsagesQuery) (control.ImageUsagesPage, string) {
	if !s.mayAny(view, session, q.Tenant, access.Read, access.ManageRegistry) {
		return control.ImageUsagesPage{}, "denied"
	}
	page, err := s.Policy.ImageUsages(view.State, session, time.Now().Unix(), q.Tenant, q.Query, q.After)
	if err != nil {
		return control.ImageUsagesPage{}, errorCode(err)
	}
	return page, "ok"
})

func (c Client) ImageUsages(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.ImageUsageQuery, after string) (control.ImageUsagesPage, error) {
	q, err := q.Canonical()
	root, last, cursorErr := control.ImageUsagesCursor(after)
	if err != nil || cursorErr != nil || tenant == "" {
		return control.ImageUsagesPage{}, sfcp.ErrAdmission
	}
	page, err := call(ctx, c, peer, session, ImageUsagesMethod, ImageUsagesQuery{Tenant: tenant, Query: q, After: after})
	if err != nil {
		return control.ImageUsagesPage{}, err
	}
	if page.Schema != 1 || page.Tenant != tenant || page.Root == ([32]byte{}) || page.Index == 0 || len(page.Rows) > 16 || after != "" && root != page.Root {
		return control.ImageUsagesPage{}, sfcp.ErrFrame
	}
	for _, row := range page.Rows {
		if row.Tenant != tenant || !row.ImageReference.Valid() || row.ID <= last || row.Match != q.Match(row.ImageReference) || row.Match == "" {
			return control.ImageUsagesPage{}, sfcp.ErrFrame
		}
		last = row.ID
	}
	if page.Next != "" {
		nextRoot, nextID, err := control.ImageUsagesCursor(page.Next)
		if err != nil || len(page.Rows) != 16 || nextRoot != page.Root || nextID != last {
			return control.ImageUsagesPage{}, sfcp.ErrFrame
		}
	}
	return page, nil
}
