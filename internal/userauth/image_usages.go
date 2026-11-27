// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (s Service) imageUsages(view cluster.View, q Request, session access.Session) Reply {
	page, err := s.Policy.ImageUsages(view.State, session, time.Now().Unix(), q.Tenant, *q.ImageUsage, q.After)
	if err != nil {
		code := "unavailable"
		if errors.Is(err, access.ErrDenied) {
			code = "denied"
		}
		if errors.Is(err, access.ErrConflict) {
			code = "conflict"
		}
		return Reply{Schema: 1, Code: code}
	}
	return Reply{Schema: 1, Code: "ok", Tenant: q.Tenant, ImageUsages: &page}
}

func (c Client) ImageUsages(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.ImageUsageQuery, after string) (control.ImageUsagesPage, error) {
	q, err := q.Canonical()
	root, last, cursorErr := control.ImageUsagesCursor(after)
	if err != nil || cursorErr != nil || tenant == "" {
		return control.ImageUsagesPage{}, sfcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "image-usages", Tenant: tenant, ImageUsage: &q, After: after})
	if err != nil {
		return control.ImageUsagesPage{}, err
	}
	page := reply.ImageUsages
	if page == nil || reply.Tenant != tenant || page.Schema != 1 || page.Tenant != tenant || page.Root == ([32]byte{}) || page.Index == 0 || len(page.Rows) > 16 || after != "" && root != page.Root {
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
	return *page, nil
}
