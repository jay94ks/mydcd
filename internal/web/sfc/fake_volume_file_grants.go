// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"slices"
	"strings"
)

type volGrantMeta struct {
	revision uint64
	by       string
	at       int64
}

func grantKey(g VolumeFileGrant) string {
	return g.Tenant + "\x00" + g.App + "\x00" + g.Volume + "\x00" + g.Prefix + "\x00" + g.User
}

// volumeFileGrants: the REQ-49 volume-file-grants rows PublicRead pages.
func (c *fakeConn) volumeFileGrants(ctx context.Context, tenant, volume string) ([]VolumeFileGrantRow, error) {
	const m = "volume-file-grants"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return nil, err
	}
	defer c.unlock()
	w := c.f.w
	if _, ok := w.tenants[tenant]; !ok {
		return nil, fail(m, CodeDenied, "")
	}
	manager := w.canManage(user, tenant)
	out := []VolumeFileGrantRow{}
	for _, g := range w.volGrants {
		if g.Tenant != tenant || volume != "" && g.Volume != volume || !manager && g.User != user {
			continue
		}
		r := VolumeFileGrantRow{Tenant: g.Tenant, App: g.App, Volume: g.Volume, Prefix: g.Prefix, User: g.User}
		if u := w.users[g.User]; u != nil {
			r.Username, r.Active = u.rec.Username, u.rec.Enabled
		}
		if meta, ok := w.volGrantMeta[grantKey(g)]; ok {
			r.Revision, r.GrantedBy, r.GrantedAt = meta.revision, w.username(meta.by), meta.at
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b VolumeFileGrantRow) int {
		return strings.Compare(a.Volume+"\x00"+a.Prefix+"\x00"+a.User, b.Volume+"\x00"+b.Prefix+"\x00"+b.User)
	})
	if !manager && len(out) == 0 {
		return nil, fail(m, CodeDenied, "")
	}
	return out, nil
}
