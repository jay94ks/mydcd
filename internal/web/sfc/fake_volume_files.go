// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"errors"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// REQ-28 in the fake: files per tenant/volume in memory (I/O in
// fake_volume_files_real.go), folder grants as (tenant, app, volume,
// prefix, user). A put adds to the volume's UsedBytes and is refused past
// CapacityBytes.

type volFile struct {
	data       []byte
	modifiedAt int64
}

// volFileAllowed (sfcd): tenant management, or tenant Read plus a folder
// grant on (tenant, app, volume) whose prefix covers path.
func (w *world) volFileAllowed(user, tenant, app, volume, path string) bool {
	if w.canManage(user, tenant) {
		return true
	}
	return w.canRead(user, tenant) && slices.ContainsFunc(w.volGrants, func(g VolumeFileGrant) bool {
		return g.Tenant == tenant && g.App == app && g.Volume == volume && g.User == user && strings.HasPrefix(path, g.Prefix)
	})
}

func validVolumePath(p string) bool {
	return validFilePath(p) && !strings.ContainsAny(p, "\x00\\")
}

func (w *world) volumeRow(tenant, name string) int {
	return slices.IndexFunc(w.volumes, func(v volumeRow) bool { return v.Tenant == tenant && v.Name == name })
}

// volumeAt: the row of sfcd's scope (tenant, app, volume); app "" is a
// tenant-registered volume (volumeRow.App "").
func (w *world) volumeAt(tenant, app, name string) int {
	return slices.IndexFunc(w.volumes, func(v volumeRow) bool { return v.Tenant == tenant && v.App == app && v.Name == name })
}

// applyVolumeGrant: volume-file-grant / -revoke with
// access.VolumeFileFolderGrant (Revision 0), as Catalog.SetVolumeFileGrant.
func (c *fakeConn) applyVolumeGrant(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	var p access.VolumeFileFolderGrant
	if decodePayload(ch.Payload, &p) != nil || p.Tenant == "" || p.Revision != 0 || !strings.HasSuffix(p.Prefix, "/") || !validVolumePath(strings.TrimSuffix(p.Prefix, "/")) || w.users[p.User] == nil {
		return errors.New("payload")
	}
	q := VolumeFileGrant{Tenant: p.Tenant, App: p.App, Volume: p.Volume, Prefix: p.Prefix, User: p.User}
	// sfcd: Expected = the catalog revision (TenantMembers Collection).
	if ch.Expected != w.keyRoot(control.CatalogKey) {
		return errCAS
	}
	// The grantee needs tenant Read.
	if !w.canManage(actor, q.Tenant) || ch.Action == ActionGrantVolumeFiles && !w.canRead(q.User, q.Tenant) {
		return errForbidden
	}
	if w.volumeAt(q.Tenant, q.App, q.Volume) < 0 {
		return errCAS
	}
	i := slices.Index(w.volGrants, q)
	if ch.Action == ActionGrantVolumeFiles {
		// Granting an existing row again refreshes its Revision.
		if i < 0 {
			w.volGrants = append(w.volGrants, q)
		}
		w.volGrantMeta[grantKey(q)] = volGrantMeta{revision: next, by: actor, at: c.f.now().Unix()}
		return nil
	}
	if i < 0 {
		return errors.New("no such grant") // sfcd: Invalid
	}
	w.volGrants = slices.Delete(w.volGrants, i, i+1)
	delete(w.volGrantMeta, grantKey(q))
	return nil
}
