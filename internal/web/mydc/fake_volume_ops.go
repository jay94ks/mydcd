// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/sha256"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Volume backup and restore reads in the fake. Backup, restore, capacity
// and delete changes are tested on real mydcd nodes
// (internal/web/server/real_volume_test.go, devel/refactor/16 step 6).

func fakeDigest(parts ...string) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p + "\x00"))
	}
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// fillVolumeSources gives fixture volume and backup rows their mydcd
// identity (Scope, native binding, backup Source).
func (w *world) fillVolumeSources() {
	w.volumes = slices.Clone(w.volumes)
	for i := range w.volumes {
		v := &w.volumes[i]
		if v.Scope.ID == "" {
			v.Scope = volumes.Scope{Cluster: w.cluster, Tenant: v.Tenant, App: v.App, ID: v.Name, Generation: 1}
			v.NativeBinding = fakeDigest("native", v.Key)
		}
	}
	w.backups = slices.Clone(w.backups)
	for i := range w.backups {
		b := &w.backups[i]
		if b.Source.ID != "" {
			continue
		}
		vi := slices.IndexFunc(w.volumes, func(v volumeRow) bool { return v.Tenant == b.Tenant && v.Name == b.Volume })
		if vi < 0 {
			continue
		}
		v := w.volumes[vi]
		b.Source = control.VolumeBackupView{Key: b.Key, Scope: v.Scope, ID: b.ID, Node: b.Node, Phase: b.Phase, Revision: b.Revision,
			MaxBytes: max(b.Bytes, 1<<30), MaxEntries: 100000, Binding: v.NativeBinding, Compatibility: fakeDigest("compat", v.Key),
			Owner: fakeNodeKey(b.Node), UID: 999, GID: 999, Mode: 0o750}
		if b.Phase == "Ready" {
			b.Source.Receipt = &volumes.ArchiveReceipt{Schema: 1, Digest: fakeDigest("archive", b.Key), Bytes: b.Bytes, DataBytes: b.Bytes, Entries: 1}
		}
	}
}

func (c *fakeConn) VolumeRestores(ctx context.Context, tenant, after string) (Page[VolumeRestoreView], error) {
	if err := c.tenantRead(ctx, "volume-restores", tenant, after); err != nil {
		return Page[VolumeRestoreView]{}, err
	}
	defer c.unlock()
	items := filterTenant(c.f.w.restores, tenant, func(v VolumeRestoreView) string { return v.Tenant })
	return paginate(items, func(v VolumeRestoreView) string { return v.Key }, after, c.f.pageSize, c.f.w.root), nil
}

func (c *fakeConn) VolumeBackupSource(ctx context.Context, tenant string, q control.VolumeSelector) (VolumeSource, error) {
	const m = "volume-backup-source"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return VolumeSource{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(user, tenant) {
		return VolumeSource{}, fail(m, CodeDenied, "")
	}
	if !q.Valid() {
		return VolumeSource{}, fail(m, CodeInvalid, "app and volume")
	}
	for _, v := range w.volumes {
		if v.Tenant == tenant && v.App == q.App && v.Name == q.ID {
			return VolumeSource{VolumeRevision: v.Revision, Source: control.VolumeBackupSource{Schema: 1, Scope: v.Scope, Node: v.Node,
				Owner: fakeNodeKey(v.Node), NativeBinding: v.NativeBinding, Compatibility: fakeDigest("compat", v.Key)}}, nil
		}
	}
	return VolumeSource{}, fail(m, CodeMissing, "")
}

func (w *world) volumeByScope(s volumes.Scope) int {
	return slices.IndexFunc(w.volumes, func(v volumeRow) bool {
		return v.Scope.Tenant == s.Tenant && v.Scope.App == s.App && v.Scope.ID == s.ID && v.Scope.Generation == s.Generation
	})
}
