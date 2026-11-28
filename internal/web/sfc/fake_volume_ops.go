// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/sha256"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Volume backup and restore reads in the fake. Backup, restore, capacity
// and delete changes are tested on real sfcd nodes
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

// fillVolumeSources gives fixture volume and backup rows their sfcd
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
	w.backups = nil
	for _, b := range w.seedBackups {
		vi := slices.IndexFunc(w.volumes, func(v volumeRow) bool { return v.Tenant == b.Tenant && v.Name == b.Volume })
		if vi < 0 {
			continue
		}
		v := w.volumes[vi]
		row := control.VolumeBackupView{Key: b.Key, Scope: v.Scope, ID: b.ID, Node: b.Node, Phase: b.Phase, Revision: b.Revision,
			MaxBytes: max(b.Bytes, 1<<30), MaxEntries: 100000, Binding: v.NativeBinding, Compatibility: fakeDigest("compat", v.Key),
			Failure: b.Failure, Owner: fakeNodeKey(b.Node), UID: 999, GID: 999, Mode: 0o750, CreatedAt: b.CreatedAt}
		if b.Phase == "Ready" || b.Phase == "Deleting" {
			row.Receipt = &volumes.ArchiveReceipt{Schema: 1, Digest: fakeDigest("archive", b.Key), Bytes: b.Bytes, DataBytes: b.Bytes, Entries: 1}
		}
		w.backups = append(w.backups, row)
	}
}

// volumeRows: one sfcd page of the volumes book (8 a page, Key order).
func volumeRows[T any](w *world, items []T, key func(T) string, tenant func(T) string, want, after string) userauth.VolumeRows[T] {
	out := userauth.VolumeRows[T]{Items: []T{}, Revision: w.root, RootRevision: w.root, ModuleEpoch: max(w.ledgerEpoch, 1)}
	sorted := slices.Clone(items)
	slices.SortFunc(sorted, func(a, b T) int { return strings.Compare(key(a), key(b)) })
	for _, it := range sorted {
		if want != "" && tenant(it) != want || key(it) <= after {
			continue
		}
		if len(out.Items) == 8 {
			out.Next = key(out.Items[7])
			break
		}
		out.Items = append(out.Items, it)
	}
	return out
}

func (c *fakeConn) VolumeBackups(ctx context.Context, tenant, after string) (userauth.VolumeBackupsPage, error) {
	if err := c.tenantRead(ctx, "volume-backups", tenant, after); err != nil {
		return userauth.VolumeBackupsPage{}, err
	}
	defer c.unlock()
	return volumeRows(c.f.w, c.f.w.backups, func(b control.VolumeBackupView) string { return b.Key },
		func(b control.VolumeBackupView) string { return b.Scope.Tenant }, tenant, after), nil
}

func (c *fakeConn) VolumeRestores(ctx context.Context, tenant, after string) (userauth.VolumeRestoresPage, error) {
	if err := c.tenantRead(ctx, "volume-restores", tenant, after); err != nil {
		return userauth.VolumeRestoresPage{}, err
	}
	defer c.unlock()
	return volumeRows(c.f.w, c.f.w.restores, func(r control.VolumeRestoreView) string { return r.Key },
		func(r control.VolumeRestoreView) string { return r.Target.Tenant }, tenant, after), nil
}

func (c *fakeConn) VolumeBackupSource(ctx context.Context, tenant string, q control.VolumeSelector) (userauth.VolumeBackupSourceReply, error) {
	const m = "volume-backup-source"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return userauth.VolumeBackupSourceReply{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(user, tenant) {
		return userauth.VolumeBackupSourceReply{}, fail(m, CodeDenied, "")
	}
	if !q.Valid() {
		return userauth.VolumeBackupSourceReply{}, fail(m, CodeInvalid, "app and volume")
	}
	for _, v := range w.volumes {
		if v.Tenant == tenant && v.App == q.App && v.Name == q.ID {
			return userauth.VolumeBackupSourceReply{VolumeRevision: v.Revision, ModuleEpoch: max(w.ledgerEpoch, 1), RootRevision: w.root, Index: w.root,
				Source: control.VolumeBackupSource{Schema: 1, Scope: v.Scope, Node: v.Node, Owner: fakeNodeKey(v.Node), NativeBinding: v.NativeBinding,
					Compatibility: fakeDigest("compat", v.Key)}}, nil
		}
	}
	return userauth.VolumeBackupSourceReply{}, fail(m, CodeMissing, "")
}

func (w *world) volumeByScope(s volumes.Scope) int {
	return slices.IndexFunc(w.volumes, func(v volumeRow) bool {
		return v.Scope.Tenant == s.Tenant && v.Scope.App == s.App && v.Scope.ID == s.ID && v.Scope.Generation == s.Generation
	})
}
