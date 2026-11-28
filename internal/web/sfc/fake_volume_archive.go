// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/volumearchive"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Volume archives as sfcd keeps them (control/volume_archives.go): the
// archive holds the Volume from Packing until a final phase, and the owner
// node's reports (FinishVolumeArchive here) move it on. The fake checks
// what the screen can get wrong: the revisions, the phase each action needs,
// both recipient keys, an app volume with no consumer.

type fakeArchives struct {
	rows map[string]*control.VolumeArchiveView // tenant/app/volume/id
	keys control.VolumeArchiveKeys
}

func (w *world) archiveState() *fakeArchives {
	if w.archives == nil {
		w.archives = &fakeArchives{rows: map[string]*control.VolumeArchiveView{}}
	}
	return w.archives
}

func archiveRowKey(tenant, app, volume, id string) string {
	return tenant + "/" + app + "/" + volume + "/" + id
}

func archiveDone(phase string) bool {
	switch phase {
	case "Restored", "Cancelled", "Failed", "Discarded":
		return true
	}
	return false
}

// archivedVolume finds a volume row by its full scope (fixture rows without a
// Scope take scopeOf).
func (w *world) archivedVolume(scope volumes.Scope) int {
	return slices.IndexFunc(w.volumes, func(v volumeRow) bool {
		s := v.Scope
		if s.ID == "" {
			s = scopeOf(w, v)
		}
		return s == scope
	})
}

// SetVolumeArchiveKeys sets both recipient keys, as a voter report and an
// administrator's set-volume-archive-admin-key would.
func (f *Fake) SetVolumeArchiveKeys(cluster, admin [32]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.w.archiveState()
	a.keys.Cluster, a.keys.Admin = cluster, admin
	a.keys.Revision++
	f.w.root++
}

func (c *fakeConn) VolumeArchives(ctx context.Context, tenant, after string) (userauth.VolumeArchivesPage, error) {
	if err := c.tenantRead(ctx, "volume-archives", tenant, after); err != nil {
		return userauth.VolumeArchivesPage{}, err
	}
	defer c.unlock()
	a := c.f.w.archiveState()
	out := userauth.VolumeArchivesPage{Keys: a.keys}
	out.Items = []control.VolumeArchiveView{}
	out.Revision, out.RootRevision, out.ModuleEpoch = c.f.w.root, c.f.w.root, max(c.f.w.ledgerEpoch, 1)
	for _, k := range sortedKeys(a.rows) {
		j := a.rows[k]
		if tenant != "" && j.Scope.Tenant != tenant || j.Key <= after {
			continue
		}
		if len(out.Items) == 8 {
			out.Next = out.Items[7].Key
			break
		}
		out.Items = append(out.Items, *j)
	}
	return out, nil
}

func (c *fakeConn) applyVolumeArchive(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	a := w.archiveState()
	ch := op.Change
	if ch.Action == ActionSetArchiveAdminKey {
		var q control.VolumeArchiveAdminKey
		if decodePayload(ch.Payload, &q) != nil || q.Key == ([32]byte{}) {
			return errors.New("payload")
		}
		if !w.admin(actor) {
			return errForbidden
		}
		if ch.Expected != a.keys.Revision || q.Key == a.keys.Admin {
			return errCAS
		}
		a.keys.Admin, a.keys.Revision = q.Key, a.keys.Revision+1
		return nil
	}
	if ch.Action == ActionArchiveVolume {
		var q control.VolumeArchiveBegin
		if decodePayload(ch.Payload, &q) != nil || !volumearchive.ValidID(q.ID) || len(q.ID) > 61 || q.MaxBytes < 1024 || q.MaxBytes > 1<<40 || q.MaxEntries == 0 || q.MaxEntries > 100000 || !q.Compression.Valid() {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Scope.Tenant) {
			return errForbidden
		}
		i := w.archivedVolume(q.Scope)
		if i < 0 || a.keys.Cluster == ([32]byte{}) || a.keys.Admin == ([32]byte{}) {
			return errCAS
		}
		v := &w.volumes[i]
		if v.Revision != ch.Expected || v.App == "" || v.Kind == "fixed" || v.Consumers != 0 || v.Phase != "" && v.Phase != "Ready" {
			return errCAS
		}
		key := archiveRowKey(q.Scope.Tenant, q.Scope.App, q.Scope.ID, q.ID)
		for k, j := range a.rows {
			if j.Scope == q.Scope && archiveDone(j.Phase) {
				delete(a.rows, k) // sfcd drops the Volume's finished records
			}
		}
		if a.rows[key] != nil {
			return errCAS
		}
		root := q.Root
		if root == "" {
			root = "default"
		}
		a.rows[key] = &control.VolumeArchiveView{Key: key, Scope: q.Scope, ID: q.ID, Node: v.Node, Phase: "Packing", Root: root, Revision: 1, MaxBytes: q.MaxBytes, MaxEntries: q.MaxEntries, Compression: q.Compression}
		v.Phase, v.ArchiveID, v.ArchivePhase, v.Revision = "Archived", q.ID, "Packing", next
		return nil
	}
	var q control.VolumeArchiveSelection
	if decodePayload(ch.Payload, &q) != nil || q.ID == "" {
		return errors.New("payload")
	}
	if !w.canManage(actor, q.Scope.Tenant) {
		return errForbidden
	}
	j := a.rows[archiveRowKey(q.Scope.Tenant, q.Scope.App, q.Scope.ID, q.ID)]
	if j == nil || j.Scope != q.Scope || j.Revision != ch.Expected {
		return errCAS
	}
	step := map[string][2]string{ // the phase the action needs, the phase it sets
		ActionCancelArchive:   {"Packing", "Cancelling"},
		ActionUnarchiveVolume: {"Archived", "Restoring"},
		ActionDiscardArchive:  {"Archived", "Discarding"},
	}[ch.Action]
	need, to := step[0], step[1]
	if need == "" || j.Phase != need {
		return errCAS
	}
	j.Phase, j.Failure = to, ""
	j.Revision++
	if i := w.archivedVolume(q.Scope); i >= 0 {
		w.volumes[i].ArchivePhase = to
	}
	return nil
}

// FinishVolumeArchive is the owner node's next report on the volume's
// archive: Packing → Archived (packed and cleared), Cancelling → Cancelled,
// Restoring → Restored, Discarding → Discarded. fail reports the failure
// instead: Packing fails, Restoring goes back to Archived (package kept).
func (f *Fake) FinishVolumeArchive(tenant, app, volume, fail string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.w
	a := w.archiveState()
	var j *control.VolumeArchiveView
	for _, x := range a.rows {
		if x.Scope.Tenant == tenant && x.Scope.App == app && x.Scope.ID == volume && !archiveDone(x.Phase) && x.Phase != "Archived" {
			j = x
		}
	}
	if j == nil {
		return errors.New("no archive work")
	}
	switch {
	case j.Phase == "Packing" && fail == "":
		j.Phase, j.TarBytes, j.DataBytes = "Archived", j.MaxBytes/4, j.MaxBytes/8
	case j.Phase == "Packing":
		j.Phase, j.Failure = "Failed", fail
	case j.Phase == "Restoring" && fail != "":
		j.Phase, j.Failure = "Archived", fail
	default:
		j.Phase = map[string]string{"Cancelling": "Cancelled", "Restoring": "Restored", "Discarding": "Discarded"}[j.Phase]
	}
	j.Revision++
	w.root++
	if i := w.archivedVolume(j.Scope); i >= 0 {
		v := &w.volumes[i]
		v.Revision = w.root
		if archiveDone(j.Phase) {
			v.Phase, v.ArchiveID, v.ArchivePhase = "Ready", "", ""
			if j.Phase == "Discarded" {
				v.UsedBytes = 0
			}
		} else {
			v.ArchivePhase = j.Phase
		}
	}
	return nil
}
