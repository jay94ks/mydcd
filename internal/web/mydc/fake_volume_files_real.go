// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// REQ-28 in mydcd's real shape (docs/reference/volume-files.md):
//
//	VolumeFilePlan → sign plan.Change as q.Method, Expected = plan.Revision
//	→ Submit (a Reserved job, VolumeFileID(op)) → VolumeFile (the I/O once,
//	then Completed) → VolumeFileStatus.
//
// The fake does the I/O inside VolumeFile. LoseNextReply("volume-file",
// applied) loses its reply: false = before the I/O (the job stays
// Reserved), true = after it (Completed, the caller sees CodeUnknown).
// A put called again with source nil returns the stored reply of a
// Completed job, or CodeUnknown while it is still Reserved; it never
// decides from the file content that is there now.

type volFileJob struct {
	view  control.VolumeFileView
	user  string
	reply *userauth.VolumeFileReply
}

func scopeOf(w *world, v volumeRow) volumes.Scope {
	return volumes.Scope{Cluster: w.cluster, Tenant: v.Tenant, App: v.App, ID: v.Name, Generation: 1}
}

func (c *fakeConn) VolumeFilePlan(ctx context.Context, tenant string, q control.VolumeFileQuery) (control.VolumeFilePlan, error) {
	const m = "volume-file-plan"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.VolumeFilePlan{}, err
	}
	defer c.unlock()
	if !q.Valid(false) {
		return control.VolumeFilePlan{}, fail(m, CodeInvalid, "")
	}
	w := c.f.w
	vi := w.volumeAt(tenant, q.App, q.Volume)
	if vi < 0 || !w.volFileAllowed(user, tenant, q.App, q.Volume, q.Path) {
		return control.VolumeFilePlan{}, fail(m, CodeDenied, "")
	}
	v := w.volumes[vi]
	ch := control.VolumeFileChange{Scope: scopeOf(w, v), Path: q.Path, After: q.After, MaxBytes: q.MaxBytes, Size: q.Size, Digest: q.Digest, Overwrite: q.Overwrite}
	node := v.Node
	if node == "" {
		node = "node-a"
	}
	return control.VolumeFilePlan{Change: ch, Revision: v.Revision, Node: node}, nil
}

// applyRealVolumeFile: Submit of volume-file-put/get/list/delete reserves
// the job. ConditionFailed: an old Expected, the same job again, or a
// writing job already on the volume (put/delete against a move or another
// writer).
func (c *fakeConn) applyRealVolumeFile(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	var q control.VolumeFileChange
	if decodePayload(ch.Payload, &q) != nil || !q.Valid(ch.Action) || q.Scope.Cluster != w.cluster {
		return errors.New("payload")
	}
	vi := w.volumeAt(q.Scope.Tenant, q.Scope.App, q.Scope.ID)
	if vi < 0 || scopeOf(w, w.volumes[vi]) != q.Scope || w.volumes[vi].Revision != ch.Expected {
		return errCAS
	}
	if !w.volFileAllowed(actor, q.Scope.Tenant, q.Scope.App, q.Scope.ID, q.Path) {
		return errForbidden
	}
	id := control.VolumeFileID(op)
	if _, ok := w.volJobs[id]; ok {
		return errCAS
	}
	writes := ch.Action == ActionPutVolumeFile || ch.Action == ActionDeleteVolumeFile
	if writes {
		if w.volumes[vi].MovePhase != "" {
			return errCAS
		}
		for _, j := range w.volJobs {
			if j.view.Phase == "Reserved" && j.view.Request.Scope == q.Scope && (j.view.Method == ActionPutVolumeFile || j.view.Method == ActionDeleteVolumeFile) {
				return errCAS
			}
		}
	}
	w.volJobs[id] = &volFileJob{view: control.VolumeFileView{ID: id, Method: ch.Action, Phase: "Reserved", Revision: 1, Request: q}, user: actor}
	w.volumes[vi].Revision = next
	w.volumes[vi].Consumers++
	return nil
}

func (c *fakeConn) VolumeFile(ctx context.Context, raw SignedOp, source io.Reader, to io.Writer) (userauth.VolumeFileReply, error) {
	const m = "volume-file"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return userauth.VolumeFileReply{}, err
	}
	defer c.unlock()
	op, _, err := c.decodeOp(m, raw)
	if err != nil {
		return userauth.VolumeFileReply{}, err
	}
	w := c.f.w
	id := control.VolumeFileID(op)
	j, ok := w.volJobs[id]
	if !ok || j.user != user || op.Session.User != user {
		return userauth.VolumeFileReply{}, fail(m, CodeDenied, "")
	}
	if j.view.Phase == "Completed" {
		// A completed job does not stream again; its reply is the record.
		r := *j.reply
		r.Entries = slices.Clone(r.Entries)
		return r, nil
	}
	if j.view.Method == ActionPutVolumeFile && source == nil {
		return userauth.VolumeFileReply{}, fail(m, CodeUnknown, "no publication receipt yet")
	}
	lost, applied := c.f.loseReply(m)
	if lost && !applied {
		return userauth.VolumeFileReply{}, fail(m, CodeUnknown, "reply lost before the I/O")
	}
	r, ioErr := c.volumeFileIO(j, source, to)
	j.reply = &r
	j.view.Phase, j.view.Revision, j.view.Code, j.view.Result = "Completed", 2, r.Code, r.Result
	q := j.view.Request
	if vi := w.volumeAt(q.Scope.Tenant, q.Scope.App, q.Scope.ID); vi >= 0 {
		w.bumpKey(control.VolumesKey)
		w.volumes[vi].Revision = w.root
		w.volumes[vi].Consumers = max(0, w.volumes[vi].Consumers-1)
	}
	if ioErr != nil {
		return r, fail(m, CodeTransport, ioErr.Error())
	}
	if lost {
		return userauth.VolumeFileReply{}, fail(m, CodeUnknown, "reply lost after the I/O")
	}
	return r, nil
}

// volumeFileIO runs the job's I/O on the files of its volume.
func (c *fakeConn) volumeFileIO(j *volFileJob, source io.Reader, to io.Writer) (userauth.VolumeFileReply, error) {
	w := c.f.w
	q := j.view.Request
	r := userauth.VolumeFileReply{Schema: 1, ID: j.view.ID}
	k := q.Scope.Tenant + "/" + q.Scope.ID
	vi := w.volumeAt(q.Scope.Tenant, q.Scope.App, q.Scope.ID)
	if vi < 0 {
		r.Code = "unavailable"
		return r, nil
	}
	switch j.view.Method {
	case ActionPutVolumeFile:
		if source == nil {
			r.Code = "invalid"
			return r, nil
		}
		data, err := io.ReadAll(io.LimitReader(source, q.Size+1))
		if err != nil {
			r.Code = "cancelled"
			return r, err
		}
		if int64(len(data)) != q.Size || sha256.Sum256(data) != q.Digest {
			r.Code = "invalid"
			return r, nil
		}
		old, exists := w.volFiles[k][q.Path]
		if exists && !q.Overwrite {
			r.Code = "conflict"
			return r, nil
		}
		v := &w.volumes[vi]
		used := v.UsedBytes - uint64(len(old.data)) + uint64(len(data))
		if v.CapacityBytes > 0 && used > v.CapacityBytes {
			r.Code = "limit"
			return r, nil
		}
		v.UsedBytes = used
		if w.volFiles[k] == nil {
			w.volFiles[k] = map[string]volFile{}
		}
		w.volFiles[k][q.Path] = volFile{data: data, modifiedAt: c.f.now().Unix()}
		r.Code, r.Result = "ok", &volumes.FileResult{Path: q.Path, Size: q.Size, Digest: q.Digest}
	case ActionGetVolumeFile:
		f, ok := w.volFiles[k][q.Path]
		if !ok {
			r.Code = "not-found"
			return r, nil
		}
		if int64(len(f.data)) > q.MaxBytes {
			r.Code = "limit"
			return r, nil
		}
		if to == nil {
			r.Code = "invalid"
			return r, nil
		}
		if _, err := io.Copy(to, bytes.NewReader(f.data)); err != nil {
			r.Code = "cancelled"
			return r, err
		}
		r.Code, r.Result = "ok", &volumes.FileResult{Path: q.Path, Size: int64(len(f.data)), Digest: sha256.Sum256(f.data)}
	case ActionListVolumeFiles:
		paths := []string{}
		for _, p := range sortedKeys(w.volFiles[k]) {
			if strings.HasPrefix(p, q.Path) && p > q.After {
				paths = append(paths, p)
			}
		}
		r.Code, r.Entries = "ok", []volumes.FileEntry{}
		for i, p := range paths {
			if i == volumes.FilePageEntries {
				r.Next = paths[i-1]
				break
			}
			f := w.volFiles[k][p]
			r.Entries = append(r.Entries, volumes.FileEntry{Path: p, Size: int64(len(f.data)), ModifiedAt: f.modifiedAt})
		}
	case ActionDeleteVolumeFile:
		old, ok := w.volFiles[k][q.Path]
		if !ok {
			r.Code = "not-found"
			return r, nil
		}
		w.volumes[vi].UsedBytes -= min(w.volumes[vi].UsedBytes, uint64(len(old.data)))
		delete(w.volFiles[k], q.Path)
		r.Code = "ok"
	}
	return r, nil
}

func (c *fakeConn) VolumeFileStatus(ctx context.Context, tenant, id string) (control.VolumeFileView, error) {
	const m = "volume-file-status"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.VolumeFileView{}, err
	}
	defer c.unlock()
	w := c.f.w
	j, ok := w.volJobs[id]
	if !ok || j.view.Request.Scope.Tenant != tenant || user != j.user && !w.canManage(user, tenant) {
		return control.VolumeFileView{}, fail(m, CodeDenied, "")
	}
	v := j.view
	if v.Result != nil {
		r := *v.Result
		v.Result = &r
	}
	return v, nil
}
