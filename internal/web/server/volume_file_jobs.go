// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// REQ-28 file jobs in mydcd's real shape (docs/reference/volume-files.md):
// volume-file-plan gives the change; the web signs it as the session user
// with Expected = plan.Revision, stores the original, submits it (the job
// is reserved), then streams the body once over purpose18 by VolumeFile.
//
// After a lost reply the web never decides from the file it finds there:
// it reads the job by VolumeFileID(op). Reserved: the same op streams
// again. Completed: VolumeFile(op, nil, nil) gives the stored reply (a get's
// bytes are gone, so a get starts over with a new op). A get is used only
// after its length and digest match the reply's Result.

const volumeFileTries = 3

var (
	errVolumeFileUnknown = errors.New("volume-file-unknown")  // the job's outcome is not known
	errVolumeFileGetLost = errors.New("volume-file-get-lost") // a get completed but its bytes were lost
)

// vfJob is one put/get/list/delete.
type vfJob struct {
	tenant string
	q      control.VolumeFileQuery
	body   []byte // put
	o      *store.Op
}

// vfResult: the reply and, for a get, the checked bytes.
type vfResult struct {
	reply userauth.VolumeFileReply
	data  []byte
	op    *store.Op
}

// newVolumeFileOp: the web op record of a job (opID "" = a new ID). The
// digest covers the query (and the body's digest), never the content.
func newVolumeFileOp(ws *webSession, opID, tenant string, q control.VolumeFileQuery, reason *store.OpReason) *store.Op {
	if opID == "" {
		opID = newOpID()
	}
	raw, _ := json.Marshal(struct {
		Tenant string
		Query  control.VolumeFileQuery
	}{tenant, q})
	sum := sha256.Sum256(raw)
	return &store.Op{ID: opID, User: ws.user.ID, Username: ws.user.Username, Action: q.Method, Tenant: tenant, Target: "volume/" + q.Volume,
		Digest: hex.EncodeToString(sum[:]), Reason: reason}
}

// runVolumeFile plans, signs, stores and submits j, then streams it. A
// stored op (j.o.Signed set, from an earlier try of the same opId) is not
// signed again: only its stream is resumed.
func (s *Server) runVolumeFile(ctx context.Context, c mydc.Conn, ws *webSession, j vfJob) (vfResult, error) {
	o := j.o
	if len(o.Signed) == 0 {
		plan, err := c.VolumeFilePlan(ctx, j.tenant, j.q)
		if err != nil {
			return vfResult{op: o}, err
		}
		raw, err := json.Marshal(plan.Change)
		if err != nil {
			return vfResult{op: o}, err
		}
		who, err := c.Whoami(ctx)
		if err != nil {
			return vfResult{op: o}, err
		}
		ch := mydc.Change{Schema: 1, Action: j.q.Method, Principal: ws.user.ID, Expected: plan.Revision, Payload: raw}
		if _, err := s.sendStored(ctx, c, o, ch, who.RootFor(j.q.Method)); err != nil {
			return vfResult{op: o}, err
		}
	}
	if o.State != store.OpApplied {
		return vfResult{op: o}, &httpErr{opStatus(o), "op-" + o.State, fmt.Sprintf("%s was not reserved (%s %s)", j.q.Method, o.State, o.ErrorCode)}
	}
	r, data, err := s.streamVolumeFile(ctx, c, j.tenant, j.q.Method, mydc.SignedOp(o.Signed), j.body)
	return vfResult{reply: r, data: data, op: o}, err
}

// streamVolumeFile streams a reserved job once, and after a lost reply
// settles it from the job's status (see above).
func (s *Server) streamVolumeFile(ctx context.Context, c mydc.Conn, tenant, method string, op mydc.SignedOp, body []byte) (userauth.VolumeFileReply, []byte, error) {
	id, err := mydc.VolumeFileID(op)
	if err != nil {
		return userauth.VolumeFileReply{}, nil, err
	}
	for range volumeFileTries {
		var src io.Reader
		var buf bytes.Buffer
		var to io.Writer
		switch method {
		case mydc.ActionPutVolumeFile:
			src = bytes.NewReader(body)
		case mydc.ActionGetVolumeFile:
			to = &buf
		}
		r, err := c.VolumeFile(ctx, op, src, to)
		if err == nil {
			if method != mydc.ActionGetVolumeFile || r.Code != "ok" {
				return r, nil, nil
			}
			if r.Result == nil || r.Result.Size != int64(buf.Len()) || r.Result.Digest != sha256.Sum256(buf.Bytes()) {
				clear(buf.Bytes())
				return r, nil, &httpErr{http.StatusBadGateway, "volume-file-mismatch", "the file read does not match its length and digest"}
			}
			return r, buf.Bytes(), nil
		}
		clear(buf.Bytes())
		if !isMydcCode(err, mydc.CodeUnknown) {
			return r, nil, err
		}
		v, serr := c.VolumeFileStatus(ctx, tenant, id)
		if serr != nil {
			return r, nil, errVolumeFileUnknown
		}
		switch v.Phase {
		case "Reserved":
			continue
		case "Completed":
			if method == mydc.ActionGetVolumeFile {
				return r, nil, errVolumeFileGetLost
			}
			if r, err := c.VolumeFile(ctx, op, nil, nil); err == nil {
				return r, nil, nil
			}
			return r, nil, errVolumeFileUnknown
		default:
			return r, nil, errVolumeFileUnknown
		}
	}
	return userauth.VolumeFileReply{}, nil, errVolumeFileUnknown
}

// volumeFileGet reads one file (at most max bytes), starting over with a
// new op once when a completed get lost its bytes.
func (s *Server) volumeFileGet(ctx context.Context, c mydc.Conn, ws *webSession, tenant, volume, path string, max int64, reason *store.OpReason) (vfResult, error) {
	q := control.VolumeFileQuery{Volume: volume, Path: path, Method: mydc.ActionGetVolumeFile, MaxBytes: max}
	var res vfResult
	var err error
	for range 2 {
		res, err = s.runVolumeFile(ctx, c, ws, vfJob{tenant: tenant, q: q, o: newVolumeFileOp(ws, "", tenant, q, reason)})
		if !errors.Is(err, errVolumeFileGetLost) {
			break
		}
	}
	return res, err
}

// volumeFileList reads every entry under prefix (one op per 64-entry page).
func (s *Server) volumeFileList(ctx context.Context, c mydc.Conn, ws *webSession, tenant, volume, prefix string, reason *store.OpReason, pages int) ([]vfEntry, string, error) {
	var out []vfEntry
	after := ""
	for range pages {
		q := control.VolumeFileQuery{Volume: volume, Path: prefix, Method: mydc.ActionListVolumeFiles, After: after}
		res, err := s.runVolumeFile(ctx, c, ws, vfJob{tenant: tenant, q: q, o: newVolumeFileOp(ws, "", tenant, q, reason)})
		if err != nil {
			return nil, "", err
		}
		if err := replyErr(res.reply); err != nil {
			return nil, "", err
		}
		for _, e := range res.reply.Entries {
			out = append(out, vfEntry{Path: e.Path, Bytes: e.Size, ModifiedAt: e.ModifiedAt})
		}
		if after = res.reply.Next; after == "" {
			break
		}
	}
	return out, after, nil
}

type vfEntry struct {
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	ModifiedAt int64  `json:"modifiedAt"`
}

// replyErr: a job that completed with a code other than ok.
func replyErr(r userauth.VolumeFileReply) error {
	switch r.Code {
	case "ok":
		return nil
	case "not-found":
		return &httpErr{http.StatusNotFound, "not-found", "no such file in the volume"}
	case "conflict":
		return &httpErr{http.StatusConflict, "exists", "the file already exists (send overwrite=1)"}
	case "limit":
		return &httpErr{http.StatusRequestEntityTooLarge, "too-large", "the file is over the size limit"}
	}
	return &httpErr{http.StatusUnprocessableEntity, "volume-file-" + r.Code, "the volume refused the file operation (" + r.Code + ")"}
}

// volumeFileErr: the HTTP error of a job error.
func volumeFileErr(err error) error {
	switch {
	case errors.Is(err, errVolumeFileUnknown):
		return &httpErr{http.StatusBadGateway, "volume-file-unknown", "the file operation's outcome is not known yet; send the same opId again"}
	case errors.Is(err, errVolumeFileGetLost):
		return &httpErr{http.StatusBadGateway, "volume-file-unknown", "the file was read but the reply was lost; read it again"}
	}
	return err
}
