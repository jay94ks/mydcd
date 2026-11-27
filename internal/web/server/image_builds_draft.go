// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Draft contexts (kind draft) on sfcd's build-draft: the daemon opens the
// draft scope (plan) for each request, edits with the Conn signing a
// DraftProof with the session key (as userauth.Client does; the browser
// never sees it), sends files over one part in parts, and commit freezes
// the draft and submits publish-build-draft. Edits are not web ops: each is
// one synchronous build-draft call, idempotent by its edit ID
// ("e-<opId>"), so a retry with the same opId is safe. File contents pass
// through and are never stored in bbolt.

// draftTree is the draft's current tree (all pages) and its scope.
type draftTree struct {
	Scope       imagebuild.DraftScope
	Revision    uint64
	Digest      [32]byte
	Initialized bool
	Entries     []imagebuild.Entry
}

func readDraft(ctx context.Context, c sfc.Conn, tenant, id string) (draftTree, error) {
	var out draftTree
	plan, err := c.BuildDraft(ctx, tenant, imagebuild.DraftRequest{Context: id, Kind: "plan"})
	if err != nil {
		return out, err
	}
	out.Scope = plan.Scope
	q := imagebuild.DraftRequest{Context: id, Kind: "tree", Scope: &out.Scope}
	first, err := c.BuildDraft(ctx, tenant, q)
	if err != nil {
		return out, err
	}
	if first.Code == "NOT_INITIALIZED" {
		// a new draft context: the first edit expects revision 1
		out.Revision, out.Entries = 1, []imagebuild.Entry{}
		return out, nil
	}
	out.Initialized, out.Revision = true, first.Revision
	if first.Digest != nil {
		out.Digest = *first.Digest
	}
	r := first
	for range 4096 {
		out.Entries = append(out.Entries, r.Entries...)
		if r.Next == 0 {
			break
		}
		q = imagebuild.DraftRequest{Context: id, Kind: "tree", Scope: &out.Scope, Revision: first.Revision, Digest: first.Digest, Offset: r.Next}
		if r, err = c.BuildDraft(ctx, tenant, q); err != nil {
			return out, err
		}
	}
	if out.Entries == nil {
		out.Entries = []imagebuild.Entry{}
	}
	return out, nil
}

// GET /t/{t}/build-contexts/{id}/tree (no version or 0) → the draft:
// {version: 0, revision, digest, initialized, entries, dockerfile}.
func (s *Server) handleDraftTree(w http.ResponseWriter, r *http.Request, ws *webSession) {
	type view struct {
		Version     uint64             `json:"version"`
		Revision    uint64             `json:"revision"`
		Digest      string             `json:"digest,omitempty"`
		Initialized bool               `json:"initialized"`
		Entries     []imagebuild.Entry `json:"entries"`
		Dockerfile  string             `json:"dockerfile"`
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (view, error) {
		d, err := readDraft(ctx, c, r.PathValue("t"), r.PathValue("id"))
		if err != nil {
			return view{}, err
		}
		v := view{Revision: d.Revision, Initialized: d.Initialized, Entries: d.Entries, Dockerfile: d.Scope.Dockerfile}
		if d.Initialized {
			v.Digest = hex.EncodeToString(d.Digest[:])
		}
		return v, nil
	})
}

// draftFile reads one file of the current draft (REQ-57 draft file).
func draftFile(ctx context.Context, c sfc.Conn, tenant, id, path string) ([]byte, bool, error) {
	d, err := readDraft(ctx, c, tenant, id)
	if err != nil {
		return nil, false, err
	}
	if !d.Initialized {
		return nil, false, &httpErr{http.StatusNotFound, "not-found", "the draft has no files yet"}
	}
	var data []byte
	var exec bool
	var offset uint32
	for range 4096 {
		res, err := c.BuildDraft(ctx, tenant, imagebuild.DraftRequest{Context: id, Kind: "file", Scope: &d.Scope, Revision: d.Revision, Digest: &d.Digest, Path: path, Offset: offset})
		if err != nil {
			return nil, false, err
		}
		f := res.Content
		if f == nil {
			switch res.Code {
			case "NOT_INITIALIZED":
				return nil, false, &httpErr{http.StatusNotFound, "not-found", "the draft has no files yet"}
			case "PENDING":
				return nil, false, &httpErr{http.StatusConflict, "conflict", "the draft is changing: read the tree again"}
			}
			return nil, false, &httpErr{http.StatusBadGateway, "draft-" + res.Code, "the draft file could not be read (" + res.Code + ")"}
		}
		if f.Total > maxBuildFileRead {
			return nil, false, &httpErr{http.StatusRequestEntityTooLarge, "too-large", "the file is larger than the web passes through; use the CLI"}
		}
		data, exec = append(data, f.Data...), f.Entry.Executable
		if f.Next == 0 || f.Next >= f.Total {
			return data, exec, nil
		}
		offset = uint32(f.Next)
	}
	return nil, false, &httpErr{http.StatusBadGateway, "bad-page", "the draft file did not end"}
}

// draftEditBody: PUT/DELETE .../files and POST .../files/move.
type draftEditBody struct {
	OpID       string  `json:"opId"`
	Path       string  `json:"path"`
	To         string  `json:"to,omitempty"`
	Text       *string `json:"text,omitempty"`
	Data       []byte  `json:"data,omitempty"`
	Executable bool    `json:"executable,omitempty"`
	Expected   uint64  `json:"expected,omitempty"`
}

// draftEdit: PUT .../files {opId, path, text? | data?(base64), executable?,
// expected?} (put), DELETE .../files {opId, path, expected?} (delete), POST
// .../files/move {opId, path, to, expected?} (move) → {code, revision}.
// expected is the draft revision from the tree (default: the current one);
// a stale one is 409 conflict.
func (s *Server) draftEdit(kind string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req draftEditBody
		if !readJSON(w, r, &req) {
			return
		}
		if !uuidRE.MatchString(req.OpID) {
			writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
			return
		}
		if !imagebuild.ContextPath(req.Path) || req.To != "" && !imagebuild.ContextPath(req.To) {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "path: a clean relative path in the context")
			return
		}
		var data []byte
		switch kind {
		case "put":
			if req.To != "" || (req.Text == nil) == (req.Data == nil) {
				writeError(w, http.StatusUnprocessableEntity, "invalid", "send text or data (base64), not both")
				return
			}
			data = req.Data
			if req.Text != nil {
				if !utf8.ValidString(*req.Text) {
					writeError(w, http.StatusUnprocessableEntity, "invalid", "text: UTF-8")
					return
				}
				data = []byte(*req.Text)
			}
			if len(data) > maxBuildFile {
				writeError(w, http.StatusUnprocessableEntity, "invalid", "a file written in the web is at most 1 MiB")
				return
			}
		case "move":
			if req.To == "" || req.Text != nil || req.Data != nil {
				writeError(w, http.StatusUnprocessableEntity, "invalid", "to: the new path")
				return
			}
		default:
			if req.To != "" || req.Text != nil || req.Data != nil {
				writeError(w, http.StatusUnprocessableEntity, "invalid", "a delete takes only the path")
				return
			}
		}
		tenant, id := r.PathValue("t"), r.PathValue("id")
		type result struct {
			Code     string `json:"code"`
			Revision uint64 `json:"revision"`
		}
		read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (result, error) {
			d, err := readDraft(ctx, c, tenant, id)
			if err != nil {
				return result{}, err
			}
			e := imagebuild.DraftEdit{ID: "e-" + req.OpID, Kind: kind, Path: req.Path, To: req.To, Expected: expectedOr(req.Expected, d.Revision)}
			var res imagebuild.DraftResponse
			if kind == "put" {
				e.File = &imagebuild.Entry{Path: req.Path, Executable: req.Executable, Bytes: int64(len(data)), Digest: sha256.Sum256(data)}
				if len(data) <= imagebuild.PartBytes {
					res, err = c.EditBuildDraft(ctx, d.Scope, e, data)
				} else {
					for i := 0; i*imagebuild.PartBytes < len(data) && err == nil; i++ {
						_, err = c.PutDraftFilePart(ctx, d.Scope, e, uint32(i), data[i*imagebuild.PartBytes:min((i+1)*imagebuild.PartBytes, len(data))])
					}
					if err == nil {
						res, err = c.CommitDraftFile(ctx, d.Scope, e)
					}
				}
			} else {
				res, err = c.EditBuildDraft(ctx, d.Scope, e, nil)
			}
			if err != nil {
				return result{}, err
			}
			if res.Code != "OK" {
				return result{}, &httpErr{http.StatusConflict, "draft-" + res.Code, "the draft did not take the edit (" + res.Code + ")"}
			}
			return result{Code: res.Code, Revision: res.Revision}, nil
		})
	}
}

// POST /t/{t}/build-contexts/{id}/commit {opId, expected?} → freeze the
// draft at its current tree (expected = the draft revision), then
// publish-build-draft (Expected = that revision) → {op}; a new version.
func (s *Server) handlePublishDraft(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, sess sfc.Session) (string, any, uint64, string, error) {
		d, err := readDraft(ctx, c, tenant, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		if !d.Initialized {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "empty-draft", "write a Dockerfile first"}
		}
		if req.Expected != 0 && req.Expected != d.Revision {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "conflict", "the draft changed: read the tree again"}
		}
		now := uint64(s.now().Unix())
		// A new freeze ID each attempt: a plan carries its own time, so a
		// retried commit freezes again rather than reusing the ID.
		fp := imagebuild.DraftFreezePlan{Schema: 1, Scope: d.Scope, ID: "fz-" + randomHex(8), Creator: sess.User, Revision: d.Revision, Draft: d.Digest, CreatedAt: now, ExpiresAt: now + 3600}
		fr, err := c.FreezeBuildDraft(ctx, fp)
		if err != nil {
			return "", nil, 0, "", err
		}
		if fr.Code != "FROZEN" || fr.Frozen == nil {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "draft-" + fr.Code, "the draft could not be frozen (" + fr.Code + ")"}
		}
		return sfc.ActionPublishBuildDraft, control.ImageBuildDraftPublish{Tenant: tenant, Context: id, Frozen: *fr.Frozen}, fp.Revision, "build-context/" + id, nil
	})
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
