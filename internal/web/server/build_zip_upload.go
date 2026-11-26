// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// Context zip uploads (upload kind) on mydcd's real REQ-47 contract
// (docs/reference/image-build-contexts.md 'ZIP 전송과 버전 생성'). The
// bytes never go through submit:
//
//  1. begin-build-zip-upload {Tenant, Context, Upload, Length, Digest,
//     ExpiresAt}, Expected 0; mydcd fixes the upload scope, read back from
//     image-builds Part uploads.
//  2. per part: the Conn sends it over build-zip-transfer as a Record part
//     (signed with the session key); the owner records the slot and
//     answers Recorded with the upload revision the next part expects. No
//     operation per part: begin and consume are the only ones.
//  3. finish: SealBuildZIP gives the SealReceipt; upload-build-zip {Tenant,
//     ID, Upload, Fact} (Expected = the upload revision) makes the version.
//
// New uploads use 32 KiB parts (ChunkBytes = imagebuild.UploadPartBytes);
// an upload begun with the old 24 KiB parts keeps them (the part size is
// fixed in its scope). The browser sends web chunks of about 4 MiB: whole
// parts, zipChunkParts of them. Part ops are
// not kept in web bbolt (a 500 MB zip has ~20,000 parts): a part is the
// same bytes at the same index, so a lost answer is settled by reading the
// upload's missing parts and sending that chunk again. begin, finish and
// abort are ordinary web ops. Zip bytes only pass through.

// maxZipChunkBytes bounds a web chunk body before the scope is read.
const maxZipChunkBytes = 4 << 20

// zipChunkParts: 128 × 32 KiB = 4 MiB, or 170 × 24 KiB ≈ 4 MiB.
func zipChunkParts(s imagebuild.UploadScope) int {
	return maxZipChunkBytes / int(s.PartSize())
}

func zipChunkBytes(s imagebuild.UploadScope) int64 {
	return int64(zipChunkParts(s)) * s.PartSize()
}

type zipUploadView struct {
	Upload        string `json:"upload"`
	Context       string `json:"context"`
	Length        int64  `json:"length"`
	Digest        string `json:"digest"`
	Revision      uint64 `json:"revision"`
	ExpiresAt     string `json:"expiresAt"`
	PartBytes     int    `json:"partBytes"`
	ChunkBytes    int    `json:"chunkBytes"`
	Chunks        int    `json:"chunks"`
	MissingChunks []int  `json:"missingChunks"`
	Complete      bool   `json:"complete"`
}

// zipUpload is the caller's open upload with its missing parts.
type zipUpload struct {
	control.ImageBuildUploadView
	Missing []uint32
}

func (u zipUpload) view() zipUploadView {
	s := u.Scope
	cb := zipChunkBytes(s)
	v := zipUploadView{Upload: s.Upload, Context: s.Context, Length: s.Length, Digest: hex.EncodeToString(s.Digest[:]), Revision: u.Revision, ExpiresAt: rfcU(s.ExpiresAt),
		PartBytes: int(s.PartSize()), ChunkBytes: int(cb), Chunks: int((s.Length + cb - 1) / cb), MissingChunks: []int{}}
	for _, p := range u.Missing {
		if n := int(p) / zipChunkParts(s); !slices.Contains(v.MissingChunks, n) {
			v.MissingChunks = append(v.MissingChunks, n)
		}
	}
	v.Complete = len(u.Missing) == 0
	return v
}

// readZipUpload reads the caller's upload (image-builds Part uploads, then
// its missing parts) and checks it is open and belongs to the context; ok
// is false when there is no such upload.
func readZipUpload(ctx context.Context, c mydc.Conn, tenant, buildCtx, upload string) (zipUpload, bool, error) {
	var out zipUpload
	p, err := c.ImageBuilds(ctx, tenant, control.ImageBuildQuery{Part: "uploads", Upload: upload}, "")
	if err != nil {
		return out, false, err
	}
	i := slices.IndexFunc(p.Uploads, func(u control.ImageBuildUploadView) bool { return u.Scope.Upload == upload })
	if i < 0 || p.Uploads[i].Scope.Context != buildCtx || p.Uploads[i].Closed {
		return out, false, nil
	}
	out.ImageBuildUploadView = p.Uploads[i]
	after := ""
	for range 1024 { // 256 indexes a page: 500 MB is ~80 pages
		m, err := c.ImageBuilds(ctx, tenant, control.ImageBuildQuery{Part: "missing", Upload: upload}, after)
		if err != nil {
			return out, false, err
		}
		out.Missing = append(out.Missing, m.Missing...)
		if m.UploadRevision != 0 {
			out.Revision = m.UploadRevision
		}
		if m.Next == "" {
			break
		}
		after = m.Next
	}
	return out, true, nil
}

func mustZipUpload(ctx context.Context, c mydc.Conn, tenant, buildCtx, upload string) (zipUpload, error) {
	u, ok, err := readZipUpload(ctx, c, tenant, buildCtx, upload)
	if err == nil && !ok {
		err = &httpErr{http.StatusNotFound, "not-found", "no such open upload for this build context"}
	}
	return u, err
}

// zipBegin checks the request and builds begin-build-zip-upload.
func zipBegin(ctx context.Context, c mydc.Conn, now uint64, tenant, id, upload string, length int64, digest [32]byte) (control.ImageBuildUploadBegin, error) {
	if length <= 0 || length > imagebuild.MaxZIPBytes {
		return control.ImageBuildUploadBegin{}, invalid("length: 1 byte to 500 MB")
	}
	x, err := realContext(ctx, c, tenant, id)
	if err != nil {
		return control.ImageBuildUploadBegin{}, err
	}
	if x == nil {
		return control.ImageBuildUploadBegin{}, &httpErr{http.StatusNotFound, "not-found", "no such build context"}
	}
	if x.Spec.Kind != "upload" {
		return control.ImageBuildUploadBegin{}, &httpErr{http.StatusConflict, "not-upload", "only an upload context takes a zip"}
	}
	// a little under mydcd's 24 h so clock skew between the hosts cannot
	// push it over
	return control.ImageBuildUploadBegin{Tenant: tenant, Context: id, Upload: upload, Length: length, Digest: digest, ExpiresAt: now + imagebuild.MaxUploadLifetime - 600,
		ChunkBytes: imagebuild.UploadPartBytes}, nil
}

// submitUnstored signs and sends one original that web bbolt does not keep
// (zip parts; the one-change zip's begin), checked by the product decoder.
// These are the exceptions to "store the signed original before sending":
// a part is the same bytes at the same index, and the one-change begin
// opens the upload "web-<opId>", which a retry with the same opId finds
// and carries on with (mydcd never opens one ID twice). Either way a lost
// answer is settled by reading the upload, not by the stored op.
func submitUnstored(ctx context.Context, c mydc.Conn, ws *webSession, action string, expected uint64, payload any) (mydc.ResultCode, error) {
	raw, _ := json.Marshal(payload)
	doc, _ := json.Marshal(control.ChangeDocument{Schema: 1, Action: action, Expected: expected, Payload: raw})
	ch, err := control.InputChange(doc, ws.user.ID)
	if err != nil {
		return 0, &httpErr{http.StatusUnprocessableEntity, "invalid", action + ": the values do not make a valid request"}
	}
	who, err := c.Whoami(ctx)
	if err != nil {
		return 0, err
	}
	op, err := c.Prepare(ctx, ch, who.RootFor(action))
	if err != nil {
		return 0, err
	}
	res, err := c.Submit(ctx, op)
	if err != nil {
		return 0, err
	}
	return res.Code, nil
}

// ioRefused maps a build-zip-transfer code other than OK and CONFLICT.
func ioRefused(what, code string) error {
	switch code {
	case "DIGEST_MISMATCH", "INVALID_ZIP":
		return &httpErr{http.StatusUnprocessableEntity, "part-refused", what + " was refused (" + code + "); check the zip and its digest"}
	case "STORAGE_UNAVAILABLE":
		return &httpErr{http.StatusServiceUnavailable, "storage-unavailable", "the build root cannot take the upload now; try again"}
	}
	return &httpErr{http.StatusBadGateway, "transfer", what + ": " + code}
}

// sendZipParts sends the parts from index first whose bytes are in data
// (data starts at part first) and that are still missing, in order, as
// Record parts: the owner confirms each slot itself (Recorded, no per-part
// operation, so a 500 MB zip stays within the user's ledger budget) and
// its UploadRevision is the next part's Expected. An owner that only
// stages (Recorded false) gets the part's receipt as put-build-zip-part.
// A conflict is an error, never retried with another revision here: the
// browser sends the chunk again, which reads the upload afresh.
func sendZipParts(ctx context.Context, c mydc.Conn, ws *webSession, u zipUpload, first uint32, data []byte) (zipUpload, error) {
	s := u.Scope
	size := int(s.PartSize())
	for i := first; i < s.Parts() && int(i-first)*size < len(data); i++ {
		if !slices.Contains(u.Missing, i) {
			continue
		}
		off := int(i-first) * size
		part := data[off:min(len(data), off+size)]
		tr, err := c.PutBuildZIPPart(ctx, s, u.Revision, i, part, true)
		if err != nil {
			return u, err
		}
		switch {
		case tr.Code == "CONFLICT":
			return u, &httpErr{http.StatusConflict, "conflict", fmt.Sprintf("part %d: the upload changed or no longer matches its context; send the chunk again", i)}
		case tr.Code != "OK" || tr.Part == nil:
			return u, ioRefused(fmt.Sprintf("part %d", i), tr.Code)
		case tr.Recorded:
			u.Revision = tr.UploadRevision
		default:
			code, err := submitUnstored(ctx, c, ws, mydc.ActionPutBuildZipPart, u.Revision, control.ImageBuildUploadPart{Tenant: s.Tenant, Upload: s.Upload, Receipt: *tr.Part})
			if err != nil {
				return u, err
			}
			if code == mydc.ResultConditionFailed {
				return u, &httpErr{http.StatusConflict, "conflict", fmt.Sprintf("part %d: the upload changed; send the chunk again", i)}
			}
			if code != mydc.ResultApplied {
				return u, &httpErr{http.StatusUnprocessableEntity, "part-refused", fmt.Sprintf("part %d was refused (result %d)", i, code)}
			}
			u.Revision++
		}
		u.Missing = slices.DeleteFunc(u.Missing, func(m uint32) bool { return m == i })
	}
	return u, nil
}

// sealZip asks for the seal receipt of a complete upload and builds
// upload-build-zip.
func sealZip(ctx context.Context, c mydc.Conn, u zipUpload) (control.ImageBuildZIPConsume, error) {
	if len(u.Missing) > 0 {
		return control.ImageBuildZIPConsume{}, &httpErr{http.StatusConflict, "incomplete", fmt.Sprintf("%d parts are still missing", len(u.Missing))}
	}
	tr, err := c.SealBuildZIP(ctx, u.Scope, u.Revision)
	if err != nil {
		return control.ImageBuildZIPConsume{}, err
	}
	if tr.Code == "CONFLICT" {
		return control.ImageBuildZIPConsume{}, &httpErr{http.StatusConflict, "conflict", "the upload changed or no longer matches its context; read it again"}
	}
	if tr.Code != "OK" || tr.Seal == nil {
		return control.ImageBuildZIPConsume{}, ioRefused("the zip", tr.Code)
	}
	return control.ImageBuildZIPConsume{Tenant: u.Scope.Tenant, ID: u.Scope.Context, Upload: u.Scope.Upload, Fact: *tr.Seal}, nil
}

// PUT /t/{t}/build-contexts/{id}/zip?opId= with the zip as the body
// (application/zip, at most 8 MiB) → a new version. The daemon begins the
// upload "web-<opId>", sends its parts and seals it directly; only the
// final upload-build-zip is a stored op, so a retry with the same opId
// carries on with the same upload.
func (s *Server) handleUploadBuildZip(w http.ResponseWriter, r *http.Request, ws *webSession) {
	zip, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBuildZipWeb))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too-large", "the zip is larger than 8 MiB; use the chunked upload or the CLI")
		return
	}
	if len(zip) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "body: the context zip")
		return
	}
	opID := r.URL.Query().Get("opId")
	sum := sha256.Sum256(zip)
	body := struct{ Zip string }{hex.EncodeToString(sum[:])}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	s.sharedCreate(w, r, ws, opID, body, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		upload := "web-" + opID
		u, ok, err := readZipUpload(ctx, c, tenant, id, upload)
		if err != nil {
			return "", nil, 0, "", err
		}
		if !ok {
			q, err := zipBegin(ctx, c, uint64(s.now().Unix()), tenant, id, upload, int64(len(zip)), sum)
			if err != nil {
				return "", nil, 0, "", err
			}
			code, err := submitUnstored(ctx, c, ws, mydc.ActionBeginBuildZipUpload, 0, q)
			if err != nil {
				return "", nil, 0, "", err
			}
			if code != mydc.ResultApplied {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "upload-refused", fmt.Sprintf("mydcd did not open the upload (result %d): check the build policy, its space and open uploads", code)}
			}
			if u, err = mustZipUpload(ctx, c, tenant, id, upload); err != nil {
				return "", nil, 0, "", err
			}
		}
		if u.Scope.Length != int64(len(zip)) || u.Scope.Digest != sum {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "op-conflict", "this opId was already used for a different zip"}
		}
		if u, err = sendZipParts(ctx, c, ws, u, 0, zip); err != nil {
			return "", nil, 0, "", err
		}
		q, err := sealZip(ctx, c, u)
		if err != nil {
			return "", nil, 0, "", err
		}
		return mydc.ActionUploadBuildZip, q, u.Revision, "build-context/" + id, nil
	})
}

// POST /t/{t}/build-contexts/{id}/zip-uploads {opId, length, digest} →
// begin-build-zip-upload (upload kind contexts, at most 500 MB, open 24 h).
// The upload's ID is "web-<opId>"; then PUT its chunks, then finish.
func (s *Server) handleBeginZipUpload(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID   string `json:"opId"`
		Length int64  `json:"length"`
		Digest string `json:"digest"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		dg, ok := parseHex32(req.Digest)
		if !ok || dg == ([32]byte{}) {
			return "", nil, 0, "", invalid("digest: sha256 of the whole zip (64 hex)")
		}
		q, err := zipBegin(ctx, c, uint64(s.now().Unix()), tenant, id, "web-"+req.OpID, req.Length, dg)
		if err != nil {
			return "", nil, 0, "", err
		}
		return mydc.ActionBeginBuildZipUpload, q, 0, "build-context/" + id, nil
	})
}

// GET /t/{t}/build-contexts/{id}/zip-uploads/{upload} → {upload, context,
// length, digest, revision, expiresAt, partBytes, chunkBytes, chunks,
// missingChunks, complete} (the uploader only; 404 once finished or aborted).
func (s *Server) handleZipUpload(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (zipUploadView, error) {
		u, err := mustZipUpload(ctx, c, r.PathValue("t"), r.PathValue("id"), r.PathValue("upload"))
		return u.view(), err
	})
}

// PUT /t/{t}/build-contexts/{id}/zip-uploads/{upload}/chunks/{n} with the
// chunk as the body (exactly chunkBytes, the last one the rest) → the
// upload view. Chunks go in any order and again after a lost answer; the
// last missing part makes mydcd check the whole zip's digest (422
// part-refused).
func (s *Server) handleZipUploadChunk(w http.ResponseWriter, r *http.Request, ws *webSession) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 0 {
		writeError(w, http.StatusBadRequest, "bad-request", "chunk: a number from 0")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxZipChunkBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too-large", fmt.Sprintf("a chunk is at most %d bytes", maxZipChunkBytes))
		return
	}
	tenant, id, upload := r.PathValue("t"), r.PathValue("id"), r.PathValue("upload")
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var view zipUploadView
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		u, err := mustZipUpload(ctx, c, tenant, id, upload)
		if err != nil {
			return err
		}
		cb := zipChunkBytes(u.Scope)
		start := int64(n) * cb
		if start >= u.Scope.Length || int64(len(data)) != min(cb, u.Scope.Length-start) {
			return invalid(fmt.Sprintf("chunk %d: expected %d bytes", n, max(0, min(cb, u.Scope.Length-start))))
		}
		if u, err = sendZipParts(ctx, c, ws, u, uint32(n*zipChunkParts(u.Scope)), data); err != nil {
			return err
		}
		view = u.view()
		return nil
	})
	if err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// POST /t/{t}/build-contexts/{id}/zip-uploads/{upload}/finish {opId} → the
// daemon seals the upload (mydcd checks the zip: 422 part-refused when it
// is not a context zip), then upload-build-zip: the context's new version
// (409 incomplete while parts are missing).
func (s *Server) handleFinishZipUpload(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id, upload := r.PathValue("t"), r.PathValue("id"), r.PathValue("upload")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		u, err := mustZipUpload(ctx, c, tenant, id, upload)
		if err != nil {
			return "", nil, 0, "", err
		}
		q, err := sealZip(ctx, c, u)
		if err != nil {
			return "", nil, 0, "", err
		}
		return mydc.ActionUploadBuildZip, q, u.Revision, "build-context/" + id, nil
	})
}

// DELETE /t/{t}/build-contexts/{id}/zip-uploads/{upload} {opId} →
// abort-build-zip-upload (Expected = the upload revision).
func (s *Server) handleAbortZipUpload(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id, upload := r.PathValue("t"), r.PathValue("id"), r.PathValue("upload")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		u, err := mustZipUpload(ctx, c, tenant, id, upload)
		if err != nil {
			return "", nil, 0, "", err
		}
		return mydc.ActionAbortBuildZipUpload, control.ImageBuildUploadSelection{Tenant: tenant, Upload: upload}, u.Revision, "build-context/" + id, nil
	})
}
