// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// The REQ-47 zip upload in mydcd's real shape (docs/reference/
// image-build-contexts.md 'ZIP 전송과 버전 생성'). The bytes never go
// through submit:
//
//  1. begin-build-zip-upload control.ImageBuildUploadBegin{Tenant, Context,
//     Upload, Length, Digest, ExpiresAt, ChunkBytes?}, Expected 0, root CAS.
//     ChunkBytes 0 (omitted) keeps 24 KiB parts (imagebuild.PartBytes);
//     imagebuild.UploadPartBytes (32 KiB) is the only other value. Part
//     lengths, offsets and missing parts follow Scope.PartSize(). mydcd fixes
//     the UploadScope (creator, Root, context/policy revisions, Dockerfile,
//     ExpandedLimit = policy WorkspaceBytes); read it from image-builds
//     Part uploads.
//  2. per part: PutBuildZIPPart (build-zip-transfer, signed with the
//     session key) → the owner's PartReceipt; then put-build-zip-part
//     control.ImageBuildUploadPart{Tenant, Upload, Receipt}, Expected = the
//     upload Revision (upload CAS, +1 each).
//  3. SealBuildZIP (all parts recorded) → SealReceipt; then upload-build-zip
//     control.ImageBuildZIPConsume{Tenant, ID, Upload, Fact}, Expected = the
//     upload Revision. That makes the next version and closes the upload;
//     the context Revision stays.
//
// abort-build-zip-upload control.ImageBuildUploadSelection (creator only).
//
// Fake-only: receipts are signed with the root node's fixture key; the
// last part checks the whole-zip digest (DIGEST_MISMATCH); the seal checks
// paths, the Dockerfile and ExpandedLimit (INVALID_ZIP). Expiry is the
// scope's ExpiresAt against the fake clock; no reclamation is modeled.

const maxOpenBuildUploads = 16

type realUpload struct {
	u      imagebuild.Upload
	staged map[uint32][]byte // owner side: written parts with issued receipts
	files  map[string][]byte // after a seal
	seal   *imagebuild.SealReceipt
}

// uploadCurrent: mydcd's currentBuildUpload — the scope still matches the
// context and policy, and has not expired.
func (w *world) uploadCurrent(r *realUpload, now uint64) bool {
	s := r.u.Scope
	x := w.build.find(s.Tenant, s.Context)
	pol, prev, deleted, ok := w.imagePolicy(s.Tenant)
	if x == nil || !ok || deleted || r.u.Closed || x.row.Kind != BuildUpload {
		return false
	}
	spec := w.contextSpec(x)
	return x.row.Revision == s.ContextRevision && prev == s.PolicyRevision && spec.Root == s.Root && spec.Dockerfile == s.Dockerfile && spec.Under(pol) &&
		s.Current(s.Creator, now) == nil
}

func (c *fakeConn) applyRealZipUpload(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	b := &w.build
	b.real.ready()
	ch := op.Change
	now := uint64(c.f.now().Unix())
	var sel control.ImageBuildUploadSelection
	if json.Unmarshal(ch.Payload, &sel) != nil || sel.Tenant == "" || sel.Upload == "" {
		return errors.New("payload")
	}
	if !w.canManage(actor, sel.Tenant) {
		return errForbidden
	}
	key := sel.Tenant + "/" + sel.Upload
	if ch.Action == ActionBeginBuildZipUpload {
		var q control.ImageBuildUploadBegin
		if decodePayload(ch.Payload, &q) != nil || !identifierRE.MatchString(q.Upload) {
			return errors.New("payload")
		}
		if ch.Expected != 0 || b.real.uploads[key] != nil {
			return errCAS // an upload ID is never reused
		}
		x := b.find(q.Tenant, q.Context)
		pol, prev, deleted, ok := w.imagePolicy(q.Tenant)
		if x == nil || x.row.Kind != BuildUpload || !ok || deleted {
			return errCAS
		}
		spec := w.contextSpec(x)
		open := 0
		for _, u := range b.real.uploads {
			if u.u.Scope.Tenant == q.Tenant && !u.u.Closed {
				open++
			}
		}
		if q.ChunkBytes != 0 && q.ChunkBytes != imagebuild.UploadPartBytes {
			return errors.New("payload: ChunkBytes")
		}
		if !spec.Under(pol) || open >= maxOpenBuildUploads || q.Length <= 0 || q.Length > imagebuild.MaxZIPBytes || q.Length > pol.CacheBytes {
			return errCAS
		}
		scope := imagebuild.UploadScope{Schema: 1, Cluster: w.cluster, Tenant: q.Tenant, Context: q.Context, Upload: q.Upload, Creator: actor, Root: spec.Root,
			ContextRevision: x.row.Revision, PolicyRevision: prev, Length: q.Length, Digest: q.Digest, Dockerfile: spec.Dockerfile, ExpandedLimit: pol.WorkspaceBytes,
			ExpiresAt: q.ExpiresAt, ChunkBytes: q.ChunkBytes}
		u, err := imagebuild.BeginUpload(scope, now)
		if err != nil {
			return errors.New("payload: scope")
		}
		b.real.uploads[key] = &realUpload{u: u, staged: map[uint32][]byte{}}
		b.rev[q.Tenant] = next
		return nil
	}
	r := b.real.uploads[key]
	if r == nil || r.u.Scope.Creator != actor || r.u.Revision != ch.Expected || r.u.Closed {
		return errCAS
	}
	switch ch.Action {
	case ActionAbortBuildZipUpload:
		if decodePayload(ch.Payload, &sel) != nil {
			return errors.New("payload")
		}
		u, err := r.u.Abort(actor, ch.Expected)
		if err != nil {
			return errCAS
		}
		r.u, r.staged, r.files, r.seal = u, nil, nil, nil
	case ActionPutBuildZipPart:
		var q control.ImageBuildUploadPart
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		if !w.uploadCurrent(r, now) {
			return errCAS
		}
		u, err := r.u.Put(actor, ch.Expected, now, q.Receipt)
		if errors.Is(err, imagebuild.ErrInvalid) {
			return errors.New("payload: receipt")
		}
		if err != nil {
			return errCAS
		}
		r.u = u
	case ActionUploadBuildZip:
		var q control.ImageBuildZIPConsume
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		if !w.uploadCurrent(r, now) || r.seal == nil || r.seal.Tree != q.Fact.Tree {
			return errCAS
		}
		u, err := r.u.Consume(actor, q.ID, ch.Expected, now, q.Fact)
		if errors.Is(err, imagebuild.ErrInvalid) {
			return errors.New("payload: fact")
		}
		if err != nil {
			return errCAS
		}
		x := b.find(sel.Tenant, q.ID)
		n := slices.Max(append([]uint64{0}, x.row.Versions...)) + 1
		x.versions[n] = r.files
		x.row.Versions = append(x.row.Versions, n)
		x.row.Version = n
		b.real.seals[fmt.Sprintf("%s/%s/%d", sel.Tenant, q.ID, n)] = realSeal{scope: r.u.Scope, seal: q.Fact}
		r.u, r.staged, r.files, r.seal = u, nil, nil, nil
	default:
		return errors.New("action")
	}
	b.rev[sel.Tenant] = next
	return nil
}

// --- build-zip-transfer (the owner's side) ---

// PutBuildZIPPart: record=true (as userauth.Client, 1add789) also confirms
// the receipt at once, as the owner's image-build-owner-report Action part
// does: the slot is recorded (Received, Revision +1, missing) with no
// put-build-zip-part, and the answer carries Recorded and UploadRevision
// (the next part's Expected). Sending an already recorded slot again with
// the same bytes returns its ACK at the current revision (≥ Expected).
// Without record it only stages, as before.
func (c *fakeConn) PutBuildZIPPart(ctx context.Context, scope imagebuild.UploadScope, expected uint64, index uint32, data []byte, record ...bool) (control.ImageBuildIOResult, error) {
	if len(record) > 1 {
		return control.ImageBuildIOResult{}, fail("build-zip-transfer", CodeInvalid, "record")
	}
	return c.zipTransfer(ctx, scope, func(at int64) (imagebuild.Transfer, error) {
		if len(data) == 0 || len(data) != scope.PartLength(index) {
			return imagebuild.Transfer{}, errors.New("part length")
		}
		p := imagebuild.PartProof{Schema: 1, Scope: scope.Hash(), Index: index, Length: uint32(len(data)), Digest: sha256.Sum256(data), Expected: expected,
			At: at, ExpiresAt: min(at+120, c.session.ExpiresAt)}
		if p.Record = len(record) == 1 && record[0]; p.Record {
			d := imagebuild.PartSessionDigest(*c.session)
			p.Session = &d
		}
		if _, err := rand.Read(p.Nonce[:]); err != nil {
			return imagebuild.Transfer{}, err
		}
		p.Signature = ed25519.Sign(c.key, imagebuild.PartProofBytes(p))
		return imagebuild.Transfer{Upload: scope.Upload, Kind: "part", Expected: expected, Index: index, Data: data, Proof: &p, Record: p.Record}, nil
	})
}

func (c *fakeConn) SealBuildZIP(ctx context.Context, scope imagebuild.UploadScope, expected uint64) (control.ImageBuildIOResult, error) {
	return c.zipTransfer(ctx, scope, func(int64) (imagebuild.Transfer, error) {
		return imagebuild.Transfer{Upload: scope.Upload, Kind: "seal", Expected: expected}, nil
	})
}

func (c *fakeConn) zipTransfer(ctx context.Context, scope imagebuild.UploadScope, build func(at int64) (imagebuild.Transfer, error)) (control.ImageBuildIOResult, error) {
	const m = "build-zip-transfer"
	if err := c.appRead(ctx, m, scope.Tenant); err != nil {
		return control.ImageBuildIOResult{}, err
	}
	defer c.unlock()
	if c.key == nil {
		return control.ImageBuildIOResult{}, fail(m, CodeNotLoggedIn, "")
	}
	w := c.f.w
	at := c.f.now().Unix()
	q, err := build(at)
	if err != nil || q.Authorize(scope, *c.session, at) != nil {
		return control.ImageBuildIOResult{}, fail(m, CodeInvalid, "transfer")
	}
	if !w.canManage(c.session.User, scope.Tenant) {
		return control.ImageBuildIOResult{}, fail(m, CodeDenied, "")
	}
	w.build.real.ready()
	r := w.build.real.uploads[scope.Tenant+"/"+scope.Upload]
	if r == nil {
		return control.ImageBuildIOResult{}, fail(m, CodeMissing, "upload")
	}
	out := control.ImageBuildIOResult{Schema: 1, Scope: scope.Hash()}
	// a recorded slot's ACK may be fetched again after other parts moved on
	recorded := q.Record && q.Kind == "part" && !r.u.Closed && r.u.Part(q.Index) == q.Proof.Digest
	if r.u.Scope.Hash() != scope.Hash() || q.Expected > r.u.Revision || q.Expected != r.u.Revision && !recorded || !w.uploadCurrent(r, uint64(at)) {
		out.Code = "CONFLICT"
		return out, nil
	}
	sign := FixtureKey(scope.Root.Node)
	if q.Kind == "part" {
		if old, ok := r.staged[q.Index]; ok && !bytes.Equal(old, q.Data) {
			out.Code = "CONFLICT"
			return out, nil
		}
		r.staged[q.Index] = bytes.Clone(q.Data)
		if len(r.staged) == int(scope.Parts()) && sha256.Sum256(r.whole()) != scope.Digest {
			delete(r.staged, q.Index)
			out.Code = "DIGEST_MISMATCH"
			return out, nil
		}
		rec := imagebuild.PartReceipt{Schema: 1, Scope: scope.Hash(), Index: q.Index, Length: uint32(len(q.Data)), Digest: sha256.Sum256(q.Data)}
		rec.Signature = ed25519.Sign(sign, imagebuild.PartReceiptBytes(rec))
		out.Code, out.Part = "OK", &rec
		if q.Record {
			if !recorded {
				u, err := r.u.Put(scope.Creator, r.u.Revision, uint64(at), rec)
				if err != nil {
					return control.ImageBuildIOResult{Schema: 1, Scope: scope.Hash(), Code: "CONFLICT"}, nil
				}
				r.u = u
				w.bumpKey(control.ImageBuildKey)
				w.build.rev[scope.Tenant] = w.root
			}
			out.Recorded, out.UploadRevision = true, r.u.Revision
		}
		return out, nil
	}
	if r.u.Received != scope.Parts() {
		out.Code = "CONFLICT" // every part's receipt is recorded first
		return out, nil
	}
	files, err := unzipContext(r.whole())
	var expanded int64
	for _, f := range files {
		expanded += int64(len(f))
	}
	if _, ok := files[scope.Dockerfile]; err != nil || !ok || expanded > scope.ExpandedLimit {
		out.Code = "INVALID_ZIP"
		return out, nil
	}
	entries := contentEntries(files)
	seal := imagebuild.SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: treeDigest(entries), Entries: uint32(len(entries)), ExpandedBytes: expanded}
	seal.Signature = ed25519.Sign(sign, imagebuild.SealReceiptBytes(seal))
	r.files, r.seal = files, &seal
	out.Code, out.Seal = "OK", &seal
	return out, nil
}

func (r *realUpload) whole() []byte {
	var b bytes.Buffer
	for i := uint32(0); i < r.u.Scope.Parts(); i++ {
		b.Write(r.staged[i])
	}
	return b.Bytes()
}

// --- image-builds Part uploads / missing ---

func (w *world) uploadRows(tenant, user, upload string) []control.ImageBuildUploadView {
	w.build.real.ready()
	var rows []control.ImageBuildUploadView
	for _, k := range sortedKeys(w.build.real.uploads) {
		r := w.build.real.uploads[k]
		if s := r.u.Scope; s.Tenant == tenant && s.Creator == user && (upload == "" || s.Upload == upload) {
			rows = append(rows, control.ImageBuildUploadView{Scope: s, Revision: r.u.Revision, Received: r.u.Received, Closed: r.u.Closed, Version: r.u.Version})
		}
	}
	return rows
}

func missingCursor(tenant, upload string, rev uint64, offset uint32) string {
	root := fakeDigest("build-missing-cursor", tenant, upload, fmt.Sprint(rev))
	raw := append(append([]byte{1}, root[:]...), fmt.Sprintf("%08d", offset)...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// uploadMissing: up to 256 part indexes not yet recorded, from after.
func (w *world) uploadMissing(tenant, user, upload, after string, now uint64) (control.ImageBuildPage, Code) {
	w.build.real.ready()
	r := w.build.real.uploads[tenant+"/"+upload]
	if r == nil || r.u.Scope.Creator != user {
		return control.ImageBuildPage{}, CodeDenied
	}
	var offset uint32
	if after != "" {
		found := false
		for o := uint32(1); o <= r.u.Scope.Parts(); o++ {
			if missingCursor(tenant, upload, r.u.Revision, o) == after {
				offset, found = o, true
				break
			}
		}
		if !found {
			return control.ImageBuildPage{}, CodeConflict
		}
	}
	missing, next, err := r.u.Missing(user, now, offset, 256)
	if err != nil {
		return control.ImageBuildPage{}, CodeConflict // closed or expired
	}
	out := control.ImageBuildPage{Missing: missing, UploadRevision: r.u.Revision}
	if next < r.u.Scope.Parts() {
		out.Next = missingCursor(tenant, upload, r.u.Revision, next)
	}
	return out, ""
}
