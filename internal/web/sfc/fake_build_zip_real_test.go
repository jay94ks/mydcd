// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

func buildZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, k := range sortedKeys(files) {
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: k, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		fw.Write(files[k])
	}
	zw.Close()
	return buf.Bytes()
}

// REQ-47 in sfcd's real shape: begin → transfer part → put receipt … →
// seal → upload-build-zip with the Fact.
func TestBuildZipRealUpload(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	blob := make([]byte, 2*imagebuild.PartBytes+100)
	r := rand.New(rand.NewPCG(1, 2))
	for i := range blob {
		blob[i] = byte(r.Uint32())
	}
	data := buildZip(t, map[string][]byte{"Dockerfile": []byte("FROM docker.io/library/busybox:1.36\nCOPY blob /blob\n"), "blob": blob})
	expires := uint64(f.now().Add(time.Hour).Unix())
	begin := func(c Conn, id string, data []byte, digest [32]byte) ResultCode {
		t.Helper()
		_, res := submit(t, c, ActionBeginBuildZipUpload, 0, control.ImageBuildUploadBegin{Tenant: "shop", Context: "worker", Upload: id, Length: int64(len(data)), Digest: digest, ExpiresAt: expires}, rootFor(t, c, ActionBeginBuildZipUpload))
		return res.Code
	}
	upload := func(id string) control.ImageBuildUploadView {
		t.Helper()
		p, err := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "uploads", Upload: id}, "")
		if err != nil || len(p.Uploads) != 1 {
			t.Fatalf("uploads %s: %+v %v", id, p.Uploads, err)
		}
		return p.Uploads[0]
	}
	contextRev := func() uint64 {
		p, _ := bob.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "contexts", ID: "worker"}, "")
		return p.Contexts[0].Revision
	}

	if c := begin(bob, "zip-bob", data, sha256.Sum256(data)); c != ResultForbidden {
		t.Fatalf("reader begin %v", c)
	}
	if c := begin(alice, "zip-1", data, sha256.Sum256(data)); c != ResultApplied {
		t.Fatalf("begin %v", c)
	}
	if c := begin(alice, "zip-1", data, sha256.Sum256(data)); c != ResultConditionFailed {
		t.Fatalf("reused id %v", c)
	}
	u := upload("zip-1")
	scope := u.Scope
	if scope.Validate() != nil || scope.Length != int64(len(data)) || scope.Parts() != 3 || u.Revision != 1 || u.Closed {
		t.Fatalf("scope %+v", u)
	}
	if p, _ := bob.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "uploads"}, ""); len(p.Uploads) != 0 {
		t.Fatalf("other creator sees the upload: %+v", p.Uploads)
	}
	before := contextRev()

	// Seal before every part is recorded: CONFLICT. A stale Expected too.
	if io, err := alice.SealBuildZIP(ctx, scope, 1); err != nil || io.Code != "CONFLICT" {
		t.Fatalf("early seal %+v %v", io, err)
	}
	if io, _ := alice.PutBuildZIPPart(ctx, scope, 2, 0, data[:imagebuild.PartBytes]); io.Code != "CONFLICT" {
		t.Fatalf("stale expected %+v", io)
	}
	rev := u.Revision
	for i := uint32(0); i < scope.Parts(); i++ {
		part := data[int(i)*imagebuild.PartBytes : min(len(data), int(i+1)*imagebuild.PartBytes)]
		io, err := alice.PutBuildZIPPart(ctx, scope, rev, i, part)
		if err != nil || io.Code != "OK" || !io.Part.Valid(scope) {
			t.Fatalf("part %d %+v %v", i, io, err)
		}
		if i == 0 {
			bad := *io.Part
			bad.Signature = append([]byte(nil), bad.Signature...)
			bad.Signature[0] ^= 1
			if _, res := submit(t, alice, ActionPutBuildZipPart, rev, control.ImageBuildUploadPart{Tenant: "shop", Upload: "zip-1", Receipt: bad}, 0); res.Code != ResultInvalid {
				t.Fatalf("forged receipt %v", res.Code)
			}
			if _, res := submit(t, bob, ActionPutBuildZipPart, rev, control.ImageBuildUploadPart{Tenant: "shop", Upload: "zip-1", Receipt: *io.Part}, 0); res.Code != ResultForbidden {
				t.Fatalf("bob part %v", res.Code)
			}
		}
		if _, res := submit(t, alice, ActionPutBuildZipPart, rev, control.ImageBuildUploadPart{Tenant: "shop", Upload: "zip-1", Receipt: *io.Part}, 0); res.Code != ResultApplied {
			t.Fatalf("put part %d %v", i, res.Code)
		}
		rev++
		if i == 0 {
			p, err := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "missing", Upload: "zip-1"}, "")
			if err != nil || len(p.Missing) != 2 || p.Missing[0] != 1 || p.UploadRevision != rev {
				t.Fatalf("missing %+v %v", p, err)
			}
		}
	}
	io, err := alice.SealBuildZIP(ctx, scope, rev)
	if err != nil || io.Code != "OK" || !io.Seal.Valid(scope) || io.Seal.Entries != 2 {
		t.Fatalf("seal %+v %v", io, err)
	}
	if _, res := submit(t, alice, ActionUploadBuildZip, rev, control.ImageBuildZIPConsume{Tenant: "shop", ID: "worker", Upload: "zip-1", Fact: *io.Seal}, 0); res.Code != ResultApplied {
		t.Fatalf("consume %v", res.Code)
	}
	if u := upload("zip-1"); !u.Closed || u.Version != imagebuild.VersionID(*io.Seal) || u.Revision != rev+1 {
		t.Fatalf("closed %+v", u)
	}
	if contextRev() != before {
		t.Fatal("consume changed the context revision")
	}
	vs, _ := bob.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "versions", ID: "worker"}, "")
	last := vs.Versions[len(vs.Versions)-1]
	if last.Number != 3 || last.ID != imagebuild.VersionID(*io.Seal) || last.Upload != "zip-1" || last.Bytes != int64(len(data)) {
		t.Fatalf("version %+v", last)
	}
	if fp, err := bob.BuildContextContent(ctx, "shop", imagebuild.ContentQuery{Version: last.ID, Part: "file", Path: "blob"}, ""); err != nil || fp.Page.File == nil || fp.Page.File.Total != uint64(len(blob)) {
		t.Fatalf("blob %+v %v", fp.Page, err)
	}

	// The last part checks the whole digest; a zip without the Dockerfile
	// fails the seal; abort closes an upload.
	small := buildZip(t, map[string][]byte{"main.go": []byte("package main\n")})
	if c := begin(alice, "zip-2", small, [32]byte{1}); c != ResultApplied {
		t.Fatalf("begin zip-2 %v", c)
	}
	if io, _ := alice.PutBuildZIPPart(ctx, upload("zip-2").Scope, 1, 0, small); io.Code != "DIGEST_MISMATCH" {
		t.Fatalf("digest %+v", io)
	}
	if c := begin(alice, "zip-3", small, sha256.Sum256(small)); c != ResultApplied {
		t.Fatalf("begin zip-3 %v", c)
	}
	s3 := upload("zip-3").Scope
	io, _ = alice.PutBuildZIPPart(ctx, s3, 1, 0, small)
	submit(t, alice, ActionPutBuildZipPart, 1, control.ImageBuildUploadPart{Tenant: "shop", Upload: "zip-3", Receipt: *io.Part}, 0)
	if io, _ := alice.SealBuildZIP(ctx, s3, 2); io.Code != "INVALID_ZIP" {
		t.Fatalf("no Dockerfile %+v", io)
	}
	if _, res := submit(t, alice, ActionAbortBuildZipUpload, 2, control.ImageBuildUploadSelection{Tenant: "shop", Upload: "zip-3"}, 0); res.Code != ResultApplied {
		t.Fatalf("abort %v", res.Code)
	}
	if !upload("zip-3").Closed {
		t.Fatal("aborted upload open")
	}
	if _, err := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "missing", Upload: "zip-3"}, ""); err == nil {
		t.Fatal("missing of a closed upload")
	}
}

// uploadZip runs the whole real-shape upload of data to worker as c and
// returns the new version's ID.
func uploadZip(t *testing.T, f *Fake, c Conn, id string, data []byte) [32]byte {
	t.Helper()
	b := control.ImageBuildUploadBegin{Tenant: "shop", Context: "worker", Upload: id, Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: uint64(f.now().Add(time.Hour).Unix())}
	if _, res := submit(t, c, ActionBeginBuildZipUpload, 0, b, rootFor(t, c, ActionBeginBuildZipUpload)); res.Code != ResultApplied {
		t.Fatalf("begin %v", res.Code)
	}
	p, _ := c.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "uploads", Upload: id}, "")
	scope, rev := p.Uploads[0].Scope, p.Uploads[0].Revision
	for i := uint32(0); i < scope.Parts(); i++ {
		io, err := c.PutBuildZIPPart(ctx, scope, rev, i, data[int(i)*imagebuild.PartBytes:min(len(data), int(i+1)*imagebuild.PartBytes)])
		if err != nil || io.Code != "OK" {
			t.Fatalf("part %d %+v %v", i, io, err)
		}
		if _, res := submit(t, c, ActionPutBuildZipPart, rev, control.ImageBuildUploadPart{Tenant: "shop", Upload: id, Receipt: *io.Part}, 0); res.Code != ResultApplied {
			t.Fatalf("put part %d %v", i, res.Code)
		}
		rev++
	}
	io, err := c.SealBuildZIP(ctx, scope, rev)
	if err != nil || io.Code != "OK" {
		t.Fatalf("seal %+v %v", io, err)
	}
	if _, res := submit(t, c, ActionUploadBuildZip, rev, control.ImageBuildZIPConsume{Tenant: "shop", ID: "worker", Upload: id, Fact: *io.Seal}, 0); res.Code != ResultApplied {
		t.Fatalf("consume %v", res.Code)
	}
	return imagebuild.VersionID(*io.Seal)
}

// 1add789: record=true confirms each part with no put-build-zip-part, so
// begin and consume are the only operations.
func TestBuildZipRecordedParts(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	blob := make([]byte, 2*imagebuild.PartBytes+100)
	r := rand.New(rand.NewPCG(3, 4))
	for i := range blob {
		blob[i] = byte(r.Uint32())
	}
	data := buildZip(t, map[string][]byte{"Dockerfile": []byte("FROM docker.io/library/busybox:1.36\nCOPY blob /blob\n"), "blob": blob})
	b := control.ImageBuildUploadBegin{Tenant: "shop", Context: "worker", Upload: "zip-r", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: uint64(f.now().Add(time.Hour).Unix())}
	if _, res := submit(t, alice, ActionBeginBuildZipUpload, 0, b, rootFor(t, alice, ActionBeginBuildZipUpload)); res.Code != ResultApplied {
		t.Fatalf("begin %v", res.Code)
	}
	p, _ := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "uploads", Upload: "zip-r"}, "")
	scope, rev := p.Uploads[0].Scope, p.Uploads[0].Revision
	part := func(i uint32) []byte {
		return data[int(i)*imagebuild.PartBytes : min(len(data), int(i+1)*imagebuild.PartBytes)]
	}
	ledger := len(f.w.ledger)

	// Without record: stage only, as before.
	if io, err := alice.PutBuildZIPPart(ctx, scope, rev, 0, part(0)); err != nil || io.Code != "OK" || io.Recorded || io.UploadRevision != 0 {
		t.Fatalf("stage only %+v %v", io, err)
	}
	if _, err := alice.PutBuildZIPPart(ctx, scope, rev, 0, part(0), true, true); err == nil {
		t.Fatal("two record arguments")
	}
	for i := uint32(0); i < scope.Parts(); i++ {
		io, err := alice.PutBuildZIPPart(ctx, scope, rev, i, part(i), true)
		proof := imagebuild.PartProof{Schema: 1, Index: i, Length: uint32(len(part(i))), Digest: sha256.Sum256(part(i)), Expected: rev, Record: true}
		q := imagebuild.Transfer{Upload: "zip-r", Kind: "part", Expected: rev, Index: i, Data: part(i), Proof: &proof, Record: true}
		if err != nil || io.Code != "OK" || !io.Recorded || io.UploadRevision != rev+1 || !io.Valid(scope, q) {
			t.Fatalf("recorded part %d %+v %v", i, io, err)
		}
		if i == 0 {
			m, _ := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "missing", Upload: "zip-r"}, "")
			if len(m.Missing) != 2 || m.Missing[0] != 1 || m.UploadRevision != rev+1 {
				t.Fatalf("missing %+v", m)
			}
		}
		rev = io.UploadRevision
	}
	// The first part's ACK again at its old Expected: the current revision.
	if io, _ := alice.PutBuildZIPPart(ctx, scope, 1, 0, part(0), true); io.Code != "OK" || !io.Recorded || io.UploadRevision != rev {
		t.Fatalf("ACK again %+v", io)
	}
	// Other bytes at a recorded slot, or a stale Expected without record: conflict.
	if io, _ := alice.PutBuildZIPPart(ctx, scope, 1, 1, part(0)[:len(part(1))], true); io.Code != "CONFLICT" {
		t.Fatalf("other bytes %+v", io)
	}
	if io, _ := alice.PutBuildZIPPart(ctx, scope, 1, 0, part(0)); io.Code != "CONFLICT" {
		t.Fatalf("stale stage-only %+v", io)
	}
	u, _ := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "uploads", Upload: "zip-r"}, "")
	if u.Uploads[0].Revision != rev || u.Uploads[0].Received != scope.Parts() {
		t.Fatalf("upload %+v", u.Uploads[0])
	}
	if len(f.w.ledger) != ledger {
		t.Fatal("a recorded part wrote an operation")
	}
	io, err := alice.SealBuildZIP(ctx, scope, rev)
	if err != nil || io.Code != "OK" || io.Recorded {
		t.Fatalf("seal %+v %v", io, err)
	}
	if _, res := submit(t, alice, ActionUploadBuildZip, rev, control.ImageBuildZIPConsume{Tenant: "shop", ID: "worker", Upload: "zip-r", Fact: *io.Seal}, 0); res.Code != ResultApplied {
		t.Fatalf("consume %v", res.Code)
	}
}

// ChunkBytes 32768 fixes 32 KiB parts for the whole upload; any other
// non-zero value is refused.
func TestBuildZip32KiBParts(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	blob := make([]byte, 3*imagebuild.PartBytes)
	r := rand.New(rand.NewPCG(5, 6))
	for i := range blob {
		blob[i] = byte(r.Uint32())
	}
	data := buildZip(t, map[string][]byte{"Dockerfile": []byte("FROM docker.io/library/busybox:1.36\nCOPY blob /blob\n"), "blob": blob})
	b := control.ImageBuildUploadBegin{Tenant: "shop", Context: "worker", Upload: "zip-odd", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: uint64(f.now().Add(time.Hour).Unix()), ChunkBytes: 4096}
	if _, res := submit(t, alice, ActionBeginBuildZipUpload, 0, b, rootFor(t, alice, ActionBeginBuildZipUpload)); res.Code != ResultInvalid {
		t.Fatalf("ChunkBytes 4096: %v", res.Code)
	}
	b.Upload, b.ChunkBytes = "zip-32", imagebuild.UploadPartBytes
	if _, res := submit(t, alice, ActionBeginBuildZipUpload, 0, b, rootFor(t, alice, ActionBeginBuildZipUpload)); res.Code != ResultApplied {
		t.Fatalf("begin %v", res.Code)
	}
	p, _ := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "uploads", Upload: "zip-32"}, "")
	scope, rev := p.Uploads[0].Scope, p.Uploads[0].Revision
	size := int(imagebuild.UploadPartBytes)
	if scope.ChunkBytes != imagebuild.UploadPartBytes || scope.Parts() != 3 {
		t.Fatalf("scope ChunkBytes %d parts %d", scope.ChunkBytes, scope.Parts())
	}
	if m, _ := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "missing", Upload: "zip-32"}, ""); len(m.Missing) != 3 {
		t.Fatalf("missing %+v", m.Missing)
	}
	// A 24 KiB first part does not fit a 32 KiB scope.
	if io, _ := alice.PutBuildZIPPart(ctx, scope, rev, 0, data[:imagebuild.PartBytes], true); io.Code == "OK" {
		t.Fatalf("24 KiB part accepted %+v", io)
	}
	for i := uint32(0); i < scope.Parts(); i++ {
		io, err := alice.PutBuildZIPPart(ctx, scope, rev, i, data[int(i)*size:min(len(data), int(i+1)*size)], true)
		if err != nil || io.Code != "OK" || !io.Recorded {
			t.Fatalf("part %d %+v %v", i, io, err)
		}
		rev = io.UploadRevision
	}
	io, err := alice.SealBuildZIP(ctx, scope, rev)
	if err != nil || io.Code != "OK" {
		t.Fatalf("seal %+v %v", io, err)
	}
	if _, res := submit(t, alice, ActionUploadBuildZip, rev, control.ImageBuildZIPConsume{Tenant: "shop", ID: "worker", Upload: "zip-32", Fact: *io.Seal}, 0); res.Code != ResultApplied {
		t.Fatalf("consume %v", res.Code)
	}
}
