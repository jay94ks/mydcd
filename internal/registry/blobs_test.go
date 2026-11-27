// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/jay94ks/seafield/internal/storage"
)

type blobFixture struct {
	m            *Metadata
	db           *storage.DB
	b            *Blobs
	path, dbPath string
	limits       BlobLimits
}

func newBlobFixture(t *testing.T, limits BlobLimits) *blobFixture {
	t.Helper()
	m, db, dbPath := metadataFixture(t, metadataScope("alpha"), MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20})
	path := filepath.Join(t.TempDir(), "objects")
	b, err := openBlobs(context.Background(), path, m, limits)
	if err != nil {
		t.Fatal(err)
	}
	f := &blobFixture{m: m, db: db, b: b, path: path, dbPath: dbPath, limits: limits}
	t.Cleanup(func() {
		if f.b != nil {
			if e := f.b.Close(); e != nil {
				t.Error(e)
			}
		}
	})
	return f
}
func smallBlobLimits() BlobLimits { return BlobLimits{BlobBytes: 1024, TotalBytes: 4096, Records: 64} }
func (f *blobFixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := openBlobs(context.Background(), f.path, f.m, f.limits)
	if err != nil {
		t.Fatal(err)
	}
	f.b = b
}
func blobDigest(data []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(data)) }
func appendFixtureBlob(t *testing.T, f *blobFixture, repo string, data []byte) oci.Upload {
	t.Helper()
	ctx := context.Background()
	u, err := f.b.Begin(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	u, err = f.b.Append(ctx, repo, u.ID, 0, int64(len(data)), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func readFixtureBlob(t *testing.T, b *Blobs, repo, digest string) []byte {
	t.Helper()
	h, err := v1.NewHash(digest)
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.Get(context.Background(), repo, h)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	closed := r.Close()
	if err != nil || closed != nil {
		t.Fatal(err, closed)
	}
	return data
}

func TestRegistryUploadLostAcknowledgmentUsesOriginalOffsetAndRepository(t *testing.T) {
	f := newBlobFixture(t, smallBlobLimits())
	ctx := context.Background()
	data := []byte("original-layer")
	u := appendFixtureBlob(t, f, "team/app", data)
	// Drop the response after the real synced offset write, then reopen files
	// using the same DB. This is a cut-point test, not a real network loss.
	f.reopen(t)
	status, err := f.b.Status(ctx, "team/app", u.ID)
	if err != nil || status.ID != u.ID || status.Offset != int64(len(data)) {
		t.Fatal(status, err)
	}
	if _, err = f.b.Append(ctx, "team/app", u.ID, 0, int64(len(data)), bytes.NewReader(data)); !errors.Is(err, oci.ErrUploadOffset) {
		t.Fatal("duplicate chunk replayed", err)
	}
	if _, err = f.b.Status(ctx, "other", u.ID); !errors.Is(err, oci.ErrNotFound) {
		t.Fatal("other repo adopted ID", err)
	}
	digest := blobDigest(data)
	done, err := f.b.Commit(ctx, "team/app", u.ID, digest)
	if err != nil || done.Digest != digest {
		t.Fatal(done, err)
	}
	f.reopen(t)
	same, err := f.b.Commit(ctx, "team/app", u.ID, digest)
	if err != nil || same != done {
		t.Fatal("original completion lost", same, err)
	}
	if !bytes.Equal(readFixtureBlob(t, f.b, "team/app", digest), data) {
		t.Fatal("original bytes lost")
	}
	h, _ := v1.NewHash(digest)
	if _, err = f.b.Get(ctx, "other", h); !errors.Is(err, oci.ErrNotFound) {
		t.Fatal("implicit cross-repository mount", err)
	}
	second := appendFixtureBlob(t, f, "other", data)
	if _, err = f.b.Commit(ctx, "other", second.ID, digest); err != nil {
		t.Fatal(err)
	}
	if f.b.used != int64(len(data)) {
		t.Fatal("same registry physical dedup counted twice", f.b.used)
	}
	if _, err = f.b.Append(ctx, "team/app", u.ID, done.Offset, 1, strings.NewReader("x")); !errors.Is(err, oci.ErrUploadOffset) {
		t.Fatal("completed ID reopened", err)
	}
}

func TestRegistryUploadPublicationRecoversBeforeAndAfterOriginalRename(t *testing.T) {
	for _, renamed := range []bool{false, true} {
		t.Run(fmt.Sprint(renamed), func(t *testing.T) {
			f := newBlobFixture(t, smallBlobLimits())
			ctx := context.Background()
			data := []byte("sealed-layer")
			u := appendFixtureBlob(t, f, "app", data)
			digest := blobDigest(data)
			original := f.b.uploads[u.ID]
			original.Phase = "publishing"
			original.Digest = digest
			if err := f.b.Close(); err != nil {
				t.Fatal(err)
			}
			// Inject the exact durable cut point. Recovery executes the same real
			// publication function used by Commit, rather than a mock algorithm.
			raw, _ := json.Marshal(original)
			if err := f.db.Write(map[string][]byte{uploadPrefix + u.ID: raw}); err != nil {
				t.Fatal(err)
			}
			if renamed {
				path, _ := blobPath(digest)
				if err := os.Rename(filepath.Join(f.path, "uploads", u.ID), filepath.Join(f.path, path)); err != nil {
					t.Fatal(err)
				}
			}
			f.reopen(t)
			v, err := f.b.Status(ctx, "app", u.ID)
			if err != nil || v.Digest != digest || len(f.b.uploads) != 1 {
				t.Fatal("original finalize not settled", v, err)
			}
			if !bytes.Equal(readFixtureBlob(t, f.b, "app", digest), data) {
				t.Fatal("recovered wrong bytes")
			}
		})
	}
}

type closeDBReader struct {
	io.Reader
	close func()
	done  bool
}

func (r *closeDBReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if !r.done {
		r.close()
		r.done = true
	}
	return n, err
}

func TestRegistryUploadUncertainOffsetWriteTruncatesOnlyUnacknowledgedTail(t *testing.T) {
	f := newBlobFixture(t, smallBlobLimits())
	ctx := context.Background()
	u, err := f.b.Begin(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	r := &closeDBReader{Reader: strings.NewReader("not-acknowledged"), close: func() {
		if e := f.db.Close(); e != nil {
			t.Fatal(e)
		}
	}}
	if _, err = f.b.Append(ctx, "app", u.ID, 0, -1, r); err == nil {
		t.Fatal("failed sync acknowledged")
	}
	if _, err = f.b.Status(ctx, "app", u.ID); err == nil {
		t.Fatal("uncertain owner returned positive view")
	}
	if err = f.b.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	m, err := OpenMetadata(db, f.m.scope, f.m.limits)
	if err != nil {
		t.Fatal(err)
	}
	f.db, f.m = db, m
	f.reopen(t)
	status, err := f.b.Status(ctx, "app", u.ID)
	st, e := os.Stat(filepath.Join(f.path, "uploads", u.ID))
	if err != nil || status.Offset != 0 || e != nil || st.Size() != 0 || f.b.used != 0 {
		t.Fatal("unacknowledged tail became committed", status, err, e)
	}
	if _, err = f.b.Append(ctx, "app", u.ID, 0, 3, strings.NewReader("ack")); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	status, err = f.b.Status(ctx, "app", u.ID)
	if err != nil || status.Offset != 3 {
		t.Fatal("acknowledged bytes lost", status, err)
	}
}

func TestRegistryUploadIncompleteBodyQuotaAndDigestFailurePreserveOriginal(t *testing.T) {
	f := newBlobFixture(t, BlobLimits{BlobBytes: 8, TotalBytes: 8, Records: 64})
	ctx := context.Background()
	u, err := f.b.Begin(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		body   string
		length int64
	}{{"short", 6}, {"123456789", -1}} {
		if _, err = f.b.Append(ctx, "app", u.ID, 0, input.length, strings.NewReader(input.body)); err == nil {
			t.Fatal("invalid chunk accepted")
		}
		status, e := f.b.Status(ctx, "app", u.ID)
		st, se := os.Stat(filepath.Join(f.path, "uploads", u.ID))
		if e != nil || status.Offset != 0 || se != nil || st.Size() != 0 {
			t.Fatal("invalid chunk advanced offset", status, e, se)
		}
	}
	if _, err = f.b.Append(ctx, "app", u.ID, 0, 8, strings.NewReader("12345678")); err != nil {
		t.Fatal(err)
	}
	if _, err = f.b.Commit(ctx, "app", u.ID, blobDigest([]byte("wrong"))); !errors.Is(err, oci.ErrDigestMismatch) {
		t.Fatal(err)
	}
	status, err := f.b.Status(ctx, "app", u.ID)
	if err != nil || status.Digest != "" || status.Offset != 8 {
		t.Fatal("digest rejection changed original", status, err)
	}
	if err = f.b.Cancel(ctx, "app", u.ID); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	if err = f.b.Cancel(ctx, "app", u.ID); err != nil || f.b.used != 0 {
		t.Fatal("cancel receipt not reusable", err, f.b.used)
	}
	if _, err = f.b.Status(ctx, "app", u.ID); !errors.Is(err, oci.ErrNotFound) {
		t.Fatal("canceled upload is active", err)
	}
	if f.b.uploads[u.ID].Phase != "canceled" {
		t.Fatal("original cancellation floor lost")
	}
}

func TestRegistryBlobReaderMustCloseBeforeRootWriterCanReturn(t *testing.T) {
	f := newBlobFixture(t, smallBlobLimits())
	ctx := context.Background()
	data := []byte("open-reader")
	u := appendFixtureBlob(t, f, "app", data)
	digest := blobDigest(data)
	if _, err := f.b.Commit(ctx, "app", u.ID, digest); err != nil {
		t.Fatal(err)
	}
	h, _ := v1.NewHash(digest)
	r, err := f.b.Get(ctx, "app", h)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = f.b.Close(); !errors.Is(err, ErrReaders) {
		t.Fatal("returned root while reader live", err)
	}
	if _, err = f.b.Begin(ctx, "app"); err == nil {
		t.Fatal("new upload admitted while draining")
	}
	if _, err = openBlobs(ctx, f.path, f.m, f.limits); err == nil {
		t.Fatal("second owner acquired open reader root")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.b.Close(); err != nil {
		t.Fatal("joined reader did not settle", err)
	}
	f.reopen(t)
	if !bytes.Equal(readFixtureBlob(t, f.b, "app", digest), data) {
		t.Fatal("close deleted retained data")
	}
}

func TestRegistryStoredHTTPChunkAndMonolithicUploadUseSameDurableStore(t *testing.T) {
	f := newBlobFixture(t, smallBlobLimits())
	h := oci.New(oci.WithBlobHandler(f.b), oci.WithUploadStore(f.b), oci.WithManifestStore(f.m, 4096), oci.Logger(log.New(io.Discard, "", 0)))
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w
	}
	base := "/v2/team/app/blobs/uploads/"
	w := call(http.MethodPost, base, "")
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	count := len(f.b.uploads)
	w = call(http.MethodPost, location, "wrong-existing-URL")
	if w.Code != http.StatusMethodNotAllowed || len(f.b.uploads) != count {
		t.Fatal("existing URL POST created replacement upload", w.Code)
	}
	w = call(http.MethodPatch, location, "chunked")
	if w.Code != 202 {
		t.Fatal(w.Code)
	}
	digest := blobDigest([]byte("chunked"))
	w = call(http.MethodPut, location+"?digest="+digest, "")
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call(http.MethodGet, "/v2/team/app/blobs/"+digest, "")
	if w.Code != 200 || w.Body.String() != "chunked" {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call(http.MethodGet, "https://registry.example/v2/team/app/blobs/"+digest, "")
	if w.Code != 200 || w.Body.String() != "chunked" {
		t.Fatal("authority changed repository identity", w.Code)
	}
	digest = blobDigest([]byte("monolithic"))
	w = call(http.MethodPost, base+"?digest="+digest, "monolithic")
	if w.Code != 201 || w.Header().Get("Docker-Content-Digest") != digest {
		t.Fatal(w.Code, w.Body.String())
	}
	f.reopen(t)
	if !bytes.Equal(readFixtureBlob(t, f.b, "team/app", digest), []byte("monolithic")) {
		t.Fatal("monolithic bytes only in memory")
	}
}
