// Copyright 2026 MyDC Authors. Licensed under the Apache License, Version 2.0.
package registry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A protocol adapter double only: real durability belongs to MyDC's store.
type recordedUpload struct {
	repo  string
	value Upload
	data  string
	fail  error
}

func (s *recordedUpload) Begin(_ context.Context, repo string) (Upload, error) {
	s.repo = repo
	s.value = Upload{ID: "original"}
	return s.value, s.fail
}
func (s *recordedUpload) Status(_ context.Context, repo, id string) (Upload, error) {
	if repo != s.repo || id != s.value.ID {
		return Upload{}, ErrNotFound
	}
	return s.value, s.fail
}
func (s *recordedUpload) Append(_ context.Context, repo, id string, offset, length int64, r io.Reader) (Upload, error) {
	if _, err := s.Status(context.Background(), repo, id); err != nil {
		return Upload{}, err
	}
	if offset != s.value.Offset {
		return Upload{}, ErrUploadOffset
	}
	data, err := io.ReadAll(io.LimitReader(r, 1024))
	if err != nil {
		return Upload{}, err
	}
	s.data += string(data)
	s.value.Offset += int64(len(data))
	return s.value, s.fail
}
func (s *recordedUpload) Commit(_ context.Context, repo, id, digest string) (Upload, error) {
	if _, err := s.Status(context.Background(), repo, id); err != nil {
		return Upload{}, err
	}
	if fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(s.data))) != digest {
		return Upload{}, ErrDigestMismatch
	}
	s.value.Digest = digest
	return s.value, s.fail
}
func (s *recordedUpload) Cancel(context.Context, string, string) error { return s.fail }

func TestDurableUploadHookPreservesNestedRepositoryOffsetAndOriginalURL(t *testing.T) {
	s := &recordedUpload{}
	h := New(WithUploadStore(s), Logger(log.New(io.Discard, "", 0)))
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w
	}
	base := "/v2/team/blobs/uploads/app/blobs/uploads/"
	w := call(http.MethodPost, base, "")
	if w.Code != 202 || s.repo != "team/blobs/uploads/app" {
		t.Fatal(w.Code, s.repo)
	}
	location := w.Header().Get("Location")
	if !strings.HasSuffix(location, "/original") {
		t.Fatal(location)
	}
	w = call(http.MethodPatch, location, "payload")
	if w.Code != 202 || s.value.Offset != 7 {
		t.Fatal(w.Code, s.value)
	}
	w = call(http.MethodGet, location, "")
	if w.Code != 204 || w.Header().Get("Range") != "0-6" {
		t.Fatal(w.Code, w.Header())
	}
	w = call(http.MethodPatch, "/v2/other/blobs/uploads/original", "bad")
	if w.Code != 404 || s.data != "payload" {
		t.Fatal("repository retarget", w.Code, s.data)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("payload")))
	w = call(http.MethodPut, location+"?digest="+digest, "")
	if w.Code != 201 || w.Header().Get("Location") != "/v2/team/blobs/uploads/app/blobs/"+digest {
		t.Fatal(w.Code, w.Header())
	}
}
