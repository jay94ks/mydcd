// Copyright 2026 MyDC Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0

package registry

import (
	"context"
	"errors"
	"io"
	"net/http"
)

// ManifestData is the original manifest body and media type, not a parsed or
// re-encoded document. Digest and tag must be published in one durable write.
type ManifestData struct {
	ContentType string
	Body        []byte
}

type ManifestStore interface {
	GetManifest(context.Context, string, string) (ManifestData, error)
	PutManifest(ctx context.Context, repo, target, digest string, data ManifestData) error
	DeleteManifest(context.Context, string, string) error
	ManifestReferences(context.Context, string) ([]string, error)
	Repositories(context.Context) ([]string, error)
}

// Upload describes the original durable upload, including a completed receipt.
// Stores serialize Append/Commit/Cancel for an ID and bind every ID to repo.
type Upload struct {
	ID     string
	Offset int64
	Digest string
}

type UploadStore interface {
	Begin(context.Context, string) (Upload, error)
	Status(ctx context.Context, repo, id string) (Upload, error)
	// Append requires the current offset. A failed/incomplete body must not
	// advance it. length=-1 means an unknown body length, never unbounded RAM.
	Append(ctx context.Context, repo, id string, offset, length int64, body io.Reader) (Upload, error)
	Commit(ctx context.Context, repo, id, digest string) (Upload, error)
	Cancel(ctx context.Context, repo, id string) error
}

var (
	ErrReadOnly        = errors.New("registry deletion disabled")
	ErrNameUnknown     = errors.New("unknown repository")
	ErrUploadOffset    = errors.New("upload offset mismatch")
	ErrDigestMismatch  = errors.New("digest does not match content")
	ErrManifestInvalid = errors.New("invalid manifest descriptor")
	ErrBlobUnknown     = errors.New("manifest blob is not available in this repository")
)

// WithManifestStore replaces all manifest/tag/catalog/referrer map authority.
// Storage errors must not be acknowledged as successful in-memory mutations.
func WithManifestStore(s ManifestStore, maxBody int64) Option {
	return func(r *registry) { r.manifests.store = s; r.manifests.maxBody = maxBody }
}

// WithUploadStore replaces the in-memory chunk map with streaming storage.
func WithUploadStore(s UploadStore) Option {
	return func(r *registry) { r.blobs.uploadStore = s }
}

func manifestStoreError(err error) *regError {
	if errors.Is(err, ErrManifestInvalid) {
		return &regError{Status: http.StatusBadRequest, Code: "MANIFEST_INVALID", Message: "Invalid manifest descriptor"}
	}
	if errors.Is(err, ErrBlobUnknown) {
		return &regError{Status: http.StatusBadRequest, Code: "MANIFEST_BLOB_UNKNOWN", Message: "Referenced content is not available in this repository"}
	}
	if errors.Is(err, ErrReadOnly) {
		return regErrUnsupported
	}
	if errors.Is(err, ErrNameUnknown) {
		return &regError{Status: http.StatusNotFound, Code: "NAME_UNKNOWN", Message: "Unknown name"}
	}
	if errors.Is(err, ErrNotFound) {
		return &regError{Status: http.StatusNotFound, Code: "MANIFEST_UNKNOWN", Message: "Unknown manifest"}
	}
	return regErrInternal(err)
}

// Callers hold the existing manifest lock, including the default map path.
func (m *manifests) readManifest(ctx context.Context, repo, target string) (manifest, error) {
	if m.store != nil {
		v, err := m.store.GetManifest(ctx, repo, target)
		return manifest{contentType: v.ContentType, blob: v.Body}, err
	}
	r, ok := m.manifests[repo]
	if !ok {
		return manifest{}, ErrNameUnknown
	}
	v, ok := r[target]
	if !ok {
		return manifest{}, ErrNotFound
	}
	return v, nil
}
func (m *manifests) writeManifest(ctx context.Context, repo, target, digest string, v manifest) error {
	if m.store != nil {
		return m.store.PutManifest(ctx, repo, target, digest, ManifestData{ContentType: v.contentType, Body: v.blob})
	}
	if m.manifests[repo] == nil {
		m.manifests[repo] = map[string]manifest{}
	}
	m.manifests[repo][digest], m.manifests[repo][target] = v, v
	return nil
}
func (m *manifests) deleteManifest(ctx context.Context, repo, target string) error {
	if m.store != nil {
		return m.store.DeleteManifest(ctx, repo, target)
	}
	if _, err := m.readManifest(ctx, repo, target); err != nil {
		return err
	}
	delete(m.manifests[repo], target)
	return nil
}
func (m *manifests) manifestReferences(ctx context.Context, repo string) ([]string, error) {
	if m.store != nil {
		return m.store.ManifestReferences(ctx, repo)
	}
	r, ok := m.manifests[repo]
	if !ok {
		return nil, ErrNameUnknown
	}
	refs := make([]string, 0, len(r))
	for k := range r {
		refs = append(refs, k)
	}
	return refs, nil
}
func (m *manifests) repositories(ctx context.Context) ([]string, error) {
	if m.store != nil {
		return m.store.Repositories(ctx)
	}
	repos := make([]string, 0, len(m.manifests))
	for k := range m.manifests {
		repos = append(repos, k)
	}
	return repos, nil
}
