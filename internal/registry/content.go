// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"io"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

// The original Store gate/reader remains borrowed until the caller's real
// Close. No second writer, credential or native Volume owner is introduced.
func (s *Store) OpenContent(ctx context.Context, q registryclient.ContentQuery) (registryclient.ContentInfo, io.ReadCloser, error) {
	if !q.Valid() {
		return registryclient.ContentInfo{}, nil, ErrStorage
	}
	return s.OpenGraphContent(ctx, registryclient.GraphContentQuery{Root: q.Ref, Kind: q.Kind, Digest: q.Digest})
}

// The complete index walk and the returned body share one Store gate hold.
// No child manifest can be selected without its original root's descriptors.
func (s *Store) OpenGraphContent(ctx context.Context, q registryclient.GraphContentQuery) (registryclient.ContentInfo, io.ReadCloser, error) {
	if !q.Valid() {
		return registryclient.ContentInfo{}, nil, ErrStorage
	}
	release, err := s.gate.acquire(ctx, false)
	if err != nil {
		return registryclient.ContentInfo{}, nil, err
	}
	fail := func(err error) (registryclient.ContentInfo, io.ReadCloser, error) {
		release()
		return registryclient.ContentInfo{}, nil, err
	}
	s.mu.Lock()
	if s.closed || s.Metadata == nil || s.Blobs == nil {
		s.mu.Unlock()
		return fail(ErrStorage)
	}
	metadata, blobs := s.Metadata, s.Blobs
	s.mu.Unlock()
	_, _, repo, err := registryclient.Normalize(q.Root)
	if err != nil {
		return fail(err)
	}
	info, raw, err := registryclient.SelectGraphContent(q, func(digest string) (string, []byte, error) {
		manifest, err := metadata.GetManifest(ctx, repo, digest)
		return manifest.ContentType, manifest.Body, err
	})
	if err != nil {
		return fail(err)
	}
	var body io.ReadCloser
	if q.Kind == "manifest" {
		body = io.NopCloser(bytes.NewReader(raw))
	} else {
		hash, cause := v1.NewHash(info.Digest)
		if cause != nil {
			return fail(cause)
		}
		body, err = blobs.Get(ctx, repo, hash)
		if err != nil {
			return fail(err)
		}
	}
	return info, &contentReader{ReadCloser: body, release: release}, nil
}

type contentReader struct {
	io.ReadCloser
	release func()
	once    sync.Once
	err     error
}

func (r *contentReader) Close() error {
	r.once.Do(func() { r.err = r.ReadCloser.Close(); r.release() })
	return r.err
}
