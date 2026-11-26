// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/registryclient"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// BuildKitSourceRead delivers tentative bytes and succeeds only after the
// original owner's complete length/digest and final response/EOF checks.
type BuildKitSourceRead func(context.Context, Source, registryclient.GraphContentQuery, io.Writer) (registryclient.ContentInfo, error)

type buildKitSourceEntry struct {
	query registryclient.GraphContentQuery
	info  registryclient.ContentInfo
	raw   []byte
	file  *os.File
	ready bool
}

// The pinned SDK's session store is ReaderAt-based. Metadata stays bounded in
// memory; layers use unlinked files in the held original job directory. These
// files live only for this solve and are never a persistent source cache.
type buildKitSourceStore struct {
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	closed        bool
	closeErr      error
	source        Source
	entries       map[digest.Digest]*buildKitSourceEntry
	metadataBytes int64
	imageBytes    int64
	metadataCount int
	checked       int64
	last          time.Time
	authorize     func(context.Context) error
	read          BuildKitSourceRead
	newFile       func() (*os.File, error)
	failure       func(error)
}

var _ content.Store = (*buildKitSourceStore)(nil)

func newBuildKitSourceStore(ctx context.Context, input FrozenSource, authorize func(context.Context) error, read BuildKitSourceRead, newFile func() (*os.File, error), failure func(error)) *buildKitSourceStore {
	ctx, cancel := context.WithCancel(ctx)
	q := registryclient.GraphContentQuery{Root: input.Image, Kind: "manifest"}
	ref, _ := parseCanonical(input.Image)
	return &buildKitSourceStore{ctx: ctx, cancel: cancel, source: input.Source, authorize: authorize, read: read, newFile: newFile, failure: failure, metadataCount: 1, entries: map[digest.Digest]*buildKitSourceEntry{ref.Digest(): {query: q}}}
}

func (s *buildKitSourceStore) current(ctx context.Context, force bool) error {
	if s.closed || s.ctx.Err() != nil || ctx.Err() != nil {
		return ErrConflict
	}
	if force || s.last.IsZero() || s.checked >= 8<<20 || time.Since(s.last) >= time.Second {
		call, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(s.ctx, cancel)
		err := s.authorize(call)
		stop()
		cancel()
		if err != nil {
			s.failure(ErrSourceFetch)
			return ErrSourceFetch
		}
		s.checked, s.last = 0, time.Now()
	}
	return nil
}

type sourceContentWriter struct {
	dst     io.Writer
	hash    hash.Hash
	bytes   int64
	limit   int64
	storage bool
}

func (w *sourceContentWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.limit-w.bytes {
		return 0, ErrSourceFetch
	}
	n, err := w.dst.Write(p)
	if n > 0 {
		_, _ = w.hash.Write(p[:n])
		w.bytes += int64(n)
	}
	if err != nil || n != len(p) {
		w.storage = true
		return n, ErrStorage
	}
	return n, nil
}

func (s *buildKitSourceStore) receive(ctx context.Context, entry *buildKitSourceEntry) (failure error) {
	if entry.ready {
		return nil
	}
	if err := s.current(ctx, true); err != nil {
		return err
	}
	defer func() {
		if failure != nil {
			s.failure(failure)
		}
	}()
	var buffer bytes.Buffer
	var file *os.File
	var target io.Writer = &buffer
	limit := registryclient.MaxMetadataBytes
	if entry.info.Schema != 0 {
		limit = entry.info.Bytes
	}
	if entry.query.Kind == "layer" {
		var err error
		file, err = s.newFile()
		if err != nil {
			return ErrStorage
		}
		target = file
		defer func() {
			if failure != nil {
				if err := file.Close(); err != nil {
					s.closeErr = errors.Join(s.closeErr, err)
					failure = errors.Join(failure, ErrStorage)
				}
			}
		}()
	}
	w := &sourceContentWriter{dst: target, hash: sha256.New(), limit: limit}
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	defer cancel()
	info, err := s.read(call, s.source, entry.query, w)
	if w.storage {
		return ErrStorage
	}
	if err != nil || !info.Valid(entry.query.Selected()) || entry.info.Schema != 0 && info != entry.info || w.bytes != info.Bytes || fmt.Sprintf("sha256:%x", w.hash.Sum(nil)) != info.Digest {
		return ErrSourceFetch
	}
	if err := s.current(call, true); err != nil {
		return err
	}
	var children []registryclient.GraphContentDescriptor
	if entry.query.Kind == "manifest" {
		children, err = registryclient.GraphContentChildren(entry.query, info.MediaType, buffer.Bytes())
		if err != nil {
			return ErrSourceFetch
		}
	}
	if file == nil && int64(buffer.Len()) > (16<<20)-s.metadataBytes {
		return ErrSourceFetch
	}
	// Validate the entire addition before publishing any graph edge.
	newEntries := map[digest.Digest]*buildKitSourceEntry{}
	imageBytes, metadataCount := s.imageBytes, s.metadataCount
	for _, child := range children {
		key := digest.Digest(child.Info.Digest)
		old := s.entries[key]
		if old == nil {
			old = newEntries[key]
		}
		if old != nil {
			if old.info.Kind != child.Info.Kind || old.info.Digest != child.Info.Digest || old.info.Bytes != child.Info.Bytes || old.info.MediaType != child.Info.MediaType {
				return ErrSourceFetch
			}
			continue
		}
		if child.Info.Kind == "manifest" {
			metadataCount++
			if metadataCount > 1024 {
				return ErrSourceFetch
			}
		} else {
			if child.Info.Bytes > registryclient.MaxImageBytes-imageBytes {
				return ErrSourceFetch
			}
			imageBytes += child.Info.Bytes
		}
		newEntries[key] = &buildKitSourceEntry{query: child.Query, info: child.Info}
	}
	if len(s.entries)+len(newEntries) > registryclient.MaxLayers+1024 {
		return ErrSourceFetch
	}
	for key, child := range newEntries {
		s.entries[key] = child
	}
	s.imageBytes, s.metadataCount = imageBytes, metadataCount
	entry.info, entry.file, entry.ready = info, file, true
	if file == nil {
		entry.raw = buffer.Bytes()
		s.metadataBytes += int64(len(entry.raw))
	}
	return nil
}

func (s *buildKitSourceStore) Info(ctx context.Context, key digest.Digest) (content.Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.current(ctx, false); err != nil {
		return content.Info{}, err
	}
	entry := s.entries[key]
	if entry == nil {
		return content.Info{}, errdefs.ErrNotFound
	}
	if entry.info.Schema == 0 {
		if err := s.receive(ctx, entry); err != nil {
			return content.Info{}, err
		}
	}
	return content.Info{Digest: key, Size: entry.info.Bytes}, nil
}

func (s *buildKitSourceStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.current(ctx, false); err != nil {
		return nil, err
	}
	entry := s.entries[desc.Digest]
	if entry == nil {
		return nil, errdefs.ErrNotFound
	}
	if err := s.receive(ctx, entry); err != nil {
		return nil, err
	}
	return &buildKitSourceReader{store: s, entry: entry, ctx: ctx}, nil
}

type buildKitSourceReader struct {
	store  *buildKitSourceStore
	entry  *buildKitSourceEntry
	ctx    context.Context
	closed atomic.Bool
}

func (r *buildKitSourceReader) Size() int64  { return r.entry.info.Bytes }
func (r *buildKitSourceReader) Close() error { r.closed.Store(true); return nil }
func (r *buildKitSourceReader) ReadAt(p []byte, offset int64) (int, error) {
	s := r.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.closed.Load() || s.closed || s.ctx.Err() != nil || r.ctx.Err() != nil {
		return 0, ErrConflict
	}
	if offset < 0 {
		return 0, errdefs.ErrInvalidArgument
	}
	if err := s.current(r.ctx, offset >= r.Size()-int64(len(p))); err != nil {
		return 0, err
	}
	var reader io.ReaderAt = bytes.NewReader(r.entry.raw)
	if r.entry.file != nil {
		reader = r.entry.file
	}
	n, err := reader.ReadAt(p, offset)
	s.checked += int64(n)
	return n, err
}

func (s *buildKitSourceStore) Close() error {
	s.cancel() // interrupt original owner I/O before waiting for its mutex
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		for _, entry := range s.entries {
			clear(entry.raw)
			entry.raw = nil
			if entry.file != nil {
				s.closeErr = errors.Join(s.closeErr, entry.file.Close())
			}
		}
	}
	return s.closeErr
}

func (*buildKitSourceStore) Update(context.Context, content.Info, ...string) (content.Info, error) {
	return content.Info{}, errdefs.ErrPermissionDenied
}
func (*buildKitSourceStore) Walk(context.Context, content.WalkFunc, ...string) error {
	return errdefs.ErrPermissionDenied
}
func (*buildKitSourceStore) Delete(context.Context, digest.Digest) error {
	return errdefs.ErrPermissionDenied
}
func (*buildKitSourceStore) Status(context.Context, string) (content.Status, error) {
	return content.Status{}, errdefs.ErrPermissionDenied
}
func (*buildKitSourceStore) ListStatuses(context.Context, ...string) ([]content.Status, error) {
	return nil, errdefs.ErrPermissionDenied
}
func (*buildKitSourceStore) Abort(context.Context, string) error { return errdefs.ErrPermissionDenied }
func (*buildKitSourceStore) Writer(context.Context, ...content.WriterOpt) (content.Writer, error) {
	return nil, errdefs.ErrPermissionDenied
}
