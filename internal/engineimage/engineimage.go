// SPDX-License-Identifier: Apache-2.0

// Package engineimage answers the engine's image requests (Seafield purpose
// 37, seafield/docs/sfcd-socket.md "이미지 원천") without the transport.
// The engine asks by repository and digest only; it carries no tenant. So
// sfcd first issues a ticket when it asks the engine to pull one pinned
// root (repository@sha256:...) for a Task or a build it has authorized. The
// ticket walks the root's graph once and records every manifest, config and
// layer in it. An engine request is answered only for an item of a live
// ticket of that repository, read through the ticket's own Opener (the local
// registry, a remote owner over SFCP, or an external source), from an
// offset so an interrupted copy can resume.
package engineimage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/distribution/reference"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// Opener reads one item of an authorized graph, starting offset bytes in.
// ContentInfo describes the whole item.
type Opener func(ctx context.Context, q registryclient.GraphContentQuery, offset int64) (registryclient.ContentInfo, io.ReadCloser, error)

var (
	// ErrRefused is a request no live ticket covers.
	ErrRefused = errors.New("no image ticket covers this repository")
	// ErrNotFound is a digest outside every ticket of the repository.
	ErrNotFound = errors.New("digest is not part of a ticketed image")
	// ErrInvalid is a malformed request or graph.
	ErrInvalid = errors.New("invalid image request")
)

const (
	maxTickets   = 256
	maxItems     = 4096
	maxDepth     = 2 // root index → image manifest; deeper nesting is refused
	maxIndexKids = 256
)

// Query is one engine request.
type Query struct {
	Op         string // "manifest" or "blob"
	Repository string // as the engine names it; docker.io/library/nginx and nginx are one repository
	Digest     string
	Offset     int64
}

// Answer describes the body that follows it.
type Answer struct {
	ContentType string
	Size        int64
}

type item struct {
	query registryclient.GraphContentQuery
	size  int64
	media string
}

type ticket struct {
	repository string
	items      map[string]item // digest → how to read it
	open       Opener
}

// Tickets is the table of live pull tickets of one node.
type Tickets struct {
	mu      sync.Mutex
	tickets map[*ticket]bool
}

func New() *Tickets { return &Tickets{tickets: map[*ticket]bool{}} }

// ClusterAppPrefix is the normalized repository prefix of cluster app
// images (sfc-cluster-app/<app>). Only IssueClusterApp keys tickets under
// it, so a tenant pull of the same name never shares a cluster app's ticket.
const ClusterAppPrefix = "docker.io/sfc-cluster-app/"

// Issue walks root (repository@sha256:...) through open and makes its
// manifests, configs and layers answerable until release is called. The
// caller has already authorized root for this pull. Cluster app names are
// refused here; they go through IssueClusterApp.
func (t *Tickets) Issue(ctx context.Context, root string, open Opener) (release func(), err error) {
	return t.issue(ctx, root, open, false)
}

// IssueClusterApp is Issue for a cluster app image sfcd verified from its
// signed bundle; root must be under ClusterAppPrefix.
func (t *Tickets) IssueClusterApp(ctx context.Context, root string, open Opener) (release func(), err error) {
	return t.issue(ctx, root, open, true)
}

func (t *Tickets) issue(ctx context.Context, root string, open Opener, clusterApp bool) (release func(), err error) {
	name, digest, ok := strings.Cut(root, "@")
	if !ok || open == nil {
		return nil, ErrInvalid
	}
	if _, _, _, err := registryclient.Normalize(root); err != nil {
		return nil, ErrInvalid
	}
	repository, ok := canonicalRepository(name)
	if !ok || strings.HasPrefix(repository, ClusterAppPrefix) != clusterApp {
		return nil, ErrInvalid
	}
	k := &ticket{repository: repository, items: map[string]item{}, open: open}
	if err := k.walk(ctx, root, nil, digest, 0); err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.tickets) >= maxTickets {
		return nil, ErrRefused
	}
	t.tickets[k] = true
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			delete(t.tickets, k)
		})
	}, nil
}

func (k *ticket) add(digest string, it item) error {
	if old, ok := k.items[digest]; ok {
		if old.size != it.size || old.query.Kind != it.query.Kind {
			return ErrInvalid
		}
		return nil
	}
	if len(k.items) >= maxItems {
		return ErrInvalid
	}
	k.items[digest] = it
	return nil
}

func (k *ticket) walk(ctx context.Context, root string, path []string, digest string, depth int) error {
	q := registryclient.GraphContentQuery{Root: root, Path: path, Kind: "manifest"}
	info, body, err := k.open(ctx, q, 0)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(body, registryclient.MaxMetadataBytes+1))
	if cerr := body.Close(); err == nil {
		err = cerr
	}
	if err != nil || int64(len(raw)) != info.Bytes || info.Digest != digest || int64(len(raw)) > registryclient.MaxMetadataBytes {
		return ErrInvalid
	}
	if err = k.add(digest, item{query: q, size: info.Bytes, media: info.MediaType}); err != nil {
		return err
	}
	media := types.MediaType(info.MediaType)
	switch {
	case media.IsIndex():
		index, err := v1.ParseIndexManifest(bytes.NewReader(raw))
		if err != nil || depth+1 >= maxDepth || len(index.Manifests) > maxIndexKids {
			return ErrInvalid
		}
		for _, child := range index.Manifests {
			if !child.MediaType.IsImage() {
				return ErrInvalid
			}
			next := append(append([]string{}, path...), child.Digest.String())
			if err := k.walk(ctx, root, next, child.Digest.String(), depth+1); err != nil {
				return err
			}
		}
	case media.IsImage():
		m, err := v1.ParseManifest(bytes.NewReader(raw))
		if err != nil {
			return ErrInvalid
		}
		blob := func(kind string, d v1.Descriptor) error {
			return k.add(d.Digest.String(), item{query: registryclient.GraphContentQuery{Root: root, Path: path, Kind: kind, Digest: d.Digest.String()}, size: d.Size, media: string(d.MediaType)})
		}
		if err = blob("config", m.Config); err != nil {
			return err
		}
		for _, l := range m.Layers {
			if err = blob("layer", l); err != nil {
				return err
			}
		}
	default:
		return ErrInvalid
	}
	return nil
}

// canonicalRepository is the full name of a repository with no tag or
// digest: the engine drops docker.io/library/ from the name it was given, so
// tickets and requests meet on the normalized form.
func canonicalRepository(name string) (string, bool) {
	named, err := reference.ParseNormalizedNamed(name)
	if err != nil || !reference.IsNameOnly(named) {
		return "", false
	}
	return named.Name(), true
}

// Serve answers one engine request. The body starts at q.Offset; the
// engine checks the digest of everything it assembled.
func (t *Tickets) Serve(ctx context.Context, q Query) (Answer, io.ReadCloser, error) {
	if q.Op != "manifest" && q.Op != "blob" || q.Repository == "" || q.Offset < 0 || !strings.HasPrefix(q.Digest, "sha256:") {
		return Answer{}, nil, ErrInvalid
	}
	repository, ok := canonicalRepository(q.Repository)
	if !ok {
		return Answer{}, nil, ErrInvalid
	}
	t.mu.Lock()
	var found *ticket
	var it item
	covered := false
	for k := range t.tickets {
		if k.repository != repository {
			continue
		}
		covered = true
		if x, ok := k.items[q.Digest]; ok && (x.query.Kind == "manifest") == (q.Op == "manifest") {
			found, it = k, x
			break
		}
	}
	t.mu.Unlock()
	if !covered {
		return Answer{}, nil, ErrRefused
	}
	if found == nil {
		return Answer{}, nil, ErrNotFound
	}
	if q.Offset > it.size {
		return Answer{}, nil, ErrInvalid
	}
	info, body, err := found.open(ctx, it.query, q.Offset)
	if err != nil {
		return Answer{}, nil, err
	}
	if info.Digest != q.Digest || info.Bytes != it.size {
		_ = body.Close()
		return Answer{}, nil, ErrInvalid
	}
	return Answer{ContentType: info.MediaType, Size: info.Bytes}, body, nil
}
