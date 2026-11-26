// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Handler connects every upstream storage path to this one retained store.
// The caller must wrap it in current tenant authorization and own TLS admission,
// request joining and the original Volume writer. This is not a public server.
func (s *Store) Handler(ctx context.Context, logger *log.Logger) (http.Handler, error) {
	release, err := s.gate.acquire(ctx, false)
	if err != nil {
		return nil, err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || s.closed || s.Metadata == nil || s.Blobs == nil || logger == nil {
		return nil, ErrStorage
	}
	manifests := &checkedManifests{Metadata: s.Metadata, blobs: s.Blobs}
	// Opening an old store must not publish a server over an incomplete image
	// graph. Metadata and blob recovery check their own original receipts first.
	repos, err := manifests.Repositories(ctx)
	if err != nil {
		return nil, err
	}
	for _, repo := range repos {
		refs, err := manifests.ManifestReferences(ctx, repo)
		if err != nil {
			return nil, err
		}
		for _, ref := range refs {
			if _, err := v1.NewHash(ref); err != nil {
				continue
			} // Tags alias a checked digest.
			data, err := manifests.GetManifest(ctx, repo, ref)
			if err != nil {
				return nil, err
			}
			if err = manifests.check(ctx, repo, data); err != nil {
				return nil, errors.Join(ErrStorage, err)
			}
		}
	}
	content := oci.New(oci.WithManifestStore(manifests, int64(s.Metadata.limits.ManifestBytes)), oci.WithBlobHandler(s.Blobs), oci.WithUploadStore(s.Blobs), oci.Logger(logger))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release, err := s.gate.acquire(r.Context(), false)
		if err != nil {
			registryError(w, 503, "UNAVAILABLE")
			return
		}
		defer release()
		content.ServeHTTP(w, r)
	}), nil
}

type checkedManifests struct {
	*Metadata
	blobs *Blobs
}

func (m *checkedManifests) PutManifest(ctx context.Context, repo, target, digest string, data oci.ManifestData) error {
	if len(data.Body) == 0 || len(data.Body) > m.limits.ManifestBytes {
		return oci.ErrManifestInvalid
	}
	if err := m.check(ctx, repo, data); err != nil {
		return err
	}
	// Immutable blobs/child manifests cannot disappear between validation and
	// publication: the Handler request gate excludes maintenance until the
	// metadata transaction finishes; the same original Store owns the graph.
	return m.Metadata.putManifest(ctx, repo, target, digest, data, m.blobs)
}

func descriptorHash(d v1.Descriptor) bool {
	raw, err := hex.DecodeString(d.Digest.Hex)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == d.Digest.Hex && d.Digest.Algorithm == "sha256" && d.Size >= 0 && d.MediaType != "" && len(d.URLs) == 0 && len(d.Data) == 0
}

func (m *checkedManifests) blobDescriptor(ctx context.Context, repo string, d v1.Descriptor) error {
	if !descriptorHash(d) {
		return oci.ErrManifestInvalid
	}
	size, err := m.blobs.Stat(ctx, repo, d.Digest)
	if errors.Is(err, oci.ErrNotFound) {
		return oci.ErrBlobUnknown
	}
	if err != nil {
		return err
	}
	if size != d.Size {
		return oci.ErrManifestInvalid
	}
	return nil
}

func (m *checkedManifests) childDescriptor(ctx context.Context, repo string, d v1.Descriptor) error {
	if !descriptorHash(d) || !d.MediaType.IsImage() && !d.MediaType.IsIndex() {
		return oci.ErrManifestInvalid
	}
	data, err := m.GetManifest(ctx, repo, d.Digest.String())
	if errors.Is(err, oci.ErrNotFound) || errors.Is(err, oci.ErrNameUnknown) {
		return oci.ErrBlobUnknown
	}
	if err != nil {
		return err
	}
	if int64(len(data.Body)) != d.Size || data.ContentType != string(d.MediaType) {
		return oci.ErrManifestInvalid
	}
	return nil
}

func (m *checkedManifests) check(ctx context.Context, repo string, data oci.ManifestData) error {
	media := types.MediaType(data.ContentType)
	if media.IsImage() {
		var image v1.Manifest
		if json.Unmarshal(data.Body, &image) != nil || image.SchemaVersion != 2 || image.MediaType != "" && image.MediaType != media {
			return oci.ErrManifestInvalid
		}
		if err := m.blobDescriptor(ctx, repo, image.Config); err != nil {
			return err
		}
		for _, layer := range image.Layers {
			if err := m.blobDescriptor(ctx, repo, layer); err != nil {
				return err
			}
		}
		if image.Subject != nil {
			return m.childDescriptor(ctx, repo, *image.Subject)
		}
		return nil
	}
	if media.IsIndex() {
		var index v1.IndexManifest
		if json.Unmarshal(data.Body, &index) != nil || index.SchemaVersion != 2 || index.MediaType != "" && index.MediaType != media {
			return oci.ErrManifestInvalid
		}
		for _, child := range index.Manifests {
			if err := m.childDescriptor(ctx, repo, child); err != nil {
				return err
			}
		}
		if index.Subject != nil {
			return m.childDescriptor(ctx, repo, *index.Subject)
		}
		return nil
	}
	return oci.ErrManifestInvalid
}
