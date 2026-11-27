// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"slices"
	"strings"

	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

// PrunePreview borrows the original Store. It neither creates a writer nor
// installs a push fence or deletes data. Metadata/blob mutexes make one local
// snapshot across repositories, aliases, publication facts and physical refs.
// User/current shared authority and native execution remain owner boundaries.
func (s *Store) PrunePreview(ctx context.Context, authority string, conditions registryclient.PruneConditions, protected []registryclient.PruneProtection) (registryclient.PrunePreview, error) {
	return s.prunePreview(ctx, authority, conditions, protected, nil)
}

// protect is a precomputed, pure shared-policy projection. It runs under the
// native snapshot locks and must perform no network/DB I/O of its own.
func (s *Store) PrunePreviewProtected(ctx context.Context, authority string, conditions registryclient.PruneConditions, protect func(registryclient.ImageMetadata) string) (registryclient.PrunePreview, error) {
	return s.prunePreview(ctx, authority, conditions, nil, protect)
}
func (s *Store) prunePreview(ctx context.Context, authority string, conditions registryclient.PruneConditions, protected []registryclient.PruneProtection, protect func(registryclient.ImageMetadata) string) (registryclient.PrunePreview, error) {
	if !conditions.Valid() {
		return registryclient.PrunePreview{}, ErrStorage
	}
	release, err := s.gate.acquire(ctx, false)
	if err != nil {
		return registryclient.PrunePreview{}, err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.Metadata == nil || s.Blobs == nil {
		return registryclient.PrunePreview{}, ErrStorage
	}
	m, b := s.Metadata, s.Blobs
	m.mu.Lock()
	defer m.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if m.enter(ctx) != nil || b.enter(ctx, false) != nil {
		return registryclient.PrunePreview{}, ErrStorage
	}
	in, err := s.pruneInventory(ctx, authority)
	if err != nil {
		return registryclient.PrunePreview{}, err
	}
	in.Protected = slices.Clone(protected)
	if protect != nil {
		seen := map[string]bool{}
		for _, image := range in.Images {
			key := image.Repository + "@" + image.Digest
			if seen[key] {
				continue
			}
			seen[key] = true
			if code := protect(image); code != "" {
				in.Protected = append(in.Protected, registryclient.PruneProtection{Repository: image.Repository, Digest: image.Digest, Code: code})
			}
		}
	}
	return registryclient.BuildPrunePreview(in, conditions)
}

// Caller holds Store/Metadata/Blobs locks. Graph decoding and unique sizes use
// the same DescribeManifest/directManifestBlobs functions as reads/deletion.
func (s *Store) pruneInventory(ctx context.Context, authority string) (registryclient.PruneInventory, error) {
	m, b := s.Metadata, s.Blobs
	in := registryclient.PruneInventory{Schema: 1, Authority: authority, UntaggedComplete: true, PhysicalComplete: true}
	repos, err := m.repositories(ctx)
	if err != nil {
		return in, err
	}
	slices.Sort(repos)
	data := map[string]oci.ManifestData{}
	var metadataBytes int
	read := func(repo, ref string) (oci.ManifestData, error) {
		key := repo + "@" + ref
		if v, ok := data[key]; ok {
			return v, nil
		}
		v, err := m.getManifest(ctx, repo, ref)
		if err != nil {
			return v, err
		}
		digest := "sha256:" + hexHash(v.Body)
		key = repo + "@" + digest
		if prior, ok := data[key]; ok {
			if prior.ContentType != v.ContentType {
				return v, ErrStorage
			}
			return prior, nil
		}
		if len(data) >= registryclient.MaxCatalogueNames || len(v.Body) > registryclient.MaxPrunePreviewBytes-metadataBytes {
			return v, &registryclient.Error{Code: "METADATA_BUDGET"}
		}
		metadataBytes += len(v.Body)
		data[key] = v
		return v, nil
	}
	meta := map[string]registryclient.ImageMetadata{}
	for _, repo := range repos {
		refs, err := m.manifestReferences(ctx, repo)
		if err != nil {
			return in, err
		}
		slices.Sort(refs)
		id, err := repoID(repo)
		if err != nil {
			return in, err
		}
		for _, ref := range refs {
			if len(in.Images) >= registryclient.MaxCatalogueNames {
				return in, &registryclient.Error{Code: "METADATA_BUDGET"}
			}
			v, err := read(repo, ref)
			if err != nil {
				return in, err
			}
			digest := "sha256:" + hexHash(v.Body)
			key := repo + "@" + digest
			image, found := meta[key]
			if !found {
				image, err = registryclient.DescribeManifest(authority, repo, digest, v.ContentType, v.Body, func(child string) (string, []byte, error) {
					childData, err := read(repo, child)
					return childData.ContentType, childData.Body, err
				})
				if err != nil {
					return in, err
				}
				meta[key] = image
			}
			image.Reference = ref
			if strings.HasPrefix(ref, "sha256:") && ref != digest {
				return in, ErrStorage
			}
			stamp, err := m.db.GetBounded(manifestPrefix+"published/"+id+"/"+ref, 1024)
			if err == nil {
				fact, err := schema.Decode[manifestPublication](stamp)
				if err != nil || fact.Schema != 1 || fact.Digest != digest || fact.At == 0 {
					return in, ErrStorage
				}
				image.UploadedAt, image.UploadedAtKnown = fact.At, true
			} else if !errors.Is(err, storage.ErrMissing) {
				return in, err
			}
			in.Images = append(in.Images, image)
		}
	}
	witnessed := map[string]bool{}
	edges := map[string]registryclient.PruneEdge{}
	for key, image := range meta {
		v := data[key]
		blobs, err := directManifestBlobs(v)
		if err != nil {
			return in, err
		}
		for _, blob := range blobs {
			if len(in.Blobs) >= 65536 {
				return in, &registryclient.Error{Code: "METADATA_BUDGET"}
			}
			association, err := blobKey(image.Repository, blob.Digest)
			actual, found := b.blobs[association]
			if err != nil || !found || actual.Size != blob.Size {
				return in, ErrStorage
			}
			witnessed[association] = true
			in.Blobs = append(in.Blobs, registryclient.PruneBlob{Repository: image.Repository, Manifest: image.Digest, Digest: blob.Digest, Size: blob.Size})
		}
		add := func(child string) {
			edges[image.Repository+"@"+image.Digest+"@"+child] = registryclient.PruneEdge{Repository: image.Repository, Parent: image.Digest, Child: child}
		}
		if types.MediaType(v.ContentType).IsIndex() {
			index, err := v1.ParseIndexManifest(strings.NewReader(string(v.Body)))
			if err != nil {
				return in, ErrStorage
			}
			for _, child := range index.Manifests {
				add(child.Digest.String())
			}
			if index.Subject != nil {
				add(index.Subject.Digest.String())
			}
		} else {
			manifest, err := v1.ParseManifest(strings.NewReader(string(v.Body)))
			if err != nil {
				return in, ErrStorage
			}
			if manifest.Subject != nil {
				add(manifest.Subject.Digest.String())
			}
		}
		if len(edges) > registryclient.MaxCatalogueNames {
			return in, &registryclient.Error{Code: "METADATA_BUDGET"}
		}
	}
	for _, edge := range edges {
		in.Edges = append(in.Edges, edge)
	}
	for association, blob := range b.blobs {
		if !witnessed[association] {
			if len(in.Blobs) >= 65536 {
				return in, &registryclient.Error{Code: "METADATA_BUDGET"}
			}
			in.Blobs = append(in.Blobs, registryclient.PruneBlob{Repository: blob.Repo, Digest: blob.Digest, Size: blob.Size})
		}
	}
	// The same core validates canonical edges, publication fields and graph/
	// physical size coherence, and owns sorting before committing its digest.
	return in, nil
}

// PruneAliasSet is the last native digest-deletion precondition. A new or
// changed tag cannot be silently swept into an older signed preview.
func (m *Metadata) pruneAliasSet(ctx context.Context, q ImageDelete) (bool, error) {
	refs, err := m.manifestReferences(ctx, q.Repository)
	if err != nil {
		return false, err
	}
	id, err := repoID(q.Repository)
	if err != nil {
		return false, err
	}
	actual := []string{}
	for _, ref := range refs {
		if strings.HasPrefix(ref, "sha256:") {
			continue
		}
		v, err := m.db.GetBounded(manifestPrefix+"ref/"+id+"/"+ref, 71)
		if err != nil {
			return false, err
		}
		if string(v) == q.ExpectedDigest {
			actual = append(actual, ref)
		}
	}
	slices.Sort(actual)
	return registryclient.PruneAliasDigest(actual) == q.Aliases, nil
}

func PruneImageDelete(operation, authority string, item registryclient.PruneItem) (ImageDelete, error) {
	if !item.Valid() {
		return ImageDelete{}, ErrStorage
	}
	q := ImageDelete{Operation: operation, Authority: authority, Repository: item.Image.Repository, Reference: item.Image.Reference, ExpectedDigest: item.Image.Digest, Item: item.ItemID()}
	if strings.HasPrefix(item.Image.Reference, "sha256:") {
		q.Aliases = registryclient.PruneAliasDigest(item.Tags)
	}
	if !q.Valid() {
		return ImageDelete{}, ErrStorage
	}
	return q, nil
}
