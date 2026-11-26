// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"bytes"
	"context"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// PruneInventory uses the same credential-bound SDK enumeration as Catalogue.
// OCI has no snapshot/untagged enumeration or authoritative upload timestamps.
// Children witnessed through an index/subject are included only to preserve
// dependencies; their discovery does not make untagged enumeration complete.
func (a *Access) PruneInventory(ctx context.Context, conditions PruneConditions, allow func(string) bool, protect func(ImageMetadata) string) (PruneInventory, error) {
	in := PruneInventory{Schema: 1, Authority: a.authority, Live: true}
	if !conditions.Valid() || allow == nil {
		return in, &Error{Code: "INVALID_IMAGE"}
	}
	if conditions.IncludeUntagged {
		return in, &Error{Code: "UNSUPPORTED"}
	}
	repos := slices.Clone(conditions.Repositories)
	if len(repos) == 0 {
		var err error
		repos, err = a.catalogueNames(ctx, "", allow)
		if err != nil {
			return in, err
		}
	}
	slices.Sort(repos)
	if _, _, err := CatalogueRange(a.authority, "", [32]byte{1}, repos, nil, ""); err != nil {
		return in, err
	}
	type manifest struct {
		media string
		body  []byte
	}
	data := map[string]manifest{}
	metadataBytes := 0
	for _, repo := range repos {
		if !allow(repo) {
			return in, &Error{Code: "DENIED"}
		}
		tags, err := a.catalogueNames(ctx, repo, allow)
		if err != nil {
			return in, err
		}
		if _, _, err = CatalogueRange(a.authority, repo, [32]byte{1}, tags, nil, ""); err != nil {
			return in, err
		}
		refs := map[string]string{}
		var read func(string) (manifest, error)
		read = func(ref string) (manifest, error) {
			if pinned, ok := refs[ref]; ok {
				return data[repo+"@"+pinned], nil
			}
			rawRef := a.authority + "/" + repo + ":" + ref
			if strings.HasPrefix(ref, "sha256:") {
				rawRef = a.authority + "/" + repo + "@" + ref
			}
			resolved, raw, err := a.manifest(ctx, rawRef)
			if err != nil {
				return manifest{}, err
			}
			key := repo + "@" + resolved.Digest
			if prior, ok := data[key]; ok {
				if prior.media != resolved.MediaType || !bytes.Equal(prior.body, raw) {
					return manifest{}, &Error{Code: "INVALID_IMAGE"}
				}
				refs[ref] = resolved.Digest
				return prior, nil
			}
			if len(data) >= MaxCatalogueNames || len(raw) > MaxPrunePreviewBytes-metadataBytes {
				return manifest{}, &Error{Code: "METADATA_BUDGET"}
			}
			metadataBytes += len(raw)
			row := manifest{resolved.MediaType, raw}
			data[key] = row
			refs[ref], refs[resolved.Digest] = resolved.Digest, resolved.Digest
			return row, nil
		}
		metadata := map[string]ImageMetadata{}
		var queue []string
		add := func(ref string) (ImageMetadata, error) {
			m, err := read(ref)
			if err != nil {
				return ImageMetadata{}, err
			}
			image, err := DescribeManifest(a.authority, repo, ref, m.media, m.body, func(child string) (string, []byte, error) { m, err := read(child); return m.media, m.body, err })
			if err != nil {
				return image, err
			}
			if _, ok := metadata[image.Digest]; !ok {
				metadata[image.Digest] = image
				queue = append(queue, image.Digest)
			}
			if len(in.Images) >= MaxCatalogueNames {
				return image, &Error{Code: "METADATA_BUDGET"}
			}
			in.Images = append(in.Images, image)
			return image, nil
		}
		for _, tag := range tags {
			if _, err = add(tag); err != nil {
				return in, err
			}
		}
		for offset := 0; offset < len(queue); offset++ {
			digest := queue[offset]
			m := data[repo+"@"+digest]
			var children []string
			if types.MediaType(m.media).IsIndex() {
				index, err := v1.ParseIndexManifest(bytes.NewReader(m.body))
				if err != nil {
					return in, &Error{Code: "INVALID_IMAGE"}
				}
				for _, child := range index.Manifests {
					children = append(children, child.Digest.String())
				}
				if index.Subject != nil {
					children = append(children, index.Subject.Digest.String())
				}
			} else {
				image, err := v1.ParseManifest(bytes.NewReader(m.body))
				if err != nil {
					return in, &Error{Code: "INVALID_IMAGE"}
				}
				if image.Subject != nil {
					children = append(children, image.Subject.Digest.String())
				}
			}
			slices.Sort(children)
			children = slices.Compact(children)
			for _, child := range children {
				if _, ok := metadata[child]; !ok {
					if _, err = add(child); err != nil {
						return in, err
					}
				}
				if len(in.Edges) >= MaxCatalogueNames {
					return in, &Error{Code: "METADATA_BUDGET"}
				}
				in.Edges = append(in.Edges, PruneEdge{Repository: repo, Parent: digest, Child: child})
			}
		}
		if protect != nil {
			for _, image := range metadata {
				if code := protect(image); code != "" {
					in.Protected = append(in.Protected, PruneProtection{Repository: repo, Digest: image.Digest, Code: code})
				}
			}
		}
	}
	return in.canonical()
}

// External OCI cannot make list+DELETE atomic. This last read refuses observed
// alias changes; Live remains true and never promises remote transaction CAS.
func (a *Access) CheckPruneAliases(ctx context.Context, item PruneItem) (bool, error) {
	if !item.Valid() || !strings.HasPrefix(item.Image.Reference, "sha256:") {
		return false, &Error{Code: "UNSUPPORTED"}
	}
	repo := item.Image.Repository
	tags, err := a.catalogueNames(ctx, repo, func(value string) bool { return value == repo })
	if err != nil {
		return false, err
	}
	if _, _, err = CatalogueRange(a.authority, repo, [32]byte{1}, tags, nil, ""); err != nil {
		return false, err
	}
	aliases := []string{}
	metadataBytes := 0
	for _, tag := range tags {
		resolved, raw, cause := a.manifest(ctx, a.authority+"/"+repo+":"+tag)
		if cause != nil {
			return false, cause
		}
		if len(raw) > MaxPrunePreviewBytes-metadataBytes {
			return false, &Error{Code: "METADATA_BUDGET"}
		}
		metadataBytes += len(raw)
		if resolved.Digest == item.Image.Digest {
			aliases = append(aliases, tag)
		}
	}
	return PruneAliasDigest(aliases) == PruneAliasDigest(item.Tags), nil
}
