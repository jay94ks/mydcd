// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// GraphContentQuery keeps the authorized root separate from the selected
// manifest. Path contains only index-child digests, in root-to-leaf order.
// It is never a grant to read arbitrary blobs or other repositories.
type GraphContentQuery struct {
	Root         string
	Path         []string `json:",omitempty"`
	Kind, Digest string
}

func (q GraphContentQuery) Selected() ContentQuery {
	ref := q.Root
	if len(q.Path) > 0 {
		repo, _, _ := strings.Cut(ref, "@")
		ref = repo + "@" + q.Path[len(q.Path)-1]
	}
	return ContentQuery{Ref: ref, Kind: q.Kind, Digest: q.Digest}
}

func (q GraphContentQuery) Valid() bool {
	if !(ContentQuery{Ref: q.Root, Kind: "manifest"}).Valid() || len(q.Path) > 8 || !q.Selected().Valid() {
		return false
	}
	_, root, _ := strings.Cut(q.Root, "@")
	for i, digest := range q.Path {
		if !pruneDigest(digest) || digest == root || slices.Contains(q.Path[:i], digest) {
			return false
		}
	}
	return true
}

// SelectGraphContent checks every parent before reading its selected child.
// It uses bounded metadata and the same parser as ordinary immutable reads;
// no sibling manifests or layer bodies are fetched to establish membership.
// A non-nil body is returned only for a manifest request.
func SelectGraphContent(q GraphContentQuery, read ManifestReader) (ContentInfo, []byte, error) {
	if !q.Valid() || read == nil {
		return ContentInfo{}, nil, &Error{Code: "INVALID_IMAGE"}
	}
	_, authority, repo, _ := Normalize(q.Root)
	_, digest, _ := strings.Cut(q.Root, "@")
	var expected *v1.Descriptor
	for depth := 0; ; depth++ {
		media, raw, err := read(digest)
		if err != nil {
			return ContentInfo{}, nil, err
		}
		parsed, err := ResolveManifest(authority+"/"+repo+"@"+digest, media, raw)
		if err != nil {
			return ContentInfo{}, nil, err
		}
		if parsed.Digest != digest || expected != nil && (media != string(expected.MediaType) || int64(len(raw)) != expected.Size) {
			return ContentInfo{}, nil, &Error{Code: "INVALID_IMAGE"}
		}
		var children []v1.Descriptor
		if types.MediaType(media).IsIndex() {
			index, err := v1.ParseIndexManifest(bytes.NewReader(raw))
			if err != nil {
				return ContentInfo{}, nil, &Error{Code: "INVALID_IMAGE"}
			}
			children = index.Manifests
			facts := make(map[string]v1.Descriptor, len(children))
			for _, child := range children {
				if !descriptorValid(child) || child.Size <= 0 || child.Size > MaxMetadataBytes || !child.MediaType.IsImage() && !child.MediaType.IsIndex() {
					return ContentInfo{}, nil, &Error{Code: "INVALID_IMAGE"}
				}
				key := child.Digest.String()
				if previous, ok := facts[key]; ok && (previous.Size != child.Size || previous.MediaType != child.MediaType) {
					return ContentInfo{}, nil, &Error{Code: "INVALID_IMAGE"}
				}
				facts[key] = child
			}
		} else if _, err := DescribeManifest(authority, repo, digest, media, raw, nil); err != nil {
			return ContentInfo{}, nil, err
		}
		if depth == len(q.Path) {
			info, err := SelectContent(q.Selected(), media, raw)
			if err != nil {
				return ContentInfo{}, nil, err
			}
			if q.Kind != "manifest" {
				raw = nil
			}
			return info, raw, nil
		}
		expected = nil
		for _, child := range children {
			if child.Digest.String() != q.Path[depth] {
				continue
			}
			copy := child
			expected = &copy
			break
		}
		if expected == nil {
			return ContentInfo{}, nil, &Error{Code: "NOT_FOUND"}
		}
		digest = q.Path[depth]
	}
}

// Authentication stays with this exact source Access, including Basic-only
// registries. Neither credentials nor a host-wide token leave the owner.
func (a *Access) OpenGraphContent(ctx context.Context, q GraphContentQuery) (ContentInfo, io.ReadCloser, error) {
	if !q.Valid() {
		return ContentInfo{}, nil, &Error{Code: "INVALID_IMAGE"}
	}
	_, authority, repo, _ := Normalize(q.Root)
	info, raw, err := SelectGraphContent(q, func(digest string) (string, []byte, error) {
		resolved, raw, err := a.manifest(ctx, authority+"/"+repo+"@"+digest)
		return resolved.MediaType, raw, err
	})
	if err != nil {
		return ContentInfo{}, nil, err
	}
	if q.Kind == "manifest" {
		return info, io.NopCloser(bytes.NewReader(raw)), nil
	}
	return a.openSelectedContent(ctx, info)
}

// OpenGraphContentAt is OpenGraphContent from offset bytes in; ContentInfo
// still describes the whole item. A blob is read from its start and the
// first offset bytes are dropped, so the source still checks the full digest.
func (a *Access) OpenGraphContentAt(ctx context.Context, q GraphContentQuery, offset int64) (ContentInfo, io.ReadCloser, error) {
	info, body, err := a.OpenGraphContent(ctx, q)
	if err != nil {
		return info, nil, err
	}
	if offset < 0 || offset > info.Bytes {
		_ = body.Close()
		return info, nil, &Error{Code: "INVALID_IMAGE"}
	}
	if offset > 0 {
		if _, err = io.CopyN(io.Discard, body, offset); err != nil {
			_ = body.Close()
			return info, nil, Sanitize(err)
		}
	}
	return info, body, nil
}
