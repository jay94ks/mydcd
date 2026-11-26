// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"bytes"
	"context"
	"io"

	"github.com/jay94ks/mydcd/internal/access"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Ref is an immutable manifest, not a tag or an arbitrary URL. A config/layer
// digest must be witnessed by that same manifest before opening its body.
type ContentQuery struct{ Ref, Kind, Digest string }

func (q ContentQuery) Valid() bool {
	image, err := access.PinImage(q.Ref)
	if err != nil || image.Reference != q.Ref {
		return false
	}
	if q.Kind == "manifest" {
		return q.Digest == ""
	}
	return (q.Kind == "config" || q.Kind == "layer") && pruneDigest(q.Digest)
}

type ContentInfo struct {
	Schema                       uint8
	Ref, Kind, Digest, MediaType string
	Bytes                        int64
}

func (i ContentInfo) Valid(q ContentQuery) bool {
	if !q.Valid() || i.Schema != 1 || i.Ref != q.Ref || i.Kind != q.Kind || !pruneDigest(i.Digest) || i.MediaType == "" || len(i.MediaType) > 128 || i.Bytes < 0 {
		return false
	}
	if q.Kind == "manifest" {
		image, _ := access.PinImage(q.Ref)
		return i.Digest == image.Digest && i.Bytes > 0 && i.Bytes <= MaxMetadataBytes && (types.MediaType(i.MediaType).IsImage() || types.MediaType(i.MediaType).IsIndex())
	}
	if i.Digest != q.Digest {
		return false
	}
	if q.Kind == "config" {
		return i.Bytes <= MaxMetadataBytes && (i.MediaType == string(types.OCIConfigJSON) || i.MediaType == string(types.DockerConfigJSON))
	}
	return i.Bytes <= MaxImageBytes
}

// SelectContent shares immutable manifest/descriptor parsing with catalogue
// and pull. It never lets a caller request unrelated blobs in a repository.
func SelectContent(q ContentQuery, media string, raw []byte) (ContentInfo, error) {
	out := ContentInfo{Schema: 1, Ref: q.Ref, Kind: q.Kind}
	if !q.Valid() {
		return out, &Error{Code: "INVALID_IMAGE"}
	}
	resolved, err := ResolveManifest(q.Ref, media, raw)
	if err != nil {
		return out, err
	}
	if q.Kind == "manifest" {
		out.Digest = resolved.Digest
		out.MediaType = media
		out.Bytes = int64(len(raw))
		return out, nil
	}
	if !types.MediaType(media).IsImage() {
		return out, &Error{Code: "UNSUPPORTED"}
	}
	_, authority, repo, _ := Normalize(q.Ref)
	if _, err = DescribeManifest(authority, repo, resolved.Digest, media, raw, nil); err != nil {
		return out, err
	}
	manifest, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		return out, &Error{Code: "INVALID_IMAGE"}
	}
	var selected *v1.Descriptor
	if q.Kind == "config" {
		if manifest.Config.Digest.String() == q.Digest {
			selected = &manifest.Config
		}
	} else {
		for index := range manifest.Layers {
			if manifest.Layers[index].Digest.String() == q.Digest {
				selected = &manifest.Layers[index]
				break
			}
		}
	}
	if selected == nil {
		return out, &Error{Code: "NOT_FOUND"}
	}
	out.Digest, out.MediaType, out.Bytes = selected.Digest.String(), string(selected.MediaType), selected.Size
	if !out.Valid(q) {
		return ContentInfo{}, &Error{Code: "INVALID_IMAGE"}
	}
	return out, nil
}

// OpenContent returns a constant-memory body. Callers own Close, current
// authority checks and full length/digest verification before accepting EOF.
func (a *Access) OpenContent(ctx context.Context, q ContentQuery) (ContentInfo, io.ReadCloser, error) {
	if !q.Valid() {
		return ContentInfo{}, nil, &Error{Code: "INVALID_IMAGE"}
	}
	resolved, raw, err := a.manifest(ctx, q.Ref)
	if err != nil {
		return ContentInfo{}, nil, err
	}
	info, err := SelectContent(q, resolved.MediaType, raw)
	if err != nil {
		return info, nil, err
	}
	if q.Kind == "manifest" {
		return info, io.NopCloser(bytes.NewReader(raw)), nil
	}
	return a.openSelectedContent(ctx, info)
}

// Only call after descriptor membership has been checked by SelectContent or
// SelectGraphContent. In particular this is not a repository-wide blob API.
func (a *Access) openSelectedContent(ctx context.Context, info ContentInfo) (ContentInfo, io.ReadCloser, error) {
	_, authority, repo, err := Normalize(info.Ref)
	if err != nil {
		return info, nil, err
	}
	digest, err := name.NewDigest(authority+"/"+repo+"@"+info.Digest, name.StrictValidation)
	if err != nil {
		return info, nil, &Error{Code: "INVALID_IMAGE"}
	}
	layer, err := remote.Layer(digest, a.options(ctx, v1.Platform{})...)
	if err != nil {
		return info, nil, Sanitize(err)
	}
	size, err := layer.Size()
	if err != nil {
		return info, nil, Sanitize(err)
	}
	if size != info.Bytes {
		return info, nil, &Error{Code: "INVALID_IMAGE"}
	}
	body, err := layer.Compressed()
	if err != nil {
		return info, nil, Sanitize(err)
	}
	return info, body, nil
}
