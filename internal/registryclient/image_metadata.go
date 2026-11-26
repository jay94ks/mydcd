// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"bytes"
	"encoding/hex"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type ManifestReader func(digest string) (media string, body []byte, err error)

// DescribeManifest shares the same strict parser with image-resolve and sums
// unique config/layer blobs across an OCI index. Compressed descriptor sizes
// are logical image bytes, not filesystem blocks or guaranteed GC recovery.
func DescribeManifest(authority, repository, target, media string, body []byte, read ManifestReader) (ImageMetadata, error) {
	ref := authority + "/" + repository + ":" + target
	if strings.HasPrefix(target, "sha256:") {
		ref = authority + "/" + repository + "@" + target
	}
	root, err := ResolveManifest(ref, media, body)
	if err != nil {
		return ImageMetadata{}, err
	}
	blobs := map[string]int64{}
	visited := map[string]bool{}
	facts := map[string]struct {
		Media string
		Size  int64
	}{}
	var total, metadataBytes int64
	add := func(d v1.Descriptor) error {
		if !descriptorValid(d) {
			return &Error{Code: "INVALID_IMAGE"}
		}
		if size, known := blobs[d.Digest.String()]; known {
			if size != d.Size {
				return &Error{Code: "INVALID_IMAGE"}
			}
			return nil
		}
		if len(blobs) >= MaxLayers+128 || d.Size > MaxImageBytes-total {
			return &Error{Code: "IMAGE_BUDGET"}
		}
		blobs[d.Digest.String()] = d.Size
		total += d.Size
		return nil
	}
	var walk func(string, string, []byte, int) error
	walk = func(digest, media string, body []byte, depth int) error {
		if depth > 8 || len(visited) >= 1024 || int64(len(body)) > (16<<20)-metadataBytes {
			return &Error{Code: "METADATA_BUDGET"}
		}
		if visited[digest] {
			return nil
		}
		parsed, e := ResolveManifest(authority+"/"+repository+"@"+digest, media, body)
		if e != nil {
			return e
		}
		if parsed.Digest != digest {
			return &Error{Code: "INVALID_IMAGE"}
		}
		visited[digest] = true
		facts[digest] = struct {
			Media string
			Size  int64
		}{media, int64(len(body))}
		metadataBytes += int64(len(body))
		if types.MediaType(media).IsImage() {
			manifest, e := v1.ParseManifest(bytes.NewReader(body))
			if e != nil {
				return &Error{Code: "INVALID_IMAGE"}
			}
			if e = add(manifest.Config); e != nil {
				return e
			}
			for _, layer := range manifest.Layers {
				if e = add(layer); e != nil {
					return e
				}
			}
			return nil
		}
		if read == nil {
			return &Error{Code: "UNSUPPORTED"}
		}
		index, e := v1.ParseIndexManifest(bytes.NewReader(body))
		if e != nil {
			return &Error{Code: "INVALID_IMAGE"}
		}
		for _, child := range index.Manifests {
			if !descriptorValid(child) {
				return &Error{Code: "INVALID_IMAGE"}
			}
			if fact, known := facts[child.Digest.String()]; known {
				if fact.Media != string(child.MediaType) || fact.Size != child.Size {
					return &Error{Code: "INVALID_IMAGE"}
				}
				continue
			}
			mt, raw, e := read(child.Digest.String())
			if e != nil {
				return e
			}
			if mt != string(child.MediaType) || int64(len(raw)) != child.Size {
				return &Error{Code: "INVALID_IMAGE"}
			}
			if e = walk(child.Digest.String(), mt, raw, depth+1); e != nil {
				return e
			}
		}
		return nil
	}
	if err = walk(root.Digest, media, body, 0); err != nil {
		return ImageMetadata{}, err
	}
	result := ImageMetadata{Repository: repository, Reference: target, Digest: root.Digest, MediaType: media, ManifestBytes: root.ManifestBytes, ImageBytes: total}
	if !result.Valid() {
		return ImageMetadata{}, &Error{Code: "INVALID_IMAGE"}
	}
	return result, nil
}
func descriptorValid(d v1.Descriptor) bool {
	raw, err := hex.DecodeString(d.Digest.Hex)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == d.Digest.Hex && d.Digest.Algorithm == "sha256" && len(d.Digest.Hex) == 64 && d.Size >= 0 && len(d.URLs) == 0 && len(d.Data) == 0 && d.MediaType != ""
}
