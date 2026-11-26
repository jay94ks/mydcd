// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// ResolveManifest is shared by authenticated OCI I/O and the installed managed
// registry's existing metadata store. It never exposes raw manifest/config data.
func ResolveManifest(raw, media string, body []byte) (Resolution, error) {
	normalized, authority, repository, err := Normalize(raw)
	if err != nil {
		return Resolution{}, err
	}
	if len(body) == 0 || int64(len(body)) > MaxMetadataBytes {
		return Resolution{}, &Error{Code: "METADATA_BUDGET"}
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	result := Resolution{Normalized: normalized, Registry: authority, Repository: repository, Pinned: authority + "/" + repository + "@" + digest, Digest: digest, MediaType: media, ManifestBytes: int64(len(body))}
	mt := types.MediaType(media)
	if mt.IsIndex() {
		index, err := v1.ParseIndexManifest(bytes.NewReader(body))
		if err != nil || index.SchemaVersion != 2 || index.MediaType != "" && index.MediaType != mt {
			return Resolution{}, &Error{Code: "INVALID_IMAGE"}
		}
		if len(index.Manifests) > 128 {
			return Resolution{}, &Error{Code: "METADATA_BUDGET"}
		}
		for _, child := range index.Manifests {
			if child.Size < 0 || child.Size > MaxMetadataBytes {
				return Resolution{}, &Error{Code: "METADATA_BUDGET"}
			}
			result.Platforms = append(result.Platforms, PlatformDigest{Digest: child.Digest.String(), Platform: child.Platform})
		}
	} else if mt.IsImage() {
		manifest, err := v1.ParseManifest(bytes.NewReader(body))
		if err != nil || manifest.SchemaVersion != 2 || manifest.MediaType != "" && manifest.MediaType != mt || manifest.Config.Digest.Algorithm != "sha256" || len(manifest.Config.Digest.Hex) != 64 || manifest.Config.Size < 0 || manifest.Config.Size > MaxMetadataBytes || len(manifest.Layers) > MaxLayers {
			return Resolution{}, &Error{Code: "INVALID_IMAGE"}
		}
		var total int64 = manifest.Config.Size
		for _, layer := range manifest.Layers {
			if layer.Digest.Algorithm != "sha256" || len(layer.Digest.Hex) != 64 || layer.Size < 0 || layer.Size > MaxImageBytes-total {
				return Resolution{}, &Error{Code: "IMAGE_BUDGET"}
			}
			total += layer.Size
		}
	} else {
		return Resolution{}, &Error{Code: "UNSUPPORTED"}
	}
	if !result.Valid(raw) {
		return Resolution{}, &Error{Code: "INVALID_IMAGE"}
	}
	return result, nil
}
