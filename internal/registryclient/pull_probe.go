// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/access"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// PullCheck records metadata/config reads and authenticated blob HEAD checks.
// It does not claim a complete layer download or successful Docker unpack.
type PullCheck struct {
	ManifestDigest  string
	Platform        v1.Platform
	Blobs           int
	CompressedBytes int64
}

func (r Resolution) Valid(raw string) bool {
	n, a, repo, err := Normalize(raw)
	if err != nil || r.Normalized != n || r.Registry != a || r.Repository != repo || r.Pinned != a+"/"+repo+"@"+r.Digest || r.ManifestBytes < 0 || r.ManifestBytes > MaxMetadataBytes || len(r.Platforms) > 128 {
		return false
	}
	if _, err := access.PinImage(r.Pinned); err != nil {
		return false
	}
	media := types.MediaType(r.MediaType)
	if requested, err := access.PinImage(n); err == nil && requested.Digest != r.Digest {
		return false
	}
	if !media.IsIndex() && !media.IsImage() || !media.IsIndex() && len(r.Platforms) != 0 {
		return false
	}
	for _, child := range r.Platforms {
		if _, err := access.PinImage(a + "/" + repo + "@" + child.Digest); err != nil {
			return false
		}
	}
	rawResult, err := json.Marshal(r)
	return err == nil && len(rawResult) <= 64<<10
}

func (p PullCheck) Valid(r Resolution) bool {
	if p.Platform.OS == "" || p.Platform.Architecture == "" || p.Blobs < 1 || p.Blobs > MaxLayers+1 || p.CompressedBytes < 0 || p.CompressedBytes > MaxImageBytes {
		return false
	}
	if len(r.Platforms) == 0 {
		return p.ManifestDigest == r.Digest
	}
	for _, child := range r.Platforms {
		if child.Digest == p.ManifestDigest && child.Platform != nil && child.Platform.OS == p.Platform.OS && child.Platform.Architecture == p.Platform.Architecture && child.Platform.Variant == p.Platform.Variant {
			return true
		}
	}
	return false
}

// CheckPull uses the previously resolved immutable root, so a moving tag cannot
// substitute a different image between the manifest and blob permission checks.
func (a *Access) CheckPull(ctx context.Context, resolved Resolution, platform v1.Platform) (PullCheck, error) {
	if !resolved.Valid(resolved.Normalized) || resolved.Registry != a.authority || platform.OS == "" || platform.Architecture == "" {
		return PullCheck{}, &Error{Code: "INVALID_IMAGE"}
	}
	image, err := a.Image(ctx, resolved.Pinned, platform)
	if err != nil {
		return PullCheck{}, err
	}
	manifest, err := image.Manifest()
	if err != nil {
		return PullCheck{}, Sanitize(err)
	}
	// ConfigFile verifies the config blob and bounds it through Image's limits.
	config, err := image.ConfigFile()
	if err != nil {
		return PullCheck{}, Sanitize(err)
	}
	if config.OS != platform.OS || config.Architecture != platform.Architecture || platform.Variant != "" && config.Variant != platform.Variant {
		// Not a format problem: the image config names another (or no) platform.
		return PullCheck{}, &Error{Code: "PLATFORM_MISMATCH"}
	}
	digest, err := image.Digest()
	if err != nil {
		return PullCheck{}, Sanitize(err)
	}
	result := PullCheck{ManifestDigest: digest.String(), Platform: v1.Platform{OS: config.OS, Architecture: config.Architecture, Variant: config.Variant}, Blobs: 1, CompressedBytes: manifest.Config.Size}
	repo, err := name.NewRepository(resolved.Registry+"/"+resolved.Repository, name.StrictValidation)
	if err != nil {
		return PullCheck{}, &Error{Code: "INVALID_IMAGE"}
	}
	for _, descriptor := range manifest.Layers {
		layer, err := remote.Layer(repo.Digest(descriptor.Digest.String()), a.options(ctx, platform)...)
		if err != nil {
			return PullCheck{}, Sanitize(err)
		}
		size, err := layer.Size()
		if err != nil {
			return PullCheck{}, Sanitize(err)
		}
		if size != descriptor.Size {
			return PullCheck{}, &Error{Code: "INVALID_IMAGE"}
		}
		result.Blobs++
		result.CompressedBytes += size
	}
	if !result.Valid(resolved) {
		return PullCheck{}, &Error{Code: "INVALID_IMAGE"}
	}
	return result, nil
}
