// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/jay94ks/mydcd/internal/registryclient"
)

// Only bounded metadata is held in memory. Layers remain on the original
// authenticated image and are copied once, without recompression or tags.
type externalArchive struct {
	image                  v1.Image
	manifest, config       v1.Descriptor
	rawManifest, rawConfig []byte
	layers                 []v1.Descriptor
}

func externalBlobPath(h v1.Hash) string { return "blobs/sha256/" + h.Hex }

func externalDigestValid(h v1.Hash) bool {
	b, err := hex.DecodeString(h.Hex)
	return err == nil && h.Algorithm == "sha256" && len(b) == sha256.Size && hex.EncodeToString(b) == h.Hex
}

func externalBlobMatches(d v1.Descriptor, raw []byte) bool {
	h := sha256.Sum256(raw)
	return externalDigestValid(d.Digest) && d.Size == int64(len(raw)) && d.Digest.Hex == hex.EncodeToString(h[:])
}

func prepareExternalArchive(image v1.Image) (*externalArchive, error) {
	invalid := func() (*externalArchive, error) { return nil, &registryclient.Error{Code: "INVALID_IMAGE"} }
	raw, err := image.RawManifest()
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || int64(len(raw)) > registryclient.MaxMetadataBytes {
		return nil, &registryclient.Error{Code: "METADATA_BUDGET"}
	}
	digest, err := image.Digest()
	if err != nil {
		return nil, err
	}
	media, err := image.MediaType()
	if err != nil {
		return nil, err
	}
	a := &externalArchive{image: image, manifest: v1.Descriptor{Digest: digest, Size: int64(len(raw)), MediaType: media}, rawManifest: raw}
	var m v1.Manifest
	if !media.IsImage() || !externalBlobMatches(a.manifest, raw) || json.Unmarshal(raw, &m) != nil || m.SchemaVersion != 2 || m.MediaType != "" && m.MediaType != media || !m.Config.MediaType.IsConfig() || !externalDigestValid(m.Config.Digest) || m.Config.Size < 0 || m.Config.Size > registryclient.MaxMetadataBytes || len(m.Layers) > registryclient.MaxLayers {
		return invalid()
	}
	a.config, a.layers = m.Config, m.Layers
	total := m.Config.Size
	seen := map[v1.Hash]v1.Descriptor{a.manifest.Digest: a.manifest, a.config.Digest: a.config}
	for _, layer := range a.layers {
		if !externalDigestValid(layer.Digest) || !layer.MediaType.IsLayer() || layer.Size < 0 || layer.Size > registryclient.MaxImageBytes-total {
			return nil, &registryclient.Error{Code: "IMAGE_BUDGET"}
		}
		total += layer.Size
		if previous, ok := seen[layer.Digest]; ok && (previous.Size != layer.Size || previous.MediaType != layer.MediaType) {
			return invalid()
		}
		seen[layer.Digest] = layer
	}
	config, err := image.ConfigName()
	if err != nil {
		return nil, err
	}
	if config != a.config.Digest || config == a.manifest.Digest {
		return invalid()
	}
	a.rawConfig, err = image.RawConfigFile()
	if err != nil {
		return nil, err
	}
	if !externalBlobMatches(a.config, a.rawConfig) {
		return invalid()
	}
	return a, nil
}

func (a *externalArchive) write(ctx context.Context, out io.Writer) error {
	tw := tar.NewWriter(out)
	write := func(name string, raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(raw)
		return err
	}
	index, err := json.Marshal(v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{a.manifest}})
	if err != nil {
		return err
	}
	paths := make([]string, len(a.layers))
	for i, layer := range a.layers {
		paths[i] = externalBlobPath(layer.Digest)
	}
	legacy, err := json.Marshal(tarball.Manifest{{Config: externalBlobPath(a.config.Digest), Layers: paths}})
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		name string
		raw  []byte
	}{{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)}, {"index.json", index}, {"manifest.json", legacy}, {externalBlobPath(a.manifest.Digest), a.rawManifest}, {externalBlobPath(a.config.Digest), a.rawConfig}} {
		if err := write(entry.name, entry.raw); err != nil {
			return err
		}
	}
	seen := map[v1.Hash]bool{}
	for _, descriptor := range a.layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if seen[descriptor.Digest] {
			continue
		}
		seen[descriptor.Digest] = true
		layer, err := a.image.LayerByDigest(descriptor.Digest)
		if err != nil {
			return err
		}
		digest, err := layer.Digest()
		if err != nil {
			return err
		}
		size, err := layer.Size()
		if err != nil {
			return err
		}
		if digest != descriptor.Digest || size != descriptor.Size {
			return &registryclient.Error{Code: "INVALID_IMAGE"}
		}
		body, err := layer.Compressed()
		if err != nil {
			return err
		}
		err = writeExternalLayer(ctx, tw, descriptor, body)
		closed := body.Close()
		if err != nil {
			return err
		}
		if closed != nil {
			return closed
		}
	}
	return tw.Close()
}

type externalLayerReader struct {
	ctx  context.Context
	body io.Reader
}

func (r externalLayerReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.body.Read(p)
}

func writeExternalLayer(ctx context.Context, tw *tar.Writer, d v1.Descriptor, body io.Reader) error {
	if err := tw.WriteHeader(&tar.Header{Name: externalBlobPath(d.Digest), Mode: 0600, Size: d.Size, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	reader := externalLayerReader{ctx: ctx, body: body}
	h := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(tw, h), reader, d.Size); err != nil {
		return err
	}
	var extra [1]byte
	n, err := io.ReadFull(reader, extra[:])
	if err != nil && err != io.EOF {
		return err
	}
	if n != 0 || err != io.EOF || hex.EncodeToString(h.Sum(nil)) != d.Digest.Hex {
		return &registryclient.Error{Code: "INVALID_IMAGE"}
	}
	return nil
}
