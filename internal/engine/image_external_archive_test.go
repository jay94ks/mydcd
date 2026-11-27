// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/jay94ks/seafield/internal/registryclient"
)

type externalArchiveTestImage struct {
	v1.Image
	raw, config []byte
	digest      *v1.Hash
	layer       v1.Layer
}

func (i externalArchiveTestImage) RawManifest() ([]byte, error) {
	if i.raw != nil {
		return i.raw, nil
	}
	return i.Image.RawManifest()
}

func (i externalArchiveTestImage) Digest() (v1.Hash, error) {
	if i.digest != nil {
		return *i.digest, nil
	}
	if i.raw != nil {
		h, _, err := v1.SHA256(bytes.NewReader(i.raw))
		return h, err
	}
	return i.Image.Digest()
}

func (i externalArchiveTestImage) RawConfigFile() ([]byte, error) {
	if i.config != nil {
		return i.config, nil
	}
	return i.Image.RawConfigFile()
}

func (i externalArchiveTestImage) LayerByDigest(h v1.Hash) (v1.Layer, error) {
	if i.layer != nil {
		return i.layer, nil
	}
	return i.Image.LayerByDigest(h)
}

type externalArchiveTestLayer struct {
	v1.Layer
	open func() (io.ReadCloser, error)
}

func (l externalArchiveTestLayer) Compressed() (io.ReadCloser, error) { return l.open() }

type externalArchiveTestBody struct {
	io.Reader
	closed *bool
}

func (b externalArchiveTestBody) Close() error { *b.closed = true; return nil }

type externalArchiveBrokenReader struct{ err error }

func (r externalArchiveBrokenReader) Read([]byte) (int, error) { return 0, r.err }

func TestExternalArchiveDeduplicatesLayerBytesAndPreservesOrderedReferences(t *testing.T) {
	image, err := random.Image(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	layers, err := image.Layers()
	if err != nil {
		t.Fatal(err)
	}
	image, err = mutate.AppendLayers(image, layers[0])
	if err != nil {
		t.Fatal(err)
	}
	opens, closes := 0, 0
	wrapped := externalArchiveTestImage{Image: image, layer: externalArchiveTestLayer{Layer: layers[0], open: func() (io.ReadCloser, error) {
		opens++
		body, err := layers[0].Compressed()
		if err != nil {
			return nil, err
		}
		return &externalArchiveCountBody{ReadCloser: body, closes: &closes}, nil
	}}}
	a, err := prepareExternalArchive(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := a.write(context.Background(), &archiveBudget{writer: &out, left: registryclient.MaxImageBytes + (32 << 20)}); err != nil {
		t.Fatal(err)
	}
	if opens != 1 || closes != 1 {
		t.Fatal("duplicate layer reopened or leaked reader", opens, closes)
	}
	reader := tar.NewReader(bytes.NewReader(out.Bytes()))
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || seen[header.Name] {
			t.Fatal("duplicate or broken tar entry", err)
		}
		seen[header.Name] = true
		if header.Name == "manifest.json" {
			var legacy tarball.Manifest
			if json.NewDecoder(reader).Decode(&legacy) != nil || len(legacy) != 1 || len(legacy[0].Layers) != 2 || legacy[0].Layers[0] != legacy[0].Layers[1] || len(legacy[0].RepoTags) != 0 {
				t.Fatal("ordered duplicate references changed", legacy)
			}
		}
	}
	if len(seen) != 6 {
		t.Fatal("duplicate layer emitted another blob", len(seen))
	}
}

type externalArchiveCountBody struct {
	io.ReadCloser
	closes *int
}

func (b *externalArchiveCountBody) Close() error { (*b.closes)++; return b.ReadCloser.Close() }

func TestExternalArchiveRejectsChangedMetadataAndDescriptorBudgets(t *testing.T) {
	image, err := random.Image(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := image.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	var manifest v1.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	wrong := manifest.Config.Digest
	for _, test := range []struct {
		name string
		edit func(*v1.Manifest)
	}{
		{"layer-sum", func(m *v1.Manifest) { m.Layers[0].Size = registryclient.MaxImageBytes }},
		{"layer-count", func(m *v1.Manifest) { m.Layers = make([]v1.Descriptor, registryclient.MaxLayers+1) }},
		{"config-size", func(m *v1.Manifest) { m.Config.Size++ }},
		{"unknown-digest", func(m *v1.Manifest) { m.Layers[0].Digest.Algorithm = "sha512" }},
		{"duplicate-size", func(m *v1.Manifest) { m.Layers = append(m.Layers, m.Layers[0]); m.Layers[1].Size++ }},
		{"duplicate-media", func(m *v1.Manifest) {
			m.Layers = append(m.Layers, m.Layers[0])
			m.Layers[1].MediaType = "application/vnd.oci.image.layer.v1.tar"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var m v1.Manifest
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			test.edit(&m)
			changed, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prepareExternalArchive(externalArchiveTestImage{Image: image, raw: changed}); err == nil {
				t.Fatal("changed descriptor accepted")
			}
		})
	}
	for _, test := range []externalArchiveTestImage{
		{Image: image, raw: raw, digest: &wrong},
		{Image: image, config: []byte("changed config")},
		{Image: image, raw: make([]byte, registryclient.MaxMetadataBytes+1)},
	} {
		if _, err := prepareExternalArchive(test); err == nil {
			t.Fatal("changed manifest/config accepted")
		}
	}
}

func TestExternalArchiveRejectsLayerDigestLengthStreamFailureAndCancellation(t *testing.T) {
	image, err := random.Image(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	layers, err := image.Layers()
	if err != nil {
		t.Fatal(err)
	}
	body, err := layers[0].Compressed()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(body)
	closed := body.Close()
	if err != nil || closed != nil || len(raw) < 2 {
		t.Fatal(err, closed)
	}
	broken := errors.New("private-test-stream-failure")
	for _, test := range []struct {
		name string
		body func(context.CancelFunc) io.Reader
	}{
		{"digest", func(context.CancelFunc) io.Reader { b := bytes.Clone(raw); b[0] ^= 1; return bytes.NewReader(b) }},
		{"short", func(context.CancelFunc) io.Reader { return bytes.NewReader(raw[:len(raw)-1]) }},
		{"long", func(context.CancelFunc) io.Reader { return bytes.NewReader(append(bytes.Clone(raw), 0)) }},
		{"stream", func(context.CancelFunc) io.Reader {
			return io.MultiReader(bytes.NewReader(raw[:len(raw)/2]), externalArchiveBrokenReader{broken})
		}},
		{"cancel", func(stop context.CancelFunc) io.Reader { stop(); return bytes.NewReader(raw) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			closed := false
			wrapped := externalArchiveTestImage{Image: image, layer: externalArchiveTestLayer{Layer: layers[0], open: func() (io.ReadCloser, error) {
				return externalArchiveTestBody{Reader: test.body(stop), closed: &closed}, nil
			}}}
			a, err := prepareExternalArchive(wrapped)
			if err != nil {
				t.Fatal(err)
			}
			err = a.write(ctx, io.Discard)
			if err == nil || !closed {
				t.Fatal("invalid stream accepted or reader leaked", err, closed)
			}
			if test.name == "stream" && !errors.Is(err, broken) || test.name == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("original stream failure lost", err)
			}
		})
	}
	a, err := prepareExternalArchive(image)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.write(context.Background(), &archiveBudget{writer: io.Discard, left: 512}); registryclient.ResultCode(err) != "IMAGE_BUDGET" {
		t.Fatal("archive budget bypassed", err)
	}
}
