// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/moby/moby/api/types/container"
	"golang.org/x/sys/unix"
)

func outputTestImage(t *testing.T, arch string) v1.Image {
	t.Helper()
	image, err := mutate.AppendLayers(empty.Image, static.NewLayer([]byte("finite test image layer"), types.OCIUncompressedLayer))
	if err != nil {
		t.Fatal(err)
	}
	config, err := image.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	config.OS, config.Architecture = "linux", arch
	image, err = mutate.ConfigFile(image, config)
	if err != nil {
		t.Fatal(err)
	}
	return mutate.ConfigMediaType(mutate.MediaType(image, types.OCIManifestSchema1), types.OCIConfigJSON)
}

// These are actual local OCI files and the pinned library/SDK HTTP fixture,
// not evidence of a BuildKit execution or a registry publication.
func outputTestFixture(t *testing.T, multi bool) (*nativeFixture, string, v1.Hash) {
	return finishOutputTestFixture(t, newNativeFixture(t, false), multi)
}
func finishOutputTestFixture(t *testing.T, f *nativeFixture, multi bool) (*nativeFixture, string, v1.Hash) {
	t.Helper()
	dir := filepath.Join(nativeWorkspacePaths(f.spec, f.plan)[1], "image")
	path, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	image := outputTestImage(t, "amd64")
	var digest v1.Hash
	if multi {
		idx := mutate.IndexMediaType(mutate.AppendManifests(empty.Index,
			mutate.IndexAddendum{Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
			mutate.IndexAddendum{Add: outputTestImage(t, "arm64"), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}}},
		), types.OCIImageIndex)
		err = path.AppendIndex(idx)
		digest, _ = idx.Digest()
	} else {
		err = path.AppendImage(image)
		digest, _ = image.Digest()
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx := f.ctx()
	f.prepare(ctx)
	if err := f.jobs.Start(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	f.edit(func() {
		f.state = container.State{Status: container.StateExited, ExitCode: 0, StartedAt: "2026-11-22T00:00:01Z", FinishedAt: "2026-11-22T00:00:02Z"}
	})
	if err := f.jobs.ObserveExit(ctx, f.spec, false); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.Remove(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	return f, dir, digest
}

func TestBuiltImageUsesOriginalSingleAndMultiPlatformOCILibraryObjects(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(map[bool]string{false: "image", true: "index"}[multi], func(t *testing.T) {
			f, _, want := outputTestFixture(t, multi)
			built, err := f.jobs.OpenBuiltImage(f.ctx(), f.spec)
			if err != nil {
				t.Fatal(err)
			}
			defer built.Close()
			if built.Metadata.Digest != want.String() || built.Metadata.ImageBytes <= 0 || !built.Metadata.Valid() {
				t.Fatal("wrong original output", built.Metadata)
			}
			if multi {
				if built.Index == nil || built.Image != nil {
					t.Fatal("multiplatform index flattened")
				}
				index, err := built.Index.IndexManifest()
				if err != nil || len(index.Manifests) != 2 {
					t.Fatal(index, err)
				}
				for _, d := range index.Manifests {
					image, err := built.Index.Image(d.Digest)
					if err != nil {
						t.Fatal(err)
					}
					config, err := image.ConfigFile()
					if err != nil || config.Architecture != d.Platform.Architecture {
						t.Fatal("lazy config did not use original layout", config, err)
					}
				}
			} else {
				if built.Image == nil || built.Index != nil {
					t.Fatal("wrong object kind")
				}
				got, err := built.Image.Digest()
				if err != nil || got != want {
					t.Fatal(got, err)
				}
			}
			if _, err := f.jobs.FinishWorkspace(f.ctx(), f.spec); !errors.Is(err, ErrUsed) {
				t.Fatal("lazy OCI output lost its hold", err)
			}
			if err := built.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := f.jobs.FinishWorkspace(f.ctx(), f.spec); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBuiltImageRejectsUntrustedFilesystemAndContentWithoutLeakingBorrow(t *testing.T) {
	for _, change := range []string{"layout-version", "index-budget", "blob-directory-link", "manifest-link", "manifest-digest", "config-budget", "layer-digest", "layer-fifo", "layer-hardlink", "extra-result", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			f, dir, digest := outputTestFixture(t, false)
			image := outputTestImage(t, "amd64")
			manifest, err := image.Manifest()
			if err != nil {
				t.Fatal(err)
			}
			blob := func(h v1.Hash) string { return filepath.Join(dir, "blobs", h.Algorithm, h.Hex) }
			ctx := f.ctx()
			switch change {
			case "layout-version":
				err = os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"unexpected"}`), 0600)
			case "index-budget":
				var file *os.File
				file, err = os.OpenFile(filepath.Join(dir, "index.json"), os.O_WRONLY, 0)
				if err == nil {
					err = file.Truncate(registryclient.MaxMetadataBytes + 1)
					_ = file.Close()
				}
			case "blob-directory-link":
				name := filepath.Join(dir, "blobs", "sha256")
				err = os.Rename(name, name+"-original")
				if err == nil {
					err = os.Symlink(name+"-original", name)
				}
			case "manifest-link":
				name := blob(digest)
				err = os.Rename(name, name+"-original")
				if err == nil {
					err = os.Symlink(name+"-original", name)
				}
			case "manifest-digest":
				err = os.WriteFile(blob(digest), []byte(`{"schemaVersion":2}`), 0600)
			case "config-budget":
				var file *os.File
				file, err = os.OpenFile(blob(manifest.Config.Digest), os.O_WRONLY, 0)
				if err == nil {
					err = file.Truncate(registryclient.MaxMetadataBytes + 1)
					_ = file.Close()
				}
			case "layer-digest":
				var raw []byte
				name := blob(manifest.Layers[0].Digest)
				raw, err = os.ReadFile(name)
				if err == nil {
					raw[0] ^= 1
					err = os.WriteFile(name, raw, 0600)
				}
			case "layer-fifo":
				name := blob(manifest.Layers[0].Digest)
				err = os.Remove(name)
				if err == nil {
					err = unix.Mkfifo(name, 0600)
				}
			case "layer-hardlink":
				name := blob(manifest.Layers[0].Digest)
				err = os.Link(name, name+"-other")
			case "extra-result":
				var path layout.Path
				path, err = layout.FromPath(dir)
				if err == nil {
					err = path.AppendImage(outputTestImage(t, "arm64"))
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := f.jobs.OpenBuiltImage(ctx, f.spec); err == nil {
				_ = got.Close()
				t.Fatal("invalid original output accepted")
			}
			if len(f.jobs.readers) != 0 {
				t.Fatal("failed output validation retained reader", f.jobs.readers)
			}
			if _, err := f.jobs.FinishWorkspace(f.ctx(), f.spec); err != nil {
				t.Fatal("failed validation prevented safe original cleanup", err)
			}
		})
	}
}

func TestBuiltImageRootDescriptorCannotSupplyExternalDataOrOversizedMetadata(t *testing.T) {
	for _, kind := range []string{"external-url", "embedded-data", "descriptor-size"} {
		t.Run(kind, func(t *testing.T) {
			f, dir, _ := outputTestFixture(t, false)
			name := filepath.Join(dir, "index.json")
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			var index v1.IndexManifest
			if err := json.Unmarshal(raw, &index); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "external-url":
				index.Manifests[0].URLs = []string{"https://outside.invalid/private"}
			case "embedded-data":
				index.Manifests[0].Data = []byte("untrusted")
			case "descriptor-size":
				index.Manifests[0].Size = registryclient.MaxMetadataBytes + 1
			}
			raw, err = json.Marshal(index)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := f.jobs.OpenBuiltImage(f.ctx(), f.spec); err == nil {
				_ = got.Close()
				t.Fatal("external/oversized descriptor accepted")
			}
		})
	}
}
