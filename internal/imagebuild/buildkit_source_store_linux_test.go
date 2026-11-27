// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/registryclient"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"
)

type sourceStoreFixture struct {
	input FrozenSource
	items map[string]struct {
		media string
		raw   []byte
	}
	children []v1.Descriptor
	layer    v1.Descriptor
	calls    map[string]int
}

func sourceStoreFixtureFor(t *testing.T) *sourceStoreFixture {
	t.Helper()
	f := &sourceStoreFixture{items: map[string]struct {
		media string
		raw   []byte
	}{}, calls: map[string]int{}}
	f.layer = f.add(t, types.OCILayer, bytes.Repeat([]byte("source-layer"), 32000))
	for _, arch := range []string{"amd64", "arm64"} {
		config := f.add(t, types.OCIConfigJSON, []byte(`{"os":"linux","architecture":"`+arch+`"}`))
		child := f.add(t, types.OCIManifestSchema1, v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: config, Layers: []v1.Descriptor{f.layer}})
		child.Platform = &v1.Platform{OS: "linux", Architecture: arch}
		f.children = append(f.children, child)
	}
	root := f.add(t, types.OCIImageIndex, v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: f.children})
	f.input = FrozenSource{Source: Source{Reference: "registry.example/team/app:latest", Kind: "from", Platform: "linux/amd64"}, Image: "registry.example/team/app@" + root.Digest.String()}
	return f
}

func (f *sourceStoreFixture) add(t *testing.T, media types.MediaType, value any) v1.Descriptor {
	t.Helper()
	raw, ok := value.([]byte)
	if !ok {
		var err error
		raw, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	key := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	f.items[key] = struct {
		media string
		raw   []byte
	}{string(media), raw}
	hash, err := v1.NewHash(key)
	if err != nil {
		t.Fatal(err)
	}
	return v1.Descriptor{MediaType: media, Digest: hash, Size: int64(len(raw))}
}

func (f *sourceStoreFixture) read(ctx context.Context, source Source, q registryclient.GraphContentQuery, to io.Writer) (registryclient.ContentInfo, error) {
	if ctx.Err() != nil || source != f.input.Source || q.Root != f.input.Image {
		return registryclient.ContentInfo{}, ErrSourceFetch
	}
	info, raw, err := registryclient.SelectGraphContent(q, func(key string) (string, []byte, error) {
		item, ok := f.items[key]
		if !ok {
			return "", nil, errdefs.ErrNotFound
		}
		return item.media, item.raw, nil
	})
	if err != nil {
		return info, err
	}
	if q.Kind != "manifest" {
		raw = f.items[info.Digest].raw
	}
	f.calls[info.Digest]++
	_, err = to.Write(raw)
	return info, err
}

func sourceStoreFor(t *testing.T, f *sourceStoreFixture, read BuildKitSourceRead, allowed *atomic.Bool) (*buildKitSourceStore, *[]*os.File) {
	t.Helper()
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	var files []*os.File
	s := newBuildKitSourceStore(context.Background(), f.input, func(ctx context.Context) error {
		if ctx.Err() != nil || allowed != nil && !allowed.Load() {
			return ErrSourceFetch
		}
		return nil
	}, read, func() (*os.File, error) {
		file, err := sourceTemporaryFile(dir)
		if err == nil {
			files = append(files, file)
		}
		return file, err
	}, func(error) {})
	t.Cleanup(func() { _ = s.Close() })
	return s, &files
}

func readSourceMetadata(t *testing.T, s *buildKitSourceStore, key string) []byte {
	t.Helper()
	r, err := s.ReaderAt(context.Background(), ocispec.Descriptor{Digest: digest.Digest(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	raw, err := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSourceStoreReusesVerifiedBodiesForSDKRangesAndSharedPlatformLayers(t *testing.T) {
	f := sourceStoreFixtureFor(t)
	s, files := sourceStoreFor(t, f, f.read, nil)
	root, _ := parseCanonical(f.input.Image)
	if _, err := s.Info(context.Background(), digest.Digest(f.layer.Digest.String())); !errors.Is(err, errdefs.ErrNotFound) || len(f.calls) != 0 {
		t.Fatal("unwitnessed blob caused source I/O", err)
	}
	if _, err := s.Info(context.Background(), root.Digest()); err != nil {
		t.Fatal(err)
	}
	readSourceMetadata(t, s, root.Digest().String())
	for _, child := range f.children {
		readSourceMetadata(t, s, child.Digest.String())
	}
	for _, offset := range []int64{32 << 10, 0, 128 << 10, f.layer.Size - 100} {
		r, err := s.ReaderAt(context.Background(), ocispec.Descriptor{Digest: digest.Digest(f.layer.Digest.String())})
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 100)
		n, err := r.ReadAt(got, offset)
		if err != nil || n != len(got) || !bytes.Equal(got, f.items[f.layer.Digest.String()].raw[offset:offset+100]) {
			t.Fatal("SDK range changed", n, err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(*files) != 1 || f.calls[f.layer.Digest.String()] != 1 {
		t.Fatal("range reads redownloaded original layer", len(*files), f.calls)
	}
	var stat unix.Stat_t
	if unix.Fstat(int((*files)[0].Fd()), &stat) != nil || stat.Nlink != 0 {
		t.Fatal("layer file remained linked")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := (*files)[0].Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("source file outlived solve", err)
	}
	if _, err := s.Info(context.Background(), root.Digest()); err == nil {
		t.Fatal("closed solve supplied source")
	}
}

func TestSourceStoreRejectsUnverifiedOrReplacedBodiesAndStorageFailure(t *testing.T) {
	for _, mode := range []string{"corrupt", "extra", "final-error", "wrong-info", "disk"} {
		t.Run(mode, func(t *testing.T) {
			f := sourceStoreFixtureFor(t)
			read := func(ctx context.Context, source Source, q registryclient.GraphContentQuery, to io.Writer) (registryclient.ContentInfo, error) {
				if q.Kind != "layer" {
					return f.read(ctx, source, q, to)
				}
				var body bytes.Buffer
				info, err := f.read(ctx, source, q, &body)
				if err != nil {
					return info, err
				}
				raw := body.Bytes()
				if mode == "corrupt" {
					raw[0] ^= 1
				}
				if mode == "extra" {
					raw = append(raw, 'x')
				}
				_, err = to.Write(raw)
				if mode == "final-error" {
					err = ErrSourceFetch
				}
				if mode == "wrong-info" {
					info.Ref = f.input.Image
				}
				return info, err
			}
			s, files := sourceStoreFor(t, f, read, nil)
			root, _ := parseCanonical(f.input.Image)
			readSourceMetadata(t, s, root.Digest().String())
			readSourceMetadata(t, s, f.children[0].Digest.String())
			if mode == "disk" {
				s.newFile = func() (*os.File, error) { return nil, ErrStorage }
			}
			r, err := s.ReaderAt(context.Background(), ocispec.Descriptor{Digest: digest.Digest(f.layer.Digest.String())})
			if err == nil || r != nil {
				t.Fatal("unverified body exposed to SDK", mode)
			}
			for _, file := range *files {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("failed body FD retained", err)
				}
			}
		})
	}
}

func TestSourceStoreClosesAndJoinsOriginalOwnerReadAndRechecksCachedAuthority(t *testing.T) {
	f := sourceStoreFixtureFor(t)
	started := make(chan struct{})
	read := func(ctx context.Context, _ Source, _ registryclient.GraphContentQuery, _ io.Writer) (registryclient.ContentInfo, error) {
		close(started)
		<-ctx.Done()
		return registryclient.ContentInfo{}, ctx.Err()
	}
	s, _ := sourceStoreFor(t, f, read, nil)
	root, _ := parseCanonical(f.input.Image)
	done := make(chan error, 1)
	go func() {
		_, err := s.ReaderAt(context.Background(), ocispec.Descriptor{Digest: root.Digest()})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("owner read did not start")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled owner read succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owner I/O did not join")
	}

	var allowed atomic.Bool
	allowed.Store(true)
	s, _ = sourceStoreFor(t, f, f.read, &allowed)
	readSourceMetadata(t, s, root.Digest().String())
	readSourceMetadata(t, s, f.children[0].Digest.String())
	r, err := s.ReaderAt(context.Background(), ocispec.Descriptor{Digest: digest.Digest(f.layer.Digest.String())})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	allowed.Store(false)
	if _, err := r.ReadAt(make([]byte, 1), r.Size()-1); err == nil {
		t.Fatal("cached final range bypassed current authority")
	}
}

func TestSourceStoreDeniesSDKMutationMethods(t *testing.T) {
	f := sourceStoreFixtureFor(t)
	s, _ := sourceStoreFor(t, f, f.read, nil)
	if err := s.Delete(context.Background(), "sha256:bad"); !errors.Is(err, errdefs.ErrPermissionDenied) {
		t.Fatal(err)
	}
	if _, err := s.Writer(context.Background()); !errors.Is(err, errdefs.ErrPermissionDenied) {
		t.Fatal(err)
	}
	if err := s.Walk(context.Background(), nil); !errors.Is(err, errdefs.ErrPermissionDenied) {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatal("mutation caused owner I/O")
	}
}
