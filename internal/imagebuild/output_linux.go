// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/registryclient"
	"golang.org/x/sys/unix"
)

// BuiltImage retains the original successful output/cache borrow through lazy
// OCI library I/O. Exactly one of Image/Index is present. The consumer must join
// its push before Close; this object owns neither a new job nor a new DB/root.
type BuiltImage struct {
	Image     v1.Image
	Index     v1.ImageIndex
	Metadata  registryclient.ImageMetadata
	directory *os.File
	output    *NativeOutput
	mu        sync.Mutex
	closed    bool
	once      sync.Once
	err       error
}

func (b *BuiltImage) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.once.Do(func() {
		b.closed = true
		b.err = b.directory.Close()
		if b.err == nil {
			b.err = b.output.Close()
		}
	})
	return b.err
}

// OpenBuiltImage accepts only a positively exited/Waited/removed original.
// Removal prevents a stopped builder being restarted while lazy readers use
// its output. No tar extraction, Docker import, or rebuilt result is involved.
func (n *NativeJobs) OpenBuiltImage(ctx context.Context, spec JobSpec) (*BuiltImage, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	out, err := n.OpenOutput(spec)
	if err != nil {
		return nil, err
	}
	dir, _, err := openNativeDirectory(int(out.Directory.Fd()), "image")
	if err != nil {
		return nil, errors.Join(ErrStorage, out.Close())
	}
	if record, err := n.Record(spec); err != nil {
		_ = dir.Close()
		return nil, errors.Join(ErrStorage, out.Close())
	} else if record.Solve != nil {
		var st unix.Stat_t
		if unix.Fstat(int(dir.Fd()), &st) != nil || nativeDirectory(st) != record.Solve.Directory {
			_ = dir.Close()
			return nil, errors.Join(ErrStorage, out.Close())
		}
	}
	b := &BuiltImage{directory: dir, output: out}
	fail := func(err error) (*BuiltImage, error) { return nil, errors.Join(err, b.Close()) }
	read := outputReader{ctx: ctx, root: int(dir.Fd()), reference: spec.OutputRepository(), manifests: map[string]outputManifest{}, expected: map[string]v1.Descriptor{}}
	marker, err := read.small("oci-layout", 4096)
	if err != nil {
		return fail(err)
	}
	var version struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if json.Unmarshal(marker, &version) != nil || version.ImageLayoutVersion != "1.0.0" {
		return fail(ErrInvalid)
	}
	raw, err := read.small("index.json", registryclient.MaxMetadataBytes)
	if err != nil {
		return fail(err)
	}
	if _, err := registryclient.ResolveManifest(spec.OutputRepository()+":output", string(types.OCIImageIndex), raw); err != nil {
		return fail(err)
	}
	index, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil || len(index.Manifests) != 1 {
		return fail(ErrInvalid)
	}
	selected := index.Manifests[0]
	if err := read.expect(selected); err != nil {
		return fail(err)
	}
	media, body, err := read.manifest(selected.Digest.String())
	if err != nil {
		return fail(err)
	}
	_, authority, repository, err := registryclient.Normalize(spec.OutputRepository() + ":output")
	if err != nil {
		return fail(err)
	}
	b.Metadata, err = registryclient.DescribeManifest(authority, repository, selected.Digest.String(), media, body, read.manifest)
	if err != nil {
		return fail(err)
	}
	// The shared descriptor graph is the authority for config/layer membership
	// and budgets. Validate each unique referenced blob once, in constant memory.
	blobs := map[string]v1.Descriptor{}
	for _, manifest := range read.manifests {
		if !types.MediaType(manifest.media).IsImage() {
			continue
		}
		image, err := v1.ParseManifest(bytes.NewReader(manifest.raw))
		if err != nil {
			return fail(ErrInvalid)
		}
		for _, descriptor := range append([]v1.Descriptor{image.Config}, image.Layers...) {
			if old, ok := blobs[descriptor.Digest.String()]; ok && (old.Size != descriptor.Size || old.MediaType != descriptor.MediaType) {
				return fail(ErrInvalid)
			}
			blobs[descriptor.Digest.String()] = descriptor
		}
		if image.Config.Size > registryclient.MaxMetadataBytes {
			return fail(ErrInvalid)
		}
	}
	buffer := make([]byte, 32<<10)
	for _, descriptor := range blobs {
		if err := read.verifyBlob(descriptor, buffer); err != nil {
			return fail(err)
		}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	// The library uses this held kernel FD, never a user-supplied host path.
	// All metadata sizes and symlink-free blob paths were checked before its
	// convenience readers can call ReadAll. The original writer is removed.
	path := layout.Path(fmt.Sprintf("/proc/self/fd/%d", dir.Fd()))
	wrapper, err := path.ImageIndex()
	if err != nil {
		return fail(ErrStorage)
	}
	if selected.MediaType.IsIndex() {
		b.Index, err = wrapper.ImageIndex(selected.Digest)
	} else {
		b.Image, err = wrapper.Image(selected.Digest)
	}
	if err != nil {
		return fail(ErrInvalid)
	}
	return b, nil
}

type outputManifest struct {
	media string
	raw   []byte
}
type outputReader struct {
	ctx           context.Context
	root          int
	reference     string
	manifests     map[string]outputManifest
	expected      map[string]v1.Descriptor
	metadataBytes int64
}

func outputBlobName(digest string) (string, error) {
	hash, err := v1.NewHash(digest)
	if err != nil || hash.Algorithm != "sha256" || !nativeID(hash.Hex) {
		return "", ErrInvalid
	}
	return "blobs/sha256/" + hash.Hex, nil
}

func (r *outputReader) open(name string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	if err := r.ctx.Err(); err != nil {
		return nil, st, err
	}
	fd, err := unix.Openat2(r.root, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, st, ErrStorage
	}
	f := os.NewFile(uintptr(fd), "imagebuild-output-content")
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size < 0 {
		_ = f.Close()
		return nil, st, ErrStorage
	}
	return f, st, nil
}

func (r *outputReader) small(name string, limit int64) ([]byte, error) {
	f, st, err := r.open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size > limit {
		return nil, ErrInvalid
	}
	body, err := io.ReadAll(io.LimitReader(contextReader{r.ctx, f}, limit+1))
	if err != nil || int64(len(body)) != st.Size || int64(len(body)) > limit {
		return nil, errors.Join(ErrStorage, err)
	}
	return body, nil
}

func (r *outputReader) expect(d v1.Descriptor) error {
	if _, err := outputBlobName(d.Digest.String()); err != nil || d.Size < 0 || d.Size > registryclient.MaxMetadataBytes || len(d.URLs) != 0 || len(d.Data) != 0 || !d.MediaType.IsImage() && !d.MediaType.IsIndex() {
		return ErrInvalid
	}
	key := d.Digest.String()
	if old, ok := r.expected[key]; ok {
		if old.Size != d.Size || old.MediaType != d.MediaType {
			return ErrInvalid
		}
	} else if len(r.expected) >= 1024 {
		return ErrInvalid
	}
	r.expected[key] = d
	return nil
}

func (r *outputReader) manifest(digest string) (string, []byte, error) {
	if got, ok := r.manifests[digest]; ok {
		return got.media, got.raw, nil
	}
	d, ok := r.expected[digest]
	if !ok || len(r.manifests) >= 1024 || d.Size > (16<<20)-r.metadataBytes {
		return "", nil, ErrInvalid
	}
	name, err := outputBlobName(digest)
	if err != nil {
		return "", nil, err
	}
	raw, err := r.small(name, registryclient.MaxMetadataBytes)
	if err != nil {
		return "", nil, err
	}
	if int64(len(raw)) != d.Size {
		return "", nil, ErrDigest
	}
	media := string(d.MediaType)
	parsed, err := registryclient.ResolveManifest(r.reference+"@"+digest, media, raw)
	if err != nil {
		return "", nil, err
	}
	if parsed.Digest != digest {
		return "", nil, ErrDigest
	}
	if d.MediaType.IsIndex() {
		index, err := v1.ParseIndexManifest(bytes.NewReader(raw))
		if err != nil {
			return "", nil, ErrInvalid
		}
		for _, child := range index.Manifests {
			if err := r.expect(child); err != nil {
				return "", nil, err
			}
		}
	}
	r.metadataBytes += d.Size
	r.manifests[digest] = outputManifest{media, raw}
	return media, raw, nil
}

func (r *outputReader) verifyBlob(d v1.Descriptor, buffer []byte) error {
	name, err := outputBlobName(d.Digest.String())
	if err != nil {
		return err
	}
	f, st, err := r.open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	if st.Size != d.Size {
		return ErrDigest
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.LimitReader(contextReader{r.ctx, f}, d.Size+1), buffer)
	if err != nil {
		return errors.Join(ErrStorage, err)
	}
	if n != d.Size || hex.EncodeToString(hash.Sum(nil)) != d.Digest.Hex {
		return ErrDigest
	}
	return nil
}
