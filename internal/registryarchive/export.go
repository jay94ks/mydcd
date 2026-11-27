// SPDX-License-Identifier: Apache-2.0

package registryarchive

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Summary counts what an export wrote or an import sent.
type Summary struct {
	Images, Blobs int
	Bytes         int64
}

// Export writes the entries, each pinned to its digest, as one OCI layout
// tar to w. It reads every manifest by digest, so a tag moved or pushed
// while it runs does not change the result; an image deleted meanwhile
// fails the export instead of leaving it out. Blobs are checked against
// their digest and size while they are copied.
func Export(ctx context.Context, w io.Writer, entries []Entry, open Remote) (Summary, error) {
	if len(entries) == 0 || len(entries) > MaxEntries {
		return Summary{}, fmt.Errorf("export needs 1 to %d images", MaxEntries)
	}
	x := exporter{ctx: ctx, tw: tar.NewWriter(w), seen: map[string]bool{}, open: open}
	if err := x.file(layoutFile, []byte(layoutVersion)); err != nil {
		return x.sum, err
	}
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex}
	for _, e := range entries {
		if !ValidRepository(e.Repository) || !ValidTag(e.Tag) {
			return x.sum, fmt.Errorf("invalid image %s", e)
		}
		desc, err := x.manifest(e.Repository, e.Digest)
		if err != nil {
			return x.sum, fmt.Errorf("%s: %w", e, err)
		}
		desc.Annotations = map[string]string{RefName: e.Tag, Repository: e.Repository}
		index.Manifests = append(index.Manifests, desc)
		x.sum.Images++
	}
	raw, err := json.Marshal(index)
	if err != nil {
		return x.sum, err
	}
	if err = x.file(indexFile, raw); err != nil {
		return x.sum, err
	}
	return x.sum, x.tw.Close()
}

type exporter struct {
	ctx  context.Context
	tw   *tar.Writer
	seen map[string]bool
	open Remote
	sum  Summary
}

func (x *exporter) header(name string, size int64) error {
	return x.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size, Mode: 0o644, ModTime: time.Unix(0, 0), Format: tar.FormatPAX})
}

func (x *exporter) file(name string, data []byte) error {
	if err := x.header(name, int64(len(data))); err != nil {
		return err
	}
	_, err := x.tw.Write(data)
	return err
}

// blob copies one blob once, checking its digest and size.
func (x *exporter) blob(digest string, size int64, open func() (io.ReadCloser, error)) error {
	if x.seen[digest] {
		return nil
	}
	hexDigest, err := digestHex(digest)
	if err != nil {
		return err
	}
	if size < 0 {
		return fmt.Errorf("blob %s has no size", digest)
	}
	r, err := open()
	if err != nil {
		return err
	}
	defer r.Close()
	if err = x.header(blobPath(hexDigest), size); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(x.tw, h), io.LimitReader(ctxReader{x.ctx, r}, size+1))
	if err != nil {
		return err
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != hexDigest {
		return fmt.Errorf("blob %s does not match its digest or size", digest)
	}
	x.seen[digest] = true
	x.sum.Blobs++
	x.sum.Bytes += size
	return nil
}

// manifest writes one manifest and everything it refers to, children first.
func (x *exporter) manifest(repository, digest string) (v1.Descriptor, error) {
	repo, opts, err := x.open(repository, false)
	if err != nil {
		return v1.Descriptor{}, err
	}
	opts = append(opts, remote.WithContext(x.ctx))
	got, err := remote.Get(repo.Digest(digest), opts...)
	if err != nil {
		return v1.Descriptor{}, err
	}
	if got.Digest.String() != digest || int64(len(got.Manifest)) != got.Size || got.Size > MaxManifestBytes {
		return v1.Descriptor{}, fmt.Errorf("the registry sent another manifest for %s", digest)
	}
	isIndex, ok := manifestType(got.MediaType)
	if !ok {
		return v1.Descriptor{}, fmt.Errorf("manifest %s has unsupported media type %s", digest, got.MediaType)
	}
	if isIndex {
		idx, err := v1.ParseIndexManifest(bytes.NewReader(got.Manifest))
		if err != nil || len(idx.Manifests) > maxChildren {
			return v1.Descriptor{}, fmt.Errorf("index %s is not valid", digest)
		}
		for _, child := range idx.Manifests {
			if _, ok := manifestType(child.MediaType); !ok {
				return v1.Descriptor{}, fmt.Errorf("index %s refers to %s, which is not an image", digest, child.MediaType)
			}
			if _, err := x.manifest(repository, child.Digest.String()); err != nil {
				return v1.Descriptor{}, err
			}
		}
	} else {
		img, err := got.Image()
		if err != nil {
			return v1.Descriptor{}, err
		}
		m, err := v1.ParseManifest(bytes.NewReader(got.Manifest))
		if err != nil {
			return v1.Descriptor{}, fmt.Errorf("image %s is not valid", digest)
		}
		if err = x.blob(m.Config.Digest.String(), m.Config.Size, func() (io.ReadCloser, error) {
			raw, err := img.RawConfigFile()
			return io.NopCloser(bytes.NewReader(raw)), err
		}); err != nil {
			return v1.Descriptor{}, err
		}
		for _, l := range m.Layers {
			layer, err := img.LayerByDigest(l.Digest)
			if err != nil {
				return v1.Descriptor{}, err
			}
			if err = x.blob(l.Digest.String(), l.Size, layer.Compressed); err != nil {
				return v1.Descriptor{}, err
			}
		}
	}
	if err = x.blob(digest, got.Size, func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(got.Manifest)), nil }); err != nil {
		return v1.Descriptor{}, err
	}
	return v1.Descriptor{MediaType: got.MediaType, Digest: got.Digest, Size: got.Size}, nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
