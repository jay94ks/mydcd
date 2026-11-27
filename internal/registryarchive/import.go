// SPDX-License-Identifier: Apache-2.0

package registryarchive

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Archive is an opened OCI layout tar. Blobs are read in place from the
// file, so an import needs no second copy on disk.
type Archive struct {
	f       *os.File
	blobs   map[string]section // sha256 hex
	Entries []Entry
}

type section struct{ offset, size int64 }

// Open indexes the tar at path and reads its index.json. repository names
// the repository of entries that carry none (a file from another tool);
// it may be empty when every entry has one.
func Open(file, repository string) (*Archive, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	a := &Archive{f: f, blobs: map[string]section{}}
	if err = a.scan(repository); err != nil {
		f.Close()
		return nil, err
	}
	return a, nil
}

func (a *Archive) Close() error { return a.f.Close() }

func (a *Archive) scan(repository string) error {
	tr := tar.NewReader(a.f)
	var layout, index []byte
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrArchive, err)
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return fmt.Errorf("%w: %s is not a regular file", ErrArchive, h.Name)
		}
		switch {
		case name == layoutFile:
			if layout, err = readSmall(tr, h.Size); err != nil {
				return err
			}
		case name == indexFile:
			if index, err = readSmall(tr, h.Size); err != nil {
				return err
			}
		case strings.HasPrefix(name, "blobs/sha256/"):
			hexDigest := strings.TrimPrefix(name, "blobs/sha256/")
			if _, err := digestHex("sha256:" + hexDigest); err != nil {
				return err
			}
			offset, err := a.f.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}
			if _, dup := a.blobs[hexDigest]; dup {
				return fmt.Errorf("%w: blob %s appears twice", ErrArchive, hexDigest)
			}
			a.blobs[hexDigest] = section{offset, h.Size}
		default:
			// Other files (a tool's own metadata) are ignored.
		}
	}
	var l struct{ ImageLayoutVersion string }
	if json.Unmarshal(layout, &l) != nil || l.ImageLayoutVersion != "1.0.0" {
		return fmt.Errorf("%w: no oci-layout 1.0.0 file", ErrArchive)
	}
	idx, err := v1.ParseIndexManifest(bytes.NewReader(index))
	if err != nil || index == nil {
		return fmt.Errorf("%w: no valid index.json", ErrArchive)
	}
	seen := map[string]bool{}
	for _, d := range idx.Manifests {
		if _, ok := manifestType(d.MediaType); !ok {
			return fmt.Errorf("%w: index.json entry %s is %s, not an image", ErrArchive, d.Digest, d.MediaType)
		}
		e := Entry{Repository: d.Annotations[Repository], Tag: d.Annotations[RefName], Digest: d.Digest.String(), MediaType: d.MediaType, Size: d.Size}
		if e.Repository == "" {
			e.Repository = repository
		}
		if e.Tag == "" {
			return fmt.Errorf("%w: image %s has no tag (%s)", ErrArchive, d.Digest, RefName)
		}
		if e.Repository == "" {
			return fmt.Errorf("%w: image %s has no repository; give one with --repository", ErrArchive, e.Tag)
		}
		if !ValidRepository(e.Repository) || !ValidTag(e.Tag) {
			return fmt.Errorf("%w: invalid image %s", ErrArchive, e)
		}
		if seen[e.String()] {
			return fmt.Errorf("%w: %s appears twice", ErrArchive, e)
		}
		seen[e.String()] = true
		if _, err := a.manifest(e.Digest, e.MediaType); err != nil {
			return err
		}
		a.Entries = append(a.Entries, e)
	}
	if len(a.Entries) == 0 || len(a.Entries) > MaxEntries {
		return fmt.Errorf("%w: needs 1 to %d tagged images", ErrArchive, MaxEntries)
	}
	return a.walk(func(string, int64) {})
}

func readSmall(r io.Reader, size int64) ([]byte, error) {
	if size > MaxManifestBytes {
		return nil, fmt.Errorf("%w: a metadata file is too large", ErrArchive)
	}
	return io.ReadAll(io.LimitReader(r, size))
}

// open returns a verified reader of one blob.
func (a *Archive) open(digest string) (io.ReadCloser, int64, error) {
	hexDigest, err := digestHex(digest)
	if err != nil {
		return nil, 0, err
	}
	s, ok := a.blobs[hexDigest]
	if !ok {
		return nil, 0, fmt.Errorf("%w: blob %s is missing", ErrArchive, digest)
	}
	return &verified{r: io.NewSectionReader(a.f, s.offset, s.size), h: sha256.New(), want: hexDigest, left: s.size}, s.size, nil
}

// verified fails the last read when the blob does not hash to its name.
type verified struct {
	r    io.Reader
	h    hash.Hash
	want string
	left int64
}

func (v *verified) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	v.h.Write(p[:n])
	v.left -= int64(n)
	if errors.Is(err, io.EOF) && (v.left != 0 || hex.EncodeToString(v.h.Sum(nil)) != v.want) {
		return n, fmt.Errorf("%w: blob sha256:%s does not match its digest", ErrArchive, v.want)
	}
	return n, err
}
func (v *verified) Close() error { return nil }

func (a *Archive) read(digest string) ([]byte, error) {
	r, size, err := a.open(digest)
	if err != nil {
		return nil, err
	}
	if size > MaxManifestBytes {
		return nil, fmt.Errorf("%w: manifest %s is too large", ErrArchive, digest)
	}
	return io.ReadAll(r)
}

func (a *Archive) manifest(digest string, mt types.MediaType) ([]byte, error) {
	raw, err := a.read(digest)
	if err != nil {
		return nil, err
	}
	var probe struct{ MediaType types.MediaType }
	if json.Unmarshal(raw, &probe) != nil || probe.MediaType != "" && probe.MediaType != mt {
		return nil, fmt.Errorf("%w: manifest %s is not %s", ErrArchive, digest, mt)
	}
	return raw, nil
}

// walk calls blob once for every blob the entries need, checking that each
// is in the file.
func (a *Archive) walk(blob func(digest string, size int64)) error {
	seen := map[string]bool{}
	var visit func(digest string, mt types.MediaType, size int64) error
	visit = func(digest string, mt types.MediaType, size int64) error {
		if seen[digest] {
			return nil
		}
		seen[digest] = true
		raw, err := a.manifest(digest, mt)
		if err != nil {
			return err
		}
		blob(digest, size)
		isIndex, _ := manifestType(mt)
		if isIndex {
			idx, err := v1.ParseIndexManifest(bytes.NewReader(raw))
			if err != nil || len(idx.Manifests) > maxChildren {
				return fmt.Errorf("%w: index %s is not valid", ErrArchive, digest)
			}
			for _, c := range idx.Manifests {
				if _, ok := manifestType(c.MediaType); !ok {
					return fmt.Errorf("%w: index %s refers to %s, which is not an image", ErrArchive, digest, c.MediaType)
				}
				if err := visit(c.Digest.String(), c.MediaType, c.Size); err != nil {
					return err
				}
			}
			return nil
		}
		m, err := v1.ParseManifest(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("%w: image %s is not valid", ErrArchive, digest)
		}
		for _, d := range append([]v1.Descriptor{m.Config}, m.Layers...) {
			hexDigest, err := digestHex(d.Digest.String())
			if err != nil {
				return err
			}
			s, ok := a.blobs[hexDigest]
			if !ok || s.size != d.Size {
				return fmt.Errorf("%w: blob %s of image %s is missing or has another size", ErrArchive, d.Digest, digest)
			}
			if !seen[d.Digest.String()] {
				seen[d.Digest.String()] = true
				blob(d.Digest.String(), d.Size)
			}
		}
		return nil
	}
	for _, e := range a.Entries {
		if err := visit(e.Digest, e.MediaType, e.Size); err != nil {
			return err
		}
	}
	return nil
}

// Bytes is the size of every blob the entries need, each counted once.
func (a *Archive) Bytes() (blobs int, total int64) {
	_ = a.walk(func(_ string, size int64) { blobs++; total += size })
	return blobs, total
}

// Change is what an import would do to one tag.
type Change struct {
	Entry
	Current string // the tag's digest in the registry now, "" when absent
}

func (c Change) Action() string {
	switch c.Current {
	case "":
		return "add"
	case c.Digest:
		return "same"
	}
	return "move"
}

// Plan reads every tag's current digest in the registry.
func (a *Archive) Plan(ctx context.Context, open Remote) ([]Change, error) {
	var out []Change
	for _, e := range a.Entries {
		repo, opts, err := open(e.Repository, false)
		if err != nil {
			return nil, err
		}
		c := Change{Entry: e}
		d, err := remote.Head(repo.Tag(e.Tag), append(opts, remote.WithContext(ctx))...)
		var terr *transport.Error
		switch {
		case err == nil:
			c.Current = d.Digest.String()
		case errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound:
		default:
			return nil, fmt.Errorf("%s: %w", e, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// Push sends each entry and tags it. The registry is asked for each blob
// first, so a blob it already has (or a rerun after an interruption) is
// not sent again. Images are sent by digest; only the tag moves.
func (a *Archive) Push(ctx context.Context, open Remote, entries []Entry) (Summary, error) {
	var sum Summary
	for _, e := range entries {
		repo, opts, err := open(e.Repository, true)
		if err != nil {
			return sum, err
		}
		opts = append(opts, remote.WithContext(ctx))
		if isIndex, _ := manifestType(e.MediaType); isIndex {
			idx, err := a.index(e.Digest, e.MediaType, e.Size)
			if err == nil {
				err = remote.WriteIndex(repo.Tag(e.Tag), idx, opts...)
			}
			if err != nil {
				return sum, fmt.Errorf("%s: %w", e, err)
			}
		} else {
			img, err := a.image(e.Digest, e.MediaType)
			if err == nil {
				err = remote.Write(repo.Tag(e.Tag), img, opts...)
			}
			if err != nil {
				return sum, fmt.Errorf("%s: %w", e, err)
			}
		}
		sum.Images++
	}
	return sum, nil
}

// archiveImage is one image manifest of the file, for remote.Write.
type archiveImage struct {
	a   *Archive
	raw []byte
	mt  types.MediaType
	m   *v1.Manifest
}

func (a *Archive) image(digest string, mt types.MediaType) (v1.Image, error) {
	raw, err := a.manifest(digest, mt)
	if err != nil {
		return nil, err
	}
	m, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: image %s is not valid", ErrArchive, digest)
	}
	return partial.CompressedToImage(archiveImage{a, raw, mt, m})
}

func (i archiveImage) RawConfigFile() ([]byte, error)      { return i.a.read(i.m.Config.Digest.String()) }
func (i archiveImage) MediaType() (types.MediaType, error) { return i.mt, nil }
func (i archiveImage) RawManifest() ([]byte, error)        { return i.raw, nil }
func (i archiveImage) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	if h == i.m.Config.Digest {
		return archiveLayer{i.a, i.m.Config}, nil
	}
	for _, l := range i.m.Layers {
		if l.Digest == h {
			return archiveLayer{i.a, l}, nil
		}
	}
	return nil, fmt.Errorf("%w: image has no blob %s", ErrArchive, h)
}

type archiveLayer struct {
	a *Archive
	d v1.Descriptor
}

func (l archiveLayer) Digest() (v1.Hash, error) { return l.d.Digest, nil }
func (l archiveLayer) Size() (int64, error)     { return l.d.Size, nil }
func (l archiveLayer) MediaType() (types.MediaType, error) {
	return l.d.MediaType, nil
}
func (l archiveLayer) Compressed() (io.ReadCloser, error) {
	r, _, err := l.a.open(l.d.Digest.String())
	return r, err
}

// archiveIndex is one index manifest of the file, for remote.WriteIndex.
type archiveIndex struct {
	a      *Archive
	raw    []byte
	mt     types.MediaType
	digest v1.Hash
	m      *v1.IndexManifest
}

func (a *Archive) index(digest string, mt types.MediaType, size int64) (v1.ImageIndex, error) {
	raw, err := a.manifest(digest, mt)
	if err != nil {
		return nil, err
	}
	m, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil || int64(len(raw)) != size {
		return nil, fmt.Errorf("%w: index %s is not valid", ErrArchive, digest)
	}
	h, err := v1.NewHash(digest)
	if err != nil {
		return nil, err
	}
	return archiveIndex{a, raw, mt, h, m}, nil
}

func (x archiveIndex) MediaType() (types.MediaType, error)       { return x.mt, nil }
func (x archiveIndex) Digest() (v1.Hash, error)                  { return x.digest, nil }
func (x archiveIndex) Size() (int64, error)                      { return int64(len(x.raw)), nil }
func (x archiveIndex) IndexManifest() (*v1.IndexManifest, error) { return x.m, nil }
func (x archiveIndex) RawManifest() ([]byte, error)              { return x.raw, nil }
func (x archiveIndex) child(h v1.Hash) (v1.Descriptor, error) {
	for _, d := range x.m.Manifests {
		if d.Digest == h {
			return d, nil
		}
	}
	return v1.Descriptor{}, fmt.Errorf("%w: index has no manifest %s", ErrArchive, h)
}
func (x archiveIndex) Image(h v1.Hash) (v1.Image, error) {
	d, err := x.child(h)
	if err != nil {
		return nil, err
	}
	return x.a.image(h.String(), d.MediaType)
}
func (x archiveIndex) ImageIndex(h v1.Hash) (v1.ImageIndex, error) {
	d, err := x.child(h)
	if err != nil {
		return nil, err
	}
	return x.a.index(h.String(), d.MediaType, d.Size)
}
