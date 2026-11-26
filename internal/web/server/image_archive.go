// SPDX-License-Identifier: Apache-2.0

package server

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
)

// Image archives the web uploads to a built-in registry: `docker save`
// output (legacy manifest.json, or the OCI layout Docker 25+ writes) and OCI
// image layouts, as .tar or gzip-compressed. Nothing is extracted: the tar is
// indexed once and blobs are read in place.

const (
	mediaOCIManifest   = "application/vnd.oci.image.manifest.v1+json"
	mediaOCIIndex      = "application/vnd.oci.image.index.v1+json"
	mediaDockerV2      = "application/vnd.docker.distribution.manifest.v2+json"
	mediaDockerList    = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIConfig     = "application/vnd.oci.image.config.v1+json"
	mediaOCILayer      = "application/vnd.oci.image.layer.v1.tar"
	mediaOCILayerGzip  = "application/vnd.oci.image.layer.v1.tar+gzip"
	maxArchiveEntries  = 100000
	maxDecompressBytes = 32 << 30
)

var errArchiveFormat = errors.New("not a docker save or OCI image archive (.tar, .tar.gz or .tgz)")

func isIndexType(mt string) bool { return mt == mediaOCIIndex || mt == mediaDockerList }
func isImageType(mt string) bool { return mt == mediaOCIManifest || mt == mediaDockerV2 }

// plainTar returns the path of the uncompressed tar of src: src itself, or
// dst after gunzip. zstd is refused (no decoder in this build).
func plainTar(src, dst string) (string, error) {
	f, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	switch {
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		zr, err := gzip.NewReader(bufio.NewReader(f))
		if err != nil {
			return "", errArchiveFormat
		}
		out, err := os.Create(dst)
		if err != nil {
			return "", err
		}
		n, err := io.Copy(out, io.LimitReader(zr, maxDecompressBytes+1))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dst)
			return "", errArchiveFormat
		}
		if n > maxDecompressBytes {
			os.Remove(dst)
			return "", errors.New("the archive unpacks to more than 32 GiB")
		}
		return dst, nil
	case len(head) >= 4 && head[0] == 0x28 && head[1] == 0xb5 && head[2] == 0x2f && head[3] == 0xfd:
		return "", errors.New(".tar.zst is not supported yet; use .tar or .tar.gz")
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return src, nil
	}
	return "", errArchiveFormat
}

type tarEntry struct{ off, size int64 }

type imageArchive struct {
	f       *os.File
	entries map[string]tarEntry
	oci     bool
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// openImageArchive indexes the regular files of a plain tar.
func openImageArchive(tarPath string) (*imageArchive, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	a := &imageArchive{f: f, entries: map[string]tarEntry{}}
	cr := &countReader{r: f}
	tr := tar.NewReader(cr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			f.Close()
			return nil, errArchiveFormat
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if len(a.entries) >= maxArchiveEntries {
			f.Close()
			return nil, errors.New("the archive has too many files")
		}
		// tar.Reader has read the header; the data starts here.
		a.entries[cleanEntry(h.Name)] = tarEntry{off: cr.n, size: h.Size}
	}
	_, a.oci = a.entries["oci-layout"]
	if _, ok := a.entries["index.json"]; !ok {
		a.oci = false
	}
	if _, ok := a.entries["manifest.json"]; !ok && !a.oci {
		f.Close()
		return nil, errArchiveFormat
	}
	return a, nil
}

func cleanEntry(n string) string { return strings.TrimPrefix(path.Clean("/"+n), "/") }

func (a *imageArchive) Close() error { return a.f.Close() }

func (a *imageArchive) section(name string) (*io.SectionReader, bool) {
	e, ok := a.entries[name]
	if !ok {
		return nil, false
	}
	return io.NewSectionReader(a.f, e.off, e.size), true
}

func (a *imageArchive) readFile(name string, max int64) ([]byte, error) {
	r, ok := a.section(name)
	if !ok {
		return nil, fmt.Errorf("%s: not in the archive", name)
	}
	if r.Size() > max {
		return nil, fmt.Errorf("%s: too large", name)
	}
	return io.ReadAll(r)
}

func blobName(digest string) string {
	alg, hx, _ := strings.Cut(digest, ":")
	return "blobs/" + alg + "/" + hx
}

func (a *imageArchive) hasBlob(digest string) bool {
	_, ok := a.entries[blobName(digest)]
	return ok
}

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	} `json:"platform,omitempty"`
}

type ociManifest struct {
	MediaType string          `json:"mediaType"`
	Config    ociDescriptor   `json:"config"`
	Layers    []ociDescriptor `json:"layers"`
	Manifests []ociDescriptor `json:"manifests"`
}

func (d ociDescriptor) platform() string {
	if d.Platform == nil || d.Platform.OS == "" || d.Platform.OS == "unknown" {
		return ""
	}
	p := d.Platform.OS + "/" + d.Platform.Architecture
	if d.Platform.Variant != "" {
		p += "/" + d.Platform.Variant
	}
	return p
}

// readBlobJSON reads a small blob and checks its digest.
func (a *imageArchive) readBlobJSON(digest string, v any) ([]byte, error) {
	b, err := a.readFile(blobName(digest), maxManifestBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("%s: content does not match the digest", digest)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return nil, fmt.Errorf("%s: not JSON", digest)
	}
	return b, nil
}

// archiveItem is one image (or multi-platform index) the archive offers.
type archiveItem struct {
	Index     int      `json:"index"`
	Kind      string   `json:"kind"` // image / index
	Refs      []string `json:"refs"` // names in the archive
	Platforms []string `json:"platforms"`
	Bytes     int64    `json:"bytes"`
	Layers    int      `json:"layers"`
	Digest    string   `json:"digest,omitempty"` // manifest digest (OCI)
	plan      *pushPlan
}

type pushBlob struct {
	Digest, MediaType string
	Size              int64
	open              func() (io.Reader, error)
}

type pushManifest struct {
	Digest, MediaType string
	Body              []byte
}

// pushPlan: blobs, then manifests in order; the last one gets the tag.
type pushPlan struct {
	Blobs     []pushBlob
	Manifests []pushManifest
}

func (p *pushPlan) digest() string { return p.Manifests[len(p.Manifests)-1].Digest }

func (a *imageArchive) blob(d ociDescriptor) pushBlob {
	name := blobName(d.Digest)
	return pushBlob{Digest: d.Digest, MediaType: d.MediaType, Size: d.Size, open: func() (io.Reader, error) {
		r, ok := a.section(name)
		if !ok {
			return nil, fmt.Errorf("%s: not in the archive", d.Digest)
		}
		return r, nil
	}}
}

// imagePlan plans one OCI image manifest; nil when a blob is missing.
func (a *imageArchive) imagePlan(d ociDescriptor) (*pushPlan, string, int64, int, error) {
	var m ociManifest
	body, err := a.readBlobJSON(d.Digest, &m)
	if err != nil {
		return nil, "", 0, 0, err
	}
	if !a.hasBlob(m.Config.Digest) {
		return nil, "", 0, 0, nil
	}
	p := &pushPlan{Blobs: []pushBlob{a.blob(m.Config)}}
	var total int64
	for _, l := range m.Layers {
		if !a.hasBlob(l.Digest) {
			return nil, "", 0, 0, nil
		}
		p.Blobs = append(p.Blobs, a.blob(l))
		total += l.Size
	}
	mt := m.MediaType
	if mt == "" {
		mt = d.MediaType
	}
	p.Manifests = []pushManifest{{Digest: d.Digest, MediaType: mt, Body: body}}
	plat := d.platform()
	if plat == "" {
		var cfg struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant"`
		}
		if _, err := a.readBlobJSON(m.Config.Digest, &cfg); err == nil && cfg.OS != "" {
			plat = cfg.OS + "/" + cfg.Architecture
			if cfg.Variant != "" {
				plat += "/" + cfg.Variant
			}
		}
	}
	return p, plat, total, len(m.Layers), nil
}

func refsOf(d ociDescriptor) []string {
	var refs []string
	for _, k := range []string{"io.containerd.image.name", "org.opencontainers.image.ref.name"} {
		if v := d.Annotations[k]; v != "" && !slices.Contains(refs, v) {
			refs = append(refs, v)
		}
	}
	return refs
}

// items lists what the archive can push.
func (a *imageArchive) items() ([]archiveItem, error) {
	var out []archiveItem
	add := func(it archiveItem) {
		it.Index = len(out)
		if it.Refs == nil {
			it.Refs = []string{}
		}
		if it.Platforms == nil {
			it.Platforms = []string{}
		}
		out = append(out, it)
	}
	if a.oci {
		raw, err := a.readFile("index.json", maxManifestBytes)
		if err != nil {
			return nil, err
		}
		var idx ociManifest
		if json.Unmarshal(raw, &idx) != nil {
			return nil, errors.New("index.json: not JSON")
		}
		for _, d := range idx.Manifests {
			switch {
			case isImageType(d.MediaType):
				p, plat, total, n, err := a.imagePlan(d)
				if err != nil {
					return nil, err
				}
				if p == nil {
					continue
				}
				it := archiveItem{Kind: "image", Refs: refsOf(d), Bytes: total, Layers: n, Digest: d.Digest, plan: p}
				if plat != "" {
					it.Platforms = []string{plat}
				}
				add(it)
			case isIndexType(d.MediaType):
				var child ociManifest
				body, err := a.readBlobJSON(d.Digest, &child)
				if err != nil {
					return nil, err
				}
				whole := &pushPlan{}
				var images []archiveItem
				complete := true
				var total int64
				var layers int
				var plats []string
				for _, cd := range child.Manifests {
					if !isImageType(cd.MediaType) || !a.hasBlob(cd.Digest) {
						complete = false
						continue
					}
					p, plat, t, n, err := a.imagePlan(cd)
					if err != nil {
						return nil, err
					}
					if p == nil {
						complete = false
						continue
					}
					whole.Blobs = append(whole.Blobs, p.Blobs...)
					whole.Manifests = append(whole.Manifests, p.Manifests...)
					total += t
					layers += n
					if plat != "" {
						plats = append(plats, plat)
						it := archiveItem{Kind: "image", Refs: refsOf(d), Platforms: []string{plat}, Bytes: t, Layers: n, Digest: cd.Digest, plan: p}
						images = append(images, it)
					}
				}
				if complete {
					mt := child.MediaType
					if mt == "" {
						mt = d.MediaType
					}
					whole.Manifests = append(whole.Manifests, pushManifest{Digest: d.Digest, MediaType: mt, Body: body})
					add(archiveItem{Kind: "index", Refs: refsOf(d), Platforms: plats, Bytes: total, Layers: layers, Digest: d.Digest, plan: whole})
					continue
				}
				// Part of a multi-platform image (Docker saves only what
				// it pulled): offer each present platform on its own.
				for _, it := range images {
					add(it)
				}
			}
		}
		return out, nil
	}
	return a.legacyItems()
}

// legacyItems reads a pre-OCI `docker save` (manifest.json with config and
// layer paths) and plans an OCI manifest for each image.
func (a *imageArchive) legacyItems() ([]archiveItem, error) {
	raw, err := a.readFile("manifest.json", maxManifestBytes)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Config   string
		RepoTags []string
		Layers   []string
	}
	if json.Unmarshal(raw, &entries) != nil {
		return nil, errors.New("manifest.json: not JSON")
	}
	var out []archiveItem
	for _, e := range entries {
		cfgBody, err := a.readFile(cleanEntry(e.Config), maxManifestBytes)
		if err != nil {
			return nil, err
		}
		var cfg struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		}
		_ = json.Unmarshal(cfgBody, &cfg)
		sum := sha256.Sum256(cfgBody)
		cfgDigest := "sha256:" + hex.EncodeToString(sum[:])
		it := archiveItem{Index: len(out), Kind: "image", Refs: e.RepoTags, Platforms: []string{}, Layers: len(e.Layers)}
		if it.Refs == nil {
			it.Refs = []string{}
		}
		if cfg.OS != "" {
			it.Platforms = []string{cfg.OS + "/" + cfg.Architecture}
		}
		var layers []string
		for _, l := range e.Layers {
			name := cleanEntry(l)
			ent, ok := a.entries[name]
			if !ok {
				return nil, fmt.Errorf("%s: not in the archive", l)
			}
			it.Bytes += ent.size
			layers = append(layers, name)
		}
		cfgCopy := cfgBody
		it.plan = &pushPlan{}
		// Layer digests are computed when the push starts (legacyPlan).
		it.plan.Manifests = []pushManifest{{MediaType: mediaOCIManifest}}
		it.plan.Blobs = []pushBlob{{Digest: cfgDigest, MediaType: mediaOCIConfig, Size: int64(len(cfgCopy)),
			open: func() (io.Reader, error) { return strings.NewReader(string(cfgCopy)), nil }}}
		for _, name := range layers {
			it.plan.Blobs = append(it.plan.Blobs, pushBlob{MediaType: name, Size: a.entries[name].size})
		}
		out = append(out, it)
	}
	return out, nil
}

// finishLegacy hashes the layers of a legacy item (reading them once) and
// writes its OCI manifest. Plans from OCI layouts are already complete.
func (a *imageArchive) finishLegacy(p *pushPlan) error {
	if p.Manifests[0].Body != nil {
		return nil
	}
	m := ociManifest{Config: ociDescriptor{MediaType: mediaOCIConfig, Digest: p.Blobs[0].Digest, Size: p.Blobs[0].Size}}
	for i := 1; i < len(p.Blobs); i++ {
		name := p.Blobs[i].MediaType
		r, _ := a.section(name)
		head := make([]byte, 2)
		_, _ = r.ReadAt(head, 0)
		mt := mediaOCILayer
		if head[0] == 0x1f && head[1] == 0x8b {
			mt = mediaOCILayerGzip
		}
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(r, 0, r.Size())); err != nil {
			return err
		}
		d := "sha256:" + hex.EncodeToString(h.Sum(nil))
		p.Blobs[i] = a.blob(ociDescriptor{Digest: d, MediaType: mt, Size: r.Size()})
		section := name
		p.Blobs[i].open = func() (io.Reader, error) {
			r, ok := a.section(section)
			if !ok {
				return nil, fmt.Errorf("%s: not in the archive", section)
			}
			return r, nil
		}
		m.Layers = append(m.Layers, ociDescriptor{MediaType: mt, Digest: d, Size: r.Size()})
	}
	body, _ := json.Marshal(struct {
		SchemaVersion int             `json:"schemaVersion"`
		MediaType     string          `json:"mediaType"`
		Config        ociDescriptor   `json:"config"`
		Layers        []ociDescriptor `json:"layers"`
	}{2, mediaOCIManifest, m.Config, m.Layers})
	sum := sha256.Sum256(body)
	p.Manifests[0] = pushManifest{Digest: "sha256:" + hex.EncodeToString(sum[:]), MediaType: mediaOCIManifest, Body: body}
	return nil
}
