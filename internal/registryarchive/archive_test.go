// SPDX-License-Identifier: Apache-2.0

package registryarchive

import (
	"archive/tar"
	"context"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/validate"
)

func memoryRegistry(t *testing.T) Remote {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	return func(repository string, push bool) (name.Repository, []remote.Option, error) {
		r, err := name.NewRepository(host+"/"+repository, name.Insecure)
		return r, nil, err
	}
}

func push(t *testing.T, open Remote, repository, tag string, v any) string {
	t.Helper()
	repo, opts, _ := open(repository, true)
	switch x := v.(type) {
	case v1.Image:
		if err := remote.Write(repo.Tag(tag), x, opts...); err != nil {
			t.Fatal(err)
		}
		d, _ := x.Digest()
		return d.String()
	case v1.ImageIndex:
		if err := remote.WriteIndex(repo.Tag(tag), x, opts...); err != nil {
			t.Fatal(err)
		}
		d, _ := x.Digest()
		return d.String()
	}
	t.Fatal("not an image")
	return ""
}

func TestExportThenImportKeepsDigests(t *testing.T) {
	ctx := context.Background()
	src, dst := memoryRegistry(t), memoryRegistry(t)
	img, err := random.Image(512, 2)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := random.Index(256, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	docker := mutate.MediaType(img, types.DockerManifestSchema2)
	entries := []Entry{
		{Repository: "shop/web", Tag: "v1", Digest: push(t, src, "shop/web", "v1", img)},
		{Repository: "shop/web", Tag: "latest", Digest: push(t, src, "shop/web", "latest", img)},
		{Repository: "shop/multi", Tag: "v2", Digest: push(t, src, "shop/multi", "v2", idx)},
		{Repository: "shop/docker", Tag: "v1", Digest: push(t, src, "shop/docker", "v1", docker)},
	}
	file := filepath.Join(t.TempDir(), "images.tar")
	out, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := Export(ctx, out, entries, src)
	if err != nil {
		t.Fatal(err)
	}
	out.Close()
	if sum.Images != 4 {
		t.Fatal("summary", sum)
	}

	// Another tool reads the same file as an OCI layout.
	dir := t.TempDir()
	untar(t, file, dir)
	p, err := layout.FromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	ii, err := p.ImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	if err = validate.Index(ii); err != nil {
		t.Fatal("not a valid OCI layout:", err)
	}

	a, err := Open(file, "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if len(a.Entries) != 4 {
		t.Fatal("entries", a.Entries)
	}
	plan, err := a.Plan(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan {
		if c.Action() != "add" {
			t.Fatal("plan into an empty registry", c)
		}
	}
	if _, err = a.Push(ctx, dst, a.Entries); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		repo, _, _ := dst(e.Repository, false)
		d, err := remote.Head(repo.Tag(e.Tag))
		if err != nil || d.Digest.String() != e.Digest {
			t.Fatal("imported digest", e, d, err)
		}
	}
	// A rerun changes nothing; a moved tag shows as a move.
	other, _ := random.Image(128, 1)
	push(t, dst, "shop/web", "v1", other)
	plan, err = a.Plan(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, c := range plan {
		actions[c.String()] = c.Action()
	}
	if actions["shop/web:v1"] != "move" || actions["shop/web:latest"] != "same" {
		t.Fatal("plan after a move", actions)
	}
}

func TestOpenRefusesBadArchives(t *testing.T) {
	ctx := context.Background()
	src := memoryRegistry(t)
	img, _ := random.Image(64, 1)
	e := Entry{Repository: "shop/web", Tag: "v1", Digest: push(t, src, "shop/web", "v1", img)}
	file := filepath.Join(t.TempDir(), "images.tar")
	f, _ := os.Create(file)
	if _, err := Export(ctx, f, []Entry{e}, src); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Corrupt one blob byte: the import refuses it while sending.
	raw, _ := os.ReadFile(file)
	layer, _ := img.Layers()
	ld, _ := layer[0].Digest()
	probe, err := Open(file, "")
	if err != nil {
		t.Fatal(err)
	}
	raw[probe.blobs[ld.Hex].offset+10] ^= 0xff
	probe.Close()
	bad := filepath.Join(t.TempDir(), "bad.tar")
	os.WriteFile(bad, raw, 0o600)
	a, err := Open(bad, "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err = a.Push(ctx, memoryRegistry(t), a.Entries); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatal("a corrupted blob was sent", err)
	}

	// A file without oci-layout is not an archive.
	empty := filepath.Join(t.TempDir(), "empty.tar")
	g, _ := os.Create(empty)
	tw := tar.NewWriter(g)
	tw.Close()
	g.Close()
	if _, err = Open(empty, ""); err == nil {
		t.Fatal("empty tar accepted")
	}
}

func untar(t *testing.T, file, dir string) {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, h.Name)
		os.MkdirAll(filepath.Dir(path), 0o755)
		data, _ := io.ReadAll(tr)
		if err = os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
