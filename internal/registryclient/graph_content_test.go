// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type graphContentFixture struct {
	query GraphContentQuery
	items map[string]struct {
		media string
		raw   []byte
	}
	config, layer string
}

func newGraphContentFixture(t *testing.T) graphContentFixture {
	t.Helper()
	f := graphContentFixture{items: map[string]struct {
		media string
		raw   []byte
	}{}}
	config := f.add(t, types.OCIConfigJSON, []byte("{}"))
	layer := f.add(t, types.OCILayer, []byte("layer bytes"))
	f.config, f.layer = config.Digest.String(), layer.Digest.String()
	manifest := f.add(t, types.OCIManifestSchema1, v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: config, Layers: []v1.Descriptor{layer}})
	inner := f.add(t, types.OCIImageIndex, v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{manifest}})
	root := f.add(t, types.OCIImageIndex, v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{inner}})
	f.query = GraphContentQuery{Root: "registry.example/team/app@" + root.Digest.String(), Path: []string{inner.Digest.String(), manifest.Digest.String()}, Kind: "manifest"}
	return f
}

func (f *graphContentFixture) add(t *testing.T, media types.MediaType, value any) v1.Descriptor {
	t.Helper()
	raw, ok := value.([]byte)
	if !ok {
		var err error
		raw, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	f.items[digest] = struct {
		media string
		raw   []byte
	}{string(media), raw}
	hash, err := v1.NewHash(digest)
	if err != nil {
		t.Fatal(err)
	}
	return v1.Descriptor{MediaType: media, Size: int64(len(raw)), Digest: hash}
}

func (f graphContentFixture) reader(t *testing.T, visited *[]string) ManifestReader {
	t.Helper()
	return func(digest string) (string, []byte, error) {
		*visited = append(*visited, digest)
		item, ok := f.items[digest]
		if !ok {
			t.Fatalf("reader called for unapproved/nonexistent metadata: %s", digest)
		}
		return item.media, item.raw, nil
	}
}

func TestGraphContentSelectsOnlyTheWitnessedPathAndKeepsOriginalQueryBytes(t *testing.T) {
	f := newGraphContentFixture(t)
	for _, kind := range []string{"manifest", "config", "layer"} {
		q := f.query
		q.Kind = kind
		if kind == "config" {
			q.Digest = f.config
		} else if kind == "layer" {
			q.Digest = f.layer
		}
		var visited []string
		info, raw, err := SelectGraphContent(q, f.reader(t, &visited))
		_, root, _ := strings.Cut(q.Root, "@")
		want := append([]string{root}, q.Path...)
		if err != nil || !info.Valid(q.Selected()) || !slices.Equal(visited, want) || (raw != nil) != (kind == "manifest") {
			t.Fatal("not an exact metadata-only path", q, info, visited, err)
		}
		if kind == "manifest" && !bytes.Equal(raw, f.items[info.Digest].raw) {
			t.Fatal("changed selected manifest bytes")
		}
	}
	// Adding an internal graph query does not change the public schema-1 query.
	legacy := ContentQuery{Ref: f.query.Root, Kind: "manifest"}
	raw, _ := json.Marshal(legacy)
	want, _ := json.Marshal(struct{ Ref, Kind, Digest string }{legacy.Ref, legacy.Kind, legacy.Digest})
	if !bytes.Equal(raw, want) {
		t.Fatal("legacy immutable read changed")
	}
}

func TestGraphContentRejectsUnrelatedPathBeforeChildIO(t *testing.T) {
	f := newGraphContentFixture(t)
	q := f.query
	q.Path = []string{"sha256:" + strings.Repeat("f", 64)}
	var visited []string
	if _, _, err := SelectGraphContent(q, f.reader(t, &visited)); ResultCode(err) != "NOT_FOUND" || len(visited) != 1 {
		t.Fatal("unwitnessed child fetched", visited, err)
	}
	for _, change := range []func(*GraphContentQuery){
		func(q *GraphContentQuery) { q.Root = "registry.example/team/app:latest" },
		func(q *GraphContentQuery) { q.Path[0] = "https://foreign.example/manifest" },
		func(q *GraphContentQuery) { q.Path[1] = q.Path[0] },
		func(q *GraphContentQuery) { _, q.Path[0], _ = strings.Cut(q.Root, "@") },
		func(q *GraphContentQuery) { q.Path = make([]string, 9) },
		func(q *GraphContentQuery) { q.Kind = "blob" },
		func(q *GraphContentQuery) { q.Kind = "manifest"; q.Digest = f.layer },
	} {
		q := f.query
		q.Path = slices.Clone(q.Path)
		change(&q)
		visited = nil
		if _, _, err := SelectGraphContent(q, f.reader(t, &visited)); err == nil || len(visited) != 0 {
			t.Fatal("invalid query reached reader", q, visited, err)
		}
	}
}

func TestGraphContentChecksParentSizeMediaHashAndForeignDescriptors(t *testing.T) {
	for _, kind := range []string{"size", "media", "foreign", "embedded", "duplicate", "hash", "error"} {
		t.Run(kind, func(t *testing.T) {
			f := newGraphContentFixture(t)
			_, rootDigest, _ := strings.Cut(f.query.Root, "@")
			var root v1.IndexManifest
			if err := json.Unmarshal(f.items[rootDigest].raw, &root); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "size":
				root.Manifests[0].Size++
			case "media":
				root.Manifests[0].MediaType = types.OCIManifestSchema1
			case "foreign":
				root.Manifests[0].URLs = []string{"https://foreign.example/index"}
			case "embedded":
				root.Manifests[0].Data = []byte("inline data")
			case "duplicate":
				root.Manifests = append(root.Manifests, root.Manifests[0])
				root.Manifests[1].Size++
			}
			if kind != "hash" && kind != "error" {
				descriptor := f.add(t, types.OCIImageIndex, root)
				f.query.Root = "registry.example/team/app@" + descriptor.Digest.String()
			}
			var visited []string
			read := f.reader(t, &visited)
			if kind == "hash" {
				item := f.items[f.query.Path[0]]
				item.raw = append(slices.Clone(item.raw), ' ')
				f.items[f.query.Path[0]] = item
			}
			if kind == "error" {
				read = func(string) (string, []byte, error) { return "", nil, &Error{Code: "CLOSED"} }
			}
			if _, _, err := SelectGraphContent(f.query, read); err == nil {
				t.Fatal("unverified graph accepted", kind)
			}
			if (kind == "foreign" || kind == "embedded" || kind == "duplicate") && len(visited) != 1 {
				t.Fatal("invalid parent fetched a child", visited)
			}
			if kind == "duplicate" {
				q := f.query
				q.Path = nil
				visited = nil
				if _, _, err := SelectGraphContent(q, f.reader(t, &visited)); err == nil || len(visited) != 1 {
					t.Fatal("conflicting index escaped as root metadata", visited, err)
				}
			}
		})
	}
}
