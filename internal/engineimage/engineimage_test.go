// SPDX-License-Identifier: Apache-2.0

package engineimage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// memory serves one repository's manifests and blobs the way the registry
// Store does: membership is checked by SelectGraphContent from the root.
func memory(t *testing.T, idx v1.ImageIndex) (Opener, *int) {
	manifests := map[string][2]string{}
	blobs := map[string][]byte{}
	raw, _ := idx.RawManifest()
	d, _ := idx.Digest()
	mt, _ := idx.MediaType()
	manifests[d.String()] = [2]string{string(mt), string(raw)}
	im, _ := idx.IndexManifest()
	for _, desc := range im.Manifests {
		img, _ := idx.Image(desc.Digest)
		raw, _ := img.RawManifest()
		mt, _ := img.MediaType()
		manifests[desc.Digest.String()] = [2]string{string(mt), string(raw)}
		cfg, _ := img.RawConfigFile()
		cd, _ := img.ConfigName()
		blobs[cd.String()] = cfg
		layers, _ := img.Layers()
		for _, l := range layers {
			ld, _ := l.Digest()
			r, _ := l.Compressed()
			b, _ := io.ReadAll(r)
			blobs[ld.String()] = b
		}
	}
	opens := new(int)
	return func(ctx context.Context, q registryclient.GraphContentQuery, offset int64) (registryclient.ContentInfo, io.ReadCloser, error) {
		*opens++
		info, raw, err := registryclient.SelectGraphContent(q, func(digest string) (string, []byte, error) {
			m, ok := manifests[digest]
			if !ok {
				return "", nil, &registryclient.Error{Code: "NOT_FOUND"}
			}
			return m[0], []byte(m[1]), nil
		})
		if err != nil {
			return info, nil, err
		}
		if q.Kind != "manifest" {
			raw = blobs[info.Digest]
		}
		return info, io.NopCloser(bytes.NewReader(raw[offset:])), nil
	}, opens
}

func TestTicketAnswersOnlyItsOwnGraphFromAnOffset(t *testing.T) {
	ctx := context.Background()
	idx, err := random.Index(512, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := memory(t, idx)
	root, _ := idx.Digest()
	repo := "registry.example/team/app"
	tickets := New()
	if _, _, err := tickets.Serve(ctx, Query{Op: "manifest", Repository: repo, Digest: root.String()}); !errors.Is(err, ErrRefused) {
		t.Fatal("answered without a ticket", err)
	}
	release, err := tickets.Issue(ctx, repo+"@"+root.String(), open)
	if err != nil {
		t.Fatal(err)
	}
	im, _ := idx.IndexManifest()
	img, _ := idx.Image(im.Manifests[1].Digest)
	layers, _ := img.Layers()
	ld, _ := layers[1].Digest()
	for _, q := range []Query{{Op: "manifest", Digest: root.String()}, {Op: "manifest", Digest: im.Manifests[1].Digest.String()}, {Op: "blob", Digest: ld.String()}} {
		q.Repository = repo
		a, body, err := tickets.Serve(ctx, q)
		if err != nil {
			t.Fatal(q, err)
		}
		whole, _ := io.ReadAll(body)
		body.Close()
		q.Offset = a.Size / 2
		_, body, err = tickets.Serve(ctx, q)
		if err != nil {
			t.Fatal("resume", err)
		}
		rest, _ := io.ReadAll(body)
		body.Close()
		joined := append(whole[:q.Offset:q.Offset], rest...)
		if int64(len(whole)) != a.Size || fmt.Sprintf("sha256:%x", sha256.Sum256(joined)) != q.Digest || a.ContentType == "" {
			t.Fatal("answer", q, a)
		}
	}
	// A blob asked as a manifest, an unknown digest, another repository.
	if _, _, err := tickets.Serve(ctx, Query{Op: "manifest", Repository: repo, Digest: ld.String()}); !errors.Is(err, ErrNotFound) {
		t.Fatal("blob served as manifest", err)
	}
	if _, _, err := tickets.Serve(ctx, Query{Op: "blob", Repository: repo, Digest: "sha256:" + fmt.Sprintf("%064x", 1)}); !errors.Is(err, ErrNotFound) {
		t.Fatal("digest outside the graph", err)
	}
	if _, _, err := tickets.Serve(ctx, Query{Op: "blob", Repository: "registry.example/team/other", Digest: ld.String()}); !errors.Is(err, ErrRefused) {
		t.Fatal("other repository", err)
	}
	if _, _, err := tickets.Serve(ctx, Query{Op: "blob", Repository: repo, Digest: ld.String(), Offset: 1 << 40}); !errors.Is(err, ErrInvalid) {
		t.Fatal("offset past the end", err)
	}
	release()
	release()
	if _, _, err := tickets.Serve(ctx, Query{Op: "manifest", Repository: repo, Digest: root.String()}); !errors.Is(err, ErrRefused) {
		t.Fatal("answered after release", err)
	}
}

// The engine drops docker.io/library/ from the name; a ticket issued under
// the full name still answers it, and a tagged name is not a repository.
func TestTicketMatchesTheEnginesShortName(t *testing.T) {
	ctx := context.Background()
	idx, err := random.Index(64, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := memory(t, idx)
	root, _ := idx.Digest()
	tickets := New()
	release, err := tickets.Issue(ctx, "docker.io/library/nginx@"+root.String(), open)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, name := range []string{"nginx", "library/nginx", "docker.io/library/nginx"} {
		if _, body, err := tickets.Serve(ctx, Query{Op: "manifest", Repository: name, Digest: root.String()}); err != nil {
			t.Fatal(name, err)
		} else {
			_ = body.Close()
		}
	}
	if _, _, err := tickets.Serve(ctx, Query{Op: "manifest", Repository: "nginx:latest", Digest: root.String()}); !errors.Is(err, ErrInvalid) {
		t.Fatal("tagged name", err)
	}
	if _, _, err := tickets.Serve(ctx, Query{Op: "manifest", Repository: "other/nginx", Digest: root.String()}); !errors.Is(err, ErrRefused) {
		t.Fatal("other repository", err)
	}
}

// A tenant pull (Issue) can never key a ticket under the cluster app names,
// and IssueClusterApp keys nothing else, so the two never share a ticket.
func TestClusterAppNamesAreKeptApartFromTenantPulls(t *testing.T) {
	ctx := context.Background()
	idx, err := random.Index(64, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	open, opens := memory(t, idx)
	root, _ := idx.Digest()
	tickets := New()
	for _, name := range []string{"sfc-cluster-app/web", "docker.io/sfc-cluster-app/web", "index.docker.io/sfc-cluster-app/web"} {
		if _, err := tickets.Issue(ctx, name+"@"+root.String(), open); !errors.Is(err, ErrInvalid) {
			t.Fatal("tenant ticket under a cluster app name", name, err)
		}
	}
	if _, err := tickets.IssueClusterApp(ctx, "registry.example/sfc-cluster-app/web@"+root.String(), open); !errors.Is(err, ErrInvalid) {
		t.Fatal("cluster app ticket outside its prefix", err)
	}
	if *opens != 0 {
		t.Fatal("refused name was walked")
	}
	// memory checks membership like the registry, which wants the full name;
	// clusterapp's own test issues the short sfc-cluster-app/web form.
	release, err := tickets.IssueClusterApp(ctx, "docker.io/sfc-cluster-app/web@"+root.String(), open)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, body, err := tickets.Serve(ctx, Query{Op: "manifest", Repository: "docker.io/sfc-cluster-app/web", Digest: root.String()}); err != nil {
		t.Fatal(err)
	} else {
		_ = body.Close()
	}
}
