// SPDX-License-Identifier: Apache-2.0

package clusterapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/jay94ks/seafield/internal/engineimage"
)

// The engine pulls a cluster app's image from the verified bundle through
// an image ticket: manifest, config and layers, each from any offset.
func TestBundleAnswersTheEnginePull(t *testing.T) {
	img, err := random.Image(4096, 2)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := img.Digest()
	b := Bundle{Image: img, Release: Release{Digest: pin.String()}}
	if b.PullRef(Web) != "sfc-cluster-app/web@"+pin.String() {
		t.Fatal(b.PullRef(Web))
	}
	tickets := engineimage.New()
	release, err := tickets.IssueClusterApp(context.Background(), b.PullRef(Web), b.Open)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := img.Manifest()
	digests := map[string]string{pin.String(): "manifest", m.Config.Digest.String(): "blob"}
	for _, l := range m.Layers {
		digests[l.Digest.String()] = "blob"
	}
	for digest, op := range digests {
		for _, offset := range []int64{0, 7} {
			answer, body, err := tickets.Serve(context.Background(), engineimage.Query{Op: op, Repository: "sfc-cluster-app/web", Digest: digest, Offset: offset})
			if err != nil {
				t.Fatal(op, digest, err)
			}
			raw, _ := io.ReadAll(body)
			body.Close()
			if int64(len(raw)) != answer.Size-offset {
				t.Fatal("short body", op, len(raw), answer.Size, offset)
			}
			if offset == 0 {
				sum := sha256.Sum256(raw)
				if "sha256:"+hex.EncodeToString(sum[:]) != digest {
					t.Fatal("wrong content", op, digest)
				}
			}
		}
	}
	// The ticket matches the normalized name (#710), so the engine's
	// docker.io spelling is the same repository; another one is not.
	_, body, err := tickets.Serve(context.Background(), engineimage.Query{Op: "manifest", Repository: "docker.io/sfc-cluster-app/web", Digest: pin.String()})
	if err != nil {
		t.Fatal("normalized spelling refused", err)
	}
	body.Close()
	if _, _, err := tickets.Serve(context.Background(), engineimage.Query{Op: "manifest", Repository: "sfc-cluster-app/other", Digest: pin.String()}); err == nil {
		t.Fatal("another repository answered")
	}
	release()
	if _, _, err := tickets.Serve(context.Background(), engineimage.Query{Op: "manifest", Repository: "sfc-cluster-app/web", Digest: pin.String()}); err == nil {
		t.Fatal("answered after release")
	}
}
