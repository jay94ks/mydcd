// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/jay94ks/seafield/internal/clusterapp"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/engineimage"
)

// The cluster app image reaches the Engine only as a digest pull that
// purpose 37 answers from the verified bundle while the pull runs. The
// Engine's image ID must be the bundle's manifest digest (the containerd
// image store Seafield uses) or its config digest.
func TestClusterAppImageIsPulledThroughATicket(t *testing.T) {
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := img.Digest()
	config, _ := img.ConfigName()
	bundle := clusterapp.Bundle{Image: img, Release: clusterapp.Release{Digest: pin.String()}}
	r := &Runtime{engineImages: engineimage.New()}

	for _, mode := range []string{"ok", "manifest-id", "other-id"} {
		t.Run(mode, func(t *testing.T) {
			var pulled atomic.Bool
			var served atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				switch {
				case q.URL.Path == "/_ping":
					w.Header().Set("API-Version", "1.56")
					_, _ = fmt.Fprint(w, "OK")
				case strings.HasSuffix(q.URL.Path, "/json"):
					if !pulled.Load() {
						w.WriteHeader(http.StatusNotFound)
						_, _ = fmt.Fprint(w, `{"message":"not present"}`)
						return
					}
					id := config.String()
					if mode == "manifest-id" {
						id = pin.String()
					}
					if mode == "other-id" {
						id = "sha256:" + strings.Repeat("b", 64)
					}
					_, _ = fmt.Fprintf(w, `{"Id":%q}`, id)
				case strings.HasSuffix(q.URL.Path, "/images/create"):
					repository := q.URL.Query().Get("fromImage")
					if repository != "docker.io/sfc-cluster-app/web" {
						t.Errorf("pulled %q", repository)
					}
					// While the pull runs, the engine's requests for the
					// pulled repository are answered.
					_, body, err := r.engineImages.Serve(q.Context(), engineimage.Query{Op: "manifest", Repository: repository, Digest: pin.String()})
					if err != nil {
						t.Errorf("manifest not served during the pull: %v", err)
					} else {
						_, _ = io.Copy(io.Discard, body)
						body.Close()
						served.Add(1)
					}
					pulled.Store(true)
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprintln(w, `{"status":"done"}`)
				default:
					http.NotFound(w, q)
				}
			})
			root, err := os.MkdirTemp("", "sfc-app-pull-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			listener, err := net.Listen("unix", filepath.Join(root, "engine.sock"))
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: handler}
			done := make(chan struct{})
			go func() { _ = server.Serve(listener); close(done) }()
			defer func() { _ = server.Close(); <-done }()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := engine.Open(ctx, "unix://"+listener.Addr().String(), "owner")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.Images = r.engineImages
			r.docker = c

			id, err := r.pullClusterAppImage(ctx, clusterapp.Web, bundle)
			if mode == "ok" && (err != nil || id != config.String()) || mode == "manifest-id" && (err != nil || id != pin.String()) {
				t.Fatal(id, err)
			}
			if mode == "other-id" && !errors.Is(err, clusterapp.ErrImage) {
				t.Fatal("wrong image ID accepted", id, err)
			}
			if served.Load() != 1 {
				t.Fatal("pull did not go through the ticket")
			}
			if _, _, err := r.engineImages.Serve(ctx, engineimage.Query{Op: "manifest", Repository: "sfc-cluster-app/web", Digest: pin.String()}); !errors.Is(err, engineimage.ErrRefused) {
				t.Fatal("ticket outlived the pull", err)
			}
		})
	}
}
