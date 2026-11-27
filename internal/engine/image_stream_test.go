// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

func TestImageStreamKeepsProgressAndOriginalCancellation(t *testing.T) {
	for _, mode := range []string{"progress", "idle-header", "idle-body", "parent", "remote-error"} {
		t.Run(mode, func(t *testing.T) {
			const idle = 200 * time.Millisecond
			id := "sha256:" + strings.Repeat("a", 64)
			ref := "docker.io/library/fixture@" + id
			var loaded atomic.Bool
			var pulls atomic.Int32
			ended := make(chan struct{})
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_ping" {
					w.Header().Set("API-Version", "1.56")
					_, _ = fmt.Fprint(w, "OK")
					return
				}
				if strings.HasSuffix(r.URL.Path, "/info") {
					<-r.Context().Done()
					return
				}
				if strings.HasSuffix(r.URL.Path, "/json") {
					if !loaded.Load() {
						w.WriteHeader(http.StatusNotFound)
						_, _ = fmt.Fprint(w, `{"message":"not present"}`)
					} else {
						_, _ = fmt.Fprintf(w, `{"Id":%q}`, id)
					}
					return
				}
				if !strings.HasSuffix(r.URL.Path, "/images/create") {
					http.NotFound(w, r)
					return
				}
				pulls.Add(1)
				defer close(ended)
				if mode == "idle-header" {
					<-r.Context().Done()
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if mode == "remote-error" {
					_, _ = fmt.Fprint(w, `{"errorDetail":{"code":404,"message":"manifest missing"},"error":"manifest missing"}`)
					return
				}
				_, _ = fmt.Fprintln(w, `{"status":"Extracting"}`)
				w.(http.Flusher).Flush()
				if mode == "idle-body" {
					<-r.Context().Done()
					return
				}
				for range 8 {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(50 * time.Millisecond):
					}
					_, _ = fmt.Fprintln(w, `{"status":"Extracting"}`)
					w.(http.Flusher).Flush()
				}
				loaded.Store(true)
			})
			root, err := os.MkdirTemp("", "sfc-image-stream-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			listener, err := net.Listen("unix", filepath.Join(root, "engine.sock"))
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: handler}
			serving := make(chan struct{})
			go func() { _ = server.Serve(listener); close(serving) }()
			defer func() { _ = server.Close(); <-serving }()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c, err := open(ctx, "unix://"+listener.Addr().String(), "explicit-owner", idle)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			request := ctx
			if mode == "parent" {
				var stop context.CancelFunc
				request, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
			}
			started := time.Now()
			err = c.pullImage(request, ref)
			var got client.ImageInspectResult
			if err == nil {
				got, err = c.Image(request, ref, false)
			}
			elapsed := time.Since(started)
			if mode == "progress" {
				if err != nil || got.ID != id || elapsed <= idle {
					t.Fatal("live body was cut by metadata deadline", got.ID, err, elapsed)
				}
				if _, err = c.Image(ctx, ref, false); err != nil {
					t.Fatal("same digest cache", err)
				}
				if _, err = c.API.Info(ctx, client.InfoOptions{}); err == nil {
					t.Fatal("metadata lost its overall deadline")
				}
			} else {
				if err == nil || loaded.Load() || got.ID != "" {
					t.Fatal("failed transfer was published", got.ID, err)
				}
				if mode == "parent" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("original caller deadline cause lost", err)
				}
				if mode == "idle-body" {
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Fatal("stalled socket timeout cause lost", err)
					}
				}
				if mode == "remote-error" && !cerrdefs.IsNotFound(err) {
					t.Fatal("SDK stream error classification lost", err)
				}
			}
			if pulls.Load() != 1 {
				t.Fatal("a failed transfer was retried", pulls.Load())
			}
			select {
			case <-ended:
			case <-ctx.Done():
				t.Fatal("original server stream did not end")
			}
		})
	}
}
