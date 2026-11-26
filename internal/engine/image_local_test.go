// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
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
)

func TestLoadImageLoadsOnceAndInspectsTheVerifiedID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	image, err := random.Image(512, 1)
	if err != nil {
		t.Fatal(err)
	}
	config, err := image.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	var loaded atomic.Bool
	var loads atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
			w.Header().Set("API-Version", "1.56")
			fmt.Fprint(w, "OK")
		case strings.HasSuffix(r.URL.Path, "/images/load"):
			loads.Add(1)
			_, _ = io.Copy(io.Discard, r.Body)
			loaded.Store(true)
			fmt.Fprintln(w, `{"stream":"Loaded"}`)
		case strings.HasSuffix(r.URL.Path, "/images/"+config.String()+"/json") && loaded.Load():
			fmt.Fprintf(w, `{"Id":%q,"Config":{}}`, config.String())
		case strings.HasSuffix(r.URL.Path, "/json"):
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"not present"}`)
		default:
			http.NotFound(w, r)
		}
	})
	root, err := os.MkdirTemp("", "mydc-local-image-")
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
	engine, err := open(ctx, "unix://"+listener.Addr().String(), "node-app-fixture", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	for i := 0; i < 2; i++ {
		got, err := engine.LoadImage(ctx, image)
		if err != nil || got.ID != config.String() || loads.Load() != 1 {
			t.Fatal("load", i, got.ID, err, loads.Load())
		}
	}
}
