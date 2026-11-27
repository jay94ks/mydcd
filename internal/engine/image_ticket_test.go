// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jay94ks/seafield/internal/engineimage"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// A fake engine pulls only through the node's ticket table, the way the
// Seafield engine asks sfcd over purpose 37; the source is a real HTTPS
// registry trusted by its own CA. No credential reaches the engine.
func TestImagePullGoesThroughATicketOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var unauthorized atomic.Bool
	backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unauthorized.Load() {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			http.Error(w, "private-test-password-echo", http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	defer source.Close()
	authority := strings.TrimPrefix(source.URL, "https://")
	image, err := random.Image(2048, 2)
	if err != nil {
		t.Fatal(err)
	}
	tag, _ := name.NewTag(authority+"/team/app:source", name.StrictValidation)
	if err = remote.Write(tag, image, remote.WithContext(ctx), remote.WithTransport(source.Client().Transport)); err != nil {
		t.Fatal(err)
	}
	digest, _ := image.Digest()
	config, _ := image.ConfigName()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: source.Certificate().Raw})
	repo := authority + "/team/app"
	root := repo + "@" + digest.String()

	tickets := engineimage.New()
	var loaded atomic.Bool
	var pulls atomic.Int32
	pulled := make(chan string, 4)
	read := func(op, d string, offset int64) ([]byte, error) {
		_, body, err := tickets.Serve(ctx, engineimage.Query{Op: op, Repository: repo, Digest: d, Offset: offset})
		if err != nil {
			return nil, err
		}
		defer body.Close()
		return io.ReadAll(body)
	}
	engineHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
			w.Header().Set("API-Version", "1.56")
			fmt.Fprint(w, "OK")
		case strings.HasSuffix(r.URL.Path, "/images/create"):
			pulls.Add(1)
			pulled <- r.URL.Query().Get("fromImage") + "@" + r.URL.Query().Get("tag")
			if r.Header.Get("X-Registry-Auth") != "" {
				t.Error("credential sent to the engine")
			}
			// What the engine does over purpose 37: manifest, then every
			// blob, one of them resumed from an offset.
			raw, err := read("manifest", digest.String(), 0)
			if err != nil {
				http.Error(w, "manifest", 500)
				return
			}
			m, err := v1.ParseManifest(strings.NewReader(string(raw)))
			if err != nil {
				http.Error(w, "manifest", 500)
				return
			}
			for i, d := range append([]v1.Descriptor{m.Config}, m.Layers...) {
				head, tail := []byte{}, []byte{}
				if i == 1 {
					head, err = read("blob", d.Digest.String(), 0)
					head = head[:100]
					if err == nil {
						tail, err = read("blob", d.Digest.String(), 100)
					}
				} else {
					tail, err = read("blob", d.Digest.String(), 0)
				}
				body := append(head, tail...)
				if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(body)) != d.Digest.String() {
					http.Error(w, "blob", 500)
					return
				}
			}
			loaded.Store(true)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"status":"done"}`)
		case strings.HasSuffix(r.URL.Path, "/json"):
			if !loaded.Load() {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"message":"not present"}`)
				return
			}
			fmt.Fprintf(w, `{"Id":%q,"Config":{}}`, config.String())
		default:
			http.NotFound(w, r)
		}
	})
	dir, err := os.MkdirTemp("", "sfc-ticket-pull-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	listener, err := net.Listen("unix", filepath.Join(dir, "engine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: engineHandler}
	done := make(chan struct{})
	go func() { _ = server.Serve(listener); close(done) }()
	defer func() { _ = server.Close(); <-done }()
	c, err := open(ctx, "unix://"+listener.Addr().String(), "ticket-fixture", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	auth := func() RegistryAuth {
		a, err := NewExternalRegistryAuth(authority, nil, nil, ca)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if _, err = c.ImageWithAuth(ctx, root, true, auth()); !errors.Is(err, ErrOwnership) || pulls.Load() != 0 {
		t.Fatal("pulled without a ticket table", err)
	}
	c.Images = tickets
	var outcomes []registryclient.PullOutcome
	observe := func(o registryclient.PullOutcome) { outcomes = append(outcomes, o) }
	// A tag beside the digest is dropped: the engine pulls the pinned root.
	got, err := c.ImageWithAuth(ctx, repo+":source@"+digest.String(), true, auth().WithPullObserver(observe))
	if err != nil || got.ID != config.String() || pulls.Load() != 1 || <-pulled != root {
		t.Fatal("ticketed pull", got.ID, err, pulls.Load())
	}
	if len(outcomes) != 1 || outcomes[0] != (registryclient.PullOutcome{Stage: "load", Code: "OK"}) {
		t.Fatal("pull outcome", outcomes)
	}
	// The ticket ended with the pull.
	if _, _, err = tickets.Serve(ctx, engineimage.Query{Op: "manifest", Repository: repo, Digest: digest.String()}); !errors.Is(err, engineimage.ErrRefused) {
		t.Fatal("ticket outlived its pull", err)
	}
	if _, err = c.ImageWithAuth(ctx, root, true, auth()); err != nil || pulls.Load() != 1 {
		t.Fatal("present image pulled again", err, pulls.Load())
	}
	// The source refuses: nothing reaches the engine and no secret leaks.
	loaded.Store(false)
	unauthorized.Store(true)
	if _, err = c.ImageWithAuth(ctx, root, true, auth().WithPullObserver(observe)); err == nil || pulls.Load() != 1 || strings.Contains(err.Error(), "private-test-password") {
		t.Fatal("refused source reached the engine", err, pulls.Load())
	}
	if len(outcomes) != 2 || outcomes[1] != (registryclient.PullOutcome{Stage: "resolve", Code: "UNAUTHORIZED"}) {
		t.Fatal("resolve outcome", outcomes)
	}
	// Another registry than the credential's is refused before any request.
	if _, err = c.ImageWithAuth(ctx, "foreign.example.test/team/app@"+digest.String(), true, auth()); !errors.Is(err, ErrOwnership) {
		t.Fatal("foreign authority accepted", err)
	}
}
