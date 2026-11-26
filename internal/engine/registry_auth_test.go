// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/json"
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

	"github.com/moby/moby/api/pkg/authconfig"
)

// Actual SDK HTTP over a private fake Engine UDS: proves request auth and digest
// wiring, not a real registry/Engine TLS or native container success.
func TestImageAuthReachesOnlyMatchingSDKPullAndNeverAmbientRetry(t *testing.T) {
	const authority = "registry.example.test:5443"
	const secret = "short-task-login-secret"
	digest := "sha256:" + strings.Repeat("a", 64)
	ref := authority + "/team/app@" + digest
	auth, err := NewRegistryAuth(authority, "mydc-task", []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(auth), secret) {
		t.Fatal("auth formatter leaked")
	}
	if _, err = json.Marshal(auth); err == nil {
		t.Fatal("request credential serialized to general JSON")
	}
	var loaded atomic.Bool
	var pulls, requests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/_ping" {
			w.Header().Set("API-Version", "1.56")
			fmt.Fprint(w, "OK")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/json") {
			if !loaded.Load() {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"message":"not present"}`)
				return
			}
			fmt.Fprintf(w, `{"Id":%q}`, digest)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/images/create") {
			http.NotFound(w, r)
			return
		}
		pulls.Add(1)
		got, err := authconfig.Decode(r.Header.Get("X-Registry-Auth"))
		if err != nil || got.ServerAddress != authority || got.Username != "mydc-task" || got.Password != secret || r.URL.Query().Get("tag") != digest || r.URL.Query().Get("fromImage") != authority+"/team/app" {
			t.Error("SDK changed auth or original pinned target")
			w.WriteHeader(403)
			return
		}
		loaded.Store(true)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"done"}`)
	})
	root, err := os.MkdirTemp("", "mydc-image-auth-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	l, err := net.Listen("unix", filepath.Join(root, "engine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() { _ = server.Serve(l); close(done) }()
	defer func() { _ = server.Close(); <-done }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := open(ctx, "unix://"+l.Addr().String(), "owned-auth-fixture", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.ImageWithAuth(ctx, ref, true, auth); err != nil {
		t.Fatal(err)
	}
	if _, err = c.ImageWithAuth(ctx, ref, false, auth); err != nil {
		t.Fatal("cached exact image failed", err)
	}
	before := requests.Load()
	if _, err = c.ImageWithAuth(ctx, "foreign.example.test/team/app@"+digest, true, auth); !errors.Is(err, ErrOwnership) {
		t.Fatal("foreign auth accepted", err)
	}
	if requests.Load() != before || pulls.Load() != 1 {
		t.Fatal("foreign request or extra pull/retry occurred", requests.Load(), before, pulls.Load())
	}
}
