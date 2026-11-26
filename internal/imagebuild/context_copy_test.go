// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

// Real pinned SDK request/body/response and production TAR encoder. The HTTP
// fixture is not Docker volume extraction or actual BuildKit execution proof.
func TestCopyContextActualSDKJoinsEncoderAndDoesNotRetryAmbiguousRequest(t *testing.T) {
	for _, mode := range []string{"ok", "rejected", "early"} {
		t.Run(mode, func(t *testing.T) {
			raw, scope, seal := tarContextFixture(t)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "PUT" || r.URL.Path != "/v1.56/containers/original/archive" || r.URL.Query().Get("path") != "/input" || r.URL.Query().Get("copyUIDGID") != "true" || r.URL.Query().Get("noOverwriteDirNonDir") != "true" {
					t.Error("broadened SDK copy", r.Method, r.URL)
					w.WriteHeader(400)
					return
				}
				if mode == "early" {
					w.WriteHeader(500)
					_, _ = io.WriteString(w, `{"message":"private response body"}`)
					return
				}
				tr := tar.NewReader(r.Body)
				var dockerfile []byte
				for {
					h, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Error(err)
						return
					}
					if h.Name == "context/Dockerfile" {
						dockerfile, err = io.ReadAll(io.LimitReader(tr, MaxDockerfileBytes+1))
						if err != nil {
							t.Error(err)
							return
						}
					} else {
						if _, err := io.Copy(io.Discard, tr); err != nil {
							t.Error(err)
							return
						}
					}
				}
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
					return
				}
				if !bytes.Contains(dockerfile, []byte("FROM scratch")) {
					t.Error("original context missing")
				}
				if mode == "rejected" {
					w.WriteHeader(500)
					_, _ = io.WriteString(w, `{"message":"private response body"}`)
					return
				}
				w.WriteHeader(200)
			}))
			defer server.Close()
			api, err := client.New(client.WithHost(server.URL), client.WithAPIVersion("1.56"))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tree, err := CopyContext(ctx, api, "original", bytes.NewReader(raw), scope, seal)
			if mode == "ok" {
				if err != nil || tree.Digest() != seal.Tree {
					t.Fatal(tree.Digest(), err)
				}
			} else if err == nil || tree.Digest() == seal.Tree || strings.Contains(err.Error(), "private response body") {
				t.Fatal("ambiguous/private SDK outcome accepted", err)
			}
			if calls.Load() != 1 {
				t.Fatal("SDK effect retried", calls.Load())
			}
		})
	}
}
