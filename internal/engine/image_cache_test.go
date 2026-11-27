// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/moby/moby/client"
)

func TestCacheSDKPreservesNativeAndDesiredReferencesAndUnknownDispatch(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	for _, scenario := range []string{"stopped-container", "desired", "sync-failed", "success", "lost-reply", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			present := true
			deletes, saves := 0, 0
			var mu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				p := strings.TrimPrefix(r.URL.Path, "/v1.56")
				w.Header().Set("Content-Type", "application/json")
				switch {
				case p == "/images/json":
					_ = json.NewEncoder(w).Encode([]map[string]any{{"Id": id, "Size": 128, "Containers": -1, "RepoTags": []string{"proof:latest"}, "RepoDigests": []string{}}})
				case p == "/containers/json":
					if scenario == "stopped-container" {
						_ = json.NewEncoder(w).Encode([]map[string]any{{"Id": strings.Repeat("b", 64), "ImageID": id, "State": "exited"}})
					} else {
						_ = json.NewEncoder(w).Encode([]any{})
					}
				case r.Method == "DELETE":
					deletes++
					if saves != 1 || r.URL.Query().Get("force") == "1" || r.URL.Query().Get("noprune") != "1" {
						t.Error("SDK deleted without synced original or widened scope")
					}
					if scenario != "unknown" {
						present = false
					}
					if scenario == "lost-reply" || scenario == "unknown" {
						w.WriteHeader(500)
						_ = json.NewEncoder(w).Encode(map[string]string{"message": "original SDK reply unavailable"})
					} else {
						_ = json.NewEncoder(w).Encode([]map[string]string{{"Deleted": id}})
					}
				case strings.HasSuffix(p, "/json"):
					if !present {
						w.WriteHeader(404)
						_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
					} else {
						_ = json.NewEncoder(w).Encode(map[string]any{"Id": id, "RepoTags": []string{"proof:latest"}, "Size": 128})
					}
				default:
					t.Error("unexpected Docker API path", r.Method, p)
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			api, err := client.New(client.WithHost(server.URL), client.WithVersion("1.56"))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			c := &Client{API: api, Owner: "owned-fixture"}
			original := imagecache.Image{ID: id, Bytes: 128, Aliases: []string{"docker.io/library/proof:latest"}}
			part, known, err := c.RemoveCachedImage(context.Background(), original, func(context.Context, imagecache.Image) (uint64, error) {
				if scenario == "desired" {
					return 1, nil
				}
				return 0, nil
			}, func() error {
				mu.Lock()
				defer mu.Unlock()
				saves++
				if scenario == "sync-failed" {
					return errors.New("original private sync failed")
				}
				return nil
			})
			mu.Lock()
			defer mu.Unlock()
			switch scenario {
			case "stopped-container", "desired":
				if !known || part.State != "skipped" || deletes != 0 || saves != 0 {
					t.Fatal("protected reference deleted", part, known, err)
				}
			case "sync-failed":
				if known || err == nil || deletes != 0 {
					t.Fatal("sync failure dispatched or invented result")
				}
			case "success":
				if !known || !part.Valid() || part.State != "removed" || deletes != 1 {
					t.Fatal("actual SDK result not observed", part, known, err)
				}
			case "lost-reply":
				if !known || part.State != "already-absent" || deletes != 1 {
					t.Fatal("positive absence not separated from causal deletion", part, known, err)
				}
			case "unknown":
				if known || err == nil || deletes != 1 {
					t.Fatal("unknown SDK became failure/non-execution")
				}
			}
		})
	}
}
