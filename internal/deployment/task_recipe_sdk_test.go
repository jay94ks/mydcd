// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jay94ks/seafield/internal/engine"
)

func TestTaskRecipeSDKResolvesAllMountsAndCurrentTrust(t *testing.T) {
	f, b, material := taskMaterialFixture(t)
	root, err := os.MkdirTemp("/tmp", "sfc-recipe-sdk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	listener, err := net.Listen("unix", filepath.Join(root, "engine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var count atomic.Int64
	image := "sha256:" + strings.Repeat("b", 64)
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.56")
		if r.URL.Path == "/_ping" {
			w.WriteHeader(200)
			return
		}
		if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/images/"+b.d.Input.Services["db"].Image+"/json") {
			t.Errorf("unexpected SDK effect %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		count.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": image, "Os": "linux", "Config": map[string]any{"User": "10001:10001", "Cmd": []string{"/backend"}, "Volumes": map[string]any{"/var/lib/mysql": map[string]any{}, "/cache": map[string]any{}}}})
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	docker, err := engine.Open(context.Background(), "unix://"+filepath.Join(root, "engine.sock"), material.Bridge.Owner)
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()
	spec, err := b.ResolveTask(context.Background(), "db", material, f.c, docker, false)
	if err != nil || spec.Process == nil || spec.Process.ImageID != image || spec.Inputs == nil || len(spec.Volumes) != 1 || len(spec.Tmpfs) != 1 || spec.Process.Command[0] != "mysqld" {
		t.Fatal("single-file recipe/actual SDK mapping", spec, err)
	}
	bad := cloneTaskMaterial(material)
	bad.Volumes = nil
	if _, err = b.ResolveTask(context.Background(), "db", bad, f.c, docker, true); err == nil {
		t.Fatal("missing original materialization admitted")
	}
	tenant, _ := f.c.Tenant("tenant")
	current, err := f.c.ChangeTrust("alice", "tenant", tenant.Revision, nil, tenant.ImageSources)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.ResolveTask(context.Background(), "db", material, current, docker, false); err == nil {
		t.Fatal("cached image bypassed current tenant trust")
	}
	if count.Load() != 1 {
		t.Fatal("invalid material/trust reached image SDK", count.Load())
	}
}
