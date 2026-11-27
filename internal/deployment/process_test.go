// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/engine"
)

func TestComposeImageAdapterUsesCurrentTenantPolicyAndTypedOverrides(t *testing.T) {
	f := makeFixture(t)
	id := "sha256:" + strings.Repeat("d", 64)
	ref := "docker.io/library/php@sha256:" + strings.Repeat("e", 64)
	// Linux sockaddr_un bounds the complete pathname, including Go's test name.
	// Keep this owned fixture root short instead of changing product endpoints.
	root, err := os.MkdirTemp("/tmp", "sfc-process-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	socket := filepath.Join(root, "engine.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var inspections atomic.Int64
	var imageHasVolume atomic.Bool
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.56")
		if r.URL.Path == "/_ping" {
			w.WriteHeader(200)
			return
		}
		if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/images/"+ref+"/json") {
			t.Errorf("unexpected Engine request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		inspections.Add(1)
		config := map[string]any{"User": "10001:10001", "Cmd": []string{"image-cmd"}, "Entrypoint": []string{"/backend"}, "Env": []string{"OVERRIDE=old"}}
		if imageHasVolume.Load() {
			config["Volumes"] = map[string]any{"/scratch": map[string]any{}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": id, "Os": "linux", "Config": config})
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	docker, err := engine.Open(context.Background(), "unix://"+socket, "owned-process-adapter")
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()
	entry := Arguments{}
	command := Arguments{"/new-command"}
	s := ComposeService{Image: ref, Command: &command, Entrypoint: &entry, Environment: Environment{"OVERRIDE": "new"}, StopGracePeriod: "120s", StopSignal: "SIGQUIT", Healthcheck: &Healthcheck{Test: []string{"CMD-SHELL", "exit 0"}, Interval: "1s", Timeout: "1s", Retries: 2, StartInterval: "1s"}}
	p, err := s.ResolveProcess(context.Background(), docker, f.c, "alice", "tenant", "node-a", false)
	if err != nil || p.ImageID != id || len(p.Entrypoint) != 0 || !reflect.DeepEqual(p.Command, []string{"/new-command"}) || !reflect.DeepEqual(p.Env, []string{"OVERRIDE=new"}) || p.Healthcheck.Retries != 2 || p.StopSignal != "SIGQUIT" {
		t.Fatal("typed Compose -> actual SDK -> product process", p, err)
	}
	if !reflect.DeepEqual(p.Healthcheck.Test, []string{"CMD-SHELL", "exit 0"}) || p.Healthcheck.StartInterval != time.Second {
		t.Fatal("SDK image resolution dropped native shell/start_interval", p.Healthcheck)
	}
	input := smallCompose(t)
	web := input.Services["web"]
	web.Image = ref
	input.Services["web"] = web
	blueprint, err := Compile(input, f.c, contextFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	needs, err := blueprint.Inputs("web", "web-task", 4, public(private(30)))
	if err != nil {
		t.Fatal(err)
	}
	f.approveAll(needs)
	bound := f.reserve(needs).Bindings[0]
	reference := projectionReference(bound)
	docker.Owner = desired.Owner(f.cluster, bound.d.Needs.Use.NodeKey)
	if _, err = blueprint.ResolveTaskProcess(context.Background(), "web", bound, reference, f.c, docker, false); err != nil {
		t.Fatal("single-file Secret recipe could not consume image adapter", err)
	}
	wrong := reference
	wrong.Binding[0] ^= 1
	if _, err = blueprint.ResolveTaskProcess(context.Background(), "web", bound, wrong, f.c, docker, false); err == nil {
		t.Fatal("foreign recipe input reference admitted")
	}
	imageHasVolume.Store(true)
	s.Memory = "8m"
	s.Tmpfs = []string{"/scratch:size=4m,mode=0700,uid=10001,gid=10001"}
	if _, err = s.ResolveProcess(context.Background(), docker, f.c, "alice", "tenant", "node-a", false); err != nil {
		t.Fatal("single-file tmpfs did not cover image VOLUME", err)
	}
	s.Tmpfs = nil
	if _, err = s.ResolveProcess(context.Background(), docker, f.c, "alice", "tenant", "node-a", false); err == nil {
		t.Fatal("unmapped image VOLUME accepted by Compose SDK adapter")
	}
	before := inspections.Load()
	if _, err = s.ResolveProcess(context.Background(), docker, f.c, "alice", "other", "node-a", true); err == nil {
		t.Fatal("cross-tenant image lookup admitted")
	}
	tenant, _ := f.c.Tenant("tenant")
	revoked, err := f.c.ChangeTrust("alice", "tenant", tenant.Revision, nil, tenant.ImageSources)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ResolveProcess(context.Background(), docker, revoked, "alice", "tenant", "node-a", false); err == nil {
		t.Fatal("cached image bypassed current trust")
	}
	s.Volumes = Mounts{{Type: "volume", Source: "data", Target: "/data"}}
	if _, err = s.ResolveProcess(context.Background(), docker, f.c, "alice", "tenant", "node-a", false); err == nil {
		t.Fatal("unsupported input mount silently dropped")
	}
	if inspections.Load() != before {
		t.Fatal("denied/unsupported service reached Engine inspect or pull")
	}
}
