// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/volume"
)

func nativeTestSpec(t *testing.T) NativeSpec {
	t.Helper()
	f := makeFixture(t)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid = 10001
	}
	if gid == 0 {
		gid = 10001
	}
	return NativeSpec{Schema: 1, Scope: f.s.Scope(), Node: "node-a", NodeKey: public(f.a), Materialization: "initial", UID: uid, GID: gid, Mode: 0750, Retain: true}
}

type nativeSDKFixture struct {
	volumes                                       map[string]volume.Volume
	volumeInspectHook                             func()
	containerHandler                              http.Handler
	mu                                            sync.Mutex
	value                                         volume.Volume
	exists, loseCreate, forgetCreate, blockRemove bool
	creates, deletes                              int
	client                                        *engine.Client
	data                                          string
}

func (f *nativeSDKFixture) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates, f.deletes
}
func (f *nativeSDKFixture) createCount() int { c, _ := f.counts(); return c }
func (f *nativeSDKFixture) deleteCount() int { _, d := f.counts(); return d }

func nativeSDK(t *testing.T, s NativeSpec) *nativeSDKFixture {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "sfc-volume-sdk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(root); e != nil {
			t.Error(e)
		}
	})
	data := filepath.Join(root, "data")
	if err = os.Mkdir(data, 0755); err != nil {
		t.Fatal(err)
	}
	f := &nativeSDKFixture{data: data}
	listener, err := net.Listen("unix", filepath.Join(root, "engine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.56")
		if r.URL.Path == "/_ping" {
			w.WriteHeader(200)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if strings.Contains(r.URL.Path, "/containers/") && f.containerHandler != nil {
			f.containerHandler.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/volumes/create"):
			var request struct {
				Name, Driver string
				DriverOpts   map[string]string
				Labels       map[string]string
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Name == "" || request.Driver != "local" || len(request.DriverOpts) != 0 {
				t.Error("unexpected native create")
				w.WriteHeader(400)
				return
			}
			f.creates++
			f.value = volume.Volume{Name: request.Name, Driver: request.Driver, Scope: "local", Labels: request.Labels, Mountpoint: data}
			if f.volumes != nil {
				dir := filepath.Join(root, request.Name)
				if e := os.Mkdir(dir, 0755); e != nil {
					t.Error(e)
					w.WriteHeader(500)
					return
				}
				f.value.Mountpoint = dir
				f.volumes[request.Name] = f.value
			}
			f.exists = !f.forgetCreate
			if f.loseCreate {
				f.loseCreate = false
				c, _, e := w.(http.Hijacker).Hijack()
				if e == nil {
					_ = c.Close()
				}
				return
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(f.value)
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/volumes"):
			values := []volume.Volume{}
			if f.exists {
				values = append(values, f.value)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Volumes": values})
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/volumes/"):
			if f.volumeInspectHook != nil {
				f.volumeInspectHook()
			}
			if f.volumes != nil {
				v, ok := f.volumes[filepath.Base(r.URL.Path)]
				if !ok {
					w.WriteHeader(404)
					_ = json.NewEncoder(w).Encode(map[string]string{"message": "missing original"})
					return
				}
				_ = json.NewEncoder(w).Encode(v)
				return
			}
			if !f.exists {
				w.WriteHeader(404)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "missing original"})
				return
			}
			_ = json.NewEncoder(w).Encode(f.value)
		case r.Method == "DELETE" && strings.Contains(r.URL.Path, "/volumes/"):
			f.deletes++
			if r.URL.Query().Get("force") != "" {
				t.Error("forced data deletion")
			}
			if f.blockRemove {
				w.WriteHeader(409)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "volume is in use"})
				return
			}
			f.exists = false
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected SDK request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	f.client, err = engine.Open(context.Background(), "unix://"+filepath.Join(root, "engine.sock"), engine.Owner(s.Scope.Cluster, s.NodeKey))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.client.Close() })
	return f
}

func TestNativeVolumeLostCreateRecoversOriginalAndRetainsPins(t *testing.T) {
	ctx := context.Background()
	s := nativeTestSpec(t)
	f := nativeSDK(t, s)
	f.loseCreate = true
	path := filepath.Join(t.TempDir(), "native.db")
	m, err := OpenNative(path, f.client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	key, err := m.Desired(s, 1, 7, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err == nil {
		t.Fatal("lost response was reported successful")
	}
	r, _ := m.View(key)
	if r.State.Pending == nil || r.State.LastID != 1 || r.State.Applied.Present {
		t.Fatal("original dispatch lost")
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = OpenNative(path, f.client)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal("original create read-back", err)
	}
	owner, scope, err := m.Owner(ctx, key)
	if err != nil || scope != s.Scope || f.createCount() != 1 {
		t.Fatal("original identity replaced", err)
	}
	c := makeFixture(t).c
	shared, err := New(c, "admin", scope, owner, 3)
	if err != nil || shared.Scope() != scope {
		t.Fatal("native owner not consumable by product Volume core", err)
	}
	changed := s
	changed.UID++
	if _, err = m.Desired(changed, 2, 7, 3); err == nil {
		t.Fatal("published volume ownership changed in place")
	}
	if _, err = m.Desired(s, 2, 8, 3); err == nil {
		t.Fatal("generation replacement would delete retained data")
	}
	pin, err := m.Pin(ctx, key, "original-task", 7)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.data, "retained"), []byte("original data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = OpenNative(path, f.client)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.Owner(ctx, key); err != nil {
		t.Fatal(err)
	}
	if b, e := os.ReadFile(filepath.Join(f.data, "retained")); e != nil || string(b) != "original data" {
		t.Fatal("reopen discarded retained data", e)
	}
	again, err := m.Pin(ctx, key, "original-task", 7)
	if err != nil || again != pin {
		t.Fatal("original local pin replaced", err)
	}
	if err = m.DeleteDesired(key, 2, 7); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); !errors.Is(err, reconcile.ErrPending) || f.deleteCount() != 0 {
		t.Fatal("live pin did not block delete", err)
	}
	if _, err = m.Pin(ctx, key, "late-task", 7); err == nil {
		t.Fatal("Drain admitted new consumer")
	}
	if err = m.Return(pin); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.blockRemove = true
	f.mu.Unlock()
	if err = m.Step(ctx, key); err == nil {
		t.Fatal("in-use removal reported Gone")
	}
	r, _ = m.View(key)
	if r.State.Pending == nil || r.State.Pending.Kind != reconcile.Remove || !r.State.Applied.Present {
		t.Fatal("unknown remove lost original")
	}
	f.mu.Lock()
	f.blockRemove = false
	f.mu.Unlock()
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = OpenNative(path, f.client)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal("original Remove continuation", err)
	}
	if gone, e := m.Gone(ctx, key, 2, 7); e != nil || !gone {
		t.Fatal("terminal volume closure", e)
	}
	if _, err = m.Desired(s, 3, 7, 3); err == nil {
		t.Fatal("deleted native generation reused")
	}
	if f.createCount() != 1 || f.deleteCount() != 2 {
		t.Fatal("unexpected native effects")
	}
}

func TestNativeVolumeMissingUnknownAndForeignNeverRecreate(t *testing.T) {
	ctx := context.Background()
	s := nativeTestSpec(t)
	f := nativeSDK(t, s)
	f.loseCreate = true
	f.forgetCreate = true
	m, err := OpenNative(filepath.Join(t.TempDir(), "native.db"), f.client)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	key, err := m.Desired(s, 1, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err == nil {
		t.Fatal("lost create response accepted")
	}
	if err = m.Step(ctx, key); !errors.Is(err, reconcile.ErrPending) || f.createCount() != 1 {
		t.Fatal("absence recreated uncertain original", err)
	}
	f.mu.Lock()
	f.exists = true
	f.value.Labels["org.sfc.spec"] = "foreign"
	f.mu.Unlock()
	if err = m.Step(ctx, key); !errors.Is(err, engine.ErrOwnership) || f.createCount() != 1 || f.deleteCount() != 0 {
		t.Fatal("foreign volume adopted/mutated", err)
	}
	r, _ := m.View(key)
	if r.State.Pending == nil || r.State.LastID != 1 {
		t.Fatal("original unknown discarded")
	}
}

func TestNativeVolumeDirectoryRejectsNonemptySymlinkAndPublishedMutation(t *testing.T) {
	var err error
	s := nativeTestSpec(t)
	root := t.TempDir()
	path := filepath.Join(root, "data")
	if os.Mkdir(path, 0755) != nil {
		t.Fatal("mkdir")
	}
	v := volume.Volume{Mountpoint: path}
	if err = os.WriteFile(filepath.Join(path, "foreign"), []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if nativeDirectory(v, s, true) == nil {
		t.Fatal("nonempty foreign data permission changed")
	}
	if os.Remove(filepath.Join(path, "foreign")) != nil {
		t.Fatal("remove fixture")
	}
	// The rootless SDK fixture uses its current UID/GID and can prepare mode;
	// a real node needs OS permission to apply a different declared owner.
	if os.Geteuid() == 0 {
		if os.Chown(path, int(s.UID), int(s.GID)) != nil {
			t.Fatal("chown")
		}
	}
	if err = nativeDirectory(v, s, true); err != nil {
		t.Fatal(err)
	}
	if os.Chmod(path, 0700) != nil {
		t.Fatal("chmod")
	}
	if nativeDirectory(v, s, false) == nil {
		t.Fatal("published permissions silently repaired")
	}
	if err = os.Symlink(path, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	v.Mountpoint = filepath.Join(root, "alias")
	if nativeDirectory(v, s, true) == nil {
		t.Fatal("symlink data root followed")
	}
	bad := s
	bad.Mode = 0777
	raw, _ := json.Marshal(bad)
	if _, err = decodeNative(string(raw)); err == nil {
		t.Fatal("world-accessible volume accepted")
	}
}

func TestNativeVolumeConcurrentDeclarationsKeepOneMaterialization(t *testing.T) {
	s := nativeTestSpec(t)
	f := nativeSDK(t, s)
	m, err := OpenNative(filepath.Join(t.TempDir(), "native.db"), f.client)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, generation := range []uint64{1, 2} {
		go func(generation uint64) { <-start; _, e := m.Desired(s, generation, generation, 3); results <- e }(generation)
	}
	close(start)
	accepted := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal("conflicting physical declarations both accepted", accepted)
	}
	r, err := m.View(NativeKey(s))
	if err != nil || !r.State.Desired.Present || r.State.Pending != nil || r.State.LastID != 0 {
		t.Fatal("declaration mutated native journal", err)
	}
	if f.createCount() != 0 || f.deleteCount() != 0 {
		t.Fatal("metadata conflict caused native effects")
	}
}
