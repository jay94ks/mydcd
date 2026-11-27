// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	bolt "go.etcd.io/bbolt"
)

// This uses the pinned SDK's real Unix HTTP/Wait/copy clients and actual bbolt.
// The server is an Engine protocol fixture, not Docker or BuildKit evidence.
type nativeFixture struct {
	t                                 *testing.T
	mu                                sync.Mutex
	spec                              JobSpec
	plan                              NativePlan
	options                           client.ContainerCreateOptions
	docker                            *engine.Client
	db                                *bolt.DB
	jobs                              *NativeJobs
	grant                             NativeGrant
	authorityErr                      error
	exists                            bool
	state                             container.State
	foreign                           bool
	lostCreate, lostStart, lostRemove bool
	badWait                           bool
	calls                             map[string]int
	archives                          [][]byte
	logFrames                         []byte
	logRelease                        <-chan struct{}
}

func newNativeFixture(t *testing.T, secrets bool) *nativeFixture {
	return newNativeFixtureWithSpec(t, secrets, nil)
}
func newNativeFixtureWithSpec(t *testing.T, secrets bool, configure func(*JobSpec)) *nativeFixture {
	t.Helper()
	if os.Geteuid() != 0 && os.Geteuid() != nativeBuilderUID {
		t.Skip("owned builder directories require root or the pinned builder UID")
	}
	spec, _ := testJobSpec(t)
	_, scope, seal := tarContextFixture(t)
	scope.Root.Path = t.TempDir()
	_, signer := testScope(1, [32]byte{1})
	seal.Scope = scope.Hash()
	seal.Signature = ed25519.Sign(signer, SealReceiptBytes(seal))
	spec.Scope, spec.Seal, spec.Version = scope, seal, VersionID(seal)
	spec.Context.Root = scope.Root
	spec.Policy.Nodes[0].Root = scope.Root
	if secrets {
		spec.Context.Secrets = []SecretMount{{ID: "signing", Realm: "tenant", Secret: "key", Key: "private"}}
	}
	if configure != nil {
		configure(&spec)
	}
	p, err := PlanNative(spec, engine.Owner(spec.Cluster, spec.Scope.Root.Key))
	if err != nil {
		t.Fatal(err)
	}
	options, err := p.CreateOptions(spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := NewJob(spec)
	if err != nil {
		t.Fatal(err)
	}
	f := &nativeFixture{t: t, spec: spec, plan: p, options: options, grant: NativeGrant{Run: run, Index: 1, Epoch: 1, Allowed: true}, calls: map[string]int{}}
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve)}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })
	f.docker, err = engine.Open(context.Background(), "unix://"+listener.Addr().String(), engine.Owner(spec.Cluster, spec.Scope.Root.Key))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.docker.Close() })
	f.db, err = bolt.Open(filepath.Join(t.TempDir(), "observations.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Close() })
	f.reopen()
	if err := f.jobs.Accept(f.grant); err != nil {
		t.Fatal(err)
	}
	// Native files/SDK are real here; the RootManager lease is an injected
	// prerequisite, separately exercised by the actual Runtime/root adapter.
	for _, use := range []RootUse{JobRoot, CacheRoot} {
		if err := f.jobs.PlanRootHold(context.Background(), spec, use); err != nil {
			t.Fatal(err)
		}
		if err := f.jobs.BindRootHold(spec, use, reconcile.Lease{Generation: spec.Scope.Root.Generation, Token: uint64(use)}); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.Open(scope.Root.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	spool, err := OpenSpool(int(root.Fd()), scope.Root, f.db)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.PrepareWorkspace(context.Background(), spec, int(root.Fd())); err != nil {
		t.Fatal(err)
	}
	f.grant.Run, err = f.grant.Run.Begin(f.grant.Run.Revision, 101, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.grant.Index++
	return f
}
func (f *nativeFixture) reopen() {
	f.t.Helper()
	var err error
	f.jobs, err = OpenNativeJobs(f.db, f.docker, func(_ context.Context, spec JobSpec, _ bool) (NativeGrant, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if spec.Digest() != f.spec.Digest() {
			return NativeGrant{}, ErrConflict
		}
		return f.grant, f.authorityErr
	})
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *nativeFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/_ping" {
		w.Header().Set("API-Version", "1.56")
		w.WriteHeader(200)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1.56")
	key := r.Method + " " + p
	f.calls[key]++
	write := func(v any) {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			f.t.Error(err)
		}
	}
	missing := func() { w.WriteHeader(404); write(map[string]string{"message": "not found"}) }
	failure := func() { w.WriteHeader(500); write(map[string]string{"message": "private native response"}) }
	if strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json") {
		write(map[string]any{"Id": "sha256:" + strings.Repeat("c", 64), "Os": "linux", "Architecture": runtime.GOARCH, "Config": map[string]any{"Env": []string{"PATH=/usr/bin"}}})
		return
	}
	if p == "/containers/create" && r.Method == "POST" {
		if r.URL.Query().Get("name") != f.plan.Container.Name {
			f.t.Error("wrong original create name")
		}
		var got map[string]any
		if json.NewDecoder(r.Body).Decode(&got) != nil {
			f.t.Error("invalid create body")
		}
		host, ok := got["HostConfig"].(map[string]any)
		if !ok {
			f.t.Error("missing Docker host configuration")
		}
		for _, name := range []string{"MaskedPaths", "ReadonlyPaths"} {
			paths, ok := host[name].([]any)
			if !ok || len(paths) != 0 {
				f.t.Error("Docker SDK omitted the explicit empty proc path list", name)
			}
		}
		f.exists = true
		f.state = container.State{Status: container.StateCreated}
		if f.lostCreate {
			failure()
			return
		}
		write(map[string]any{"Id": strings.Repeat("b", 64), "Warnings": []string{}})
		return
	}
	if strings.HasPrefix(p, "/containers/") {
		parts := strings.Split(strings.TrimPrefix(p, "/containers/"), "/")
		if parts[0] != f.plan.Container.Name && parts[0] != strings.Repeat("b", 64) {
			f.t.Error("wrong original native lookup", parts[0])
			missing()
			return
		}
		if !f.exists {
			missing()
			return
		}
		if len(parts) == 2 {
			switch parts[1] {
			case "attach":
				q := r.URL.Query()
				if r.Method != "POST" || q.Get("stream") != "1" || q.Get("stdout") != "1" || q.Get("stderr") != "1" || q.Has("stdin") || q.Has("logs") {
					f.t.Error("broadened attach", r.Method, r.URL)
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					f.t.Error(err)
					return
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
				frames, release := bytes.Clone(f.logFrames), f.logRelease
				go func() {
					defer conn.Close()
					if release != nil {
						<-release
					}
					_, _ = conn.Write(frames)
				}()
				return
			case "json":
				cfg := *f.options.Config
				if f.foreign {
					cfg.Labels = map[string]string{"foreign": "true"}
				}
				write(map[string]any{"Id": strings.Repeat("b", 64), "Name": "/" + f.plan.Container.Name, "Image": "sha256:" + strings.Repeat("c", 64), "Config": cfg, "HostConfig": f.options.HostConfig, "State": f.state})
				return
			case "archive":
				if r.Method != "PUT" || r.URL.Query().Get("path") != "/input" || r.URL.Query().Get("noOverwriteDirNonDir") != "true" {
					f.t.Error("broadened copy", r.Method, r.URL)
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				if err != nil {
					f.t.Error(err)
				}
				f.archives = append(f.archives, body)
				w.WriteHeader(200)
				return
			case "start":
				if !f.lostStart {
					f.state = container.State{Status: container.StateRunning, Running: true, Pid: 123, StartedAt: "2026-11-22T00:00:01Z"}
				}
				if f.lostStart {
					failure()
					return
				}
				w.WriteHeader(204)
				return
			case "stop":
				if r.URL.Query().Get("t") != "10" || r.URL.Query().Get("signal") != "SIGTERM" {
					f.t.Error("wrong stop policy", r.URL)
				}
				f.state = container.State{Status: container.StateExited, StartedAt: f.state.StartedAt, FinishedAt: "2026-11-22T00:00:02Z", ExitCode: 143}
				w.WriteHeader(204)
				return
			case "wait":
				code := f.state.ExitCode
				if f.badWait {
					code++
				}
				write(map[string]any{"StatusCode": code, "Error": nil})
				return
			}
		}
		if len(parts) == 1 && r.Method == "DELETE" {
			if f.lostRemove {
				failure()
				return
			}
			f.exists = false
			w.WriteHeader(204)
			return
		}
	}
	f.t.Error("unexpected Docker boundary", key)
	missing()
}
func (f *nativeFixture) ctx() context.Context {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	f.t.Cleanup(cancel)
	return ctx
}
func (f *nativeFixture) edit(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}
func (f *nativeFixture) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[key]
}
func (f *nativeFixture) copied() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var result [][]byte
	for _, body := range f.archives {
		result = append(result, bytes.Clone(body))
	}
	return result
}
func (f *nativeFixture) prepare(ctx context.Context) {
	f.t.Helper()
	if err := f.jobs.Create(ctx, f.spec); err != nil {
		r, recordErr := f.jobs.Record(f.spec)
		f.mu.Lock()
		f.t.Logf("original create receipt: sent=%t not-sent=%t native=%q record-error=%v requests=%v", r.CreateSent, r.CreateNotSent, r.NativeID, recordErr, f.calls)
		f.mu.Unlock()
		f.t.Fatal("prepare original container", err)
	}
	raw, _, _ := tarContextFixture(f.t)
	if err := f.jobs.StageContext(ctx, f.spec, bytes.NewReader(raw)); err != nil {
		f.t.Fatal("prepare context archive", err)
	}
	var values []SecretValue
	for _, ref := range f.spec.Context.Secrets {
		values = append(values, SecretValue{Reference: ref, Value: []byte("ephemeral-private-value")})
	}
	record, err := f.jobs.Record(f.spec)
	if err != nil {
		f.t.Fatal("prepare control record", err)
	}
	if record.Solve != nil && record.Solve.TLS {
		err = f.jobs.StageControlsTLS(ctx, f.spec, values, nil)
	} else {
		err = f.jobs.StageControls(ctx, f.spec, values)
	}
	if err != nil {
		f.t.Fatal("prepare control archive", err)
	}
}

func TestNativeBuildLostCreateReplyAdoptsOnlyOriginalAndDoesNotRecreate(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	f.edit(func() { f.lostCreate = true })
	if err := f.jobs.Create(ctx, f.spec); err == nil || strings.Contains(err.Error(), "private native response") {
		t.Fatal("lost/private Create outcome", err)
	}
	f.reopen()
	f.edit(func() { f.exists = false })
	if err := f.jobs.Create(ctx, f.spec); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("absence retried Create", err)
	}
	f.edit(func() { f.exists = true })
	f.edit(func() { f.foreign = true })
	if err := f.jobs.ObserveExit(ctx, f.spec, true); !errors.Is(err, engine.ErrOwnership) {
		t.Fatal("foreign original adopted", err)
	}
	f.edit(func() { f.foreign = false })
	for _, readonly := range []bool{false, true} {
		f.edit(func() {
			if readonly {
				f.options.HostConfig.ReadonlyPaths = []string{"/proc/sys"}
			} else {
				f.options.HostConfig.MaskedPaths = []string{"/proc/kcore"}
			}
		})
		if err := f.jobs.ObserveExit(ctx, f.spec, true); !errors.Is(err, engine.ErrOwnership) {
			t.Fatal("different proc configuration adopted", readonly, err)
		}
		f.edit(func() {
			f.options.HostConfig.MaskedPaths = []string{}
			f.options.HostConfig.ReadonlyPaths = []string{}
		})
	}
	f.edit(func() { f.authorityErr = errors.New("quorum unavailable") })
	if err := f.jobs.ObserveExit(ctx, f.spec, true); err != nil {
		t.Fatal("could not recover original created native for cleanup", err)
	}
	if err := f.jobs.Remove(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	r, err := f.jobs.Record(f.spec)
	if err != nil || r.Exited || !r.Waited || !r.Removed || !r.Cancel {
		t.Fatal("created object reported execution", r, err)
	}
	if f.count("POST /containers/create") != 1 {
		t.Fatal("Create resent")
	}
}

func TestNativeBuildLostStartDoesNotFabricateExitAndCancelNeedsNoQuorum(t *testing.T) {
	f := newNativeFixture(t, true)
	ctx := f.ctx()
	f.prepare(ctx)
	f.edit(func() { f.lostStart = true })
	if err := f.jobs.Start(ctx, f.spec); err == nil {
		t.Fatal("lost Start acknowledged")
	}
	f.reopen()
	if err := f.jobs.Start(ctx, f.spec); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("Start resent", err)
	}
	if err := f.jobs.ObserveExit(ctx, f.spec, false); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("created became exit", err)
	}
	if f.count("POST /containers/"+strings.Repeat("b", 64)+"/wait") != 0 {
		t.Fatal("created was passed to Wait before cancellation")
	}
	f.edit(func() { f.authorityErr = errors.New("quorum unavailable") })
	if err := f.jobs.ObserveExit(ctx, f.spec, true); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.Remove(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	r, err := f.jobs.Record(f.spec)
	if err != nil || r.Exited || !r.Waited || !r.Removed {
		t.Fatal(r, err)
	}
	if f.count("POST /containers/"+strings.Repeat("b", 64)+"/start") != 1 {
		t.Fatal("Start resent")
	}
	archives := f.copied()
	if len(archives) != 2 {
		t.Fatal("context/control archive not staged once")
	}
	for i, raw := range archives {
		tr := tar.NewReader(bytes.NewReader(raw))
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 && strings.HasPrefix(h.Name, "secrets/") {
				t.Fatal("secret in public context")
			}
			if _, err := io.Copy(io.Discard, tr); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := f.db.View(func(tx *bolt.Tx) error {
		if bytes.Contains(tx.Bucket(nativeBucket).Get(nativeKey(f.spec)), []byte("ephemeral-private-value")) {
			return errors.New("raw secret journaled")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeBuildWaitMustMatchPositiveExitAndRemovalNeverResends(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	f.prepare(ctx)
	if err := f.jobs.Start(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	f.edit(func() {
		f.state = container.State{Status: container.StateExited, ExitCode: 137, OOMKilled: true, StartedAt: "2026-11-22T00:00:01Z", FinishedAt: "2026-11-22T00:00:02Z"}
	})
	f.edit(func() { f.badWait = true })
	if err := f.jobs.ObserveExit(ctx, f.spec, false); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("mismatched Wait forged exit", err)
	}
	f.edit(func() { f.badWait = false })
	if err := f.jobs.ObserveExit(ctx, f.spec, false); err != nil {
		t.Fatal(err)
	}
	r, err := f.jobs.Record(f.spec)
	if err != nil || !r.Exited || r.ExitCode != 137 || !r.Waited {
		t.Fatal("OOM did not settle actual process", r, err)
	}
	f.edit(func() { f.authorityErr = errors.New("quorum unavailable") })
	f.edit(func() { f.lostRemove = true })
	if err := f.jobs.Remove(ctx, f.spec); err == nil || strings.Contains(err.Error(), "private native response") {
		t.Fatal("lost/private removal", err)
	}
	f.reopen()
	if err := f.jobs.Remove(ctx, f.spec); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("Remove resent", err)
	}
	f.edit(func() { f.exists = false })
	if err := f.jobs.Remove(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	r, err = f.jobs.Record(f.spec)
	if err != nil || !r.Removed || !r.AbsentObserved {
		t.Fatal("original known ID absence not settled", r, err)
	}
	if f.count("DELETE /containers/"+strings.Repeat("b", 64)) != 1 {
		t.Fatal("Remove resent")
	}
}

func TestNativeBuildRunningCancellationStopsOriginalBeforeWaitAndRemove(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	f.prepare(ctx)
	if err := f.jobs.Start(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.ObserveExit(ctx, f.spec, false); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("running build closed", err)
	}
	f.edit(func() { f.authorityErr = errors.New("quorum unavailable") })
	if err := f.jobs.ObserveExit(ctx, f.spec, true); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.Remove(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	r, err := f.jobs.Record(f.spec)
	if err != nil || !r.Exited || r.ExitCode != 143 || !r.Cancel || !r.Removed {
		t.Fatal(r, err)
	}
	if f.count("POST /containers/"+strings.Repeat("b", 64)+"/stop") != 1 {
		t.Fatal("original not stopped")
	}
}

func TestNativeBuildMissingRunningJournalAndCorruptionCannotInitializeReplacement(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	if err := f.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(nativeBucket).Delete(nativeKey(f.spec))
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.Accept(f.grant); !errors.Is(err, ErrNativeMissing) {
		t.Fatal("missing running journal initialized", err)
	}
	if err := f.jobs.Create(ctx, f.spec); !errors.Is(err, ErrNativeMissing) {
		t.Fatal("missing original issued SDK effect", err)
	}
	if f.count("POST /containers/create") != 0 {
		t.Fatal("replacement container created")
	}
	f = newNativeFixture(t, false) // independent intact original for corruption
	if err := f.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		raw := bytes.Clone(b.Get(nativeKey(f.spec)))
		return b.Put(nativeKey(f.spec), append(raw, '\n'))
	}); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if _, err := f.jobs.Record(f.spec); !errors.Is(err, ErrStorage) {
		t.Fatal("noncanonical/corrupt journal adopted", err)
	}
}
