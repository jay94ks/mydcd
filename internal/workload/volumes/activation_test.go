// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

func TestGateUnsentChallengeAndPositiveClosure(t *testing.T) {
	f := makeFixture(t)
	c := f.acquire("database", 1, true)
	g, e := NewGate(f.s.Scope(), c.Owner, [32]byte{1})
	if e != nil {
		t.Fatal(e)
	}
	g, r, e := g.Request(c, [32]byte{2})
	if e != nil {
		t.Fatal(e)
	}
	g, e = g.CancelRequest(r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.Accept(Permit{r, f.s.Revision()}); e == nil {
		t.Fatal("cancelled challenge reused")
	}
	g, next, e := g.Request(c, [32]byte{3})
	if e != nil || next.Sequence <= r.Sequence {
		t.Fatal("sequence reused", e)
	}
	g, e = g.Accept(Permit{next, f.s.Revision()})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.CancelRequest(next); e == nil {
		t.Fatal("accepted Start abandoned")
	}
	if _, e = g.Fence(c.OwnerRevision); e == nil {
		t.Fatal("unknown Start bypassed fence")
	}
	wrong := c
	wrong.Generation++
	if _, e = g.CloseStart(wrong); e == nil {
		t.Fatal("other closure settled original")
	}
	g, e = g.CloseStart(c)
	if e != nil {
		t.Fatal(e)
	}
	g, e = g.Fence(c.OwnerRevision)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = g.Request(c, [32]byte{4}); e == nil {
		t.Fatal("fenced owner restarted")
	}
}

type activationSDK struct {
	startHook                                         func() error
	stopHook                                          func() error
	removeHook                                        func() error
	exitInspectHook                                   func()
	exitState                                         *container.State
	mu                                                sync.Mutex
	value                                             container.InspectResponse
	exists, running, loseStart, startRuns, loseRemove bool
	loseStop, keepRunningOnStop                       bool
	stopGrace, stopSignal                             string
	starts, stops, removes                            int
}

func (f *activationSDK) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/containers/json"):
		items := []container.Summary{}
		if f.exists {
			items = append(items, container.Summary{ID: f.value.ID})
		}
		_ = json.NewEncoder(w).Encode(items)
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/json"):
		if !f.exists {
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "missing original"})
			return
		}
		v := f.value
		v.State = &container.State{Running: f.running, Status: container.StateCreated}
		if f.running {
			v.State.Status = container.StateRunning
		}
		if !f.running && f.exitState != nil {
			state := *f.exitState
			v.State = &state
			if f.exitInspectHook != nil {
				f.exitInspectHook()
			}
		}
		_ = json.NewEncoder(w).Encode(v)
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/start"):
		if f.startHook != nil {
			if err := f.startHook(); err != nil {
				w.WriteHeader(500)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
				return
			}
		}
		f.starts++
		f.running = f.startRuns
		if f.loseStart {
			f.loseStart = false
			c, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				_ = c.Close()
			}
			return
		}
		w.WriteHeader(204)
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/stop"):
		if f.stopHook != nil {
			if err := f.stopHook(); err != nil {
				w.WriteHeader(500)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
				return
			}
		}
		f.stops++
		f.stopGrace, f.stopSignal = r.URL.Query().Get("t"), r.URL.Query().Get("signal")
		if !f.keepRunningOnStop {
			f.running = false
		}
		if f.loseStop {
			f.loseStop = false
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(204)
	case r.Method == "DELETE":
		if f.removeHook != nil {
			if err := f.removeHook(); err != nil {
				w.WriteHeader(500)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
				return
			}
		}
		f.removes++
		if r.URL.Query().Get("force") != "" {
			w.WriteHeader(400)
			return
		}
		f.exists = false
		if f.loseRemove {
			f.loseRemove = false
			c, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				_ = c.Close()
			}
			return
		}
		w.WriteHeader(204)
	default:
		w.WriteHeader(400)
	}
}

type activationFixture struct {
	sdk       *nativeSDKFixture
	spec      NativeSpec
	native    *NativeManager
	docker    *engine.Client
	ref       Activation
	http      *activationSDK
	path      string
	authority PermitAuthority
	calls     int
	deny      bool
}

func activationTest(t *testing.T) *activationFixture {
	t.Helper()
	ctx := context.Background()
	spec := nativeTestSpec(t)
	sdk := nativeSDK(t, spec)
	n, e := OpenNative(filepath.Join(t.TempDir(), "native.db"), sdk.client)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = n.Close() })
	key, e := n.Desired(spec, 1, 1, 4)
	if e != nil {
		t.Fatal(e)
	}
	if e = n.Step(ctx, key); e != nil {
		t.Fatal(e)
	}
	owner, scope, e := n.Owner(ctx, key)
	if e != nil {
		t.Fatal(e)
	}
	fake := makeFixture(t)
	core, e := New(fake.c, "admin", scope, owner, 4)
	if e != nil {
		t.Fatal(e)
	}
	core, c, e := core.Acquire(fake.c, "admin", core.Revision(), "database", 1, true)
	if e != nil {
		t.Fatal(e)
	}
	r := Activation{Scope: scope, Consumer: c, NativeKey: key, NativeGeneration: 1, TaskKey: "workload/task/tenant/app/database", Task: reconcile.Resource{Present: true, Generation: 1, Spec: `{"Schema":1,"test":"activation"}`}, Operation: 1}
	id, e := sdk.client.Identity("container", r.TaskKey, r.Task)
	if e != nil {
		t.Fatal(e)
	}
	h := &activationSDK{startRuns: true, value: container.InspectResponse{ID: strings.Repeat("a", 64), Name: "/" + id.Name, Config: &container.Config{Labels: id.Labels}, Mounts: []container.MountPoint{{Type: mount.TypeVolume, Name: owner.Native, Destination: "/data", RW: true}}}}
	sdk.mu.Lock()
	sdk.containerHandler = h
	sdk.mu.Unlock()
	f := &activationFixture{sdk: sdk, spec: spec, native: n, docker: sdk.client, ref: r, http: h, path: filepath.Join(t.TempDir(), "activation.db")}
	f.authority = func(ctx context.Context, r StartRequest) (Permit, error) {
		f.calls++
		if f.deny {
			return Permit{}, ErrVolume
		}
		return core.PermitStart(fake.c, "admin", r)
	}
	return f
}
func (f *activationFixture) open(t *testing.T) *Activations {
	t.Helper()
	s, e := OpenActivations(f.path, f.native, f.docker, f.spec.Scope.Cluster, f.spec.NodeKey, f.authority)
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func TestActivationUnknownRunningAndStoppedOriginalRecovery(t *testing.T) {
	for _, running := range []bool{true, false} {
		t.Run(map[bool]string{true: "running", false: "stopped"}[running], func(t *testing.T) {
			f := activationTest(t)
			s := f.open(t)
			defer func() { _ = s.Close() }()
			ctx := context.Background()
			if e := s.Plan(ctx, f.ref); e != nil {
				t.Fatal(e)
			}
			f.http.mu.Lock()
			f.http.exists = true
			f.http.startRuns = running
			f.http.loseStart = true
			f.http.mu.Unlock()
			if e := s.Activate(ctx, f.ref); e == nil {
				t.Fatal("lost Start reported successful")
			}
			before, e := s.Checkpoint(f.ref)
			if e != nil || before.Starting == nil {
				t.Fatal("unknown Start discarded", e)
			}
			if _, e = s.Fence(f.ref, 1); e == nil {
				t.Fatal("unknown Start bypassed fence")
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			s = f.open(t)
			f.deny = true
			e = s.Activate(ctx, f.ref)
			if running && e != nil || !running && !errors.Is(e, reconcile.ErrPending) {
				t.Fatal("original result recovery", e)
			}
			f.http.mu.Lock()
			starts := f.http.starts
			f.http.mu.Unlock()
			if starts != 1 || f.calls != 1 {
				t.Fatal("original Start/permit retransmitted", starts, f.calls)
			}
			f.http.mu.Lock()
			f.http.loseRemove = true
			f.http.mu.Unlock()
			if e = s.Retire(ctx, f.ref); e == nil {
				t.Fatal("lost Remove reported complete")
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			s = f.open(t)
			if e = s.Retire(ctx, f.ref); e != nil {
				t.Fatal("positive original ID removal", e)
			}
			proof, e := s.Gone(ctx, f.ref, makeFixture(t).a)
			if e != nil || proof.Consumer != f.ref.Consumer || !verify(f.spec.NodeKey, GoneBytes(proof), proof.Signature) {
				t.Fatal("signed Gone", e)
			}
			if cp, e := s.Fence(f.ref, 1); e != nil || cp.Starting != nil || cp.FenceThrough != 1 {
				t.Fatal("post-closure fence", e)
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			s = f.open(t)
			if _, e = s.Checkpoint(f.ref); e != nil {
				t.Fatal(e)
			}
			if e = s.Plan(ctx, f.ref); e == nil {
				t.Fatal("returned generation reborrowed")
			}
			r, _ := f.native.View(f.ref.NativeKey)
			if len(r.Consumers) != 0 {
				t.Fatal("native pin leaked")
			}
		})
	}
}
func TestActivationUnobservedCreateAndFreshAbort(t *testing.T) {
	f := activationTest(t)
	s := f.open(t)
	defer s.Close()
	ctx := context.Background()
	if e := s.Plan(ctx, f.ref); e != nil {
		t.Fatal(e)
	}
	if e := s.Retire(ctx, f.ref); !errors.Is(e, reconcile.ErrPending) {
		t.Fatal("unknown absent Create retired", e)
	}
	if _, e := s.Gone(ctx, f.ref, makeFixture(t).a); e == nil {
		t.Fatal("unknown absence signed Gone")
	}
	if e := s.AbortBeforeCreate(ctx, f.ref); e != nil {
		t.Fatal("positive fresh no-Create", e)
	}
	if _, e := s.Gone(ctx, f.ref, makeFixture(t).a); e != nil {
		t.Fatal("no-call closure", e)
	}
}
func TestActivationPermissionAndSyncFailuresNeverStart(t *testing.T) {
	f := activationTest(t)
	s := f.open(t)
	defer s.Close()
	ctx := context.Background()
	f.deny = true
	if e := s.Plan(ctx, f.ref); e != nil {
		t.Fatal(e)
	}
	f.http.mu.Lock()
	f.http.exists = true
	f.http.mu.Unlock()
	if e := s.Activate(ctx, f.ref); e == nil {
		t.Fatal("denied Start dispatched")
	}
	f.deny = false
	if e := s.db.Close(); e != nil {
		t.Fatal(e)
	}
	if e := s.Activate(ctx, f.ref); e == nil {
		t.Fatal("unsynced Start accepted")
	}
	f.http.mu.Lock()
	starts := f.http.starts
	f.http.mu.Unlock()
	if starts != 0 {
		t.Fatal("Start before durable accept")
	}
}

func TestActivationBorrowReceiptLossKeepsOriginalCleanupIntent(t *testing.T) {
	f := activationTest(t)
	s := f.open(t)
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	inspects := 0
	f.sdk.mu.Lock()
	f.sdk.volumeInspectHook = func() {
		inspects++
		if inspects == 2 {
			_ = s.db.Close()
		}
	}
	f.sdk.mu.Unlock()
	if e := s.Plan(ctx, f.ref); e == nil {
		t.Fatal("lost Borrow receipt sync accepted")
	}
	r, e := f.native.View(f.ref.NativeKey)
	if e != nil || len(r.Consumers) != 1 {
		t.Fatal("original Borrow not retained", e)
	}
	_ = s.Close()
	s = f.open(t)
	if e = s.AbortBeforeCreate(ctx, f.ref); e != nil {
		t.Fatal("durable intent could not return original token", e)
	}
	r, e = f.native.View(f.ref.NativeKey)
	if e != nil || len(r.Consumers) != 0 {
		t.Fatal("orphaned local pin", e)
	}
	if _, e = s.Gone(ctx, f.ref, makeFixture(t).a); e != nil {
		t.Fatal(e)
	}
}

func TestActivationFenceSerializesWithOriginalStart(t *testing.T) {
	f := activationTest(t)
	entered, release := make(chan struct{}), make(chan struct{})
	authority := f.authority
	f.authority = func(ctx context.Context, r StartRequest) (Permit, error) {
		close(entered)
		<-release
		return authority(ctx, r)
	}
	s := f.open(t)
	defer s.Close()
	ctx := context.Background()
	if e := s.Plan(ctx, f.ref); e != nil {
		t.Fatal(e)
	}
	f.http.mu.Lock()
	f.http.exists = true
	f.http.mu.Unlock()
	started := make(chan error, 1)
	fenced := make(chan error, 1)
	go func() { started <- s.Activate(ctx, f.ref) }()
	<-entered
	go func() { _, e := s.Fence(f.ref, 1); fenced <- e }()
	select {
	case e := <-fenced:
		t.Fatal("Fence passed an outstanding Start", e)
	default:
	}
	close(release)
	if e := <-started; e != nil {
		t.Fatal(e)
	}
	if e := <-fenced; e != nil {
		t.Fatal(e)
	}
	f.http.mu.Lock()
	f.http.running = false
	f.http.mu.Unlock()
	if e := s.Activate(ctx, f.ref); e == nil {
		t.Fatal("fenced restart dispatched")
	}
	f.http.mu.Lock()
	calls := f.http.starts
	f.http.mu.Unlock()
	if calls != 1 {
		t.Fatal("unexpected native Start count", calls)
	}
	if e := s.Retire(ctx, f.ref); e != nil {
		t.Fatal(e)
	}
}

func TestActivationConcurrentPlanKeepsOneOriginalPin(t *testing.T) {
	f := activationTest(t)
	s := f.open(t)
	defer s.Close()
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { <-start; results <- s.Plan(context.Background(), f.ref) }()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	r, err := f.native.View(f.ref.NativeKey)
	if err != nil || len(r.Consumers) != 1 {
		t.Fatal("duplicate or lost original pin", err)
	}
	e, err := s.entry(f.ref, false)
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	count := len(e.disk.Bindings)
	e.mu.Unlock()
	if count != 1 {
		t.Fatal("concurrent entry publication forked bindings")
	}
	if err = s.AbortBeforeCreate(context.Background(), f.ref); err != nil {
		t.Fatal(err)
	}
}
