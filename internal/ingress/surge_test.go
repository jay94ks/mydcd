// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A newer generation takes a draining ID at once; the older one keeps only its
// pins, is never selected, and survives a checkpoint until it is removed.
func TestBalancerSuccessorTakesDrainingID(t *testing.T) {
	b, _ := NewBalancer(1000)
	if err := b.Update(Backend{ID: "a", Generation: 2, Weight: 1, Capacity: 2, Healthy: true, ObservedAt: 100}); err != nil {
		t.Fatal(err)
	}
	old, err := b.Acquire(100)
	if err != nil || old.Lease.Generation != 2 {
		t.Fatal(old, err)
	}
	if err := b.Update(Backend{ID: "a", Generation: 3, Weight: 1, Capacity: 2, Healthy: true, ObservedAt: 100}); err == nil {
		t.Fatal("serving generation replaced without draining")
	}
	if err := b.Update(Backend{ID: "a", Generation: 2, Weight: 1, Capacity: 2, Healthy: true, Draining: true, ObservedAt: 100}); err != nil {
		t.Fatal(err)
	}
	if err := b.Update(Backend{ID: "a", Generation: 3, Weight: 1, Capacity: 2, Healthy: true, ObservedAt: 100}); err != nil {
		t.Fatal("successor refused", err)
	}
	next, err := b.Acquire(100)
	if err != nil || next.Backend != "a" || next.Lease.Generation != 3 {
		t.Fatal("successor not selected", next, err)
	}
	restored, err := RestoreBalancer(b.Checkpoint())
	if err != nil {
		t.Fatal("checkpoint with a retiring generation", err)
	}
	if err := restored.Remove("a", 2); err == nil {
		t.Fatal("pinned older generation removed")
	}
	if err := restored.Update(Backend{ID: "a", Generation: 2, Weight: 1, Capacity: 2, Healthy: true, ObservedAt: 100}); err == nil {
		t.Fatal("retiring generation served again")
	}
	if err := restored.Release(old); err != nil {
		t.Fatal(err)
	}
	if err := restored.Remove("a", 2); err != nil {
		t.Fatal(err)
	}
	if err := restored.Release(next); err != nil {
		t.Fatal("successor lease lost", err)
	}
	if err := restored.Update(Backend{ID: "a", Generation: 2, Weight: 1, Capacity: 2, Draining: true, ObservedAt: 100}); err == nil {
		t.Fatal("removed generation came back")
	}
	// The successor can also leave first; the older one still restores.
	b, _ = NewBalancer(1000)
	_ = b.Update(Backend{ID: "a", Generation: 2, Weight: 1, Capacity: 2, Healthy: true, Draining: true, ObservedAt: 100})
	_ = b.Update(Backend{ID: "a", Generation: 3, Weight: 1, Capacity: 2, Healthy: true, ObservedAt: 100})
	_ = b.Update(Backend{ID: "a", Generation: 3, Weight: 1, Capacity: 2, Healthy: true, Draining: true, ObservedAt: 100})
	if err := b.Remove("a", 3); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreBalancer(b.Checkpoint()); err != nil {
		t.Fatal("orphaned retiring generation", err)
	}
}

func TestSpecListsOnlyDrainingOlderGenerationBesideSuccessor(t *testing.T) {
	surge := func() Spec {
		s := backendUpdateSpec()
		old := s.Services[0].Backends[0]
		old.Draining = true
		next := s.Services[0].Backends[0]
		next.Generation, next.Revision = 3, 3
		s.Services[0].Backends = []BackendSpec{next, old, s.Services[0].Backends[1]}
		return s
	}
	if _, err := DecodeSpec(marshal(surge())); err != nil {
		t.Fatal("surge view refused", err)
	}
	for name, change := range map[string]func(*Spec){
		"older serving":   func(s *Spec) { s.Services[0].Backends[1].Draining = false },
		"other task":      func(s *Spec) { s.Services[0].Backends[1].Task = "workload/task/tenant/app/web/node-c/r1" },
		"same generation": func(s *Spec) { s.Services[0].Backends[0].Generation, s.Services[0].Backends[0].Revision = 2, 2 },
		"third generation": func(s *Spec) {
			third := s.Services[0].Backends[1]
			third.Generation, third.Revision = 1, 1
			s.Services[0].Backends = append(s.Services[0].Backends, third)
		},
		"fixed backends": func(s *Spec) {
			s.DynamicBackends = false
			for at := range s.Services[0].Backends {
				s.Services[0].Backends[at].Revision, s.Services[0].Backends[at].Draining = 0, false
			}
		},
	} {
		s := surge()
		change(&s)
		if _, err := DecodeSpec(marshal(s)); err == nil {
			t.Fatal(name, "accepted")
		}
	}
}

// The surge view completes at once although the older generation still holds
// a request: the successor serves, and once that request returns the older
// generation is reported drained beside the serving successor.
func TestBackendUpdateSurgeServesSuccessorBeforeOlderDrains(t *testing.T) {
	ctx := context.Background()
	deps := &backendTestDependencies{held: map[string]BackendSpec{}}
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	spec := backendUpdateSpec()
	r, err := newRecord(8, 7, spec)
	if err != nil {
		t.Fatal(err)
	}
	balancer, _ := RestoreBalancer(r.Balances["web"])
	for _, backend := range spec.Services[0].Backends {
		if err := balancer.Update(Backend{ID: backend.ID, Generation: 2, Weight: 1, Capacity: 2, Healthy: true, ObservedAt: 100}); err != nil {
			t.Fatal(err)
		}
		_ = deps.Acquire(ctx, backend, backendConsumer("listener", 7, spec, backend))
	}
	var pinned BackendLease
	for pinned.Backend != "a" {
		if pinned, err = balancer.Acquire(100); err != nil {
			t.Fatal(err)
		}
	}
	r.Balances["web"] = balancer.Checkpoint()
	i := newInstance(m, "listener", r)
	i.started = true
	m.instances["listener"] = i
	if err := i.save(r); err != nil {
		t.Fatal(err)
	}
	surge := backendUpdateSpec()
	surge.BindingRevision = 20
	old := surge.Services[0].Backends[0]
	old.Draining = true
	next := old
	next.Draining, next.Generation, next.Revision = false, 3, 3
	surge.Services[0].Backends = []BackendSpec{next, old, surge.Services[0].Backends[1]}
	if err := m.reconcileBackends(ctx, i, 8, 7, surge); err != nil {
		t.Fatal(err)
	}
	if i.record.Update != nil || len(i.record.Spec.Services[0].Backends) != 3 || len(deps.returned) != 0 {
		t.Fatal("surge view waited for the older generation's request", i.record.Update != nil, deps.returned)
	}
	if _, held := deps.held[backendConsumer("listener", 7, surge, next)]; !held {
		t.Fatal("successor network source not acquired")
	}
	if err := validateRecord(i.copyRecord()); err != nil {
		t.Fatal("surge record", err)
	}
	active, _ := RestoreBalancer(i.record.Balances["web"])
	if err := active.Update(Backend{ID: "a", Generation: 3, Weight: 1, Capacity: 2, Healthy: true, ObservedAt: 100}); err != nil {
		t.Fatal(err)
	}
	serving := false
	for range 4 {
		lease, err := active.Acquire(100)
		if err != nil {
			t.Fatal(err)
		}
		if lease.Backend == "a" && lease.Lease.Generation != 3 {
			t.Fatal("draining generation selected")
		}
		serving = serving || lease.Backend == "a"
		_ = active.Release(lease)
	}
	if !serving {
		t.Fatal("successor not selected")
	}
	o, err := m.Observe("listener")
	if err != nil {
		t.Fatal(err)
	}
	if len(o.DrainedBackends) != 0 {
		t.Fatal("older generation reported drained while its request runs", o.DrainedBackends)
	}
	if err := active.Release(pinned); err != nil {
		t.Fatal(err)
	}
	r = i.copyRecord()
	r.Balances["web"] = active.Checkpoint()
	if err := i.save(r); err != nil {
		t.Fatal(err)
	}
	o, err = m.Observe("listener")
	if err != nil {
		t.Fatal(err)
	}
	if len(o.DrainedBackends) != 1 || o.DrainedBackends[0] != (BackendObservation{Task: old.Task, Generation: 2, Revision: 2}) {
		t.Fatal("older generation not reported drained", o.DrainedBackends)
	}
	for _, row := range o.Backends {
		if row.Task == old.Task && row.Generation != 3 {
			t.Fatal("older generation reported serving", o.Backends)
		}
	}
	// After IngressDrained the older generation leaves the view at once.
	final := backendUpdateSpec()
	final.BindingRevision = 30
	final.Services[0].Backends[0] = next
	if err := m.reconcileBackends(ctx, i, 8, 7, final); err != nil {
		t.Fatal(err)
	}
	if i.record.Update != nil || len(i.record.Spec.Services[0].Backends) != 2 || len(deps.returned) != 1 || deps.returned[0] != backendConsumer("listener", 7, spec, spec.Services[0].Backends[0]) {
		t.Fatal("older generation not released", i.record.Update != nil, deps.returned)
	}
	if err := validateRecord(i.copyRecord()); err != nil {
		t.Fatal("final record", err)
	}
}

// A single-instance service over real listeners: during the surge view the
// successor answers new requests while the older generation's stream runs.
func TestRealBoundarySurgeKeepsSingleBackendServing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	backend := func(name string) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ready" {
				return
			}
			fmt.Fprintln(w, name)
			if r.URL.Path == "/events" {
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}
		}))
		t.Cleanup(server.Close)
		return server
	}
	original, successor := backend("old"), backend("new")
	at := func(b *BackendSpec, server *httptest.Server) {
		address := netip.MustParseAddrPort(strings.TrimPrefix(server.URL, "http://"))
		b.Address, b.Port = address.Addr(), address.Port()
	}
	spec := backendUpdateSpec()
	spec.Listeners[0].Address = ingressPort(t)
	spec.Services[0].Backends = spec.Services[0].Backends[:1]
	at(&spec.Services[0].Backends[0], original)
	deps := &backendTestDependencies{held: map[string]BackendSpec{}}
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	const key = "listener"
	if err := m.Reconcile(ctx, key, 8, 7, &spec); err != nil {
		t.Fatal(err)
	}
	wait := func(label string, predicate func() bool) {
		t.Helper()
		for !predicate() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	wait("original probe", func() bool { o, err := m.Observe(key); return err == nil && o.Ready && len(o.Backends) == 1 })
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	request := func(requestCtx context.Context, path string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://"+spec.Listeners[0].Address+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "app.test"
		reply, err := client.Do(req)
		if err != nil {
			t.Fatal("actual listener", err)
		}
		return reply
	}
	streamCtx, endStream := context.WithCancel(ctx)
	defer endStream()
	stream := request(streamCtx, "/events")
	defer stream.Body.Close()
	if first, err := bufio.NewReader(stream.Body).ReadString('\n'); err != nil || first != "old\n" {
		t.Fatal("stream on the original generation", first, err)
	}
	surge, _ := DecodeSpec(marshal(spec))
	surge.BindingRevision = 20
	old := surge.Services[0].Backends[0]
	old.Draining = true
	next := old
	next.Draining, next.Generation, next.Revision = false, 3, 3
	at(&next, successor)
	surge.Services[0].Backends = []BackendSpec{old, next}
	if err := m.Reconcile(ctx, key, 8, 7, &surge); err != nil {
		t.Fatal(err)
	}
	wait("successor probe", func() bool {
		o, _ := m.Observe(key)
		return len(o.Backends) == 1 && o.Backends[0].Generation == 3
	})
	for range 3 {
		reply := request(ctx, "/ping")
		body, err := io.ReadAll(reply.Body)
		reply.Body.Close()
		if err != nil || reply.StatusCode != 200 || string(body) != "new\n" {
			t.Fatal("single backend interrupted during surge", reply.StatusCode, string(body), err)
		}
		wait("request return beside the stream", func() bool { o, _ := m.Observe(key); return o.Requests == 1 })
	}
	if o, _ := m.Observe(key); len(o.DrainedBackends) != 0 {
		t.Fatal("older generation drained while its stream runs", o.DrainedBackends)
	}
	endStream()
	stream.Body.Close()
	wait("older generation drained", func() bool {
		o, _ := m.Observe(key)
		return len(o.DrainedBackends) == 1 && o.DrainedBackends[0] == BackendObservation{Task: old.Task, Generation: 2, Revision: 2}
	})
	final, _ := DecodeSpec(marshal(surge))
	final.BindingRevision = 30
	final.Services[0].Backends = []BackendSpec{next}
	if err := m.Reconcile(ctx, key, 8, 7, &final); err != nil {
		t.Fatal(err)
	}
	if len(deps.held) != 1 {
		t.Fatal("older generation's network source kept", deps.held)
	}
	reply := request(ctx, "/ping")
	body, _ := io.ReadAll(reply.Body)
	reply.Body.Close()
	if reply.StatusCode != 200 || string(body) != "new\n" {
		t.Fatal("successor after the older generation left", reply.StatusCode, string(body))
	}
}
