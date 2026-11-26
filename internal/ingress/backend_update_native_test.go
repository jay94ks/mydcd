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

	"github.com/jay94ks/mydcd/internal/schema"
)

// Uses real HTTP streams/listeners, probes and the durable Manager. Only the
// network pin adapter is fake: Docker/TUN ownership is covered by the app fixture.
func TestRealBoundaryBackendUpdateStreamsRestartAndWholeDrain(t *testing.T) {
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
	a, b, c := backend("a"), backend("b"), backend("c")
	spec := backendUpdateSpec()
	spec.Listeners[0].Address = ingressPort(t)
	setAddress := func(s *Spec, at int, server *httptest.Server) {
		address := netip.MustParseAddrPort(strings.TrimPrefix(server.URL, "http://"))
		s.Services[0].Backends[at].Address = address.Addr()
		s.Services[0].Backends[at].Port = address.Port()
	}
	setAddress(&spec, 0, a)
	setAddress(&spec, 1, b)
	deps := &backendTestDependencies{held: map[string]BackendSpec{}}
	path := filepath.Join(t.TempDir(), "ingress.db")
	m, err := Open(ctx, path, deps)
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
	wait("both original backend probes", func() bool {
		o, err := m.Observe(key)
		return err == nil && o.Ready && len(o.Backends) == 2
	})
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
	first, err := bufio.NewReader(stream.Body).ReadString('\n')
	if err != nil || first != "a\n" {
		t.Fatal("original request did not retain backend a", first, err)
	}
	target, err := DecodeSpec(marshal(spec))
	if err != nil {
		t.Fatal(err)
	}
	target.BindingRevision = 20
	target.Services[0].Backends[0].Generation, target.Services[0].Backends[0].Revision = 3, 3
	setAddress(&target, 0, c)
	if err := m.Reconcile(ctx, key, 8, 7, &target); err != nil {
		t.Fatal(err)
	}
	if o, err := m.Observe(key); err != nil || len(o.DrainedBackends) != 0 {
		t.Fatal("live original HTTP stream was acknowledged drained", o, err)
	}
	for range 3 {
		reply := request(ctx, "/ping")
		body, err := io.ReadAll(reply.Body)
		reply.Body.Close()
		if err != nil || reply.StatusCode != 200 || string(body) != "b\n" {
			observation, observeErr := m.Observe(key)
			t.Fatal("healthy peer interrupted while original stream drains", reply.StatusCode, string(body), err, observation, observeErr)
		}
		// Reading response EOF does not prove the handler's durable lease
		// return has finished. Keep this serving check below MaxRequests=2.
		wait("peer request durable return beside original stream", func() bool { o, _ := m.Observe(key); return o.Requests == 1 })
	}
	if len(deps.held) != 2 {
		t.Fatal("live stream lost its original network pin")
	}
	endStream()
	stream.Body.Close()
	wait("exact stream return", func() bool { o, _ := m.Observe(key); return o.Requests == 0 })
	o, err := m.Observe(key)
	if err != nil || len(o.DrainedBackends) != 1 || o.DrainedBackends[0].Task != spec.Services[0].Backends[0].Task || o.DrainedBackends[0].Generation != spec.Services[0].Backends[0].Generation {
		t.Fatal("positive original HTTP drain acknowledgement missing", o, err)
	}
	deps.unknown = true
	if err := m.Reconcile(ctx, key, 8, 7, &target); err == nil {
		t.Fatal("lost native acquire was reported as ready")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = Open(ctx, path, deps)
	if err != nil {
		t.Fatal("restart lost pending native source", err)
	}
	o, err = m.Observe(key)
	if err != nil || o.Started || o.Ready || len(o.Backends) != 0 {
		t.Fatal("restart reused old health", o, err)
	}
	if err := m.Reconcile(ctx, key, 8, 7, &target); err != nil {
		t.Fatal(err)
	}
	wait("replacement actual health after restart", func() bool {
		o, _ := m.Observe(key)
		return o.Ready && len(o.Backends) == 2 && o.Backends[0].Generation == 3
	})
	o, _ = m.Observe(key)
	if o.Generation != 7 || o.Revision != 8 || o.Listeners["http"] != spec.Listeners[0].Address || len(deps.held) != 2 {
		t.Fatal("restart changed listener identity or leaked pin", o)
	}
	seen := map[string]bool{}
	for range 4 {
		reply := request(ctx, "/ping")
		body, err := io.ReadAll(reply.Body)
		reply.Body.Close()
		if err != nil || reply.StatusCode != 200 {
			t.Fatal("actual replacement serving", err)
		}
		seen[string(body)] = true
	}
	if len(seen) != 2 || !seen["b\n"] || !seen["c\n"] {
		t.Fatal("actual replacement distribution", seen)
	}
	// Whole app termination can arrive with a newer, empty projected pool.
	// It must return both the actual old pins and the unknown pending acquire.
	pending, err := DecodeSpec(marshal(target))
	if err != nil {
		t.Fatal(err)
	}
	pending.BindingRevision = 30
	pending.Services[0].Backends[0].Generation, pending.Services[0].Backends[0].Revision = 4, 4
	deps.unknown = true
	if err := m.Reconcile(ctx, key, 8, 7, &pending); err == nil {
		t.Fatal("pending whole-drain setup lacks unknown acquire")
	}
	drain, err := DecodeSpec(marshal(target))
	if err != nil {
		t.Fatal(err)
	}
	drain.BindingRevision = 40
	drain.Services[0].Backends = nil
	drain.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
	if err := m.Reconcile(ctx, key, 9, 7, &drain); err != nil {
		t.Fatal("whole drain", err)
	}
	o, err = m.Observe(key)
	if err != nil || !o.Gone || o.Started || o.Requests != 0 || len(o.Listeners) != 0 || len(deps.held) != 0 {
		t.Fatal("whole drain did not settle actual and unknown sources", o, len(deps.held), err)
	}
	// Listener declaration changes require a positively closed predecessor.
	cold, err := DecodeSpec(marshal(target))
	if err != nil {
		t.Fatal(err)
	}
	cold.BindingRevision = 50
	cold.Listeners[0].Address = ingressPort(t)
	if err := m.Reconcile(ctx, key, 10, 8, &cold); err != nil {
		t.Fatal("cold successor after positive closure", err)
	}
	wait("cold successor probes", func() bool { o, _ := m.Observe(key); return o.Ready })
	cold.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{2}}
	if err := m.Reconcile(ctx, key, 11, 8, &cold); err != nil {
		t.Fatal(err)
	}
	if len(deps.held) != 0 {
		t.Fatal("cold successor leaked its consumers")
	}
}
