// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the actual HTTP client, health loop, balancer and persisted record.
// Delayed successful and rejected responses must both retain a post-read pause.
func TestHealthSlowResponseKeepsPostReadIntervalAndCancellation(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			starts, ends := make(chan time.Time, 4), make(chan time.Time, 4)
			var requests atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				starts <- time.Now()
				select {
				case <-time.After(250 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
				w.WriteHeader(status)
				ends <- time.Now()
			}))
			defer backend.Close()
			addr := netip.MustParseAddrPort(strings.TrimPrefix(backend.URL, "http://"))
			spec := Spec{Schema: 1, Owner: "owner", Listeners: []Listener{{ID: "http", Address: ingressPort(t)}}, Routes: []Route{{ID: "r", Host: "*", Prefix: "/", Service: "api"}}, Services: []Service{{ID: "api", Backends: []BackendSpec{{ID: "a", Task: "workload/task/a", Network: "net", Generation: 1, Address: addr.Addr(), Port: addr.Port(), Weight: 1, Capacity: 1, HealthPath: "/health"}}}}, MaxRequests: 1, MaxConnections: 1, MaxHeaderBytes: 1024, BufferBytes: 64 << 10, MaxBodyBytes: 1024, RequestTimeoutMS: 1000, DialTimeoutMS: 100, ResponseHeaderTimeoutMS: 1000, HealthIntervalMS: 100}
			manager, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			defer func() {
				if !closed {
					if err := manager.Close(); err != nil {
						t.Error(err)
					}
				}
			}()
			if err = manager.Reconcile(ctx, "ingress/app/a", 1, 1, &spec); err != nil {
				t.Fatal(err)
			}
			receive := func(ch <-chan time.Time) time.Time {
				t.Helper()
				select {
				case v := <-ch:
					return v
				case <-ctx.Done():
					t.Fatal(ctx.Err())
					return time.Time{}
				}
			}
			_ = receive(starts)
			finished := receive(ends)
			second := receive(starts)
			if gap := second.Sub(finished); gap < 90*time.Millisecond {
				t.Fatalf("health catch-up after slow response: gap=%s", gap)
			}
			cancel()
			if err = manager.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
			time.Sleep(120 * time.Millisecond)
			if got := requests.Load(); got != 2 {
				t.Fatalf("canceled health loop dispatched more reads: %d", got)
			}
		})
	}
}
