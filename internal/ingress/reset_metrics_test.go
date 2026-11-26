// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Reuses the owned ingress Manager/listener, actual TCP proxy and existing
// backend dependency fixture. All sockets/DBs belong to this finite test.
func TestIngressResetWithoutHTTPStatusIsBlockedFailureAndNeverSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hints" {
			w.Header().Set("Link", "</early.css>; rel=preload")
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Del("Link")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, "created")
		}
		// /empty and /health deliberately return an implicit, bodyless 200.
	}))
	defer backend.Close()
	addr := netip.MustParseAddrPort(strings.TrimPrefix(backend.URL, "http://"))
	endpoint := ingressPort(t)
	spec := Spec{Schema: 1, Owner: "owner", Tenant: "tenant", App: "app", Listeners: []Listener{{ID: "clear", Address: endpoint}}, Routes: []Route{{ID: "root", Host: "example.test", Prefix: "/", Service: "api"}}, Services: []Service{{ID: "api", Backends: []BackendSpec{{ID: "original", Task: "workload/task/a", Network: "net", Generation: 1, Address: addr.Addr(), Port: addr.Port(), Weight: 1, Capacity: 2, HealthPath: "/health"}}}}, MaxRequests: 2, MaxConnections: 16, MaxHeaderBytes: 4096, BufferBytes: 2 * 64 << 10, MaxBodyBytes: 32, RequestTimeoutMS: 1500, DialTimeoutMS: 100, ResponseHeaderTimeoutMS: 200, HealthIntervalMS: 50}
	manager, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	}()
	key := "ingress/app/tenant/app/http"
	if err := manager.Reconcile(ctx, key, 1, 1, &spec); err != nil {
		t.Fatal(err)
	}
	wait := func(label string, ready func() bool) {
		t.Helper()
		for !ready() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	wait("original backend healthy", func() bool { got, err := manager.Observe(key); return err == nil && got.Ready })
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request := func(requestCtx context.Context, path string, want int) {
		t.Helper()
		r, err := http.NewRequestWithContext(requestCtx, "GET", "http://"+endpoint+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "example.test"
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(path, err)
		}
		body, err := io.ReadAll(response.Body)
		closed := response.Body.Close()
		if err != nil || closed != nil || response.StatusCode != want || path == "/empty" && len(body) != 0 || path == "/hints" && string(body) != "created" {
			t.Fatal("actual response", path, response.StatusCode, string(body), err, closed)
		}
	}
	snapshot := func() Metrics { return manager.Metrics(key, uint64(time.Now().UnixMilli())) }
	settle := func(requests uint64) Metrics {
		t.Helper()
		wait("request metric recorded", func() bool { return snapshot().Instance.Requests == requests })
		return snapshot()
	}
	request(ctx, "/empty", http.StatusOK)
	if got := settle(1); got.Instance.Responses != [4]uint64{1, 0, 0, 0} || got.Instance.Blocked != 0 {
		t.Fatal("implicit bodyless 200 lost", got.Instance)
	}
	hints := make(chan int, 1)
	trace := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textproto.MIMEHeader) error { hints <- code; return nil }})
	request(trace, "/hints", http.StatusCreated)
	select {
	case code := <-hints:
		if code != http.StatusEarlyHints {
			t.Fatal("unexpected informational code", code)
		}
	default:
		t.Fatal("upstream 103 was not forwarded")
	}
	if got := settle(2); got.Instance.Responses != [4]uint64{2, 0, 0, 0} || got.Instance.Blocked != 0 {
		t.Fatal("103 displaced final 201 metric", got.Instance)
	}
	for index, mode := range []string{"403", "503", "reset"} {
		before := snapshot()
		now := uint64(time.Now().Unix())
		block := Block{ID: "maintenance", Scope: "route", Tenant: "tenant", App: "app", Node: "node-a", Key: key, Route: "root", Host: "example.test", Prefix: "/", Response: mode, Actor: "admin", CreatedAt: now - 1, ExpiresAt: now + 60}
		if err := manager.SetBlocks(uint64(index+1), "node-a", []Block{block}, now); err != nil {
			t.Fatal(err)
		}
		if mode == "reset" {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				conn.Close()
				t.Fatal(err)
			}
			_, err = fmt.Fprint(conn, "GET /reset HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
			if err != nil {
				conn.Close()
				t.Fatal(err)
			}
			response, readErr := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
			conn.Close()
			if response != nil || readErr == nil {
				t.Fatal("reset emitted an HTTP response", response, readErr)
			}
			if timed, ok := readErr.(net.Error); ok && timed.Timeout() {
				t.Fatal("reset did not close the actual TCP stream", readErr)
			}
		} else {
			status := http.StatusForbidden
			if mode == "503" {
				status = http.StatusServiceUnavailable
			}
			request(ctx, "/blocked", status)
		}
		after := settle(before.Instance.Requests + 1)
		want := before.Instance.Responses
		if mode == "403" {
			want[2]++
		}
		if mode == "503" {
			want[3]++
		}
		if after.Instance.Responses != want || after.Instance.Blocked != before.Instance.Blocked+1 || len(after.Routes) != 1 || after.Routes[0].Responses != want || after.Routes[0].Blocked != after.Instance.Blocked || len(after.Backends) != 1 || after.Backends[0].Requests != 2 {
			t.Fatal("block response misclassified as successful upstream response", mode, before, after)
		}
		last := after.Errors[len(after.Errors)-1]
		if mode == "reset" && (after.Instance.Failures["blocked-reset"] != before.Instance.Failures["blocked-reset"]+1 || last.Status != 0 || last.Block != block.ID || last.Failure != "blocked-reset" || after.Instance.SentBytes != before.Instance.SentBytes) {
			t.Fatal("reset lacks code-free blocked/failure observation", after.Instance, last)
		}
	}
	if err := manager.SetBlocks(4, "node-a", nil, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	before := snapshot()
	request(ctx, "/empty", http.StatusOK)
	after := settle(before.Instance.Requests + 1)
	if after.Instance.Responses[0] != before.Instance.Responses[0]+1 || after.Instance.Blocked != before.Instance.Blocked {
		t.Fatal("reset changed subsequent implicit 200 handling", after.Instance)
	}
}
