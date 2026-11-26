// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestACMEChallengeGoesToResponderAheadOfAppRoutes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "app "+r.URL.Path) }))
	defer backend.Close()
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "acme "+r.Host+" "+r.URL.Path)
	}))
	defer responder.Close()
	addr := netip.MustParseAddrPort(strings.TrimPrefix(backend.URL, "http://"))
	clear := ingressPort(t)
	s := Spec{Schema: 1, Owner: "owner", Listeners: []Listener{{ID: "clear", Address: clear}}, Routes: []Route{{ID: "root", Host: "shop.example", Prefix: "/", Service: "api"}, {ID: "other", Host: "other.test", Prefix: "/", Service: "api"}}, Services: []Service{{ID: "api", Backends: []BackendSpec{{ID: "b", Task: "workload/task/a", Network: "net", Generation: 1, Address: addr.Addr(), Port: addr.Port(), Weight: 1, Capacity: 2, HealthPath: "/health"}}}}, MaxRequests: 2, MaxConnections: 16, MaxHeaderBytes: 4096, BufferBytes: 2 * 64 << 10, MaxBodyBytes: 32, RequestTimeoutMS: 1500, DialTimeoutMS: 100, ResponseHeaderTimeoutMS: 500, HealthIntervalMS: 50}
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	key := "ingress/app/a"
	if err = m.Reconcile(ctx, key, 1, 1, &s); err != nil {
		t.Fatal(err)
	}
	for {
		if o, e := m.Observe(key); e == nil && o.Ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("ingress not ready")
		case <-time.After(10 * time.Millisecond):
		}
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	get := func(host, method, path string) (int, string) {
		t.Helper()
		r, _ := http.NewRequestWithContext(ctx, method, "http://"+clear+path, nil)
		r.Host = host
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	covers := func(host string) bool { return host == "shop.example" }
	path := ACMEChallengePath + "token"
	// Registered host, no responder: the path answers 404, never the app.
	if err = m.SetACMEResponder("", covers); err != nil {
		t.Fatal(err)
	}
	if code, body := get("shop.example", "GET", path); code != 404 || strings.HasPrefix(body, "app") {
		t.Fatal("challenge without responder reached the app", code, body)
	}
	if err = m.SetACMEResponder(strings.TrimPrefix(responder.URL, "http://"), covers); err != nil {
		t.Fatal(err)
	}
	if code, body := get("shop.example", "GET", path); code != 200 || body != "acme shop.example "+path {
		t.Fatal("challenge not forwarded with Host and path unchanged", code, body)
	}
	if code, _ := get("shop.example", "POST", path); code != 404 {
		t.Fatal("only GET/HEAD reach the responder", code)
	}
	if _, body := get("shop.example", "GET", "/.well-known/other"); body != "app /.well-known/other" {
		t.Fatal("other well-known path left the app", body)
	}
	if _, body := get("other.test", "GET", path); body != "app "+path {
		t.Fatal("host outside a registered domain must stay with the app", body)
	}
	// Route-free emergency blocks and the header limit still apply.
	now := uint64(time.Now().Unix())
	block := Block{ID: "host", Scope: "host", Host: "shop.example", Node: "node-a", Response: "403", Actor: "admin", CreatedAt: now}
	if err = m.SetBlocks(1, "node-a", []Block{block}, now); err != nil {
		t.Fatal(err)
	}
	if code, body := get("shop.example", "GET", path); code != 403 || strings.HasPrefix(body, "acme") {
		t.Fatal("blocked host reached the responder", code, body)
	}
	if err = m.SetBlocks(2, "node-a", nil, now); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequestWithContext(ctx, "GET", "http://"+clear+path, nil)
	r.Host, r.Header = "shop.example", http.Header{"X-Big": {strings.Repeat("a", 5000)}}
	if res, err := client.Do(r); err != nil || res.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatal("header limit skipped", err)
	} else {
		res.Body.Close()
	}
	if err = m.SetACMEResponder("web:80", covers); err == nil {
		t.Fatal("named responder accepted")
	}
}
