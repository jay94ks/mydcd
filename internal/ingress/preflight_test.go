// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealBoundaryIngressPreflightClosesPartialTCPUDPAndChecksActualTLS(t *testing.T) {
	ctx := context.Background()
	certificate, _ := ingressCertificate(t)
	deps := boundaryDependencies{}
	m, err := openWithCertificates(ctx, filepath.Join(t.TempDir(), "ingress.db"), deps, certificate)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	first, second := ingressPort(t), udp.LocalAddr().String()
	listeners := []Listener{{ID: "plain", Address: first}, {ID: "secure", Address: second, TLS: true, HTTP3: true}}
	if m.CheckListeners(ctx, "app", 0, 0, nil, listeners) == nil {
		t.Fatal("occupied HTTP3 UDP endpoint was not checked")
	}
	checkFree := func(address string, packet bool) {
		t.Helper()
		if packet {
			l, e := net.ListenPacket("udp4", address)
			if e != nil {
				t.Fatal("temporary UDP socket leaked", e)
			}
			if e = l.Close(); e != nil {
				t.Fatal(e)
			}
		} else {
			l, e := net.Listen("tcp4", address)
			if e != nil {
				t.Fatal("partial TCP socket leaked", e)
			}
			if e = l.Close(); e != nil {
				t.Fatal(e)
			}
		}
	}
	checkFree(first, false)
	checkFree(second, false)
	if err = udp.Close(); err != nil {
		t.Fatal(err)
	}
	if err = m.CheckListeners(ctx, "app", 0, 0, nil, listeners); err != nil {
		t.Fatal("available ports/TLS rejected", err)
	}
	checkFree(first, false)
	checkFree(second, false)
	checkFree(second, true)
	tcp, err := net.Listen("tcp4", first)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	if m.CheckListeners(ctx, "app", 0, 0, nil, listeners) == nil {
		t.Fatal("occupied TCP endpoint was not checked")
	}
	checkFree(second, false)
	checkFree(second, true)
	if err = tcp.Close(); err != nil {
		t.Fatal(err)
	}
	if len(m.Keys()) != 0 || len(deps) != 0 {
		t.Fatal("preflight published a native instance/dependency")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if m.CheckListeners(cancelled, "app", 0, 0, nil, listeners) == nil {
		t.Fatal("cancelled preflight accepted")
	}
}

func TestRealBoundaryIngressPreflightFencesCurrentOwnerSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer backend.Close()
	address := netip.MustParseAddrPort(strings.TrimPrefix(backend.URL, "http://"))
	s := Spec{Schema: 1, Owner: "owner", Listeners: []Listener{{ID: "http", Address: ingressPort(t)}}, Routes: []Route{{ID: "r", Host: "*", Prefix: "/", Service: "api"}}, Services: []Service{{ID: "api", Backends: []BackendSpec{{ID: "a", Task: "workload/task/a", Network: "net", Generation: 1, Address: address.Addr(), Port: address.Port(), Weight: 1, Capacity: 1, HealthPath: "/health"}}}}, MaxRequests: 1, MaxConnections: 1, MaxHeaderBytes: 1024, BufferBytes: 64 << 10, MaxBodyBytes: 1024, RequestTimeoutMS: 1000, DialTimeoutMS: 100, ResponseHeaderTimeoutMS: 100, HealthIntervalMS: 100}
	if err = m.Reconcile(ctx, "app", 7, 3, &s); err != nil {
		t.Fatal(err)
	}
	if err = m.CheckListeners(ctx, "app", 7, 3, &s, s.Listeners); err != nil {
		t.Fatal("exact already-open owner source could not be observed", err)
	}
	if m.CheckListeners(ctx, "app", 7, 4, &s, s.Listeners) == nil {
		t.Fatal("different generation borrowed live owner listener")
	}
	if m.CheckListeners(ctx, "app", 8, 3, &s, s.Listeners) == nil {
		t.Fatal("different source revision borrowed live owner listener")
	}
	if m.CheckListeners(ctx, "app", 0, 0, nil, s.Listeners) == nil {
		t.Fatal("unrecorded source adopted native listener")
	}
	wrong := s
	wrong.MaxConnections++
	if m.CheckListeners(ctx, "app", 7, 3, &wrong, s.Listeners) == nil {
		t.Fatal("different source spec borrowed live owner listener")
	}
	if m.CheckListeners(ctx, "other", 0, 0, nil, s.Listeners) == nil {
		t.Fatal("other resource borrowed occupied endpoint")
	}
}
