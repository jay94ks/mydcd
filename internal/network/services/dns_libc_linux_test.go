// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

// This isolates the real libc/PHP resolver from SQL/image preparation. The
// DNS algorithms are the product core, with fixture authority/origin/clock.
// Native owner provenance and Settings are deliberately outside this test.
func TestRealBoundaryDNSLibcSearchOrdering(t *testing.T) {
	host := os.Getenv("SFC_KERNEL_HOST_NETNS")
	ns, err := os.Readlink("/proc/self/ns/net")
	if host == "" || os.Geteuid() != 0 {
		t.Skip("prebuilt binary in explicit private network/mount namespace only")
	}
	if err != nil || host == ns {
		t.Fatal("refuse host namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	lo, err := net.InterfaceByName("lo")
	if err != nil || lo.Flags&net.FlagUp != 0 {
		t.Fatal("fresh isolated loopback required", err)
	}
	if out, err := exec.CommandContext(ctx, "ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	defer func() {
		if out, err := exec.Command("ip", "link", "set", "lo", "down").CombinedOutput(); err != nil {
			t.Error(err, string(out))
		}
	}()
	original, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		got, err := os.ReadFile("/etc/resolv.conf")
		if err != nil || !bytes.Equal(original, got) {
			t.Error("original namespace resolver bytes not restored", err)
		}
	}()
	d := newDNSFixture(t)
	d.cfg.Upstreams = nil
	d.cfg.Names = []DNSName{{"db", "web-four", 2}}
	d = publishDNS(t, d, d.cfg, 190)
	allocation, _ := d.f.a.book.Allocation("web-four")
	var mu sync.Mutex
	var trace []string
	packet, err := net.ListenPacket("udp4", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		mu.Lock()
		defer mu.Unlock()
		raw, err := request.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		m, h, err := d.m.Acquire(d.f.c, d.f.n, d.f.a, "first", "dns", d.origin, raw, d.clock(200))
		if err != nil {
			t.Error("original query acquisition", err)
			return
		}
		d.m = m
		answer, err := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(200))
		if err != nil || answer.Forward != nil || answer.Response == nil {
			t.Error("local product answer", err)
			return
		}
		wire, err := EncodeDNSReply(raw, answer.Response, false, d.cfg.MaxResponseBytes)
		if err == nil {
			_, err = w.Write(wire)
		}
		trace = append(trace, fmt.Sprintf("%s/%s rcode=%s", request.Question[0].Name, dns.TypeToString[request.Question[0].Qtype], dns.RcodeToString[answer.Response.Rcode]))
		if err != nil {
			t.Error(err)
		}
		d.m, err = d.m.Release(h, d.clock(200))
		if err != nil {
			t.Error(err)
		}
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	defer func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(d.m.Queries()) != 0 {
			t.Error("original query not returned")
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for _, ndots := range []int{0, 1} {
		func() {
			path := filepath.Join(t.TempDir(), "resolv.conf")
			data := fmt.Sprintf("nameserver 127.0.0.1\nsearch app.sfc.test\noptions timeout:1 attempts:1 ndots:%d\n", ndots)
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mount(path, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := unix.Unmount("/etc/resolv.conf", 0); err != nil {
					t.Error(err)
				}
			}()
			at := time.Now()
			out, err := exec.CommandContext(ctx, "/usr/bin/php8.3", "-n", "-r", `echo json_encode([gethostbyname("db.app.sfc.test."),gethostbyname("db")]);`).CombinedOutput()
			var result []string
			if err != nil || json.Unmarshal(out, &result) != nil || len(result) != 2 || result[0] != allocation.Address.String() {
				t.Fatal("actual PHP FQDN resolver", ndots, string(out), err)
			}
			t.Log("actual PHP", "ndots", ndots, "result", result, "elapsed", time.Since(at))
			if ndots == 1 && result[1] != allocation.Address.String() {
				t.Error("search-first policy did not resolve actual PHP short name", result)
			}
			out, err = exec.CommandContext(ctx, "python3", "-c", `import socket,json; print(json.dumps(sorted(set(a[4][0] for a in socket.getaddrinfo("db",None)))))`).CombinedOutput()
			t.Log("actual glibc getaddrinfo", "ndots", ndots, "result", string(out), "error", err)
			mu.Lock()
			t.Log("actual query trace", "ndots", ndots, trace)
			trace = nil
			mu.Unlock()
		}()
	}
}
