// SPDX-License-Identifier: Apache-2.0

package workload_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/tests/enginefixture"
	"github.com/miekg/dns"
	"github.com/moby/moby/client"
)

func TestRealBoundaryDockerResolverSearchAndOriginalJournal(t *testing.T) {
	owner, backend := os.Getenv("MYDC_DOCKER_TEST_OWNER"), os.Getenv("MYDC_DOCKER_TEST_BACKEND")
	if owner == "" || backend == "" || os.Geteuid() != 0 {
		t.Skip("requires owned rollback prestate and user-prebuilt backend/test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	f := enginefixture.OpenPrepared(t, ctx, owner, owner, []string{`USER 10001:10001`, `ENV MYDC_DNS_FIXTURE=1`}, backend)
	root := t.TempDir()
	nPath, wPath := filepath.Join(root, "network.db"), filepath.Join(root, "workload.db")
	n, err := network.OpenManager(nPath, f.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	w, err := workload.OpenManager(wPath, f.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	prefix := netip.MustParsePrefix(os.Getenv("MYDC_DOCKER_TEST_CIDR"))
	gateway := prefix.Addr().Next()
	bridgeKey, taskKey := "network/resolver", "workload/resolver"
	bridge := network.BridgeSpec{Schema: 1, Network: "resolver", Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "resolver", Network: "resolver", Owner: owner, Prefix: prefix, Gateway: gateway, MTU: 1280}}}
	if err = n.Desired(bridgeKey, 1, 1, &bridge, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	lease, err := n.Acquire(ctx, bridgeKey, "resolver-fixture", 1)
	if err != nil {
		t.Fatal(err)
	}
	// This is an upstream fixture for the real Docker resolver adapter, not
	// MyDC's embedded DNS owner or proof of its authority/tenant admission.
	address := net.JoinHostPort(gateway.String(), "53")
	udp, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	var queries atomic.Int64
	var udpQueries, tcpQueries atomic.Int64
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if len(q.Question) != 1 || q.Question[0].Name != "probe.app.mydc.test." {
			m.Rcode = dns.RcodeNameError
		} else {
			queries.Add(1)
			if w.RemoteAddr().Network() == "tcp" {
				tcpQueries.Add(1)
			} else {
				udpQueries.Add(1)
			}
			if q.Question[0].Qtype == dns.TypeA {
				m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(192, 0, 2, 23)}}
			}
		}
		_ = w.WriteMsg(m)
	})
	udpReady, tcpReady := make(chan struct{}), make(chan struct{})
	u := &dns.Server{PacketConn: udp, Handler: handler, NotifyStartedFunc: func() { close(udpReady) }}
	s := &dns.Server{Listener: tcp, Handler: handler, NotifyStartedFunc: func() { close(tcpReady) }}
	udpDone, tcpDone := make(chan error, 1), make(chan error, 1)
	go func() { udpDone <- u.ActivateAndServe() }()
	go func() { tcpDone <- s.ActivateAndServe() }()
	stop := func() {
		clean, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_ = u.ShutdownContext(clean)
		_ = s.ShutdownContext(clean)
	}
	defer stop()
	for _, ready := range []chan struct{}{udpReady, tcpReady} {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	image, err := f.Client.Image(ctx, f.Image, false)
	if err != nil {
		t.Fatal(err)
	}
	process, err := workload.ResolveImageProcess(image, workload.ProcessOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	spec := workload.ContainerSpec{Schema: 1, Node: owner, Image: f.Image, Bridge: bridgeKey, BridgeGeneration: 1, IPv4: gateway.Next(), Memory: 32 << 20, NanoCPU: 100000000, Process: &process, Resolver: &workload.Resolver{Servers: []netip.Addr{gateway}, Search: []string{"app.mydc.test"}}}
	if err = w.Desired(taskKey, 2, 2, &spec, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	status, err := w.Status(ctx, taskKey)
	if err != nil || !status.Running {
		t.Fatal("not running", status, err)
	}
	originalID := status.NativeID
	inspect, err := f.Client.API.ContainerInspect(ctx, originalID, client.ContainerInspectOptions{})
	if err != nil || !slices.Equal(inspect.Container.HostConfig.DNS, spec.Resolver.Servers) || !slices.Equal(inspect.Container.HostConfig.DNSSearch, spec.Resolver.Search) {
		t.Fatal("Docker changed resolver input", err)
	}
	httpClient := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer httpClient.CloseIdleConnections()
	query := func(transport string) {
		t.Helper()
		before := queries.Load()
		url := "http://" + spec.IPv4.String() + ":8080/resolve?name=probe&transport=" + transport
		for {
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := httpClient.Do(req)
			if err == nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 128))
				_ = response.Body.Close()
				if readErr != nil || response.StatusCode != 200 || string(body) != "192.0.2.23" || queries.Load() <= before {
					t.Fatal("native lookup/search failed", response.StatusCode, string(body), readErr)
				}
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	query("udp")
	query("tcp")
	if udpQueries.Load() == 0 || tcpQueries.Load() == 0 {
		t.Fatal("actual DNS transport not exercised", udpQueries.Load(), tcpQueries.Load())
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	n, err = network.OpenManager(nPath, f.Client)
	if err != nil {
		t.Fatal(err)
	}
	w, err = workload.OpenManager(wPath, f.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	status, err = w.Status(ctx, taskKey)
	record, readErr := w.View(taskKey)
	if err != nil || readErr != nil || status.NativeID != originalID || record.State.LastID != 1 {
		t.Fatal("recreated original task", status, err, readErr)
	}
	query("udp")
	if err = w.Desired(taskKey, 3, 2, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	if gone, err := w.Gone(ctx, taskKey, 3, 2); err != nil || !gone {
		t.Fatal("task closure", gone, err)
	}
	stop()
	for _, done := range []chan error{udpDone, tcpDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err = n.Return(lease); err != nil {
		t.Fatal(err)
	}
	if err = n.Desired(bridgeKey, 4, 1, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	t.Log("actual native resolver HostConfig/search -> nonroot container UDP/TCP name lookup -> original DB/native ID/Apply1 -> positive task closure -> fixture Stop/Wait and original bridge pin return/removal; DNS authority is a fixture, not embedded product DNS")
}
