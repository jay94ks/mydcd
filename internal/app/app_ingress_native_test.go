// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/schema"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func TestRealBoundaryManagedAppIngress(t *testing.T) {
	testRealManagedAppOwner(t, true, true, true, true, true, true, true)
}

func managedIngressFixture(t *testing.T, root, document string) (string, string) {
	t.Helper()
	port := func(udp bool) string {
		t.Helper()
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		address := l.Addr().String()
		if udp {
			u, e := net.ListenPacket("udp4", address)
			if e != nil {
				t.Fatal(e)
			}
			_ = u.Close()
		}
		return address
	}
	plain, secure := port(false), port(true)
	document = strings.Replace(document, "ingress: {enabled: false}", "ingress: {enabled: true}", 1)
	yaml := fmt.Sprintf(`x-sfc:
 ingress:
  node: node-a
  host: app.test
  runtime: {max_requests: 2, max_connections: 8, max_header_bytes: 4096, max_body_bytes: 1048576, buffer_bytes: 131072, request_timeout_ms: 5000, dial_timeout_ms: 1000, response_header_timeout_ms: 2000, health_interval_ms: 100}
  listeners:
   - {address: %q}
   - {address: %q, tls: true, http3: true}
  backend: {service: web, port: 8080, health_path: /readyz}`, plain, secure)
	return document, yaml
}

func verifyManagedIngressServing(t *testing.T, ctx context.Context, r *Runtime, cfg config.Node, p control.Policy, read func() cluster.View, wait func(string, func() bool), trustedRoots ...[]byte) {
	t.Helper()
	key := deployment.ResourceKey("ingress", "tenant", "app", "http")
	wait("managed actual ingress/listeners/health", func() bool {
		v, e := r.ingress.Observe(key)
		if e != nil || !v.Ready || len(v.Listeners) != 2 {
			return false
		}
		apps, e := p.Apps(read().State)
		if e != nil {
			return false
		}
		execution, _ := apps.Execution("tenant", "app")
		s, _ := execution.Stage(key)
		return s.Observation != nil && s.Observation.Applied && s.Observation.Healthy
	})
	projection, e := p.ProjectResources(read().State)
	if e != nil {
		t.Fatal(e)
	}
	spec := projection.Goals[key].Ingress
	if spec == nil {
		t.Fatal("missing original managed spec")
	}
	if len(spec.Services) != 1 || len(spec.Services[0].Backends) != 1 {
		t.Fatal("native backend source")
	}
	b := spec.Services[0].Backends[0]
	dependency, generation, local, e := (ingressDependencies{r}).dependency(ctx, b)
	if e != nil || !local {
		t.Fatal("actual original dependency", e)
	}
	row, e := r.network.View(dependency)
	if e != nil {
		t.Fatal(e)
	}
	pins := 0
	for consumer, pin := range row.Consumers {
		if strings.HasPrefix(consumer, "ingress/") {
			if pin.Generation != generation {
				t.Fatal("foreign ingress native pin")
			}
			pins++
		}
	}
	// Other live managed workloads may borrow the same network. Derive each
	// expected pin from the actual local Ingress projection instead of
	// treating this app as the only listener in the fixture.
	wantPins := 0
	for _, goal := range projection.Goals {
		if goal.Ingress == nil || goal.Ingress.Owner != r.owner {
			continue
		}
		for _, service := range goal.Ingress.Services {
			for _, backend := range service.Backends {
				key, currentGeneration, isLocal, err := (ingressDependencies{r}).dependency(ctx, backend)
				if err != nil {
					t.Fatal("projected ingress dependency", err)
				}
				if isLocal && key == dependency {
					if currentGeneration != generation {
						t.Fatal("projected ingress has another network generation")
					}
					wantPins++
				}
			}
		}
	}
	if wantPins == 0 || pins != wantPins {
		t.Fatal("original durable ingress dependency count", pins, "want", wantPins)
	}
	tlsCfg := &tls.Config{ServerName: "app.test", MinVersion: tls.VersionTLS13}
	// Trust the same public chain the store serves for the host; never
	// disable TLS verification.
	var root []byte
	if len(trustedRoots) == 1 {
		root = trustedRoots[0]
	} else {
		catalog, e := p.Certificates(read().State)
		if e != nil {
			t.Fatal(e)
		}
		served := catalog.LookupHost("app.test", time.Now().Unix())
		if len(served) == 0 {
			t.Fatal("no store certificate for app.test")
		}
		root = served[0].Chain
	}
	tlsCfg.RootCAs = x509.NewCertPool()
	if !tlsCfg.RootCAs.AppendCertsFromPEM(root) {
		t.Fatal("fixture CA")
	}
	h1 := &http.Transport{}
	defer h1.CloseIdleConnections()
	h2 := &http2.Transport{TLSClientConfig: tlsCfg.Clone()}
	defer h2.CloseIdleConnections()
	h3 := &http3.Transport{TLSClientConfig: tlsCfg.Clone()}
	defer h3.Close()
	for n, transport := range []http.RoundTripper{h1, h2, h3} {
		url := "http://" + spec.Listeners[0].Address + "/ping"
		if n > 0 {
			url = "https://" + spec.Listeners[1].Address + "/ping"
		}
		client := http.Client{Transport: transport, Timeout: 3 * time.Second}
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if e != nil {
			t.Fatal(e)
		}
		request.Host = "app.test"
		response, e := client.Do(request)
		if e != nil {
			t.Fatal("actual mapped HTTP", n, e)
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if e != nil || response.StatusCode != http.StatusOK || string(body) != "sfc-boundary /ping" || response.ProtoMajor != n+1 {
			t.Fatal("actual ingress/backend", n, response.StatusCode, response.ProtoMajor, e)
		}
	}
	t.Log("actual managed Task -> owner signed Ingress -> H1/H2/H3, trusted local TLS, same original network dependency pin")
}

// Only cleanup after Runtime.Close proves all listener/request producers ended.
// The dependency is fixed by the original committed Task/Bridge reference.
type ingressCleanupDependency struct {
	manager    *network.Manager
	backend    ingress.BackendSpec
	key        string
	generation uint64
}

func (d ingressCleanupDependency) Acquire(context.Context, ingress.BackendSpec, string) error {
	return reconcile.ErrLease
}
func (d ingressCleanupDependency) Release(_ context.Context, b ingress.BackendSpec, consumer string) error {
	if !reflect.DeepEqual(b, d.backend) || !strings.HasPrefix(consumer, "ingress/") {
		return reconcile.ErrLease
	}
	return d.manager.ReturnConsumer(d.key, consumer, d.generation)
}
func cleanupManagedIngress(t *testing.T, ctx context.Context, cfg config.Node, n *network.Manager, v cluster.View) {
	t.Helper()
	key := deployment.ResourceKey("ingress", "tenant", "app", "http")
	o := v.State.Object(key)
	if !o.Present {
		return
	}
	_, record, err := bootstrap.Effective(cfg)
	if err != nil {
		t.Error(err)
		return
	}
	spec, err := deployment.ResolveIngress(record.Root.Cluster, key, o, v.State.Objects(""))
	if err != nil {
		t.Error("original ingress cleanup source", err)
		return
	}
	b := spec.Services[0].Backends[0]
	g := v.State.Object(b.Task)
	var task deployment.GoalCommand
	if json.Unmarshal([]byte(g.Value), &task) != nil {
		t.Error("original Task cleanup source")
		return
	}
	bridge := ""
	generation := uint64(0)
	for _, dep := range task.Dependencies {
		if strings.HasPrefix(dep.Key, "network/bridge/") {
			bridge = dep.Key
			generation = dep.Generation
		}
	}
	if bridge == "" {
		t.Error("original ingress Bridge cleanup source")
		return
	}
	m, err := ingress.Open(ctx, filepath.Join(cfg.Node.StateDir, "ingress/runtime.db"), ingressCleanupDependency{n, b, bridge, generation})
	if err != nil {
		t.Error(err)
		return
	}
	defer m.Close()
	if !slices.Contains(m.Keys(), key) {
		return
	}
	status, err := m.Observe(key)
	if err != nil {
		t.Error(err)
		return
	}
	if status.Gone {
		return
	}
	spec.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
	if err = m.Reconcile(ctx, key, o.Revision+1, o.Generation, &spec); err != nil {
		t.Error("original ingress cleanup Drain", err)
		return
	}
	status, err = m.Observe(key)
	if err != nil || !status.Gone {
		t.Error("original ingress cleanup not Gone", err)
	}
}
