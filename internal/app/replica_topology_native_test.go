// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/tests/registryfixture"
	"github.com/miekg/dns"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

// The parent fixture owns namespaces, private Engines and original journals;
// every workload transition uses the normal CLI/FSM/Runtime, never fake facts.
func testManagedReplicaTopology(t *testing.T, ctx context.Context, a *Runtime, root, products string, configs, sockets [2]string, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), stopB, startB func()) {
	t.Helper()
	phase := os.Getenv("SFC_TEST_RQ5_TOPOLOGY_PHASE")
	if phase != "" && phase != "changes" && phase != "rolling" {
		t.Fatal("unknown RQ5 topology verification phase")
	}
	p := a.controlPolicy
	backend := os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if !filepath.IsAbs(backend) {
		t.Fatal("prebuilt static backend required")
	}
	registry := registryfixture.OpenPreparedAt(t, backend, container.Config{Cmd: []string{"/backend"}, Env: []string{"SFC_DNS_FIXTURE=1", "SFC_READINESS_FIXTURE=1"}, User: "10001:10001", Labels: map[string]string{"org.sfc.test.owner": os.Getenv("SFC_KERNEL_TEST_OWNER")}}, "192.0.2.1:0")
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	change("replicas/trust", "set-trust", tenant.Revision, control.TrustChange{Tenant: "tenant", Add: []access.TrustRule{access.TrustRule{Registry: registry.Registry, Repository: "fixture"}}})
	var docker [2]*engine.Client
	var owners [2][32]byte
	public := sqlPublicFixture{Images: map[string]string{registry.Reference: registry.ConfigDigest}}
	for n, path := range configs {
		cfg, err := loadTestNode(path)
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.Load(cfg.Node.IdentityDir)
		if err != nil {
			t.Fatal(err)
		}
		clear(id.Private)
		owners[n] = id.Public
		docker[n], err = engine.Open(ctx, "unix://"+sockets[n], engine.Owner(p.Cluster, id.Public))
		if err != nil {
			t.Fatal(err)
		}
		defer docker[n].Close()
		info, err := docker[n].API.Info(ctx, client.InfoOptions{})
		if err != nil {
			t.Fatal(err)
		}
		public.EngineIDs[n] = info.Info.ID
	}
	if public.EngineIDs[0] == "" || public.EngineIDs[0] == public.EngineIDs[1] {
		t.Fatal("independent private Engine identities required")
	}
	publicBytes, _ := json.Marshal(public)
	if err := os.WriteFile(filepath.Join(root, "sql-fixture.json"), publicBytes, 0644); err != nil {
		t.Fatal(err)
	}
	definition := tenancy.TUNDefinition{Tenant: "tenant", Name: "replica-lan", GatewayMode: network.ManagedGatewayMode}
	for n, node := range []string{"node-a", "node-b"} {
		definition.Members = append(definition.Members, tenancy.TUNNode{Node: node, Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix(fmt.Sprintf("198.19.88.%d/28", n*16)), Gateway: netip.MustParseAddr(fmt.Sprintf("198.19.88.%d", n*16+1)), MTU: 1280}}})
	}
	change("replicas/network", "create-tun-network", 0, definition)
	policy := services.ManagedDNSDefinition{Schema: 1, Tenant: "tenant", Network: "replica-lan", Policy: services.ManagedDNSPolicy{Enabled: true, Zone: "replicas.sfc.test.", TTL: 1, NegativeTTL: 1, Transports: []string{"udp", "tcp"}, Upstreams: []netip.AddrPort{}, MaxQueries: 8, MaxCacheEntries: 8, MaxResponseBytes: 4096, MaxConnections: 8, RequestTimeoutMS: 1000}}
	change("replicas/dns", "configure-network-dns", 0, policy)
	profile, home, file := filepath.Join(root, "replicas-client.yaml"), filepath.Join(root, "replicas-home"), filepath.Join(root, "replicas-app.yaml")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%s', endpoint: '192.0.2.1:44101', voter: true}\n", p.Cluster, a.Identity.Actor())), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(wantSuccess bool, args ...string) []byte {
		t.Helper()
		body, diagnostic, err := runManagedCLICommand(ctx, filepath.Join(products, "sfc"), home, profile, args, nil)
		if (err == nil) != wantSuccess {
			t.Fatal("replica CLI", args, err, string(diagnostic), string(body))
		}
		return append(body, diagnostic...)
	}
	call(true, "wallet", "init")
	call(true, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin/key.pem"))
	document := fmt.Sprintf(`name: app
x-sfc:
 ingress:
  - {node: node-a, host: app.test, service: web, network: lan, port: 8080, health: /readyz}
services:
 web:
  image: %s
  command: [/backend]
  user: '10001:10001'
  cpus: 0.1
  mem_limit: 32m
  environment: {REVISION: '1'}
  networks: {lan: {}}
  x-sfc: {nodes: [node-a, node-b], per_node: 1, ready: {http: /readyz, port: 8080}}
 utility:
  image: %s
  command: [/backend]
  user: '10001:10001'
  cpus: 0.1
  mem_limit: 32m
  networks: {lan: {ipv4_address: '198.19.88.20'}}
  x-sfc: {node: node-b, ready: {http: /readyz, port: 8080}}
networks:
 lan: {external: true, name: replica-lan}
`, registry.Reference, registry.Reference)
	model, err := deployment.ParseApp([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	write := func(c deployment.Compose) {
		t.Helper()
		raw, err := yaml.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	up := func(operation string) {
		t.Helper()
		call(true, "compose", "up", "--tenant", "tenant", "--operation", operation, "--file", file, "--no-input")
	}
	execution := func() deployment.Execution {
		t.Helper()
		apps, err := p.ReadApps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		e, ok := apps.Execution("tenant", "app")
		if !ok {
			t.Fatal("accepted replica execution missing")
		}
		return e
	}
	taskKeys := [2]string{}
	for n, node := range []string{"node-a", "node-b"} {
		taskKeys[n] = deployment.ResourceKey("task", "tenant", "app", (deployment.TaskInstance{Service: "web", Node: node, Ordinal: 1}).ResourceID())
	}
	natives := func() [2]string {
		e := execution()
		var ids [2]string
		for n, key := range taskKeys {
			stage, _ := e.Stage(key)
			if stage.Observation != nil {
				ids[n] = stage.Observation.Native
			}
		}
		return ids
	}
	succeeded := func(operation string) bool {
		e := execution()
		if e.ActiveOperation() == operation && e.Status() == "Failed" {
			for _, step := range e.Steps() {
				stage, _ := e.Stage(step.Key)
				if stage.Result != nil && stage.Result.Code != 0 {
					t.Log("original failed stage", step.Key, "result", *stage.Result, "previous", stage.Previous != nil)
				}
			}
			t.Fatal("original operation failed before expected success", operation)
		}
		return e.ActiveOperation() == operation && e.Status() == "Succeeded"
	}
	write(model)
	call(true, "compose", "plan", "--tenant", "tenant", "--file", file)
	up("replicas-initial")
	wait("both actual replica owners and backend health", func() bool { return succeeded("replicas-initial") })
	initial := natives()
	if initial[0] == "" || initial[1] == "" || initial[0] == initial[1] {
		t.Fatal("independent real replica natives missing")
	}
	var ingressKey string
	for _, step := range execution().Steps() {
		if step.Kind == "ingress" {
			ingressKey = step.Key
		}
	}
	if ingressKey == "" {
		t.Fatal("replica listener missing")
	}
	listener, err := a.ingress.Observe(ingressKey)
	if err != nil || !listener.Ready || len(listener.Backends) != 2 {
		t.Fatal("actual listener did not observe both exact backends", err)
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	type identityResult struct{ Hostname, Revision string }
	request := func(address, path string, body []byte) ([]byte, error) {
		method := http.MethodGet
		if body != nil {
			method = http.MethodPost
		}
		req, err := http.NewRequestWithContext(ctx, method, "http://"+address+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Host = "app.test"
		if body != nil {
			req.Header.Set("Content-Type", "application/dns-message")
		}
		reply, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer reply.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(reply.Body, 4097))
		if err != nil || reply.StatusCode != 200 || len(raw) > 4096 {
			return nil, fmt.Errorf("actual HTTP status=%d read=%v", reply.StatusCode, err)
		}
		return raw, nil
	}
	identityFromIngress := func() (identityResult, error) {
		raw, err := request("192.0.2.1:18080", "/identity", nil)
		var v identityResult
		if err == nil && (json.Unmarshal(raw, &v) != nil || v.Hostname == "") {
			err = fmt.Errorf("invalid actual backend identity")
		}
		return v, err
	}
	hostnames := func(ids [2]string) [2]string {
		t.Helper()
		var names [2]string
		for n, id := range ids {
			x, err := docker[n].API.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
			if err != nil || x.Container.Config == nil {
				t.Fatal("actual replica hostname", err)
			}
			names[n] = x.Container.Config.Hostname
		}
		return names
	}
	addressA := func() string {
		service, _, err := execution().Blueprint().TaskInput((deployment.TaskInstance{Service: "web", Node: "node-a", Ordinal: 1}).ResourceID())
		if err != nil {
			t.Fatal(err)
		}
		return service.Networks["lan"].IPv4
	}
	query := func() ([]string, error) {
		q := new(dns.Msg)
		q.SetQuestion("web.app.replicas.sfc.test.", dns.TypeA)
		wire, err := q.Pack()
		if err != nil {
			return nil, err
		}
		raw, err := request(addressA()+":8080", "/dns-query?server=198.19.88.1%3A53&transport=udp&timeout_ms=1000", wire)
		if err != nil {
			return nil, err
		}
		answer := new(dns.Msg)
		if err := answer.Unpack(raw); err != nil {
			return nil, err
		}
		if !answer.Response || answer.Id != q.Id || answer.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("actual DNS response invalid")
		}
		var addresses []string
		for _, rr := range answer.Answer {
			if a, ok := rr.(*dns.A); ok {
				addresses = append(addresses, a.A.String())
			}
		}
		return addresses, nil
	}
	if phase == "" {
		names := hostnames(initial)
		seen := map[string]bool{}
		for range 4 {
			v, err := identityFromIngress()
			if err != nil || v.Revision != "1" {
				t.Fatal("actual initial replica routing", v, err)
			}
			seen[v.Hostname] = true
		}
		if len(seen) != 2 || !seen[names[0]] || !seen[names[1]] {
			t.Fatal("Ingress did not distribute actual requests to both owners", seen)
		}
		wait("shared alias reaches both exact replicas", func() bool { addresses, err := query(); return err == nil && len(addresses) == 2 })
		// Stop the non-voter owner including its packet plane. Installed quorum
		// stays available; DNS must stop using expired owner facts.
		stopB()
		wait("surviving owner serves alias and external ingress after peer loss", func() bool {
			addresses, err := query()
			v, ingressErr := identityFromIngress()
			return err == nil && len(addresses) == 1 && addresses[0] == addressA() && ingressErr == nil && v.Hostname == names[0]
		})
		startB()
		wait("same DB peer recovery restores replica serving", func() bool { addresses, err := query(); return err == nil && len(addresses) == 2 })
		if natives() != initial {
			t.Fatal("peer recovery replaced original native without a new app operation")
		}
	}
	// Single-writer admission is rejected before any candidate is submitted.
	bad, err := deployment.ParseApp([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	web := bad.Services["web"]
	web.Volumes = deployment.Mounts{{Type: "volume", Source: "shared", Target: "/data"}}
	bad.Services["web"] = web
	bad.Volumes = map[string]deployment.ComposeVolume{"shared": {External: true, Name: "shared"}}
	write(bad)
	if reply := call(false, "compose", "plan", "--tenant", "tenant", "--file", file); !bytes.Contains(reply, []byte("REPLICA_SINGLE_WRITER_FORBIDDEN")) {
		t.Fatal("wrong writer rejection", string(reply))
	}
	if phase != "rolling" {
		utilityKey := deployment.ResourceKey("task", "tenant", "app", "utility")
		oldUtility, _ := execution().Stage(utilityKey)
		utility := model.Services["utility"]
		utility.Sfc.Node = "node-a"
		attachment := utility.Networks["lan"]
		attachment.IPv4 = "198.19.88.6"
		utility.Networks["lan"] = attachment
		model.Services["utility"] = utility
		write(model)
		call(true, "compose", "plan", "--tenant", "tenant", "--file", file)
		up("replicas-utility-move")
		wait("stateless node-b to node-a relocation and old owner closure", func() bool {
			gone, err := docker[1].Gone(ctx, "container", utilityKey)
			return succeeded("replicas-utility-move") && err == nil && gone
		})
		newUtility, _ := execution().Stage(utilityKey)
		if newUtility.Observation == nil || oldUtility.Observation == nil || newUtility.Observation.Native == oldUtility.Observation.Native || natives() != initial {
			t.Fatal("stateless move reused native or replaced unrelated replicas")
		}
		// The same local journal must retain Target/expected/IDs after acceptance;
		// replay queries that original result instead of submitting a new move.
		call(true, "compose", "up", "--tenant", "tenant", "--operation", "replicas-utility-move")
	}
	monitorCtx, stopMonitor := context.WithCancel(ctx)
	var workers sync.WaitGroup
	failure := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-monitorCtx.Done():
				return
			case <-ticker.C:
				if _, err := identityFromIngress(); err != nil {
					e := execution()
					wave, _ := e.Replacement()
					observed, observeErr := a.ingress.Observe(ingressKey)
					failure <- fmt.Errorf("operation=%s wave=%+v observed=%+v observe_error=%v: %w", e.ActiveOperation(), wave, observed, observeErr, err)
					return
				}
			}
		}
	}()
	defer func() { stopMonitor(); workers.Wait() }()
	web = model.Services["web"]
	web.Environment["REVISION"] = "2"
	model.Services["web"] = web
	write(model)
	up("replicas-rolling-two")
	wait("one original operation replaces both nodes sequentially", func() bool { return succeeded("replicas-rolling-two") })
	second := natives()
	if second[0] == initial[0] || second[1] == initial[1] {
		t.Fatal("normal rolling update skipped a replica")
	}
	currentListener, err := a.ingress.Observe(ingressKey)
	if err != nil || currentListener.Generation != listener.Generation || currentListener.Revision != listener.Revision || len(currentListener.Backends) != 2 {
		t.Fatal("image/environment rolling update replaced the listener source", err)
	}
	// Both future replicas receive the same declaration, but node-a's new
	// readiness port fails first. node-b must keep its actual version-2 native.
	web = model.Services["web"]
	web.Environment["REVISION"] = "3"
	web.Sfc.Readiness = &deployment.Readiness{Kind: "http", Path: "/readyz", Port: 8081}
	model.Services["web"] = web
	write(model)
	up("replicas-rolling-fail")
	wait("first new owner reports actual health failure without advancing node-b", func() bool {
		e := execution()
		first, _ := e.Stage(taskKeys[0])
		other, _ := e.Stage(taskKeys[1])
		return e.ActiveOperation() == "replicas-rolling-fail" && first.Observation != nil && first.Result != nil && first.Observation.Applied && !first.Observation.Healthy && first.Observation.Native != second[0] && other.Previous != nil
	})
	for range 3 {
		e := execution()
		other, _ := e.Stage(taskKeys[1])
		if other.Previous == nil || other.Previous.Result.Generation == 0 {
			t.Fatal("unhealthy first node advanced the next wave")
		}
		x, err := docker[1].API.ContainerInspect(ctx, second[1], client.ContainerInspectOptions{})
		if err != nil || x.Container.State == nil || !x.Container.State.Running || x.Container.Config == nil || !strings.Contains(strings.Join(x.Container.Config.Env, "\n"), "REVISION=2") {
			t.Fatal("failed first node stopped/replaced original peer", err)
		}
		if _, err := identityFromIngress(); err != nil {
			t.Fatal("failure wave interrupted serving", err)
		}
	}
	stopMonitor()
	workers.Wait()
	select {
	case err := <-failure:
		t.Fatal("listener availability during actual rolling changes", err)
	default:
	}
	call(true, "compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "replicas-down")
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 {
		t.Fatal("original topology fixture budget exhausted before retirement observation")
	}
	// The CLI default bounds one request, not this multi-owner retirement.
	// Observe the SAME accepted down within the original fixture envelope.
	call(true, "--timeout", min(time.Until(deadline), 5*time.Minute).String(), "compose", "wait", "--tenant", "tenant", "-p", "app", "--operation", "replicas-down", "--condition", "retired")
	for n, key := range taskKeys {
		if gone, err := docker[n].Gone(ctx, "container", key); err != nil || !gone {
			t.Fatal("partial rollout down left original/target native", n, err)
		}
	}
	policy.Policy.Enabled = false
	change("replicas/dns-disable", "configure-network-dns", read().State.Object(services.ManagedDNSKey("tenant", "replica-lan")).Revision, policy)
	wait("DNS original sockets and own network borrows close", func() bool {
		apps, err := p.ReadApps(read().State)
		if err != nil {
			return false
		}
		for _, owner := range owners {
			authority, rows, ok := apps.NetworkDNS(owner)
			if !ok {
				return false
			}
			matched := 0
			for _, row := range rows {
				// Config.Network is the physical member ID, not the tenant's
				// logical management name. Bind to the original policy source.
				if row.Source.Key != services.ManagedDNSKey("tenant", "replica-lan") {
					continue
				}
				ref, ok := authority.ReferenceConsumer(row.Reference)
				if !ok || ref.Closed == nil {
					return false
				}
				matched++
			}
			if matched == 0 {
				return false
			}
		}
		return true
	})
	t.Logf("RQ5 topology phase=%q: initial healthy native preparation; selected peer-loss/relocation assertions only when enabled; writer refusal; sequential normal update; failed first owner preserves old peer; original down and DNS shutdown. Parent owns native rollback.", phase)
}
