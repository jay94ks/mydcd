// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"github.com/jay94ks/mydcd/tests/gitfixture"
	"github.com/jay94ks/mydcd/tests/registryfixture"
	"github.com/jay94ks/mydcd/tests/vaultfixture"
	"github.com/moby/moby/client"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"gopkg.in/yaml.v3"
)

// This scenario supplies real application inputs, never fake native readiness
// or a second orchestrator. Every effect is submitted through the prebuilt CLI
// and performed by the same product Runtime/daemon and their private Engines.
func testManagedTwoNodeSQL(t *testing.T, ctx context.Context, a *Runtime, root, products string, configs, sockets [2]string, manifest string, user userauth.Client, source mydcp.Peer, session access.Session, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), stopB, startB func(), cutB func(func()), vault *vaultfixture.Vault, gitSource *gitfixture.Fixture, withRestore, withDNS, dnsOnly bool, moveSQL ...bool) {
	t.Helper()
	phaseStarted := time.Now()
	phase := func(label string) {
		if withDNS {
			t.Log("DNS SQL phase", label, "elapsed", time.Since(phaseStarted).Round(time.Millisecond))
		}
	}
	phase("scenario entered")
	deployedOperation := "rollout"
	if vault == nil {
		t.Fatal("explicit real protected provider required")
	}
	registry := registryfixture.OpenCached(t, "192.0.2.1:0", os.Getenv("MYDC_SQL_IMAGE_CACHE"))
	phase("cached Registry inputs verified")
	policy := a.controlPolicy
	catalog, err := policy.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	change("sql-image-trust", "set-trust", tenant.Revision, control.TrustAssignment{Tenant: "tenant", Rules: append(tenant.ImageSources, access.TrustRule{Registry: registry.Registry, Repository: "php"}, access.TrustRule{Registry: registry.Registry, Repository: "mysql"})})
	public := sqlPublicFixture{Images: registry.Configs}
	var docker [2]*engine.Client
	for n := range configs {
		cfg, err := config.LoadNode(configs[n])
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.Load(cfg.Node.IdentityDir)
		if err != nil {
			t.Fatal(err)
		}
		clear(id.Private)
		docker[n], err = engine.Open(ctx, "unix://"+sockets[n], engine.Owner(user.Cluster, id.Public))
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
		t.Fatal("independent Engine identities required")
	}
	remoteIdentity, err := identity.Load(filepath.Join(root, "key-1"))
	if err != nil {
		t.Fatal(err)
	}
	clear(remoteIdentity.Private)
	remote := mydcp.Peer{ID: "node-b", Endpoint: "192.0.2.2:44101", Policy: mydcp.Policy{Key: mydcp.Identity(remoteIdentity.Public), Member: true, Read: true, Respond: true}}
	observeB := func(key string) (ModuleObservation, error) {
		reply, e := cluster.CallManagement(ctx, a.Mesh, a.Identity, user.Cluster, remote, cluster.ManagementRequest{Method: "observe", Key: key, Latest: false})
		var v ModuleObservation
		if e == nil {
			e = json.Unmarshal(reply.Data, &v)
		}
		return v, e
	}
	raw, _ := json.Marshal(public)
	if err = os.WriteFile(filepath.Join(root, "sql-fixture.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(manifest)
	var ownerManifest map[string]any
	if err != nil || json.Unmarshal(raw, &ownerManifest) != nil {
		t.Fatal("original public owner manifest", err)
	}
	var topology struct {
		NamespacePaths []string `json:"namespace_paths"`
	}
	if json.Unmarshal(raw, &topology) != nil || len(topology.NamespacePaths) != 2 {
		t.Fatal("original two namespace paths required")
	}
	ownerManifest["sql_fixture"] = public
	raw, _ = json.Marshal(ownerManifest)
	if err = os.WriteFile(manifest, raw, 0644); err != nil {
		t.Fatal(err)
	}
	prepareSQLSecrets(t, ctx, a, user, source, session, read, change)
	phase("protected SQL input ready")

	document := fmt.Sprintf(`name: app
x-mydc:
 ingress:
  node: node-b
  host: app.test
  runtime: {max_requests: 2, max_connections: 8, max_header_bytes: 4096, max_body_bytes: 1048576, buffer_bytes: 131072, request_timeout_ms: 10000, dial_timeout_ms: 1000, response_header_timeout_ms: 3000, health_interval_ms: 200}
  listeners:
   - {address: '192.0.2.2:8080'}
   - {address: '192.0.2.2:8443', tls: true, http3: true}
  backend: {service: web, port: 8080, health_path: /readyz}
services:
 web:
  image: %s
  user: '10001:10001'
  read_only: true
  cap_drop: [ALL]
  security_opt: ['no-new-privileges:true']
  cpus: 0.5
  mem_limit: 128m
  environment: {DB_HOST: '198.19.80.18'}
  secrets: [{source: password, target: /run/secrets/db-password, uid: '10001', gid: '10001', mode: '0400'}]
  tmpfs: ['/tmp:size=4m,mode=1777']
  healthcheck: {test: [CMD, /usr/bin/php8.3, -n, -d, extension=pdo, -d, extension=mysqlnd, -d, extension=pdo_mysql, /app/web.php], interval: 1s, timeout: 3s, retries: 3}
  depends_on: {db: {condition: service_healthy}}
  networks: {app: {ipv4_address: 198.19.80.2}}
  x-mydc: {node: node-a, secrets_from: [group/common], ready: {http: /readyz, port: 8080}}
 db:
  image: %s
  user: '10001:10001'
  read_only: true
  cap_drop: [ALL]
  security_opt: ['no-new-privileges:true']
  cpus: 1.0
  mem_limit: 512m
  secrets:
   - {source: password, target: /run/secrets/db-password, uid: '10001', gid: '10001', mode: '0400'}
   - {source: root-password, target: /run/secrets/db-root-password, uid: '10001', gid: '10001', mode: '0400'}
  volumes: [data:/var/lib/mysql]
  tmpfs: ['/tmp:size=16m,mode=1777', '/run/mydc:size=4m,uid=10001,gid=10001,mode=0700']
  healthcheck: {test: [CMD, /mydc-mysql, --health], interval: 1s, timeout: 3s, retries: 30, start_period: 30s}
  networks: {app: {ipv4_address: 198.19.80.18}}
  x-mydc: {node: node-b, secrets_from: [group/common, group/db-admin]}
networks:
 app:
  x-mydc:
   mtu: 1280
   pools:
    node-a: {cidr: 198.19.80.0/28, gateway: 198.19.80.1}
    node-b: {cidr: 198.19.80.16/28, gateway: 198.19.80.17}
   tunnel_addresses: {node-a: 198.19.81.1/32, node-b: 198.19.81.2/32}
volumes:
 data:
  x-mydc: {node: node-b, uid: 10001, gid: 10001, mode: '0750'}
secrets:
 password:
  x-mydc: {key: DB_PASSWORD}
 root-password:
  x-mydc: {key: MYSQL_ROOT_PASSWORD}
`, registry.References["php"], registry.References["mysql"])
	if withDNS {
		document = strings.Replace(document, "DB_HOST: '198.19.80.18'", "DB_HOST: 'db', MYDC_DNS_TIMING: '1'", 1)
		document = strings.Replace(document, "ready: {http: /readyz, port: 8080}", "ready: {http: /readyz, port: 8080, timeout: 3s}", 1)
		// Three PHP HTTP workers (A/AAAA), exec health, and the original wire
		// observer can exceed four in-flight queries. This is an explicit
		// normal-input budget; owner enforcement and low-limit tests stay intact.
		document = strings.Replace(document, "   mtu: 1280", "   mtu: 1280\n   dns: {enabled: true, zone: app.mydc.test, ttl_seconds: 1, negative_ttl_seconds: 1, transports: [udp, tcp], limits: {cache_entries: 4, queries_inflight: 16, tcp_connections: 2, request_timeout_ms: 1500}}", 1)
	}
	if dnsOnly {
		document = strings.Replace(document, "environment: {DB_HOST: 'db', MYDC_DNS_TIMING: '1'}", "environment: {DB_HOST: 'db', MYDC_DNS_TIMING: '1', MYDC_DNS_FIXTURE: '1', MYDC_DNS_EXPECTED: '198.19.80.18'}", 1)
		document = strings.Replace(document, "  depends_on: {db: {condition: service_healthy}}\n", "", 1)
		document = strings.Replace(document, "  image: "+registry.References["mysql"], "  image: "+registry.References["php"]+"\n  environment: {DB_HOST: 'web', MYDC_DNS_FIXTURE: '1', MYDC_DNS_EXPECTED: '198.19.80.2'}", 1)
		document = strings.Replace(document, "{test: [CMD, /mydc-mysql, --health], interval: 1s, timeout: 3s, retries: 30, start_period: 30s}", "{test: [CMD, /usr/bin/php8.3, -n, /app/web.php], interval: 1s, timeout: 3s, retries: 3}", 1)
	}
	if withDNS && !dnsOnly {
		document = strings.Replace(document, "environment: {DB_HOST: 'db',", "environment: {PHP_CLI_SERVER_WORKERS: '2', DB_HOST: 'db',", 1)
	}
	input, managementInput := managedSampleNetworkInputs(t, []byte(document), map[string]string{"app": "app-services"})
	if gitSource != nil {
		// This scenario positively stops MySQL while its owner is offline.
		// Default restart=no/keep cannot restart it. Declare the existing
		// builtin policy instead of expecting an undeclared recovery effect.
		change("sql-lifecycle-policy", "set-lifecycle-policy", 0, checker.TenantPolicy{
			Tenant: "tenant", Enabled: true,
			Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100000000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"dependency"}},
			Resolver:  checker.ResolverPolicy{AllowPackages: []string{"context", "github.com/jay94ks/mydcd/lifecycle/v1"}, SourceCacheBytes: 1 << 20},
		})
		app, err := deployment.ParseApp(input)
		if err != nil {
			t.Fatal(err)
		}
		cd := nativeGitPolicy(gitSource.Repository())
		cd.Sync.Mode = "automatic"
		app.MyDC.Delivery = &cd
		db := app.Services["db"]
		retries := uint32(1)
		db.MyDC.Lifecycle = &deployment.ServiceLifecycle{Checks: []deployment.LifecycleCheck{{
			ID: "sql-running", Phase: "liveness", Interval: "1s", Timeout: "3s", Retries: &retries,
			LifecycleTemplate: deployment.LifecycleTemplate{Builtin: "docker_health"},
			Actions:           &checker.ActionPolicy{OnDead: checker.StartContainer},
		}}}
		app.Services["db"] = db
		web := app.Services["web"]
		if web.Environment == nil {
			web.Environment = map[string]string{}
		}
		web.Environment["MYDC_CD_REVISION"] = "1"
		app.Services["web"] = web
		input, err = yaml.Marshal(app)
		if err != nil {
			t.Fatal(err)
		}
		ownerManifest["git_first_commit"] = gitSource.Commit(input)
	}
	document = string(input)
	ownerManifest["compose"] = document
	raw, _ = json.Marshal(ownerManifest)
	if err = os.WriteFile(manifest, raw, 0644); err != nil {
		t.Fatal(err)
	}
	home, profile, file := filepath.Join(root, "home"), filepath.Join(root, "client.yaml"), filepath.Join(root, "app.yaml")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%s', endpoint: '192.0.2.1:44101', voter: true}\n", user.Cluster, a.Identity.Actor())), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(fds []*os.File, args ...string) []byte {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, filepath.Join(products, "mydc"), home, profile, args, fds)
		if err != nil {
			t.Fatal("prebuilt SQL CLI", args, err, string(diagnostic), string(out))
		}
		return out
	}
	cli(nil, "wallet", "init")
	cli(nil, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin/key.pem"))
	if len(managementInput) > 0 {
		applyManagementChanges(t, root, "prepare-network", managementInput, func(args ...string) { cli(nil, args...) })
	}
	if withDNS {
		lastPreparation := ""
		preparation := func(node string, observation ModuleObservation, err error) {
			cause := fmt.Sprintf("%s ready=%t error=%v/%s/%s DNS=%+v", node, observation.Ready, err, observation.ModuleError, observation.Error, observation.DNS)
			if cause != lastPreparation {
				lastPreparation = cause
				phase("original managed DNS preparation " + cause)
			}
		}
		wait("explicit managed DNS has real local and remote owners before app planning", func() bool {
			v := read()
			key := "control/network-services/dns/tenant/app-services"
			raw, err := a.observeManaged(ctx, key, v)
			var local ModuleObservation
			if err == nil {
				err = json.Unmarshal(raw, &local)
			}
			if err != nil || !local.Ready || local.DNS == nil || local.DNS.Desired == 0 || local.DNS.Desired != local.DNS.Applied || local.DNS.Applied != local.DNS.Observed {
				preparation("node-a", local, err)
				return false
			}
			remote, err := observeB(key)
			if err != nil || !remote.Ready || remote.DNS == nil || remote.DNS.Desired != local.DNS.Desired || remote.DNS.Applied != local.DNS.Applied || remote.DNS.Observed != local.DNS.Observed {
				preparation("node-b", remote, err)
			}
			return err == nil && remote.Ready && remote.DNS != nil && remote.DNS.Desired == local.DNS.Desired && remote.DNS.Applied == local.DNS.Applied && remote.DNS.Observed == local.DNS.Observed
		})
	}
	nativeKey := func(kind, node string) string {
		if kind == "bridge" {
			return "control/network-sources/bridge/tenant/app-services/" + node
		}
		return "control/network-sources/tun/tenant/app-services/" + node
	}

	var fds []*os.File
	for range 2 {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err = w.Write([]byte("private-native-group-password\n")); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		fds = append(fds, r)
	}
	cli(fds, "compose", "up", "--operation", "rollout", "--tenant", "tenant", "-f", file, "--no-input", "--group-password-fd", "tenant/common=3", "--group-password-fd", "tenant/db-admin=4")
	phase("single-file CLI accepted")
	for _, fd := range fds {
		_ = fd.Close()
	}
	defer func() {
		if !t.Failed() {
			return
		}
		v, err := a.Engine().Read(context.Background(), false)
		if err == nil {
			apps, _ := policy.Apps(v.State)
			if withDNS {
				if owner := a.dnsOwner(); owner != nil {
					_, rows, _ := apps.NetworkDNS(a.Identity.Public)
					for _, row := range rows {
						s := owner.Status(row.Config.Tenant, row.Config.ID)
						t.Log("original DNS failure cause", s.QueryFailures, s.LastQueryError, "queries", s.Queries, "failed", s.Failed)
					}
				}
			}
			ex, _ := apps.Execution("tenant", "app")
			for _, step := range ex.Steps() {
				s, _ := ex.Stage(step.Key)
				if s.Observation == nil {
					t.Log("original SQL stage", step.Key, "pending", s.Journal.Pending != nil, "result", s.Result)
				} else {
					t.Log("original SQL stage", step.Key, "native", s.Observation.Native, "applied", s.Observation.Applied, "healthy", s.Observation.Healthy)
				}
			}
		}
		// Preparation can fail before the SQL/DNS assertions are reached.
		// Read the remote product's original error before its daemon is closed.
		inspect, stop := context.WithTimeout(context.Background(), 2*time.Second)
		reply, callErr := cluster.CallManagement(inspect, a.Mesh, a.Identity, user.Cluster, remote, cluster.ManagementRequest{Method: "observe", Key: deployment.ResourceKey("task", "tenant", "app", "db"), Latest: false})
		if callErr == nil {
			var o ModuleObservation
			if json.Unmarshal(reply.Data, &o) == nil {
				t.Log("original remote SQL preparation cause", o.ModuleError, o.Error)
			}
		}
		stop()
		for n, c := range docker {
			logs, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			rows, err := c.API.ContainerList(logs, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.mydc.owner="+c.Owner)})
			if err == nil {
				for _, row := range rows.Items {
					r, e := c.API.ContainerLogs(logs, row.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "80"})
					if e == nil {
						b, _ := io.ReadAll(io.LimitReader(r, 20000))
						_ = r.Close()
						t.Log("owned SQL container diagnostics", n, row.ID, string(b))
					}
				}
			}
			cancel()
		}
	}()
	stage := func(key string) deployment.StageRecord {
		apps, e := policy.Apps(read().State)
		if e != nil {
			t.Fatal(e)
		}
		ex, _ := apps.Execution("tenant", "app")
		s, _ := ex.Stage(key)
		return s
	}
	lastContainerCheck := time.Time{}
	seenPhases := map[string]string{}
	var lastDNSFailures uint64
	var lastPreparationCause string
	wait("actual PHP/PDO MySQL plus remote Ingress", func() bool {
		if time.Since(lastContainerCheck) >= time.Second {
			lastContainerCheck = time.Now()
			if withDNS {
				o, e := observeB(nativeKey("bridge", "node-b"))
				cause := fmt.Sprint(e, "/", o.ModuleError)
				if cause != lastPreparationCause {
					t.Log("original remote preparation progress", cause)
					lastPreparationCause = cause
				}
			}
			for n, c := range docker {
				rows, e := c.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.mydc.owner="+c.Owner)})
				if e != nil {
					t.Fatal("owned Engine readiness read", n, e)
				}
				for _, row := range rows.Items {
					if withDNS {
						// Log state changes, not Docker's continuously changing age text.
						state := fmt.Sprint(row.State)
						if seenPhases[row.ID] != state {
							phase(fmt.Sprintf("native node=%d container=%s state=%s", n, row.ID, state))
							seenPhases[row.ID] = state
						}
					}
					if row.State == "exited" || row.State == "dead" {
						t.Fatal("owned SQL server exited before Ready", n, row.ID, row.Status)
					}
				}
			}
		}
		apps, e := policy.Apps(read().State)
		if e != nil {
			return false
		}
		ex, _ := apps.Execution("tenant", "app")
		if withDNS {
			if a.dnsOwner() != nil {
				_, rows, _ := apps.NetworkDNS(a.Identity.Public)
				for _, row := range rows {
					diagnostic := a.dnsOwner().Status(row.Config.Tenant, row.Config.ID)
					if diagnostic.QueryFailures != lastDNSFailures {
						t.Log("actual DNS query diagnostic", diagnostic.QueryFailures, diagnostic.LastQueryError, "queries", diagnostic.Queries, "source", diagnostic.Settings.Applied)
						lastDNSFailures = diagnostic.QueryFailures
					}
				}
			}
			for _, step := range ex.Steps() {
				stage, _ := ex.Stage(step.Key)
				state := fmt.Sprintf("command=%t result=%t", stage.Command != nil, stage.Result != nil)
				if stage.Observation != nil {
					state += fmt.Sprintf(" applied=%t healthy=%t", stage.Observation.Applied, stage.Observation.Healthy)
				}
				if seenPhases[step.Key] != state {
					phase(step.Key + " " + state)
					seenPhases[step.Key] = state
				}
			}
		}
		return ex.Status() == "Succeeded" && ex.Health(uint64(time.Now().Unix())) == "Healthy"
	})
	phase("actual SQL app Healthy")
	task := deployment.ResourceKey("task", "tenant", "app", "db")
	oldTask, err := observeB(task)
	original := stage(task)
	if err != nil || !oldTask.Ready || original.Observation == nil || oldTask.NativeID != original.Observation.Native || !ed25519.Verify(remoteIdentity.Public[:], deployment.ObservationBytes(*original.Observation), original.Observation.Signature) {
		t.Fatal("real remote SQL native identity/signature", err, oldTask)
	}
	web := deployment.ResourceKey("task", "tenant", "app", "web")
	var webStatus workload.ContainerStatus
	wait("current original PHP/PDO readiness", func() bool {
		var err error
		webStatus, err = a.workload.Status(ctx, web)
		return err == nil && webStatus.Ready && webStatus.HTTPReady && webStatus.HealthConfigured
	})
	nativeRoutes := map[string]json.RawMessage{}
	resources, err := policy.Resources(read().State)
	if err != nil {
		t.Fatal("committed Task route sources", err)
	}
	sources, err := resources.Networks.TUNSources("tenant", "app-services")
	if err != nil {
		t.Fatal("original managed network", err)
	}
	bridges := map[string]network.BridgeSpec{}
	for _, source := range sources {
		bridges[source.Network.Node] = source.Bridge
	}
	for n, native := range []string{webStatus.NativeID, oldTask.NativeID} {
		info, e := docker[n].API.ContainerInspect(ctx, native, client.ContainerInspectOptions{})
		if e != nil || info.Container.State == nil || !info.Container.State.Running {
			t.Fatal("original Task route owner", n, e)
		}
		cmd := exec.CommandContext(ctx, "nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", info.Container.State.Pid), "--", "ip", "-j", "route", "show", "table", "all")
		b, e := cmd.CombinedOutput()
		var routes []struct {
			Dst, Gateway, Protocol, Dev string
			Metric                      int
		}
		if e != nil || json.Unmarshal(b, &routes) != nil {
			t.Fatal("original Task route readback", n, e)
		}
		// Preserve the actual observation even when a route assertion fails.
		nativeRoutes[fmt.Sprintf("node-%d", n)] = b
		ownerManifest["task_routes"] = nativeRoutes
		raw, _ = json.Marshal(ownerManifest)
		if err = os.WriteFile(manifest, raw, 0644); err != nil {
			t.Fatal(err)
		}
		bridge, exists := bridges[[]string{"node-a", "node-b"}[n]]
		if !exists || len(bridge.Pools) != 1 {
			t.Fatal("original single-pool bridge source", n)
		}
		managed := bridge.GatewayMode == network.ManagedGatewayMode && !bridge.Internal
		if !managed && !bridge.Internal {
			t.Fatal("unrecognized bridge gateway contract", n)
		}
		local, gateway := bridge.Pools[0].Prefix.String(), bridge.Pools[0].Gateway.String()
		device := ""
		for _, route := range routes {
			if route.Dst == local && route.Protocol == "kernel" && route.Gateway == "" {
				device = route.Dev
			}
		}
		if device == "" {
			t.Fatal("Task missing original connected pool", n)
		}
		pool, peer := "198.19.80.16/28", "198.19.81.2"
		if n == 1 {
			pool, peer = "198.19.80.0/28", "198.19.81.1"
		}
		found := map[string]bool{}
		defaults := 0
		for _, route := range routes {
			if route.Dst == "default" || route.Dst == "0.0.0.0/0" {
				// Managed nat-unprotected bridges use Docker's original local
				// gateway. MyDC overlay routes still never grant a default.
				defaults++
				if !managed || defaults != 1 || route.Gateway != gateway || route.Dev != device {
					t.Fatal("Task default differs from original Docker bridge", n, route)
				}
			}
			if route.Dst == pool || route.Dst == peer {
				if route.Protocol != "static" || route.Metric != 100 || route.Gateway != gateway || route.Dev != device {
					t.Fatal("Task route identity", n, route)
				}
				found[route.Dst] = true
			}
		}
		if !found[pool] || !found[peer] {
			t.Fatal("Task missing remote pool/node return route", n)
		}
		if managed && defaults != 1 {
			t.Fatal("Task missing original Docker default gateway", n)
		}
	}
	cert, err := os.ReadFile(filepath.Join(root, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("owned SQL CA")
	}
	tlsConfig := &tls.Config{ServerName: "app.test", RootCAs: roots, MinVersion: tls.VersionTLS13}
	h1 := &http.Transport{Proxy: nil}
	defer h1.CloseIdleConnections()
	h2 := &http2.Transport{TLSClientConfig: tlsConfig.Clone()}
	defer h2.CloseIdleConnections()
	h3 := &http3.Transport{TLSClientConfig: tlsConfig.Clone()}
	defer h3.Close()
	tcpSnapshot := func(label string) {
		if !withDNS {
			return
		}
		inspectCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		diagnosticView, viewErr := a.Engine().Read(inspectCtx, false)
		delivered, dropped := a.Mesh.PacketCounts()
		t.Log("original packet counters", label, delivered, dropped)
		t.Log("original packet drop reasons", label, a.Mesh.PacketDropCounts())
		for _, node := range []string{"node-a", "node-b"} {
			key := "control/network-services/dns/tenant/app-services"
			var o ModuleObservation
			var e error
			if node == "node-a" {
				var raw json.RawMessage
				e = viewErr
				if e == nil {
					raw, e = a.observeManaged(inspectCtx, key, diagnosticView)
				}
				if e == nil {
					e = json.Unmarshal(raw, &o)
				}
			} else {
				o, e = observeB(key)
			}
			t.Log("current DNS at HTTP boundary", label, node, e, o.Ready, o.DNS)
		}
		if remote, e := observeB(nativeKey("tunnel", "node-b")); e == nil && remote.Tunnel != nil {
			t.Log("remote packet drop reasons", label, remote.Tunnel.TransportDrops)
		}
		for node, native := range []string{webStatus.NativeID, oldTask.NativeID} {
			inspection, inspectErr := docker[node].API.ContainerInspect(ctx, native, client.ContainerInspectOptions{})
			if inspectErr != nil || inspection.Container.State == nil || !inspection.Container.State.Running {
				t.Log("original TCP counters unavailable", node, inspectErr)
				continue
			}
			readCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			cmd := exec.CommandContext(readCtx, "nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", inspection.Container.State.Pid), "--", "cat", "/proc/net/snmp")
			raw, readErr := cmd.CombinedOutput()
			stop()
			if len(raw) > 8192 {
				raw = raw[:8192]
			}
			t.Log("original TCP counters", label, node, readErr, string(raw))
		}
	}
	defer func() {
		if t.Failed() {
			tcpSnapshot("failed original scenario")
		}
	}()
	request := func(n int, method, path, value string, wantStatus ...int) map[string]any {
		t.Helper()
		transport := []http.RoundTripper{h1, h2, h3}[n]
		address := "http://192.0.2.2:8080"
		if n > 0 {
			address = "https://192.0.2.2:8443"
		}
		req, e := http.NewRequestWithContext(ctx, method, address+path, bytes.NewBufferString(value))
		if e != nil {
			t.Fatal(e)
		}
		req.Host = "app.test"
		phase("HTTP " + method + " " + path)
		c := http.Client{Transport: transport, Timeout: 8 * time.Second}
		response, e := c.Do(req)
		if e != nil {
			t.Fatal("actual remote SQL HTTP", n+1, method, path, e)
		}
		b, e := io.ReadAll(io.LimitReader(response.Body, 256<<10))
		_ = response.Body.Close()
		var result map[string]any
		want := 200
		if len(wantStatus) > 0 {
			want = wantStatus[0]
		}
		if e != nil || response.StatusCode != want || response.ProtoMajor != n+1 || json.Unmarshal(b, &result) != nil {
			if observed, observationErr := observeB(deployment.ResourceKey("ingress", "tenant", "app", "http")); observationErr == nil && observed.Ingress != nil {
				t.Log("original Ingress proxy failure", observed.Ingress.ProxyFailures, observed.Ingress.LastProxyFailure, observed.Ingress.LastProxyFailureMS, "ms", "requests", observed.Ingress.Requests)
				t.Log("original Ingress health failure", observed.Ingress.HealthFailures, observed.Ingress.LastHealthFailure, observed.Ingress.LastHealthFailureMS, "ms")
			}
			if withDNS && (method == "POST" || method == "PUT" || method == "DELETE") {
				// Observe this original operation once. Never replay a mutation
				// after an upstream timeout or call observation a successful reply.
				operation := req.URL.Query().Get("operation")
				lookup, lookupErr := http.NewRequestWithContext(ctx, "GET", address+"/operation?id="+operation, nil)
				if lookupErr == nil {
					lookup.Host = "app.test"
					observed, callErr := c.Do(lookup)
					if callErr == nil {
						data, readErr := io.ReadAll(io.LimitReader(observed.Body, 256<<10))
						_ = observed.Body.Close()
						var saved map[string]any
						decodeErr := json.Unmarshal(data, &saved)
						savedValue, _ := saved["value"].(string)
						t.Log("original SQL operation after proxy failure", observed.StatusCode, "matches ID", saved["operation"] == operation, "value bytes", len(savedValue), "read", readErr, "decode", decodeErr)
						// E4 verifies the committed write through a lost response.
						// Preserve the original HTTP failure; never replay the write.
						settleWrite := len(moveSQL) == 1 && moveSQL[0] && want == http.StatusOK
						ambiguous := response.StatusCode == http.StatusBadGateway || response.StatusCode == http.StatusGatewayTimeout
						readOriginal := observed.StatusCode == http.StatusOK && observed.ProtoMajor == n+1 && readErr == nil && decodeErr == nil
						if settleWrite && ambiguous && readOriginal && originalSQLWriteResult(method, req.URL.Query().Get("key"), operation, value, saved) {
							t.Log("SQL original write response UNKNOWN -> original operation result SETTLED", "HTTP", response.StatusCode, "method", method, "operation", operation, "value bytes", len(value))
							return saved
						}
					} else {
						t.Log("original SQL operation observation unavailable", callErr)
					}
				}
			}
			t.Fatal("actual PHP/PDO SQL result", n+1, method, path, response.StatusCode, response.ProtoMajor, "body bytes", len(b), e)
		}
		return result
	}
	if len(moveSQL) == 1 && moveSQL[0] {
		rejectSQLMoveOverlappingCIDR(t, ctx, a, user, source, session, docker[1], read)
		stageMove := func(id, plan string) {
			t.Helper()
			out, diagnostic, err := runManagedCLICommand(ctx, filepath.Join(products, "mydc"), home, profile, []string{"--tenant", "tenant", "volume", "move", "--plan", plan}, nil)
			exit, exited := err.(*exec.ExitError)
			// The move is accepted, then stops for the Group passwords; the
			// saved operation continues it with 'mydc op resume ID'.
			if !exited || exit.ExitCode() != 2 || !bytes.Contains(diagnostic, []byte("approval needed")) || !bytes.Contains(diagnostic, []byte("op resume "+id)) {
				t.Fatal("original move must be accepted and await explicit Group input before native faults", err, string(diagnostic), string(out))
			}
		}
		cut := testManagedSQLColdMove(t, ctx, a, root, file, document, docker, cli, stageMove, request, observeB, read, change, wait, stopB, startB, cutB, configs[1], topology.NamespacePaths[1])
		retireManagedSQLDNS(t, ctx, a, remote, root, cli, read, wait)
		stopB()
		inspectSQLReverseReceiveTerminal(t, configs[1], cut)
		return
	}
	if withRestore {
		testManagedSQLBackupRestore(t, ctx, a, root, file, document, docker, cli, request, read, change, wait, stopB, startB)
		return
	}
	protocols := 3
	if withDNS {
		protocols = 1 // New contract is DNS/name-based SQL, not the old H1/H2/H3 matrix.
		verifyManagedSQLDNS(t, ctx, a, docker, [2]string{webStatus.NativeID, oldTask.NativeID}, remote, read)
	}
	tcpSnapshot("before HTTP sequence")
	for n := range protocols {
		wantDriver := "mysql"
		if dnsOnly {
			wantDriver = "dns"
		}
		if result := request(n, "GET", "/readyz", ""); result["driver"] != wantDriver || result["ready"] != true {
			t.Fatal("actual PDO mysql readiness", result)
		} else if withDNS && result["db_host"] != "db" {
			t.Fatal("actual PDO DNS host was bypassed", result)
		}
		if withDNS {
			if result := request(n, "GET", "/dns", ""); result["db_host"] != "db" || result["db_address"] != "198.19.80.18" {
				t.Fatal("actual PHP resolver was bypassed", result)
			}
		}
		if dnsOnly {
			continue
		}
		key, value := fmt.Sprintf("original%d", n), strings.Repeat(string(rune('A'+n)), 128<<10)
		create := fmt.Sprintf("create-%d", n)
		if result := request(n, "POST", "/row?key="+key+"&operation="+create, value); result["id"] != key || result["operation"] != create || result["value"] != value {
			t.Fatal("SQL INSERT128KiB", n)
		}
		if result := request(n, "GET", "/row?key="+key, ""); result["id"] != key || result["value"] != value {
			t.Fatal("SQL SELECT128KiB", n)
		}
		updated := strings.Repeat(string(rune('D'+n)), 128<<10)
		if result := request(n, "PUT", "/row?key="+key+fmt.Sprintf("&operation=update-%d", n), updated); result["value"] != updated {
			t.Fatal("SQL UPDATE128KiB", n)
		}
		if result := request(n, "POST", "/row?key="+key+"&operation="+create, value); result["value"] != value {
			t.Fatal("original committed result replay", n)
		}
		request(n, "POST", "/row?key="+key+"&operation="+create, "different", 409)
		if result := request(n, "GET", "/operation?id="+create, ""); result["value"] != value || result["operation"] != create {
			t.Fatal("original SQL operation result lookup", n)
		}
		if result := request(n, "GET", "/row?key="+key, ""); result["value"] != updated {
			t.Fatal("replay/conflict changed current row", n)
		}
	}
	if !dnsOnly {
		request(0, "POST", "/row?key=temporary&operation=create-temp", "temporary")
		if result := request(0, "DELETE", "/row?key=temporary&operation=delete-temp", ""); result["deleted"] != true {
			t.Fatal("SQL DELETE")
		}
		request(0, "GET", "/row?key=temporary", "", 404)
		if withDNS {
			t.Log("actual independent Engines: same declared DNS -> PHP/PDO CRUD128KiB/original result/replay conflict -> remote Ingress H1; original H2/H3 matrix reused")
		} else {
			t.Log("actual independent Engines: CLI -> Group FD approvals -> remote Secret -> nonroot MySQL/PDO CRUD128KiB/atomic operation result/replay conflict -> remote Ingress H1/H2/H3/trusted TLS")
		}
	} else {
		t.Log("actual two-owner PHP/libc DNS HTTP/CLI health boundary; no MySQL or SQL operations in this diagnostic scenario")
	}
	if gitSource != nil {
		app, err := deployment.ParseApp([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		web := app.Services["web"]
		web.Environment["MYDC_CD_REVISION"] = "2"
		app.Services["web"] = web
		next, err := yaml.Marshal(app)
		if err != nil {
			t.Fatal(err)
		}
		commit := gitSource.Commit(next)
		phase("second Git commit published")
		var candidate deployment.DeliverySelection
		wait("SQL app exact immutable Git candidate", func() bool {
			apps, err := policy.Apps(read().State)
			d, found := apps.Delivery("tenant", "app")
			candidate, _ = d.CandidateSelection()
			return err == nil && found && candidate.Commit == commit && d.SourceError() == ""
		})
		// The strict manual CLI CAS and original receipts retain their E6/
		// current7/current8 evidence. Exercise the existing automatic controller
		// here, without retrying a rejected user operation or changing its CAS.
		var selectedOperation string
		wait("automatic Git CD replaces PHP while preserving original SQL writer", func() bool {
			apps, err := policy.Apps(read().State)
			e, found := apps.Execution("tenant", "app")
			d, registered := apps.Delivery("tenant", "app")
			selection, selected := d.Selection()
			currentWeb, webErr := a.workload.Status(ctx, deployment.ResourceKey("task", "tenant", "app", "web"))
			currentDB, dbErr := observeB(task)
			// Retirement rebases incidental CAS/usage bases. The original
			// artifact and semantic intent, rather than that plan ID, stay fixed.
			if err != nil || !found || !registered || !selected || selection.Commit != commit || selection.Artifact != candidate.Artifact || selection.Intent != candidate.Intent || selection.Operation == "" || e.ActiveOperation() != selection.Operation || e.Status() != "Succeeded" || webErr != nil || !currentWeb.Ready || currentWeb.NativeID == webStatus.NativeID || dbErr != nil || !currentDB.Ready || currentDB.NativeID != oldTask.NativeID || currentDB.Journal.LastID != oldTask.Journal.LastID {
				return false
			}
			webStatus = currentWeb
			selectedOperation = selection.Operation
			return true
		})
		phase("automatic Git CD replaced PHP with original SQL writer")
		deployedOperation = selectedOperation
		cli(nil, "cd", "show", "app", "--tenant", "tenant")
		if result := request(0, "GET", "/row?key=original0", ""); result["value"] != strings.Repeat("D", 128<<10) {
			t.Fatal("Git CD lost original SQL row", result)
		}
		ownerManifest["git_second_commit"] = commit
		ownerManifest["git_auto_operation"] = selectedOperation
		ownerManifest["git_source"] = gitSource.Stats()
		raw, _ := json.Marshal(ownerManifest)
		if err := os.WriteFile(manifest, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if gitSource != nil {
		query := func(call context.Context) error {
			_, err := user.Query(call, source, session, "apps", "tenant")
			return err
		}
		checkRows := func() {
			if result := request(0, "GET", "/row?key=original0", ""); result["value"] != strings.Repeat("D", 128<<10) {
				t.Fatal("SQL fault recovery lost row")
			}
			if result := request(0, "GET", "/operation?id=create-0", ""); result["value"] != strings.Repeat("A", 128<<10) || result["operation"] != "create-0" {
				t.Fatal("SQL fault recovery changed original operation")
			}
		}
		ownerManifest["e7_sql_faults"] = verifyE7SQLPauseAndUnderlay(t, ctx, a, docker, query, oldTask, func() (ModuleObservation, error) { return observeB(task) }, wait, "http://192.0.2.2:8080/readyz", checkRows)
		phase("SQL pause and underlay faults recovered")
		ownerManifest["e7_sql_load"] = verifyE7SQLBoundedLoad(t, ctx, "http://192.0.2.2:8080")
		phase("finite SQL load completed")
		raw, _ := json.Marshal(ownerManifest)
		if err := os.WriteFile(manifest, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	localTunnel := nativeKey("tunnel", "node-a")
	remoteTunnel := nativeKey("tunnel", "node-b")
	oldLocal, err := a.tunnel.Observe(localTunnel)
	if err != nil {
		t.Fatal(err)
	}
	oldRemote, err := observeB(remoteTunnel)
	if err != nil || oldRemote.Tunnel == nil {
		t.Fatal("original remote native path", err)
	}
	if err = a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	h1.CloseIdleConnections()
	h2.CloseIdleConnections()
	_ = h3.Close()
	stopB()
	if gitSource != nil {
		probe, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		_, err := user.Query(probe, source, session, "apps", "tenant")
		cancel()
		if err == nil {
			t.Fatal("SQL N2 latest read succeeded with one stopped voter")
		}
		native, err := docker[1].API.ContainerInspect(ctx, oldTask.NativeID, client.ContainerInspectOptions{})
		if err != nil || native.Container.State == nil || !native.Container.State.Running {
			t.Fatal("control quorum loss erased original SQL native", err)
		}
		grace := 60
		if _, err := docker[1].API.ContainerStop(ctx, oldTask.NativeID, client.ContainerStopOptions{Timeout: &grace}); err != nil {
			t.Fatal("explicit original SQL graceful stop", err)
		}
		exited, err := docker[1].API.ContainerInspect(ctx, oldTask.NativeID, client.ContainerInspectOptions{})
		if err != nil || exited.Container.State == nil || exited.Container.State.Running || exited.Container.State.ExitCode != 0 || exited.Container.State.FinishedAt == "" {
			t.Fatal("positive clean SQL exit", err)
		}
		ownerManifest["e7_sql_original_clean_exit"] = map[string]any{"native_id": oldTask.NativeID, "started_at": exited.Container.State.StartedAt, "finished_at": exited.Container.State.FinishedAt, "exit_code": exited.Container.State.ExitCode}
		raw, _ := json.Marshal(ownerManifest)
		if err := os.WriteFile(manifest, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	startB()
	h3 = &http3.Transport{TLSClientConfig: tlsConfig.Clone()}
	defer h3.Close()
	wait("same remote DB/Task/TUN pins and fresh packet planes", func() bool {
		now, e := observeB(task)
		if e != nil || !now.Ready || now.NativeID != oldTask.NativeID || now.Journal.LastID != oldTask.Journal.LastID {
			return false
		}
		now, e = observeB(remoteTunnel)
		if e != nil || !now.Ready || now.Tunnel == nil || now.NativeID != oldRemote.NativeID || !maps.Equal(now.Journal.Pins, oldRemote.Journal.Pins) || maps.Equal(now.Tunnel.Connections, oldRemote.Tunnel.Connections) {
			return false
		}
		local, e := a.tunnel.Observe(localTunnel)
		if e != nil || local.PacketUsers != 1 || maps.Equal(local.Connections, oldLocal.Connections) {
			return false
		}
		ing, e := observeB(deployment.ResourceKey("ingress", "tenant", "app", "http"))
		if e != nil || !ing.Ready {
			return false
		}
		if withDNS {
			dns, e := observeB("control/network-services/dns/tenant/app-services")
			return e == nil && dns.Ready && dns.DNS != nil && dns.DNS.Desired > 0 && dns.DNS.Desired == dns.DNS.Applied && dns.DNS.Applied == dns.DNS.Observed
		}
		return true
	})
	if withDNS {
		verifyManagedSQLDNS(t, ctx, a, docker, [2]string{webStatus.NativeID, oldTask.NativeID}, remote, read)
	}
	if gitSource != nil {
		ownerManifest["e7_sql_daemon_http_recovery"] = waitManagedSQLHTTPReady(t, ctx, wait, "http://192.0.2.2:8080/readyz")
		phase("same-DB daemon and actual HTTP boundary recovered")
	}
	for n := range protocols {
		if dnsOnly {
			if result := request(n, "GET", "/readyz", ""); result["db_address"] != "198.19.80.18" {
				t.Fatal("original DNS app after daemon restart", result)
			}
			continue
		}
		updated := strings.Repeat(string(rune('D'+n)), 128<<10)
		if result := request(n, "GET", fmt.Sprintf("/row?key=original%d", n), ""); result["value"] != updated {
			t.Fatal("SQL row after original daemon restart", n)
		}
		if result := request(n, "GET", fmt.Sprintf("/operation?id=update-%d", n), ""); result["value"] != updated {
			t.Fatal("original committed SQL result after restart", n)
		}
	}
	cli(nil, "compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "down")
	var lastRetirementState, lastOwnerCause string
	var lastOwnerCheck time.Time
	lastRetirementChange := time.Now()
	wait("original SQL/Ingress/Task/inputs/TUN retirement", func() bool {
		apps, err := policy.Apps(read().State)
		if err != nil {
			return false
		}
		i, ok := apps.Inventory("tenant", "app")
		if withDNS {
			// The remote daemon is tied to the scenario context. Inspect an
			// original live bridge before that context kills the process; the
			// removed task's observer can no longer expose its module error.
			if time.Since(lastOwnerCheck) >= 2*time.Second {
				lastOwnerCheck = time.Now()
				o, err := observeB(nativeKey("bridge", "node-b"))
				cause := fmt.Sprint(err, "/", o.ModuleError, "/", o.Error)
				if cause != lastOwnerCause {
					t.Log("original remote retirement cause", cause)
					lastOwnerCause = cause
				}
			}
			var targets []string
			if retirement, active := i.Retirement(); active {
				for _, target := range retirement.Targets {
					targets = append(targets, fmt.Sprintf("%s closed=%t eligible=%t retain=%t drain=%t proof=%t delete=%t", target.Original.Step.Key, target.Closed, i.CanRetire(target.Original.Step.Key), target.Original.Step.Retain, target.Drain != nil && target.Drain.Result != nil, target.Proof != nil, target.Delete != nil))
				}
			}
			var local any
			if a.dnsOwner() != nil {
				_, rows, _ := apps.NetworkDNS(a.Identity.Public)
				for _, row := range rows {
					local = a.dnsOwner().Status(row.Config.Tenant, row.Config.ID)
				}
			}
			data, _ := json.Marshal(struct {
				Targets []string
				DNS     any
			}{targets, local})
			if string(data) != lastRetirementState {
				t.Log("original DNS retirement progress", string(data))
				lastRetirementState, lastRetirementChange = string(data), time.Now()
			} else if dnsOnly && time.Since(lastRetirementChange) > 30*time.Second {
				t.Fatal("original retirement state stopped changing; diagnostic boundary, references preserved for rollback", string(data))
			}
		}
		// A completed Git sync archives the first rollout as Succeeded.
		// Down retires the actual selected execution; it cannot rewrite that
		// earlier immutable result into a new retirement result.
		op, found := i.Operation(deployedOperation)
		if !ok || !found || op.Status != "Retired" || len(apps.Bindings().Live()) != 0 {
			return false
		}
		for _, claim := range i.Claims() {
			if !claim.Removed && !claim.Retained {
				return false
			}
		}
		if _, retiring := i.Retirement(); retiring {
			return false
		}
		return true
	})
	if gitSource != nil {
		wait("SQL CD original source jobs settle after down", func() bool {
			apps, err := policy.Apps(read().State)
			d, found := apps.Delivery("tenant", "app")
			return err == nil && found && d.Quiescent()
		})
	}
	volumes, err := policy.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	volume, ok := volumes.Native("tenant", "app", "data")
	if !ok || volume.Verify() != nil {
		t.Fatal("original retained SQL Volume registration")
	}
	got, err := docker[1].API.VolumeInspect(ctx, volume.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if b, e := os.ReadFile(filepath.Join(got.Volume.Mountpoint, ".mydc-app-initialized")); !dnsOnly && (e != nil || string(b) != "1\n") {
		t.Fatal("retained real SQL datadir", e)
	}
	for _, c := range docker {
		rows, e := c.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.mydc.owner="+c.Owner)})
		if e != nil || len(rows.Items) != 0 {
			t.Fatal("original owned SQL Task not removed", e)
		}
	}
	if withDNS {
		retireManagedSQLDNS(t, ctx, a, remote, root, cli, read, wait)
	}
	t.Log("same original remote DB/container ID/TUN pin restart preserved SQL rows; CLI down closed original Ingress/Task/input and returned app network borrows/Bindings while keeping management sources; explicit DNS disable settled its own instances before separate fixture cleanup; retained datadir awaits explicit fixture deletion")
}

func prepareSQLSecrets(t *testing.T, ctx context.Context, provider *Runtime, user userauth.Client, peer mydcp.Peer, session access.Session, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	current := func() control.Vault {
		v, e := provider.controlPolicy.Vault(read().State)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	change("vault-init", "vault-init", 0, control.VaultRealm{Realm: "tenant", Root: "root"})
	for _, name := range []string{"common", "db-admin"} {
		group := secrets.Object{ID: name, Parent: "root", Kind: secrets.Group}
		if name == "db-admin" {
			group.ACL.Services = []string{"db"}
		}
		change("group-"+name, "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: group})
	}
	for _, row := range []struct{ id, parent, key string }{{"password", "common", "DB_PASSWORD"}, {"root-password", "db-admin", "MYSQL_ROOT_PASSWORD"}} {
		change("secret-"+row.id, "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: row.id, Parent: row.parent, Kind: secrets.Secret, Reference: secrets.Reference{Profile: "values", Object: "tenant/" + row.id, Keys: []string{row.key}}}})
	}
	for _, p := range []secrets.WriteProfile{{ID: "values", Node: "node-a", Key: provider.Identity.Public, Enabled: true, Values: true}, {ID: "auth", Node: "node-a", Key: provider.Identity.Public, Enabled: true, Verifiers: true}} {
		change("profile-"+p.ID, "vault-set-profile", current().Trees["tenant"].Revision(), control.VaultProfile{Realm: "tenant", Profile: p})
	}
	write := func(q secrets.WriteRequest, values map[string][]byte) {
		q.Epoch = current().Trees["tenant"].WriteEpoch()
		change(q.ID+"-prepare", "vault-prepare-write", current().Trees["tenant"].Revision(), control.VaultWrite{Realm: "tenant", Request: q})
		change(q.ID+"-dispatch", "vault-dispatch-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: q.ID, Epoch: q.Epoch})
		reply, e := user.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "tenant", ID: q.ID, Mode: "execute", Values: values})
		if e != nil || reply.VaultObservation == nil || reply.VaultObservation.Outcome != reconcile.EffectApplied {
			t.Fatal("real SQL Vault provider write", q.ID, e)
		}
		change(q.ID+"-observe", "vault-observe-write", current().Trees["tenant"].Revision(), control.VaultObserve{Observation: *reply.VaultObservation})
		record, _ := current().Trees["tenant"].Write(q.ID)
		change(q.ID+"-publish", "vault-publish-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: q.ID, Epoch: q.Epoch, ObjectRevision: record.ExpectedObjectRevision})
		for _, b := range values {
			clear(b)
		}
	}
	write(secrets.WriteRequest{ID: "password-write", Object: "password", Profile: "values", ProviderObject: "tenant/password", Kind: secrets.ValueWrite, Keys: []string{"DB_PASSWORD"}}, map[string][]byte{"DB_PASSWORD": []byte("private_sql_app_password_123")})
	write(secrets.WriteRequest{ID: "root-password-write", Object: "root-password", Profile: "values", ProviderObject: "tenant/root-password", Kind: secrets.ValueWrite, Keys: []string{"MYSQL_ROOT_PASSWORD"}}, map[string][]byte{"MYSQL_ROOT_PASSWORD": []byte("private_sql_root_password_456")})
	for n, name := range []string{"common", "db-admin"} {
		password := []byte("private-native-group-password")
		h, e := identity.PasswordHash(password, bytes.Repeat([]byte{byte(84 + n)}, 16), identity.DefaultPasswordCost())
		clear(password)
		if e != nil {
			t.Fatal(e)
		}
		protected, e := h.ProtectedBytes()
		if e != nil {
			t.Fatal(e)
		}
		group, _ := current().Trees["tenant"].Object(name)
		write(secrets.WriteRequest{ID: "protect-" + name, Object: name, Profile: "auth", ProviderObject: fmt.Sprintf("groups/tenant/%s/%d", name, group.Generation), Kind: secrets.VerifierWrite, Protected: true}, map[string][]byte{"verifier": protected})
		clear(protected)
	}
	change("approval-issuer", "vault-set-issuer", current().Approvals.Revision(), control.VaultIssuer{Key: provider.Identity.Public, Enabled: true})
}
