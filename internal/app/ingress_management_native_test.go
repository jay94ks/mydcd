// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	bolt "go.etcd.io/bbolt"
	"gopkg.in/yaml.v3"
)

// Extends the existing owned Docker/CLI/Raft/remote-provider fixture. The
// caller supplies the prebuilt products, the primary /28 and separate remote
// /24. The adjacent /28 is the same two-tenant baseline as app_tenant_native.
// Extra app shutdown and both Runtime.Close/owned journal cleanup are installed
// before accepting an extra app; no host network setting or image is fetched.
func TestRQ7ManagedIngressCLIThreeMappingsTwoOwners(t *testing.T) {
	if os.Getenv("SFC_DOCKER_TEST_REMOTE_CIDR") == "" {
		t.Skip("existing owned remote CIDR baseline required")
	}
	runManagedAppOwner(t, true, true, true, true, managedAppIngressManagement, true, true, false, true)
}

func configureManagedIngressGateways(t *testing.T, cfg *config.Node) {
	t.Helper()
	first, second := "127.0.0.1", "127.0.0.2"
	if cfg.Node.ID == "node-b" {
		first, second = "127.0.0.3", "127.0.0.4"
	}
	// This fixture owns a separate network namespace. Both logical servers
	// expose the required HTTPS port on their distinct external/local IPs.
	l, err := net.Listen("tcp4", net.JoinHostPort(first, "443"))
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	local := config.IngressLocal{Enabled: true}
	local.Gateways.External = ingress.Gateway{Enabled: true, Addresses: []netip.Addr{netip.MustParseAddr(first)}, Ports: []uint16{port}, Listeners: []ingress.Listener{{ID: "rq7-external", Address: net.JoinHostPort(first, fmt.Sprint(port)), TLS: true}}}
	local.Gateways.Local = ingress.Gateway{Enabled: true, Addresses: []netip.Addr{netip.MustParseAddr(second)}, Ports: []uint16{port}, AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")}, Listeners: []ingress.Listener{{ID: "rq7-local", Address: net.JoinHostPort(second, fmt.Sprint(port)), TLS: true}}}
	var body yaml.Node
	if err := body.Encode(local); err != nil {
		t.Fatal(err)
	}
	cfg.Modules["ingress"] = config.Module{Enabled: true, Body: body}
}

func rq7Certificate(t *testing.T, hosts ...string) (certstore.Material, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return rq7CertificateForKey(t, key, hosts...)
}

func rq7CertificateForKey(t *testing.T, key crypto.Signer, hosts ...string) (certstore.Material, *x509.Certificate) {
	t.Helper()
	return rq7CertificateLasting(t, key, 24*time.Hour, hosts...)
}

// rq7CertificateLasting sets the lifetime; a later NotAfter takes the link.
func rq7CertificateLasting(t *testing.T, key crypto.Signer, lifetime time.Duration, hosts ...string) (certstore.Material, *x509.Certificate) {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: serial, DNSNames: hosts, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	return certstore.Material{Chain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}, parsed
}

func verifyManagedIngressManagement(t *testing.T, ctx context.Context, a, b *Runtime, cfg config.Node, root string, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), image string, public map[string]any, save func(), fixtureTest func(*testing.T)) {
	t.Helper()
	parent := t
	selectedAny := false
	run := func(name string, action func(*testing.T)) bool {
		selected := false
		ok := parent.Run(name, func(current *testing.T) {
			selected = true
			previous := t
			t = current
			fixtureTest(current)
			defer func() { t = previous; fixtureTest(previous) }()
			action(current)
		})
		if !selected && (!selectedAny || strings.HasPrefix(name, "RQ7-S2-")) {
			parent.Skip("RQ7 native sets require the shared S2 preparation; select preceding sets in the same root")
		}
		selectedAny = selectedAny || selected
		// Preserve testing.T.Run's successful skip semantics for independent
		// sets; the shared S2 setup above is mandatory even for a later selector.
		return ok
	}
	primary := netip.MustParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	if primary.Bits() != 28 || !primary.Addr().Is4() {
		t.Fatal("same primary/adjacent owned /28 baseline as tenant isolation required")
	}
	secondIP := primary.Addr()
	for range 16 {
		secondIP = secondIP.Next()
	}
	second, remote := netip.PrefixFrom(secondIP, 28), checkerRemoteNativeCIDR(t)
	if remote.Overlaps(second) || b == nil || b.ingress == nil || b.docker == nil {
		t.Fatal("disjoint owned CIDRs and installed second native owner required")
	}
	public["RQ7"] = map[string]any{"Primary": primary.String(), "Second": second.String(), "Remote": remote.String(), "OwnerA": a.Identity.Public, "OwnerB": b.Identity.Public, "Apps": []string{"tenant/rq7-shop", "second/rq7-internal", "tenant/rq7-remote"}}
	save()
	t.Cleanup(func() {
		// Reuse the existing positive Task closure/route/Bridge journal rollback
		// after joining every producer. This also covers early test failure.
		for _, r := range []*Runtime{a, b} {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		}
		clean, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		for _, owner := range []struct {
			r   *Runtime
			cfg config.Node
		}{{a, cfg}, {b, b.installation.config}} {
			docker, err := engine.Open(clean, "unix:///var/run/docker.sock", owner.r.docker.Owner)
			if err != nil {
				t.Error(err)
				continue
			}
			cleanupOwnedRuntimeSources(t, clean, docker, owner.cfg, p.Cluster, owner.r.Identity.Public)
			_ = docker.Close()
		}
	})
	home, profile := filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml")
	call := func(success bool, inputs []*os.File, args ...string) []byte {
		t.Helper()
		if len(args) >= 2 && args[0] == "compose" && args[1] == "wait" {
			// Retirement serially joins the original Ingress, three Tasks and
			// their DNS/address receipts. Keep that observation budget separate
			// from startup; neither budget changes a product/effect deadline.
			budget := "90s"
			for i := 2; i+1 < len(args); i++ {
				if args[i] == "--condition" && args[i+1] == "retired" {
					budget = "180s"
				}
			}
			args = append([]string{"--timeout", budget}, args...)
		}
		body, why, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), home, profile, args, inputs)
		if (err == nil) != success {
			// Preserve first-failure facts before deferred app retirement/Close
			// can replace them with shutdown errors. No diagnostic CLI or retry.
			for _, owner := range []*Runtime{a, b} {
				owner.mu.RLock()
				moduleError, reportError := owner.moduleError, owner.reportError
				owner.mu.RUnlock()
				t.Log("RQ7 first CLI failure owner", owner.Identity.Public, "module", moduleError, "report", reportError)
			}
			view, readErr := a.Engine().Read(ctx, false)
			if readErr == nil {
				book, bookErr := p.Apps(view.State)
				if bookErr == nil {
					for _, app := range book.Records() {
						execution, exists := book.Execution(app.Tenant, app.App)
						if !exists {
							continue
						}
						for _, step := range execution.Steps() {
							stage, _ := execution.Stage(step.Key)
							t.Log("RQ7 original stage", step.Key, "command", stage.Command != nil, "result", stage.Result)
							if observed := stage.Observation; observed != nil {
								t.Log("RQ7 original stage fact", step.Key, "at", observed.At, "applied", observed.Applied, "healthy", observed.Healthy)
							}
						}
					}
				}
			}
			t.Fatal("RQ7 CLI", args, err, string(why), string(body))
		}
		return body
	}
	writeJSON := func(name string, value any) string {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name+".json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	put := func(id string, material certstore.Material, success bool) {
		t.Helper()
		chain, key := filepath.Join(root, id+"-chain.pem"), filepath.Join(root, id+"-key.pem")
		if err := os.WriteFile(chain, material.Chain, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(key, material.Key, 0600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(key)
		call(success, nil, "certificate", "put", "--chain", chain, "--key", key, "--id", id)
	}
	shop, leaf := rq7Certificate(t, "shop.example")
	defer shop.Clear()
	nextKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	next, nextLeaf := rq7CertificateLasting(t, nextKey, 48*time.Hour, "shop.example")
	defer next.Clear()
	unpaired, _ := rq7Certificate(t, "shop.example")
	defer unpaired.Clear()
	internal, internalLeaf := rq7Certificate(t, "grafana.internal", "metrics.example")
	defer internal.Clear()
	// The requester transport belongs to the shared root, not one stage.
	follower, provider := rq7FollowerCertificateClient(t, ctx, a, b, user, peer, p)
	if !run("RQ7-S2-protected-input-and-original-recovery", func(current *testing.T) {
		for _, domain := range []string{"shop.example", "metrics.example", "grafana.internal"} {
			call(true, nil, "domain", "add", domain)
		}
		put("rq7-cert-first", shop, true)
		internalVersion := rq7PrepareFollowerCertificate(t, ctx, a, b, follower, provider, session, "rq7-cert-internal", internal)
		change("rq7-cert-internal", "put-certificate", 0, control.CertificatePut{Certificate: internalVersion})
		put("rq7-cert-mismatch", certstore.Material{Chain: unpaired.Chain, Key: internal.Key}, false)
		// The same operation ID continues without reading the key again.
		call(true, nil, "certificate", "put", "--chain", filepath.Join(root, "rq7-cert-first-chain.pem"), "--key", filepath.Join(root, "missing-key.pem"), "--id", "rq7-cert-first")
	}) {
		return
	}
	change("rq7-second", "create-tenant", 0, control.TenantID{ID: "second"})
	users, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"tenant", "second"} {
		tenant, _ := users.Tenant(scope)
		nodes := []string{"node-a"}
		if scope == "tenant" {
			nodes = append(nodes, "node-b")
		}
		change("rq7-nodes-"+scope, "set-nodes", tenant.Revision, control.NodeChangeTo(scope, tenant.AllowedNodes, nodes))
	}
	users, _ = p.Catalog(read().State)
	other, _ := users.Tenant("second")
	change("rq7-trust", "set-trust", other.Revision, control.TrustChange{Tenant: "second", Add: []access.TrustRule{{Registry: strings.Split(image, "/")[0], Repository: "fixture"}}, Remove: other.ImageSources})
	for _, item := range []struct{ tenant, node string }{{"", "node-b"}, {"tenant", "node-b"}, {"second", "node-a"}} {
		// Match the initial RQ7 node-a global ceiling, including distinct
		// Task/route/DNS edges; a tenant limit cannot exceed its node.
		change("rq7-quota-"+item.tenant+"-"+item.node, "set-node-quota", 0, tenancy.NodeLimit{Tenant: item.tenant, Node: item.node, Capacity: workload.Resources{CPU: 1e9, Memory: 256 << 20}, Networks: 2, MaxConsumers: 16, MaxIngressInstances: 2, MaxIngressListeners: 4, MaxIngressRequests: 4, MaxIngressConnections: 16, IngressBufferBytes: 256 << 10})
	}
	for _, def := range []tenancy.TUNDefinition{
		{Tenant: "second", Name: "rq7-second", Members: []tenancy.TUNNode{{Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: second, Gateway: second.Addr().Next(), MTU: 1280}}}}},
		{Tenant: "tenant", Name: "rq7-remote", Members: []tenancy.TUNNode{{Node: "node-b", Pools: []tenancy.Subnet{{ID: "pool", Prefix: remote, Gateway: remote.Addr().Next(), MTU: 1280}}}}},
	} {
		resources, err := p.Resources(read().State)
		if err != nil {
			t.Fatal(err)
		}
		change("rq7-network-"+def.Name, "create-tun-network", resources.Networks.Revision(), def)
	}
	dns := services.ManagedDNSDefinition{Schema: 1, Tenant: "tenant", Network: "shared-services", Policy: services.ManagedDNSPolicy{Enabled: true, Zone: "rq7.sfc.test.", TTL: 1, NegativeTTL: 1, Transports: []string{"udp", "tcp"}, Upstreams: []netip.AddrPort{}, MaxQueries: 8, MaxCacheEntries: 8, MaxResponseBytes: 4096, MaxConnections: 8, RequestTimeoutMS: 1000}}
	change("rq7-dns", "configure-network-dns", 0, dns)
	// Tenant route hosts open under the tenant's own domains
	// (devel/design/tenant-domains.md); second gets its domains later.
	giveDomain := func(name, tenant string) {
		certificates, err := p.Certificates(read().State)
		if err != nil {
			t.Fatal(err)
		}
		if d, ok := certificates.Domain(name); ok {
			if d.Tenant != tenant {
				change("rq7-assign-"+name, "assign-domain", certificates.Revision, control.DomainChange{Name: name, Tenant: tenant})
			}
			return
		}
		change("rq7-domain-"+name, "add-domain", certificates.Revision, control.DomainChange{Name: name, Tenant: tenant})
	}
	giveDomain("shop.example", "tenant")
	rq7ExerciseIngressApps(t, ctx, a, b, root, cfg, user, peer, session, follower, provider, p, read, change, wait, call, writeJSON, put, image, primary, second, remote, shop, next, internal, leaf, nextLeaf, internalLeaf, run)
}

func rq7ExerciseIngressApps(t *testing.T, ctx context.Context, a, b *Runtime, root string, cfg config.Node, user userauth.Client, peer sfcp.Peer, session access.Session, follower userauth.Client, provider sfcp.Peer, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), call func(bool, []*os.File, ...string) []byte, writeJSON func(string, any) string, put func(string, certstore.Material, bool), image string, primary, second, remote netip.Prefix, shop, next, internal certstore.Material, leaf, nextLeaf, internalLeaf *x509.Certificate, run func(string, func(*testing.T)) bool) {
	t.Helper()
	// Rebind this helper's closures as well as the root's callbacks. A failed
	// predecessor stops subsequent dependent native mutations. Independent sets
	// may be unselected while required preparation stays selected.
	rootTest := t
	runHere := func(name string, action func(*testing.T)) bool {
		return run(name, func(current *testing.T) {
			previous := t
			t = current
			defer func() { t = previous }()
			action(current)
		})
	}
	phase := func(name string, action func()) bool {
		return runHere(name, func(*testing.T) { action() })
	}
	type app struct {
		tenant, name, node, network, host string
		pool                              netip.Prefix
	}
	apps := []app{{"tenant", "rq7-shop", "node-a", "shared-services", "shop.example", primary}, {"second", "rq7-internal", "node-a", "rq7-second", "metrics.example", second}, {"tenant", "rq7-remote", "node-b", "rq7-remote", "shop.example", remote}}
	files := map[string]string{}
	for _, item := range apps {
		doc := rq7IngressDocument(t, image, item.tenant, item.name, item.node, item.network, item.host, item.pool)
		file := filepath.Join(root, item.name+".yaml")
		if err := os.WriteFile(file, doc, 0600); err != nil {
			t.Fatal(err)
		}
		files[item.name] = file
	}
	// A host under no registered domain is refused before the second
	// tenant owns its domains.
	denied, err := os.ReadFile(files["rq7-internal"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = user.StreamAppPlan(ctx, peer, session, "second", control.AppPlanRequest{Document: denied}); err == nil {
		t.Fatal("an app routed a host under no registered domain")
	}
	for _, name := range []string{"metrics.example", "grafana.internal"} {
		certificates, err := p.Certificates(read().State)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := certificates.Domain(name); !ok {
			change("rq7-second-domain-"+name, "add-domain", certificates.Revision, control.DomainChange{Name: name, Tenant: "second"})
		}
	}
	// Existing CLI down/wait handles original accepted apps even after a lost up
	// reply. Register before the first extra app can create native resources.
	retirementStarted := false
	retireApps := func() {
		// One cleanup attempt preserves each original operation ID. A failed
		// named retirement is not automatically resubmitted by the fallback.
		retirementStarted = true
		for i := len(apps) - 1; i >= 0; i-- {
			item := apps[i]
			book, err := p.Apps(read().State)
			if err != nil {
				t.Error(err)
				continue
			}
			if _, exists := book.Inventory(item.tenant, item.name); !exists {
				continue
			}
			call(true, nil, "compose", "down", "--tenant", item.tenant, "-p", item.name, "--operation", "rq7-down-"+item.name)
			call(true, nil, "compose", "wait", "--tenant", item.tenant, "-p", item.name, "--operation", "rq7-down-"+item.name, "--condition", "retired")
		}
	}
	defer func() {
		if !retirementStarted {
			retireApps()
		}
	}()
	for _, item := range apps {
		call(true, nil, "compose", "up", "--tenant", item.tenant, "-f", files[item.name], "--operation", "rq7-up-"+item.name, "--no-input")
		call(true, nil, "compose", "wait", "--tenant", item.tenant, "-p", item.name, "--operation", "rq7-up-"+item.name, "--condition", "healthy")
	}
	page := func(item app, part string) control.IngressMapping {
		t.Helper()
		q := control.IngressQuery{Tenant: item.tenant, App: item.name, Node: item.node, Key: deployment.ResourceKey("ingress", item.tenant, item.name, "http"), Part: part}
		got, err := user.Ingresses(ctx, peer, session, q)
		if err != nil || len(got.Mappings) != 1 || got.Mappings[0].Runtime == nil {
			t.Fatal("actual user/owner ingress page", item, got, err)
		}
		if item.node == "node-b" {
			direct, err := follower.Ingresses(ctx, provider, session, q)
			if err != nil || b.Engine().IsLeader() || len(direct.Mappings) != 1 || direct.Mappings[0].Runtime == nil || direct.Mappings[0].Owner != b.Identity.Public || direct.Mappings[0].Key != got.Mappings[0].Key || direct.Mappings[0].Generation != got.Mappings[0].Generation || direct.Mappings[0].Revision != got.Mappings[0].Revision || direct.RootRevision == 0 {
				t.Fatal("direct non-voter route/owner observation lost exact resource", err)
			}
			// Public User ingress may relay to its control leader. Also consume
			// this installed runtime's routing entry itself, using the same
			// authenticated session and current exact resource selection.
			native, err := b.readIngresses(ctx, control.IngressRead{Session: session, Query: q, At: time.Now().Unix()})
			if err != nil || len(native.Mappings) != 1 || native.Mappings[0].Runtime == nil || native.Mappings[0].Owner != b.Identity.Public || native.Mappings[0].Key != direct.Mappings[0].Key || native.Mappings[0].Generation != direct.Mappings[0].Generation || native.Mappings[0].Revision != direct.Mappings[0].Revision {
				t.Fatal("non-voter runtime routing rejected current exact owner observation", err)
			}
		}
		return got.Mappings[0]
	}
	var localA, localB config.IngressLocal
	if cfg.Modules["ingress"].Decode(&localA) != nil || b.installation.config.Modules["ingress"].Decode(&localB) != nil {
		t.Fatal("installed shared gateway configuration")
	}
	roots := x509.NewCertPool()
	for _, cert := range []*x509.Certificate{leaf, nextLeaf, internalLeaf} {
		roots.AddCert(cert)
	}
	client := func(host, source string) *http.Client {
		dialer := &net.Dialer{Timeout: time.Second}
		if source != "" {
			dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
		}
		tr := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: false}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 3 * time.Second}
	}
	externalA, internalA, externalB := localA.Gateways.External.Listeners[0].Address, localA.Gateways.Local.Listeners[0].Address, localB.Gateways.External.Listeners[0].Address
	shopClient, metricsClient, localClient := client("shop.example", ""), client("metrics.example", ""), client("grafana.internal", "127.0.0.2")
	request := func(c *http.Client, address, host, path, cookie string, status int) [32]byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		req.Header.Set("Cookie", "session="+cookie)
		if cookie == "canary-input" {
			req.Header.Set("X-Canary", "1")
		}
		req.Header.Set("Authorization", "Bearer rq7-never-observe")
		response, err := c.Do(req)
		if err != nil {
			t.Fatal("actual trusted gateway request", host, path, err)
		}
		defer response.Body.Close()
		if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 4096)); err != nil || response.StatusCode != status || response.TLS == nil {
			t.Fatal("actual gateway status", host, path, response.StatusCode, status, err)
		}
		return sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
	}
	oldFingerprint := sha256.Sum256(leaf.Raw)
	if !phase("RQ7-S2-physical-tls-sni-and-material-source", func() {
		for _, address := range []string{externalA, externalB} {
			if got := request(client("shop.example", ""), address, "shop.example", "/tenant", "same-user", 200); got != oldFingerprint {
				t.Fatal("two owners did not serve the same stored certificate")
			}
		}
		if got := request(metricsClient, externalA, "metrics.example", "/tenant", "other", 200); got != sha256.Sum256(internalLeaf.Raw) {
			t.Fatal("SNI selected another tenant's certificate")
		}
		rq7FollowerCertificateMaterialBoundary(t, ctx, a, b, p, read)
		request(localClient, internalA, "grafana.internal", "/tenant", "", 200)
		request(shopClient, externalA, "metrics.example", "/tenant", "", 421)
		for _, trial := range []struct {
			c             *http.Client
			address, host string
		}{{client("grafana.internal", ""), externalA, "grafana.internal"}, {client("grafana.internal", "127.0.0.1"), internalA, "grafana.internal"}} {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+trial.address+"/", nil)
			req.Host = trial.host
			if response, err := trial.c.Do(req); err == nil {
				response.Body.Close()
				t.Fatal("local gateway/host source boundary was bypassed")
			}
		}
	}) {
		return
	}
	var rsaMaterial certstore.Material
	defer func() { rsaMaterial.Clear() }()
	// The certificate pair is an independent optional verification group.
	// A selected failure stops dependent work; an unselected pair must not
	// force re-running passed certificate tests just to reach S4/S5.
	if !phase("RQ7-S3-rotation-failure-retention-rollback-and-key-selection", func() {
		// Rotation uses real protected input and committed public receipt. A damaged
		// owner-local wrapping record is installed before publication, so neither
		// owner can load version2 early and conceal the failure-retention case.
		v2 := rq7PrepareFollowerCertificate(t, ctx, a, b, follower, provider, session, "rq7-cert-rotate", next)
		restore := rq7DamageWrappedCertificate(t, b, v2)
		defer restore()
		change("rq7-cert-rotate", "put-certificate", 0, control.CertificatePut{Certificate: v2})
		wait("both owners expose failed reload and retain last good key", func() bool {
			for _, item := range []app{apps[0], apps[2]} {
				row := page(item, "mappings")
				found := false
				for _, cert := range row.Runtime.Certificates {
					found = found || cert.Fingerprint == oldFingerprint && cert.Error == "certificate-load-failed"
				}
				if !found {
					return false
				}
			}
			return true
		})
		for _, address := range []string{externalA, externalB} {
			if got := request(client("shop.example", ""), address, "shop.example", "/tenant", "", 200); got != oldFingerprint {
				t.Fatal("failed unwrap discarded original certificate")
			}
		}
		restore()
		newFingerprint := sha256.Sum256(nextLeaf.Raw)
		wait("same listeners load the restored exact new certificate", func() bool {
			for _, item := range []app{apps[0], apps[2]} {
				found := false
				for _, cert := range page(item, "mappings").Runtime.Certificates {
					found = found || cert.Fingerprint == newFingerprint && cert.Error == ""
				}
				if !found {
					return false
				}
			}
			return true
		})
		for _, address := range []string{externalA, externalB} {
			if got := request(client("shop.example", ""), address, "shop.example", "/tenant", "", 200); got != newFingerprint {
				t.Fatal("new handshakes missed rotation")
			}
		}
		// Existing accepted keepalive requests retain their original TLS connection.
		if got := request(shopClient, externalA, "shop.example", "/tenant", "same-user", 200); got != oldFingerprint {
			t.Fatal("rotation replaced an already open connection")
		}
		// Disabling the new certificate moves the link back to the old one.
		newID := hex.EncodeToString(newFingerprint[:])
		call(false, nil, "certificate", "delete", newID, "--id", "rq7-used-delete")
		call(true, nil, "certificate", "disable", newID, "--id", "rq7-disable")
		wait("both original owners serve the old certificate again", func() bool {
			for _, item := range []app{apps[0], apps[2]} {
				found := false
				for _, cert := range page(item, "mappings").Runtime.Certificates {
					found = found || cert.Fingerprint == oldFingerprint && cert.Error == ""
				}
				if !found {
					return false
				}
			}
			return true
		})
		for _, address := range []string{externalA, externalB} {
			if got := request(client("shop.example", ""), address, "shop.example", "/tenant", "", 200); got != oldFingerprint {
				t.Fatal("new handshake missed the disabled certificate's link move")
			}
		}
		// Both key algorithms travel through protected input and both actual
		// owners. ClientHello signature ceilings use the existing TLS callback
		// fixture; Go's public Client config cannot restrict TLS1.3 signatures.
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		var rsaLeaf *x509.Certificate
		rsaMaterial, rsaLeaf = rq7CertificateForKey(t, rsaKey, "shop.example")
		roots.AddCert(rsaLeaf)
		put("rq7-rsa", rsaMaterial, true)
		rsaFingerprint := sha256.Sum256(rsaLeaf.Raw)
		wait("both owners publish both host key algorithms", func() bool {
			for _, item := range []app{apps[0], apps[2]} {
				ecdsaFound, rsaFound := false, false
				for _, cert := range page(item, "mappings").Runtime.Certificates {
					ecdsaFound = ecdsaFound || cert.Fingerprint == oldFingerprint
					rsaFound = rsaFound || cert.Fingerprint == rsaFingerprint
				}
				if !ecdsaFound || !rsaFound {
					return false
				}
			}
			return true
		})
		for _, address := range []string{externalA, externalB} {
			if got := request(client("shop.example", ""), address, "shop.example", "/tenant", "", 200); got != oldFingerprint {
				t.Fatal("modern client did not prefer ECDSA")
			}
		}
	}) && rootTest.Failed() {
		return
	}
	if !phase("RQ7-S3-current-authority-and-public-key-nondisclosure", func() {
		if len(rsaMaterial.Key) == 0 {
			t.Fatal("S3 authority verification requires the S3 rotation/key preparation in the same fixture")
		}
		rq7ExerciseUserAuthority(t, ctx, root, user, peer, session, p, read, change, shop, provider)
		// Inspect the same actual public paths for plaintext key leakage.
		encoded, err := state.Encode(read().State)
		if err != nil {
			t.Fatal(err)
		}
		publicBytes := bytes.Join([][]byte{encoded, call(true, nil, "certificate", "list"), call(true, nil, "certificate", "show", "shop.example"), call(true, nil, "ingress", "inspect", deployment.ResourceKey("ingress", "tenant", "rq7-shop", "http"), "--tenant", "tenant")}, nil)
		for _, material := range []certstore.Material{shop, next, internal, rsaMaterial} {
			if bytes.Contains(publicBytes, material.Key) || bytes.Contains(publicBytes, []byte(base64.StdEncoding.EncodeToString(material.Key))) {
				t.Fatal("certificate private key entered shared/public state")
			}
		}
	}) && rootTest.Failed() {
		return
	}
	phase("RQ7-S4-mapping-ownership-paging-and-host-isolation", func() {
		for _, mode := range []string{"collision", "unassigned"} {
			raw, err := os.ReadFile(files["rq7-shop"])
			if err != nil {
				t.Fatal(err)
			}
			input, err := deployment.ParseApp(raw)
			if err != nil {
				t.Fatal(err)
			}
			input.Name = "rq7-" + mode
			input.Sfc.Ingress.Routes[0].Balance = nil
			if mode == "unassigned" {
				for i := range input.Sfc.Ingress.Routes {
					input.Sfc.Ingress.Routes[i].Host = "unassigned.example"
				}
			}
			raw, err = yaml.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = user.StreamAppPlan(ctx, peer, session, "tenant", control.AppPlanRequest{Document: raw}); err == nil {
				t.Fatal("invalid shared host plan accepted", mode)
			}
		}
		for _, item := range apps {
			row := page(item, "mappings")
			owner := a.Identity.Public
			if item.node == "node-b" {
				owner = b.Identity.Public
			}
			if !row.Ready || row.Owner != owner || len(row.Runtime.Listeners) != 2 || len(row.Runtime.Backends) == 0 {
				t.Fatal("mapping lost original native owner/listener/backend", row)
			}
		}
		for after, count := "", 0; ; {
			// Next is omitted on the last page. Decode into a fresh response so
			// the preceding cursor cannot survive json.Unmarshal's merge behavior.
			var clusterPage control.IngressPage
			args := []string{"ingress", "list", "--cluster-scope"}
			if after != "" {
				args = append(args, "--after", after)
			}
			if err := json.Unmarshal(call(true, nil, args...), &clusterPage); err != nil {
				t.Fatal(err)
			}
			count += len(clusterPage.Mappings)
			if count > len(apps) || clusterPage.Next != "" && (len(clusterPage.Mappings) == 0 || clusterPage.Next <= after) {
				t.Fatal("ingress page repeated or exceeded the original mapping set")
			}
			if clusterPage.Next == "" {
				if count != 3 {
					t.Fatal("three actual ingress mappings were not paged", count)
				}
				break
			}
			after = clusterPage.Next
		}
	})
	if ctx.Err() != nil {
		return
	}
	// The mapping probe is read-only. Node-a block tests depend on their own
	// transitions, while the original node-b reopen remains independent of them.
	rq7ExerciseBlocks(t, ctx, a, b, root, user, peer, session, p, read, change, wait, call, writeJSON, apps[0].tenant, apps[0].name, externalA, internalA, shopClient, metricsClient, localClient, request, runHere)
	if ctx.Err() != nil {
		return
	}
	if !phase("RQ7-S5-original-owner-reopen-and-block-recovery", func() {
		rq7ReopenBlockedOwner(t, ctx, b, user, peer, session, wait, call, writeJSON, request, client("shop.example", ""), externalB, rootTest)
	}) {
		return
	}
	phase("RQ7-S5-original-app-down-and-retirement", retireApps)

}

func rq7IngressDocument(t *testing.T, image, tenant, app, node, network, host string, pool netip.Prefix) []byte {
	t.Helper()
	document := fmt.Sprintf(`name: %s
x-sfc:
 ingress:
  - {id: root, node: %[2]s, host: %[3]s, service: web, port: 8080, health: /readyz, gateway: external}
  - {id: root-local, node: %[2]s, host: %[3]s, service: web, port: 8080, health: /readyz, gateway: local}
services:
 web:
  image: %s
  cpus: 0.1
  mem_limit: 16m
  environment: {SFC_READINESS_FIXTURE: "1", SFC_TENANT_FIXTURE: %s}
  tmpfs: ["/data:size=4m,uid=10001,gid=10001,mode=0700"]
  healthcheck: {test: [CMD, /backend, --probe], interval: 1s, timeout: 1s, retries: 2}
  networks: {app: {ipv4_address: %s}}
  x-sfc: {node: %s, ready: {http: /readyz, port: 8080}}
networks:
 app: {external: true, name: %s}
`, app, node, host, image, tenant, pool.Addr().Next().Next(), node, network)
	input, err := deployment.ParseApp([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	if app == "rq7-shop" {
		web := input.Services["web"]
		web.Sfc.Node, web.Sfc.Nodes, web.Sfc.PerNode = "", []string{node}, 2
		web.Networks = map[string]deployment.Attachment{"app": {}}
		input.Services["web"] = web
		admin := web
		admin.Sfc.Nodes, admin.Sfc.PerNode, admin.Sfc.Node = nil, 0, node
		admin.Networks = map[string]deployment.Attachment{"app": {IPv4: pool.Addr().Next().Next().Next().Next().Next().Next().String()}}
		input.Services["admin"] = admin
		task := deployment.ResourceKey("task", tenant, app, (deployment.TaskInstance{Service: "web", Node: node, Ordinal: 2}).ResourceID())
		hash := sha256.Sum256([]byte(task))
		input.Sfc.Ingress.Routes[0].Balance = &ingress.Balance{Method: "hash", Key: "cookie:session", Groups: map[string]ingress.BackendGroup{"canary": {Backends: []string{"root/task-" + hex.EncodeToString(hash[:])}}}, Match: []ingress.BalanceCondition{{ID: "canary", Group: "canary", Headers: map[string]ingress.ValueMatch{"X-Canary": {Equal: rq7String("1")}}}}}
		input.Sfc.Ingress.Routes = append(input.Sfc.Ingress.Routes, deployment.IngressRouteDeclaration{ID: "admin", Host: host, Prefix: "/admin", Service: "admin", Port: 8080, HealthPath: "/readyz", Gateway: "both"})
	}
	if app == "rq7-internal" {
		input.Sfc.Ingress.Routes = append(input.Sfc.Ingress.Routes, deployment.IngressRouteDeclaration{ID: "grafana", Host: "grafana.internal", Prefix: "/", Service: "web", Port: 8080, HealthPath: "/readyz", Gateway: "local"})
	}
	raw, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func rq7String(value string) *string { return &value }

func rq7DamageWrappedCertificate(t *testing.T, r *Runtime, version certstore.Certificate) func() {
	t.Helper()
	bucket := []byte("certificate-native-2")
	digest := version.Digest()
	key := []byte("key/" + hex.EncodeToString(digest[:]))
	var original []byte
	if err := r.reports.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("missing original certificate bucket")
		}
		original = bytes.Clone(b.Get(key))
		var record map[string]json.RawMessage
		if err := json.Unmarshal(original, &record); err != nil {
			return err
		}
		var wrapped []byte
		if err := json.Unmarshal(record["Key"], &wrapped); err != nil || len(wrapped) == 0 {
			return fmt.Errorf("missing wrapped owner key")
		}
		wrapped[len(wrapped)-1] ^= 1
		record["Key"], _ = json.Marshal(wrapped)
		clear(wrapped)
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return b.Put(key, raw)
	}); err != nil {
		t.Fatal(err)
	}
	restored := false
	return func() {
		if restored {
			return
		}
		if err := r.reports.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put(key, original) }); err != nil {
			t.Error("restore exact original wrapped certificate record", err)
			return
		}
		restored = true
		clear(original)
	}
}

func rq7ExerciseBlocks(t *testing.T, ctx context.Context, a, b *Runtime, root string, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), call func(bool, []*os.File, ...string) []byte, writeJSON func(string, any) string, tenant, app, external, local string, shopClient, metricsClient, localClient *http.Client, request func(*http.Client, string, string, string, string, int) [32]byte, run func(string, func(*testing.T)) bool) bool {
	t.Helper()
	phase := func(name string, action func()) bool {
		return run(name, func(current *testing.T) {
			previous := t
			t = current
			defer func() { t = previous }()
			action()
		})
	}
	key := deployment.ResourceKey("ingress", tenant, app, "http")
	original := read().State.Object(key)
	row := func(part string) control.IngressMapping {
		t.Helper()
		page, err := user.Ingresses(ctx, peer, session, control.IngressQuery{Tenant: tenant, App: app, Key: key, Part: part})
		if err != nil || len(page.Mappings) != 1 || page.Mappings[0].Runtime == nil {
			t.Fatal("real ingress read", err)
		}
		return page.Mappings[0]
	}
	counts := func() map[string]uint64 {
		out := map[string]uint64{}
		for _, metric := range row("metrics").Runtime.Metrics.Backends {
			out[metric.ID] = metric.Requests
		}
		return out
	}
	settleRequests := func(want int, active <-chan struct{}) {
		t.Helper()
		wait("original ingress request lease return", func() bool {
			if active != nil {
				select {
				case <-active:
					t.Fatal("slow original request ended before least-request comparison")
				default:
				}
			}
			actual, err := a.ingress.Observe(key)
			if err != nil {
				t.Fatal("original owner request lease observation", err)
			}
			return actual.Requests == want
		})
	}
	waitClear := func(id string) {
		t.Helper()
		book, err := p.IngressManagement(read().State)
		if err != nil {
			t.Fatal("original unblock management revision", err)
		}
		wait("original block cleared on actual owner: "+id, func() bool {
			actual := row("mappings").Runtime
			// The public mapping filters out removed desired IDs before the
			// asynchronous owner necessarily installs the unblock revision.
			if actual.BlockRevision < book.Revision {
				return false
			}
			for _, applied := range actual.Blocks {
				if applied.ID == id {
					return false
				}
			}
			return true
		})
	}
	if !phase("RQ7-S4-route-and-host-block-isolation", func() {
		block := ingress.Block{ID: "rq7-route", Scope: "route", Tenant: tenant, App: app, Node: "node-a", Key: key, Route: "admin", Host: "shop.example", Prefix: "/admin", Gateway: "both", Response: "503", ExpiresAt: uint64(time.Now().Add(2 * time.Minute).Unix()), Reason: "owned ingress fixture"}
		bad := block
		bad.ID, bad.Prefix = "rq7-arbitrary-subpath", "/admin/login"
		call(false, nil, "ingress", "block", writeJSON(bad.ID, bad), "--tenant", tenant, "--request-id", bad.ID)
		call(true, nil, "ingress", "block", writeJSON(block.ID, block), "--tenant", tenant, "--request-id", block.ID)
		wait("route block actual owner applied within original timeout", func() bool {
			for _, applied := range row("mappings").Runtime.Blocks {
				if applied.ID == block.ID && applied.Applied {
					return true
				}
			}
			return false
		})
		request(shopClient, external, "shop.example", "/admin/login?secret=rq7-query-never-observe", "rq7-cookie-never-observe", 503)
		request(shopClient, external, "shop.example", "/tenant", "same-user", 200)
		request(metricsClient, external, "metrics.example", "/tenant", "", 200)
		if current := read().State.Object(key); current != original {
			t.Fatal("emergency block changed app generation/revision")
		}
		call(true, nil, "ingress", "extend", block.ID, "--tenant", tenant, "--expires-at", fmt.Sprint(block.ExpiresAt+120), "--request-id", "rq7-route-extend")
		call(true, nil, "ingress", "unblock", block.ID, "--tenant", tenant, "--request-id", "rq7-route-clear")
		waitClear(block.ID)
		request(shopClient, external, "shop.example", "/admin/login", "", 200)
		host := ingress.Block{ID: "rq7-host", Scope: "host", Tenant: tenant, Node: "node-a", Host: "shop.example", Response: "403"}
		call(true, nil, "ingress", "block", writeJSON(host.ID, host), "--tenant", tenant, "--request-id", host.ID)
		wait("host block applied", func() bool {
			for _, applied := range row("mappings").Runtime.Blocks {
				if applied.ID == host.ID && applied.Applied {
					return true
				}
			}
			return false
		})
		request(shopClient, external, "shop.example", "/admin/login", "", 403)
		request(shopClient, external, "shop.example", "/tenant", "", 403)
		request(metricsClient, external, "metrics.example", "/tenant", "", 200)
		call(true, nil, "ingress", "unblock", host.ID, "--tenant", tenant, "--request-id", "rq7-host-clear")
		waitClear(host.ID)
	}) {
		return false
	}
	if !phase("RQ7-S5-sticky-canary-and-backend-distribution", func() {
		// Keep the original backend tasks while changing only the balance policy.
		before := row("mappings")
		var blockedBackend string
		for _, service := range before.Spec.Services {
			if service.ID == "root" && len(service.Backends) == 2 {
				blockedBackend = service.Backends[0].ID
			}
		}
		if blockedBackend == "" {
			t.Fatal("replicated service did not expose both native Tasks")
		}
		stickyBefore := counts()
		for range 20 {
			request(shopClient, external, "shop.example", "/tenant", "sticky-client", 200)
		}
		stickyAfter := counts()
		changed := 0
		for id, count := range stickyAfter {
			if strings.HasPrefix(id, "root/") && count > stickyBefore[id] {
				changed++
				if count-stickyBefore[id] != 20 {
					t.Fatal("same cookie was split across native backends")
				}
			}
		}
		if changed != 1 {
			t.Fatal("hash did not retain the same native backend")
		}
		canaryBefore := counts()
		for range 20 {
			request(shopClient, external, "shop.example", "/tenant", "canary-input", 200)
		}
		var canary string
		for _, route := range before.Spec.Routes {
			if route.ID == "root" && route.Balance != nil {
				canary = route.Balance.Groups["canary"].Backends[0]
			}
		}
		canaryAfter := counts()
		if canary == "" || canaryAfter[canary]-canaryBefore[canary] != 20 {
			t.Fatal("canary header missed its declared native group")
		}
		backendBlock := ingress.Block{ID: "rq7-backend", Scope: "backend", Tenant: tenant, App: app, Node: "node-a", Key: key, Service: "root", Backend: blockedBackend, Response: "503"}
		call(true, nil, "ingress", "block", writeJSON(backendBlock.ID, backendBlock), "--tenant", tenant, "--request-id", backendBlock.ID)
		wait("backend block actual application", func() bool {
			for _, application := range row("mappings").Runtime.Blocks {
				if application.ID == backendBlock.ID && application.Applied {
					return true
				}
			}
			return false
		})
		priorCounts := counts()
		for range 20 {
			request(shopClient, external, "shop.example", "/tenant", "same-user", 200)
		}
		nextCounts := counts()
		if nextCounts[blockedBackend] != priorCounts[blockedBackend] {
			t.Fatal("blocked native backend received new requests")
		}
		var delivered uint64
		for id, count := range nextCounts {
			if id != blockedBackend {
				delivered += count - priorCounts[id]
			}
		}
		if delivered < 20 {
			t.Fatal("remaining native backend did not receive blocked share")
		}
		call(true, nil, "ingress", "unblock", backendBlock.ID, "--tenant", tenant, "--request-id", "rq7-backend-clear")
		waitClear(backendBlock.ID)
	}) {
		return false
	}
	if !phase("RQ7-S5-source-cut-and-original-request-termination", func() {
		// The existing backend's /slow handler waits for cancellation. Source
		// CutExisting must join that real request, not only update a policy record.
		slowCtx, stopSlow := context.WithCancel(ctx)
		slowComplete := make(chan struct{})
		defer func() { stopSlow(); <-slowComplete }()
		priorCanceled := row("metrics").Runtime.Metrics.Instance.Failures["request-canceled"]
		slowDone := make(chan error, 1)
		slowClient := *shopClient
		slowClient.Timeout = 0 // product's fixed10s request budget still bounds this input
		go func() {
			defer close(slowComplete)
			req, err := http.NewRequestWithContext(slowCtx, http.MethodGet, "https://"+external+"/slow", nil)
			if err == nil {
				req.Host = "shop.example"
				var response *http.Response
				response, err = slowClient.Do(req)
				if response != nil {
					_, readErr := io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if response.StatusCode < 400 && readErr == nil {
						err = fmt.Errorf("slow request completed without cut")
					}
				}
			}
			slowDone <- err
		}()
		wait("original slow proxy request is active", func() bool { return row("mappings").Runtime.Requests > 0 })
		sourceBlock := ingress.Block{ID: "rq7-source", Scope: "source", Tenant: tenant, Apps: []string{app}, Node: "node-a", Source: "127.0.0.1/32", Gateway: "external", CutExisting: true, Response: "403"}
		call(true, nil, "ingress", "block", writeJSON(sourceBlock.ID, sourceBlock), "--tenant", tenant, "--request-id", sourceBlock.ID)
		wait("source block actual application", func() bool {
			for _, application := range row("mappings").Runtime.Blocks {
				if application.ID == sourceBlock.ID && application.Applied {
					return true
				}
			}
			return false
		})
		select {
		case <-slowDone:
		case <-ctx.Done():
			t.Fatal("source cut did not terminate original request", ctx.Err())
		}
		wait("actual proxy request was canceled by the cut", func() bool {
			return row("metrics").Runtime.Metrics.Instance.Failures["request-canceled"] > priorCanceled
		})
		request(shopClient, external, "shop.example", "/tenant", "", 403)
		request(metricsClient, external, "metrics.example", "/tenant", "", 200)
		request(localClient, local, "grafana.internal", "/tenant", "", 200)
		call(true, nil, "ingress", "unblock", sourceBlock.ID, "--tenant", tenant, "--request-id", "rq7-source-clear")
		waitClear(sourceBlock.ID)
	}) {
		return false
	}
	if !phase("RQ7-S5-least-request-policy-and-native-lease", func() {
		// The policy update needs the current original backend identities, not
		// the preceding sticky/canary requests. Capture its own exact baseline
		// so a passed independent distribution set can remain unselected.
		before := row("mappings")
		file := filepath.Join(root, app+".yaml")
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		input, err := deployment.ParseApp(raw)
		if err != nil {
			t.Fatal(err)
		}
		input.Sfc.Ingress.Routes[0].Balance.Method = "least-request"
		input.Sfc.Ingress.Routes[0].Balance.Key = ""
		raw, err = yaml.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		call(true, nil, "compose", "up", "--tenant", tenant, "-f", file, "--operation", "rq7-balance-only", "--no-input")
		call(true, nil, "compose", "wait", "--tenant", tenant, "-p", app, "--operation", "rq7-balance-only", "--condition", "healthy")
		after := row("mappings")
		if after.Generation != before.Generation || len(after.Runtime.Backends) != len(before.Runtime.Backends) {
			t.Fatal("balance-only update replaced original listeners/backends")
		}
		for i, b := range before.Runtime.Backends {
			if b.Task != after.Runtime.Backends[i].Task || b.Generation != after.Runtime.Backends[i].Generation {
				t.Fatal("balance update replaced a Task")
			}
		}
		leastCtx, stopLeast := context.WithCancel(ctx)
		leastDone := make(chan struct{})
		var leastFailure error
		var leastStatus int
		leastClient := *shopClient
		leastClient.Timeout = 0
		go func() {
			defer close(leastDone)
			req, err := http.NewRequestWithContext(leastCtx, http.MethodGet, "https://"+external+"/slow", nil)
			if err == nil {
				req.Host = "shop.example"
				req.Header.Set("Cookie", "session=same-user")
				response, err := leastClient.Do(req)
				leastFailure = err
				if err == nil {
					leastStatus = response.StatusCode
					_, leastFailure = io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
			} else {
				leastFailure = err
			}
		}()
		defer func() { stopLeast(); <-leastDone }()
		var slowBackend string
		wait("least-request observes original slow native lease", func() bool {
			select {
			case <-leastDone:
				t.Fatal("slow original request ended before native entry", leastStatus, leastFailure)
			default:
			}
			for _, metric := range row("metrics").Runtime.Metrics.Backends {
				if strings.HasPrefix(metric.ID, "root/") && metric.OpenConnections > 0 {
					slowBackend = metric.ID
					return true
				}
			}
			return false
		})
		leastBefore := counts()
		for range 20 {
			request(shopClient, external, "shop.example", "/tenant", "same-user", 200)
			settleRequests(1, leastDone)
		}
		if leastAfter := counts(); leastAfter[slowBackend] != leastBefore[slowBackend] {
			t.Fatal("least-request kept assigning work to the slow native backend")
		}
		stopLeast()
		<-leastDone
		settleRequests(0, nil)
	}) {
		return false
	}
	return phase("RQ7-S5-metrics-privacy-gateway-and-health-events", func() {
		after := row("mappings")
		page, err := user.Ingresses(ctx, peer, session, control.IngressQuery{Node: "node-a", Part: "mappings"})
		if err != nil || len(page.Nodes) != 1 || page.Nodes[0].Instances != 2 || page.Nodes[0].Listeners != 2 {
			t.Fatal("two apps did not share the same two node listener addresses", page.Nodes, err)
		}
		baseline := row("metrics").Runtime.Metrics.Instance
		// Missing hash keys use round-robin; least-request rotates equal loads.
		// Exercise both settled replicas and admin's own route explicitly.
		request(shopClient, external, "shop.example", "/tenant", "", 200)
		settleRequests(0, nil)
		request(shopClient, external, "shop.example", "/tenant", "", 200)
		settleRequests(0, nil)
		request(shopClient, external, "shop.example", "/admin/login", "", 200)
		settleRequests(0, nil)
		// Node-wide external denial leaves the local gateway and the other owner up.
		gateway := ingress.Block{ID: "rq7-node-external", Scope: "node", Node: "node-a", Gateway: "external", Response: "503"}
		call(true, nil, "ingress", "block", writeJSON(gateway.ID, gateway), "--cluster-scope", "--request-id", gateway.ID)
		wait("external node block applied", func() bool {
			for _, applied := range row("mappings").Runtime.Blocks {
				if applied.ID == gateway.ID && applied.Applied {
					return true
				}
			}
			return false
		})
		request(shopClient, external, "shop.example", "/tenant?secret=rq7-query-never-observe", "rq7-cookie-never-observe", 503)
		request(localClient, local, "grafana.internal", "/tenant", "", 200)
		call(true, nil, "ingress", "unblock", gateway.ID, "--cluster-scope", "--request-id", "rq7-node-external-clear")
		waitClear(gateway.ID)
		// Use this set's own blocked request/error rather than requiring a
		// successful source-cut set to be replayed for metric preparation.
		metrics := row("metrics").Runtime.Metrics
		if len(metrics.Backends) < 3 || len(metrics.Routes) < 2 || metrics.Instance.Requests < baseline.Requests+4 || metrics.Instance.Blocked <= baseline.Blocked {
			t.Fatal("actual request distribution/route/block metrics missing", metrics)
		}
		errorsPage := row("errors")
		encoded, _ := json.Marshal(errorsPage)
		for _, private := range []string{"rq7-query-never-observe", "rq7-cookie-never-observe", "rq7-never-observe", "Authorization", "Cookie"} {
			if bytes.Contains(encoded, []byte(private)) {
				t.Fatal("request private data leaked in error samples", private)
			}
		}
		if len(errorsPage.Runtime.Metrics.Errors) == 0 || errorsPage.Runtime.Metrics.Errors[0].Source != "127.0.0.0/24" {
			t.Fatal("source address was not masked")
		}
		// Health changes use the existing backend fixture endpoint, never forged
		// observations. The existing health loop must emit a real failure event.
		emptyBefore, err := user.EventsPage(ctx, peer, session, eventlog.Query{Tenant: tenant, App: app, Kind: "ingress-backends-empty", Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, backend := range after.Runtime.Backends {
			if !strings.Contains(backend.ID, "root/") {
				continue
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(backend.Address, fmt.Sprint(backend.Port))+"/readiness-state?ready=0", nil)
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
		}
		wait("native health emits route backends-empty", func() bool {
			page, err := user.EventsPage(ctx, peer, session, eventlog.Query{Tenant: tenant, App: app, Kind: "ingress-backends-empty", After: emptyBefore.Cursor, Limit: 100})
			return err == nil && len(page.Items) > 0
		})
		restoredBefore, err := user.EventsPage(ctx, peer, session, eventlog.Query{Tenant: tenant, App: app, Kind: "ingress-backends-restored", Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, backend := range after.Runtime.Backends {
			if !strings.Contains(backend.ID, "root/") {
				continue
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(backend.Address, fmt.Sprint(backend.Port))+"/readiness-state?ready=1", nil)
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
		}
		wait("native health emits route backends-restored", func() bool {
			page, err := user.EventsPage(ctx, peer, session, eventlog.Query{Tenant: tenant, App: app, Kind: "ingress-backends-restored", After: restoredBefore.Cursor, Limit: 100})
			return err == nil && len(page.Items) > 0
		})
	})

}

func rq7ExerciseUserAuthority(t *testing.T, ctx context.Context, root string, admin userauth.Client, peer sfcp.Peer, adminSession access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), material certstore.Material, provider sfcp.Peer) {
	t.Helper()
	for _, name := range []string{"rq7-uploader", "rq7-manager", "rq7-second-manager"} {
		key, err := identity.Create(filepath.Join(root, name+"-key"))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key.Private)
		credential := access.Credential{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}
		if name == "rq7-uploader" {
			credential.Operations = []string{"put-certificate"}
		}
		change(name, "put-user", 0, access.User{ID: name, Username: name, Enabled: true, SystemAdmin: name == "rq7-uploader", Credentials: []access.Credential{credential}})
		managerTenant := "tenant"
		if name == "rq7-second-manager" {
			managerTenant = "second"
		}
		if name != "rq7-uploader" {
			change(name+"-membership", "set-membership", 0, access.Membership{Tenant: managerTenant, User: name, Role: access.Manager, Enabled: true})
		}
		self, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(self.Private)
		mesh, err := sfcp.NewTransport(self, admin.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) {
			if key == peer.Key {
				return peer, true
			}
			return provider, key == provider.Key
		})
		if err != nil {
			t.Fatal(err)
		}
		defer mesh.Close()
		user := userauth.Client{Mesh: mesh, Self: self, Cluster: admin.Cluster, Peers: []sfcp.Peer{peer, provider}}
		session, err := user.Login(ctx, peer, name, key.Private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = user.QueryCertificates(ctx, peer, session, control.CertificateQuery{}); err == nil {
			t.Fatal("restricted account read cluster certificate store")
		}
		if name != "rq7-uploader" {
			for after := ""; ; {
				page, err := user.Ingresses(ctx, peer, session, control.IngressQuery{Node: "node-a", After: after})
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range page.Mappings {
					if row.Tenant != managerTenant {
						t.Fatal("node-only query disclosed another tenant")
					}
				}
				for _, node := range page.Nodes {
					for _, gateway := range node.Gateways {
						if gateway.Unmatched != 0 || gateway.SourceRejected != 0 {
							t.Fatal("tenant query disclosed global gateway counts")
						}
						for _, listener := range gateway.Listeners {
							for _, host := range listener.Hosts {
								if host.Tenant != managerTenant {
									t.Fatal("shared listener disclosed another tenant's route")
								}
							}
						}
					}
				}
				if page.Next == "" {
					break
				}
				after = page.Next
			}
			if _, err = user.WriteCertificate(ctx, provider, session, userauth.CertificateInput{Request: "rq7-manager-put", Chain: material.Chain, Key: material.Key}); err == nil {
				t.Fatal("tenant manager wrote a cluster certificate")
			}
			if name == "rq7-second-manager" {
				raw, err := os.ReadFile(filepath.Join(root, "rq7-internal.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				input, err := deployment.ParseApp(raw)
				if err != nil {
					t.Fatal(err)
				}
				input.Name = "rq7-cross-collision"
				input.Sfc.Ingress.Routes[0].Host = "shop.example"
				raw, err = yaml.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = user.StreamAppPlan(ctx, peer, session, "second", control.AppPlanRequest{Document: raw}); err == nil || strings.Contains(err.Error(), "rq7-shop") {
					t.Fatal("cross-tenant collision admitted or leaked another app", err)
				}
			}
			users, err := p.Catalog(read().State)
			if err != nil {
				t.Fatal(err)
			}
			membership, ok := users.Membership(managerTenant, name)
			if !ok {
				t.Fatal("original tenant membership missing")
			}
			change(name+"-revoke", "set-membership", membership.Revision, access.Membership{Tenant: managerTenant, User: name, Role: access.Manager, Enabled: false})
			if _, err = user.Ingresses(ctx, peer, session, control.IngressQuery{Tenant: managerTenant, Node: "node-a"}); err == nil {
				t.Fatal("revoked tenant manager retained ingress observation access")
			}
			continue
		}
		// The shared material is already stored; a stored ID is refused.
		fresh, _ := rq7Certificate(t, "shop.example")
		v, err := user.WriteCertificate(ctx, provider, session, userauth.CertificateInput{Request: "rq7-delegated-put", Chain: fresh.Chain, Key: fresh.Key})
		fresh.Clear()
		if err != nil {
			t.Fatal("put-only delegated protected input", err)
		}
		raw, err := control.ChangeBytes("put-certificate", name, 0, control.CertificatePut{Certificate: v})
		if err != nil {
			t.Fatal(err)
		}
		var ch control.Change
		if json.Unmarshal(raw, &ch) != nil {
			t.Fatal("typed certificate publication")
		}
		op, err := user.Prepare(ctx, peer, session, v.Request, ch)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := user.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal("put-only delegated publication", reply, err)
		}
		users, err := p.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := users.User(name)
		expected := u.Revision
		u.Enabled = false
		u.Revision = 0
		change(name+"-revoke", "put-user", expected, u)
		if _, err = user.WriteCertificate(ctx, provider, session, userauth.CertificateInput{Request: v.Request, Recover: true}); err == nil {
			t.Fatal("revoked uploader recovered protected receipt")
		}
	}
}

func rq7ReopenBlockedOwner(t *testing.T, ctx context.Context, owner *Runtime, user userauth.Client, peer sfcp.Peer, session access.Session, wait func(string, func() bool), call func(bool, []*os.File, ...string) []byte, writeJSON func(string, any) string, request func(*http.Client, string, string, string, string, int) [32]byte, client *http.Client, address string, lifetime *testing.T) {
	t.Helper()
	key := deployment.ResourceKey("ingress", "tenant", "rq7-remote", "http")
	task := deployment.ResourceKey("task", "tenant", "rq7-remote", "web")
	before, err := owner.workload.Status(ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	cfg := owner.installation.config
	if err = owner.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	block := ingress.Block{ID: "rq7-offline-owner", Scope: "instance", Tenant: "tenant", App: "rq7-remote", Node: "node-b", Key: key, Response: "503"}
	call(true, nil, "ingress", "block", writeJSON(block.ID, block), "--tenant", "tenant", "--request-id", block.ID)
	page, err := user.Ingresses(ctx, peer, session, control.IngressQuery{Tenant: "tenant", Key: key, Node: "node-b"})
	if err != nil || len(page.Mappings) != 1 || page.Mappings[0].Error != "NODE_UNREACHABLE" {
		t.Fatal("offline owner was reported applied", page, err)
	}
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Reopened owner serves the following original down/retirement stage too.
	lifetime.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			lifetime.Error(err)
		}
	})
	if _, err = reopened.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	wait("reopened original owner applies committed offline block", func() bool {
		page, err := user.Ingresses(ctx, peer, session, control.IngressQuery{Tenant: "tenant", Key: key, Node: "node-b"})
		if err != nil || len(page.Mappings) != 1 || page.Mappings[0].Runtime == nil {
			return false
		}
		for _, application := range page.Mappings[0].Runtime.Blocks {
			if application.ID == block.ID && application.Applied {
				return true
			}
		}
		return false
	})
	request(client, address, "shop.example", "/tenant", "", 503)
	after, err := reopened.workload.Status(ctx, task)
	if err != nil || after.NativeID != before.NativeID {
		t.Fatal("block/reopen replaced the original container", err)
	}
	call(true, nil, "ingress", "unblock", block.ID, "--tenant", "tenant", "--request-id", "rq7-offline-clear")
	wait("reopened owner clears the original block", func() bool {
		for _, application := range reopened.ingress.BlockApplications() {
			if application.ID == block.ID {
				return false
			}
		}
		return true
	})
	request(client, address, "shop.example", "/tenant", "", 200)
}
