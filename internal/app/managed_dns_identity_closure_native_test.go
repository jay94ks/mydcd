// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/tests/registryfixture"
	"github.com/miekg/dns"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// The existing DNS private-Engine/TUN/CLI fixture and 240-second envelope own
// rollback. This focused remainder does not rerun the route/app fault matrix.
func TestRQ12CurrentIdentityClosesOriginalManagedDNS(t *testing.T) {
	testManagedTwoNodeFixture(t, false, managedTwoNodeOptions{managedDNSRuntime: true, identityDNSClosure: true})
}

func testCurrentIdentityDNSClosure(t *testing.T, ctx context.Context, a *Runtime, root, products string, configs, sockets [2]string, manifest string, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), run func(int, []string, ...string) ([]byte, error)) {
	t.Helper()
	const name, appName, address, gateway = "dns-identity-close", "dns-original-client", "198.19.86.18", "198.19.86.17"
	p := a.controlPolicy
	resources := func() control.Resources {
		t.Helper()
		r, err := p.Resources(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	backend := os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if !filepath.IsAbs(backend) {
		t.Fatal("prebuilt original DNS client backend required")
	}
	registry := registryfixture.OpenPreparedAt(t, backend, container.Config{Cmd: []string{"/backend"}, Env: []string{"SFC_DNS_FIXTURE=1"}, User: "10001:10001", Labels: map[string]string{"org.sfc.test.owner": os.Getenv("SFC_KERNEL_TEST_OWNER")}}, "192.0.2.1:0")
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	change("dns-identity/trust", "set-trust", tenant.Revision, control.TrustChange{Tenant: "tenant", Add: []access.TrustRule{access.TrustRule{Registry: registry.Registry, Repository: "fixture"}}})
	public := sqlPublicFixture{Images: map[string]string{registry.Reference: registry.ConfigDigest}}
	var originalOwner [32]byte
	for n, path := range configs {
		cfg, err := loadTestNode(path)
		if err != nil {
			t.Fatal(err)
		}
		key, err := identity.Load(cfg.Node.IdentityDir)
		if err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			originalOwner = key.Public
		}
		c, err := engine.Open(ctx, "unix://"+sockets[n], engine.Owner(p.Cluster, key.Public))
		clear(key.Private)
		if err != nil {
			t.Fatal(err)
		}
		info, err := c.API.Info(ctx, client.InfoOptions{})
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
		public.EngineIDs[n] = info.Info.ID
	}
	if public.EngineIDs[0] == "" || public.EngineIDs[0] == public.EngineIDs[1] {
		t.Fatal("distinct original private Engines required")
	}
	raw, _ := json.Marshal(public)
	if err := os.WriteFile(filepath.Join(root, "dns-fixture.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	definition := tenancy.TUNDefinition{Tenant: "tenant", Name: name, GatewayMode: network.ManagedGatewayMode, Members: []tenancy.TUNNode{{Node: "node-b", Pools: []tenancy.Subnet{{ID: "v4", Prefix: netip.MustParsePrefix("198.19.86.16/28"), Gateway: netip.MustParseAddr(gateway), MTU: 1280}}}}}
	change("dns-identity/network", "create-tun-network", resources().Networks.Revision(), definition)
	policy := services.ManagedDNSDefinition{Schema: 1, Tenant: "tenant", Network: name, Policy: services.ManagedDNSPolicy{Enabled: true, Zone: name + ".sfc.test.", TTL: 30, NegativeTTL: 5, Transports: []string{"udp", "tcp"}, Upstreams: []netip.AddrPort{}, MaxQueries: 8, MaxCacheEntries: 8, MaxResponseBytes: 4096, MaxConnections: 4, RequestTimeoutMS: 1000}}
	policyKey := services.ManagedDNSKey("tenant", name)
	change("dns-identity/enable", "configure-network-dns", 0, policy)
	profile, home := filepath.Join(root, "dns-identity-client.yaml"), filepath.Join(root, "dns-identity-home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%s', endpoint: '192.0.2.1:44101', voter: true}\n", p.Cluster, a.Identity.Actor())), 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, filepath.Join(products, "sfc"), home, profile, args, nil)
		if err != nil {
			t.Fatal("focused DNS CLI", args, err, string(out), string(diagnostic))
		}
	}
	cli("wallet", "init")
	cli("login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin/key.pem"))
	path := filepath.Join(root, "dns-original-client-app.yaml")
	document := fmt.Sprintf("name: %s\nservices:\n client:\n  image: %s\n  command: [/backend]\n  environment: {SFC_DNS_FIXTURE: '1'}\n  user: '10001:10001'\n  cpus: 0.1\n  mem_limit: 16m\n  healthcheck: {test: [CMD, /backend, --tcp-probe, '127.0.0.1:8080'], interval: 1s, timeout: 2s, retries: 3}\n  networks: {lan: {ipv4_address: '%s'}}\n  x-sfc: {node: node-b}\nnetworks:\n lan: {external: true, name: %s}\n", appName, registry.Reference, address, name)
	if err := os.WriteFile(path, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	cli("compose", "up", "--tenant", "tenant", "--operation", "dns-original-up", "--file", path, "--no-input")
	observe := func(node, key string) (ModuleObservation, error) {
		var value ModuleObservation
		if node != "node-b" {
			return value, sfcp.ErrAdmission
		}
		peer, ok := a.resourcePeerForKey(ctx, originalOwner)
		if !ok || peer.ID != node {
			return value, sfcp.ErrAdmission
		}
		reply, err := cluster.CallManagement(ctx, a.Mesh, a.commandIdentity(), p.Cluster, peer, cluster.ManagementRequest{Method: "observe", Key: key, Latest: false})
		if err == nil {
			err = json.Unmarshal(reply.Data, &value)
		}
		return value, err
	}
	taskKey := deployment.ResourceKey("task", "tenant", appName, "client")
	wait("one original DNS client and one owner/pool socket are ready", func() bool {
		apps, err := p.Apps(read().State)
		execution, found := apps.Execution("tenant", appName)
		native, nativeErr := observe("node-b", taskKey)
		dns, dnsErr := observe("node-b", policyKey)
		return err == nil && found && execution.Status() == "Succeeded" && nativeErr == nil && native.Ready && native.NativeID != "" && dnsErr == nil && dns.Ready && dns.DNS != nil && !dns.DNS.Failed && dns.DNS.Sockets == 1
	})
	apps, err := p.Apps(read().State)
	authority, rows, known := apps.NetworkDNS(originalOwner)
	if err != nil || !known || len(rows) != 1 || rows[0].Managed == nil || rows[0].Managed.Node != "node-b" || rows[0].Source.Key != policyKey || rows[0].Config.TTL != 30 {
		t.Fatal("one exact original managed DNS scope required", err)
	}
	originalRow := rows[0]
	originalRef, found := authority.ReferenceConsumer(originalRow.Reference)
	if !found || originalRef.Closed != nil || originalRef.Local.Owner != originalOwner {
		t.Fatal("original live DNS lifetime missing")
	}
	originalNative, err := observe("node-b", taskKey)
	if err != nil {
		t.Fatal(err)
	}
	query := func(protocol string, kind uint16) {
		t.Helper()
		name := "client." + appName + "." + policy.Policy.Zone
		if kind == dns.TypeSOA {
			name = policy.Policy.Zone
		}
		question := new(dns.Msg)
		question.SetQuestion(name, kind)
		wire, err := question.Pack()
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(root, fmt.Sprintf("dns-identity-wire-%s-%d", protocol, question.Id))
		if err := os.WriteFile(file, wire, 0600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(file)
		values := url.Values{"server": {gateway + ":53"}, "transport": {protocol}, "timeout_ms": {"1000"}}
		raw, err := run(1, nil, "curl", "--noproxy", "*", "--silent", "--show-error", "--fail-with-body", "--max-time", "3", "-H", "Content-Type: application/dns-message", "--data-binary", "@"+file, "http://"+address+":8080/dns-query?"+values.Encode())
		answer := new(dns.Msg)
		if err != nil || answer.Unpack(raw) != nil || answer.Id != question.Id || !answer.Response || !answer.Authoritative || answer.Rcode != dns.RcodeSuccess || len(answer.Question) != 1 || answer.Question[0] != question.Question[0] || len(answer.Answer) != 1 {
			t.Fatal("actual original endpoint UDP/TCP DNS query", protocol, kind, err, string(raw))
		}
		switch kind {
		case dns.TypeA:
			record, ok := answer.Answer[0].(*dns.A)
			if !ok || record.A.String() != address || record.Hdr.Ttl != 30 {
				t.Fatal("original DNS address/TTL changed", answer)
			}
		case dns.TypeSOA:
			record, ok := answer.Answer[0].(*dns.SOA)
			if !ok || record.Hdr.Ttl != 30 || record.Serial != originalRow.Config.Serial {
				t.Fatal("original DNS SOA source/TTL changed", answer)
			}
		}
	}
	probe := func() {
		t.Helper()
		wait("current key observes original DNS/client native readiness", func() bool {
			value, err := observe("node-b", taskKey)
			dns, dnsErr := observe("node-b", policyKey)
			if err == nil && value.Ready && (value.NativeID != originalNative.NativeID || value.Journal.Applied != originalNative.Journal.Applied || value.Journal.LastID != originalNative.Journal.LastID) {
				t.Fatal("identity switch replaced original DNS client Task/native")
			}
			return err == nil && value.Ready && dnsErr == nil && dns.Ready && dns.DNS != nil && !dns.DNS.Failed && dns.DNS.Sockets == 1
		})
		apps, err := p.Apps(read().State)
		authority, rows, known := apps.NetworkDNS(originalOwner)
		ref, found := authority.ReferenceConsumer(originalRow.Reference)
		if err != nil || !known || len(rows) != 1 || !reflect.DeepEqual(rows[0], originalRow) || !found || !reflect.DeepEqual(ref, originalRef) {
			t.Fatal("identity switch replaced original DNS source/reference lifetime", err)
		}
		for _, protocol := range []string{"udp", "tcp"} {
			query(protocol, dns.TypeA)
			query(protocol, dns.TypeSOA)
		}
	}
	probe()
	prepareTrafficIdentityRotations(t, ctx, a, root, configs[1], manifest, read, change, wait)(probe)
	cli("compose", "down", "--tenant", "tenant", "-p", appName, "--operation", "dns-original-down")
	wait("original DNS client app is retired before policy disable", func() bool {
		apps, err := p.Apps(read().State)
		inventory, found := apps.Inventory("tenant", appName)
		summary, finished := inventory.Operation("dns-original-up")
		return err == nil && found && finished && inventory.Quiescent() && summary.Status == "Retired" && summary.CompletedAt != 0
	})
	view := read()
	sources, err := p.ManagedDNS(view.State)
	source, found := sources[policyKey]
	if err != nil || !found || !source.Definition.Policy.Enabled || source.Definition.Policy.TTL != 30 {
		t.Fatal("explicit disable lost original TTL30 policy", err)
	}
	source.Definition.Policy.Enabled = false
	change("dns-identity/disable", "configure-network-dns", view.State.Object(policyKey).Revision, source.Definition)
	var closed services.ReferenceConsumer
	wait("original TTL30 and exact signed current-key DNS closure", func() bool {
		apps, err := p.Apps(read().State)
		authority, rows, known := apps.NetworkDNS(originalOwner)
		if err != nil || !known || len(rows) != 1 || rows[0].Config.Enabled || rows[0].Config.TTL != 30 || rows[0].Reference != originalRow.Reference {
			return false
		}
		ref, found := authority.ReferenceConsumer(originalRow.Reference)
		if !found || ref.Closed == nil {
			return false
		}
		proof := ref.Closed
		if ref.ID != originalRef.ID || ref.Generation != originalRef.Generation || ref.Lifetime != originalRef.Lifetime || ref.Local != originalRef.Local || proof.Owner != originalOwner || proof.Consumer != originalRef.ID || proof.Generation != originalRef.Generation || proof.Lifetime != originalRef.Lifetime || proof.Target != ([32]byte{}) || proof.Native != appDNSNativeID(originalRow) || !proof.Fenced || !proof.Settled || !proof.TTLExpired || proof.PendingQueries != 0 || proof.PendingFlows != 0 || proof.PendingPins != 0 || !ed25519.Verify(originalOwner[:], services.ReferenceCloseBytes(*proof), proof.Signature) {
			t.Fatal("DNS closure replaced original signed native lifetime")
		}
		value, err := observe("node-b", policyKey)
		if err != nil || value.Ready || value.DNS == nil || value.DNS.Failed || value.DNS.Queries != 0 || value.DNS.Sockets != 0 {
			return false
		}
		closed = ref
		return true
	})
	// Existing explicit network drain/fence/empty-group commit consumes the
	// original native closure. It never manufactures Ready/Gone for rollback.
	group, err := resources().Networks.TUNSources("tenant", name)
	if err != nil || len(group) != 1 || group[0].Network.Owner != originalOwner {
		t.Fatal("original native network source missing before final retirement", err)
	}
	originalNetwork := group[0]
	retireDNSManagedGroup(t, p, read, change, wait, observe, name)
	keys := []string{originalNetwork.BridgeKey}
	if originalNetwork.Tunnel != nil {
		if originalNetwork.TunnelKey == "" {
			t.Fatal("original declared tunnel has no exact source key")
		}
		keys = append(keys, originalNetwork.TunnelKey)
	} else if originalNetwork.TunnelKey != "" {
		t.Fatal("single-member network fabricated a tunnel key")
	}
	wait("original DNS declared native terminal journals before rollback", func() bool {
		for _, key := range keys {
			value, err := observe("node-b", key)
			object := read().State.Object(key)
			if err != nil || value.Ready || object.Present || value.Journal.PendingID != 0 || value.Journal.Applied.Present || value.Journal.Desired.Present || value.Journal.Consumers != 0 || value.Journal.GenerationFloor != object.Generation {
				return false
			}
		}
		return len(resources().Networks.AllNetworks()) == 0
	})
	peer, ok := a.resourcePeerForKey(ctx, originalOwner)
	if !ok || [32]byte(peer.Key) == originalOwner {
		t.Fatal("closure did not use the installed current identity boundary")
	}
	record := map[string]any{}
	raw, err = os.ReadFile(manifest)
	if err != nil || json.Unmarshal(raw, &record) != nil {
		t.Fatal("original rollback manifest", err)
	}
	record["identity_dns_closure"] = map[string]any{"original_owner": originalOwner, "current_reporter": [32]byte(peer.Key), "original_row": originalRow, "closed_reference": closed, "ttl": 30, "queries_sockets": 0, "original_network": originalNetwork, "native_terminal": true, "native_keys": keys, "scope": "one original IPv4 DNS/client across two same-DB identity rotations; exact signed DNS closure and original Bridge retirement; single-member network has no TUN native, two-member TUN closure uses native13; no route fault matrix"}
	raw, _ = json.Marshal(record)
	if err = os.WriteFile(manifest, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("focused RQ12 original DNS: one actual client/pool UDP+TCP A/SOA across two current identity installations using original same DB/native/source/ref; original TTL30 disable, exact old-owner signed close through current owner, zero query/socket census, explicit original declared Bridge drain/fence/reconfigure (single-member network has no TUN native); enclosing fixture verifies both namespace baselines")
}
