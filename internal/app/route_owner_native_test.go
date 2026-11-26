// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/tests/registryfixture"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Docker owns/recreates its counter and handle observations. Preserve the raw
// evidence separately; compare rule STRUCTURE without resetting kernel state.
// Other snapshot sections, comments, counter expressions and verdicts remain.
func routeSnapshotStructure(raw []byte) ([]byte, error) {
	var rows map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	var nft any
	decoder := json.NewDecoder(bytes.NewReader(rows["nft"]))
	decoder.UseNumber()
	if err := decoder.Decode(&nft); err != nil {
		return nil, err
	}
	var visit func(any)
	visit = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			delete(v, "handle")
			if counter, ok := v["counter"].(map[string]any); ok {
				delete(counter, "packets")
				delete(counter, "bytes")
			}
			for _, child := range v {
				visit(child)
			}
		case []any:
			for _, child := range v {
				visit(child)
			}
		}
	}
	visit(nft)
	var err error
	rows["nft"], err = json.Marshal(nft)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rows)
}

// A carrier transition or JSON flag order is not a new native incarnation.
// The serving driver and successful post-restart packet verify live behavior;
// this comparison pins the original kernel device rather than its presentation.
func sameRouteDevice(before, after []byte) bool {
	type device struct {
		Index int    `json:"ifindex"`
		Name  string `json:"ifname"`
		Alias string `json:"ifalias"`
		MTU   int    `json:"mtu"`
		Type  string `json:"link_type"`
	}
	var a, b []device
	return json.Unmarshal(before, &a) == nil && json.Unmarshal(after, &b) == nil && len(a) == 1 && len(b) == 1 && a[0].Index > 0 && a[0].Alias != "" && a[0] == b[0]
}

func saveRouteNativeSnapshots(t *testing.T, path string, before, after [2][]byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return
	} // Bootstrap failed before the public manifest existed.
	var report map[string]any
	if err != nil || json.Unmarshal(raw, &report) != nil || report == nil {
		t.Error("original route public manifest", err)
		return
	}
	report["route_native_before"] = []json.RawMessage{before[0], before[1]}
	report["route_native_after"] = []json.RawMessage{after[0], after[1]}
	report["route_native_comparison"] = "policy structure; raw counters/handles retained, never reset"
	raw, err = json.Marshal(report)
	if err == nil {
		err = os.WriteFile(path, raw, 0644)
	}
	if err != nil {
		t.Error("route native before/after evidence", err)
	}
}

// Reuses the real managed two-owner namespace/Engine/daemon fixture. No fake
// native facts, packet relay, state reconstruction or retrying socket probe.
func testManagedCrossTenantRoutes(t *testing.T, ctx context.Context, a *Runtime, root, products string, configs, sockets [2]string, manifest string, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), stopB, startB func(), run func(int, []string, ...string) ([]byte, error), faults, discoveryOnly bool, identityChecks ...func(func())) {
	t.Helper()
	if !faults && !discoveryOnly {
		verifyLegacyBridgeGatewayNative(t, ctx, root, sockets[0], manifest)
	}
	backend := os.Getenv("MYDC_DOCKER_TEST_BACKEND")
	if backend == "" || !filepath.IsAbs(backend) {
		t.Fatal("explicit prebuilt static route backend required")
	}
	registry := registryfixture.OpenPreparedAt(t, backend, container.Config{Cmd: []string{"/backend", "--route-serve"}, User: "10001:10001", Labels: map[string]string{"org.mydc.test.owner": os.Getenv("MYDC_KERNEL_TEST_OWNER")}}, "192.0.2.1:0")
	policy := a.controlPolicy
	resources := func() control.Resources {
		t.Helper()
		value, err := policy.Resources(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	change("route-other-tenant", "create-tenant", 0, control.TenantID{ID: "other"})
	catalog, err := policy.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := catalog.Tenant("other")
	change("route-other-nodes", "set-nodes", other.Revision, control.NodeAssignment{Tenant: "other", Nodes: []string{"node-a", "node-b"}})
	for _, node := range []string{"node-a", "node-b"} {
		change("route-other-quota/"+node, "set-node-quota", 0, tenancy.NodeLimit{Tenant: "other", Node: node, Capacity: workload.Resources{CPU: 2e9, Memory: 256 << 20}, Networks: 8, MaxConsumers: 32, PacketQueuePackets: 32, PacketQueueBytes: 128 << 10})
	}
	for _, tenant := range []string{"tenant", "other"} {
		catalog, err := policy.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		value, _ := catalog.Tenant(tenant)
		change("route-image-trust/"+tenant, "set-trust", value.Revision, control.TrustAssignment{Tenant: tenant, Rules: append(value.ImageSources, access.TrustRule{Registry: registry.Registry, Repository: "fixture"})})
	}
	public := sqlPublicFixture{Images: map[string]string{registry.Reference: registry.ConfigDigest}}
	var docker [2]*engine.Client
	for n, path := range configs {
		cfg, err := config.LoadNode(path)
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.Load(cfg.Node.IdentityDir)
		if err != nil {
			t.Fatal(err)
		}
		clear(id.Private)
		docker[n], err = engine.Open(ctx, "unix://"+sockets[n], engine.Owner(policy.Cluster, id.Public))
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
		t.Fatal("independent private route Engines required")
	}
	raw, _ := json.Marshal(public)
	if err := os.WriteFile(filepath.Join(root, "route-fixture.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	var ownerManifest map[string]any
	raw, err = os.ReadFile(manifest)
	if err != nil || json.Unmarshal(raw, &ownerManifest) != nil {
		t.Fatal("original route owner manifest", err)
	}
	ownerManifest["route_fixture"] = public
	ownerManifest["route_cidrs"] = []string{"198.19.84.0/28", "198.19.84.16/28", "198.19.84.32/28"}
	ownerManifest["route_docker_firewall"] = true
	if faults {
		ownerManifest["route_cidrs"] = []string{"198.19.84.0/28", "198.19.84.16/28"}
		ownerManifest["route_fault_input"] = true
	}
	ownerManifest["route_untrusted_underlay"] = map[string]any{"node": "node-b", "table": "main", "prefix": "198.19.84.0/28", "gateway": "192.0.2.1", "protocol": "static", "metric": 42701}
	raw, _ = json.Marshal(ownerManifest)
	if err := os.WriteFile(manifest, raw, 0644); err != nil {
		t.Fatal(err)
	}

	type appInput struct {
		tenant, name, network, node, address, gateway, cidr string
		engine                                              int
	}
	inputs := []appInput{{"tenant", "route-source", "source", "node-a", "198.19.84.2", "198.19.84.1", "198.19.84.0/28", 0}, {"other", "route-target", "target", "node-b", "198.19.84.18", "198.19.84.17", "198.19.84.16/28", 1}, {"other", "route-near", "near", "node-a", "198.19.84.34", "198.19.84.33", "198.19.84.32/28", 0}}
	if faults {
		inputs = inputs[:2]
	}
	cleanupInputs := inputs
	var dnsDefinitions []services.ManagedDNSDefinition
	for n, input := range inputs {
		definition := tenancy.TUNDefinition{Tenant: input.tenant, Name: input.network, Members: []tenancy.TUNNode{{Node: input.node, Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix(input.cidr), Gateway: netip.MustParseAddr(input.gateway), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("198.19.85.%d/32", n+1))}}}}
		change("route-network/"+input.network, "create-tun-network", resources().Networks.Revision(), definition)
		// This /28 fixture checks forward-zone authority and gateway isolation.
		// Reverse ownership is a separate explicit /24 (or IPv6 nibble) contract.
		dns := services.ManagedDNSDefinition{Schema: 1, Tenant: input.tenant, Network: input.network, Policy: services.ManagedDNSPolicy{Enabled: true, Reverse: false, Zone: input.network + ".mydc.test.", TTL: 30, NegativeTTL: 5, Transports: []string{"udp", "tcp"}, Upstreams: []netip.AddrPort{}, MaxQueries: 8, MaxCacheEntries: 8, MaxResponseBytes: 4096, MaxConnections: 4, RequestTimeoutMS: 1000}}
		dnsDefinitions = append(dnsDefinitions, dns)
	}
	profile, home := filepath.Join(root, "route-client.yaml"), filepath.Join(root, "route-home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%s', endpoint: '192.0.2.1:44101', voter: true}\n", policy.Cluster, a.Identity.Actor())), 0600); err != nil {
		t.Fatal(err)
	}
	cliCode := func(want int, args ...string) []byte {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, filepath.Join(products, "mydc"), home, profile, args, nil)
		code := 0
		if err != nil {
			var exited *exec.ExitError
			if !errors.As(err, &exited) {
				t.Fatal("real route CLI did not return a process result", args, err)
			}
			code = exited.ExitCode()
		}
		if code != want {
			t.Fatal("real route CLI", args, code, want, err, string(diagnostic), string(out))
		}
		return out
	}
	cli := func(args ...string) []byte { t.Helper(); return cliCode(0, args...) }
	cli("wallet", "init")
	cli("login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	proposePublicEndpoint := nativeRouteEndpointProposer(t, ctx, a, root, products, change)
	if !faults && !discoveryOnly {
		testRouteManagementRecovery(t, ctx, a, root, home, dnsDefinitions, read, cliCode)
	} else {
		for _, definition := range dnsDefinitions {
			change("route-fault-dns/"+definition.Network, "configure-network-dns", 0, definition)
		}
	}
	for _, input := range inputs {
		path := filepath.Join(root, input.name+"-app.yaml")
		document := fmt.Sprintf("name: %s\nservices:\n endpoint:\n  image: %s\n  command: [/backend, --route-serve]\n  user: '10001:10001'\n  cpus: 0.1\n  mem_limit: 16m\n  healthcheck: {test: [CMD, /backend, --tcp-probe, '127.0.0.1:33100'], interval: 1s, timeout: 2s, retries: 3}\n  networks: {lan: {ipv4_address: %s}}\n  x-mydc: {node: %s}\nnetworks:\n lan: {external: true, name: %s}\n", input.name, registry.Reference, input.address, input.node, input.network)
		if err := os.WriteFile(path, []byte(document), 0600); err != nil {
			t.Fatal(err)
		}
		cli("compose", "up", "--tenant", input.tenant, "--operation", "up-"+input.name, "--file", path, "--no-input")
		// The next plan freezes this tenant's available node capacity. Wait for
		// this original app to settle before planning another app on that node;
		// a concurrently materialized Task legitimately invalidates the digest.
		wait("original route app settled before next plan "+input.name, func() bool {
			apps, err := policy.Apps(read().State)
			if err != nil {
				return false
			}
			execution, found := apps.Execution(input.tenant, input.name)
			return found && execution.Status() == "Succeeded"
		})
	}
	remoteIdentity, err := identity.Load(filepath.Join(root, "key-1"))
	if err != nil {
		t.Fatal(err)
	}
	clear(remoteIdentity.Private)
	observe := func(node, key string) (ModuleObservation, error) {
		var out ModuleObservation
		if node == "node-b" {
			current, known := a.resourcePeerForKey(ctx, remoteIdentity.Public)
			if !known {
				return out, mydcp.ErrAdmission
			}
			reply, err := cluster.CallManagement(ctx, a.Mesh, a.commandIdentity(), policy.Cluster, current, cluster.ManagementRequest{Method: "observe", Key: key, Latest: false})
			if err != nil {
				return out, err
			}
			err = json.Unmarshal(reply.Data, &out)
			return out, err
		}
		data, err := a.observeManaged(ctx, key, read())
		if err == nil {
			err = json.Unmarshal(data, &out)
		}
		return out, err
	}
	ids := map[string]string{}
	for _, input := range inputs {
		wait("actual managed DNS ready "+input.network, func() bool {
			value, err := observe(input.node, services.ManagedDNSKey(input.tenant, input.network))
			return err == nil && value.Ready && value.DNS != nil && !value.DNS.Failed
		})
		key := deployment.ResourceKey("task", input.tenant, input.name, "endpoint")
		wait("actual route workload ready "+input.name, func() bool {
			value, err := observe(input.node, key)
			if err != nil || !value.Ready || value.NativeID == "" {
				return false
			}
			ids[input.name] = value.NativeID
			return true
		})
		inspection, err := docker[input.engine].API.ContainerInspect(ctx, ids[input.name], client.ContainerInspectOptions{})
		if err != nil || inspection.Container.State == nil || !inspection.Container.State.Running || inspection.Container.Config == nil || inspection.Container.Config.Labels["org.mydc.owner"] != docker[input.engine].Owner {
			t.Fatal("actual route container identity", input.name, err)
		}
		if inspection.Container.NetworkSettings == nil || len(inspection.Container.NetworkSettings.Networks) != 1 {
			t.Fatal("original managed endpoint missing or mixed with another network")
		}
		for _, endpoint := range inspection.Container.NetworkSettings.Networks {
			if endpoint == nil || endpoint.IPAddress.String() != input.address || endpoint.NetworkID == "" {
				t.Fatal("actual SDK IPAM assignment differs from original app address")
			}
			bridge, err := docker[input.engine].API.NetworkInspect(ctx, endpoint.NetworkID, client.NetworkInspectOptions{})
			if err != nil || bridge.Network.Internal || bridge.Network.Options["com.docker.network.bridge.gateway_mode_ipv4"] != network.ManagedGatewayMode || bridge.Network.Options["com.docker.network.bridge.enable_ip_masquerade"] != "false" {
				t.Fatal("actual managed SDK gateway/packet source mode differs", err)
			}
		}
	}
	if !faults {
		verifyRouteStaticAddressCollision(t, ctx, a, root, manifest, ids["route-source"], policy, read)
	}
	execNativeProbe := func(input appInput, native string, want int, command ...string) {
		t.Helper()
		created, err := docker[input.engine].API.ExecCreate(ctx, native, client.ExecCreateOptions{User: "10001:10001", Cmd: command, AttachStdout: true, AttachStderr: true})
		if err != nil {
			t.Fatal(err)
		}
		attached, err := docker[input.engine].API.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer attached.Close()
		stopOutput := context.AfterFunc(ctx, func() { attached.Close() })
		defer stopOutput()
		var stdout, stderr bytes.Buffer
		_, outputErr := stdcopy.StdCopy(&stdout, &stderr, io.LimitReader(attached.Reader, 64<<10))
		attached.Close()
		wait("actual container probe "+fmt.Sprint(command), func() bool {
			result, err := docker[input.engine].API.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if result.Running {
				return false
			}
			if result.ContainerID != native || result.ExitCode != want || outputErr != nil {
				delivered, dropped := a.Mesh.PacketCounts()
				t.Log("actual route packet counts", delivered, dropped)
				failure := map[string]any{"command": command, "exec": created.ID, "container": native, "exit": result.ExitCode, "want": want, "stdout": stdout.String(), "stderr": stderr.String(), "output_error": fmt.Sprint(outputErr), "local_packets_delivered": delivered, "local_packets_dropped": dropped}
				failure["admission"] = a.routeAdmission.Load()
				failure["admission_error"] = a.routeAdmissionError.Load()
				for node := 0; node < 2; node++ {
					for name, args := range map[string][]string{"link": {"ip", "-s", "-d", "-j", "link"}, "rule": {"ip", "-j", "rule"}, "routes": {"ip", "-j", "route", "show", "table", "all"}, "nft": {"nft", "-j", "list", "ruleset"}, "conntrack": {"conntrack", "-L", "-o", "extended"}, "netstat": {"cat", "/proc/net/netstat", "/proc/net/snmp"}} {
						raw, readErr := run(node, nil, args...)
						failure[fmt.Sprintf("node-%d-%s", node, name)] = map[string]any{"output": string(raw), "error": fmt.Sprint(readErr)}
					}
				}
				if raw, err := json.Marshal(failure); err != nil {
					t.Error("original packet failure evidence", err)
				} else if err := os.WriteFile(filepath.Join(root, "route-packet-failure.json"), raw, 0600); err != nil {
					t.Error("original packet failure evidence", err)
				}
				t.Fatal("actual route probe result", input.name, command, result.ExitCode, want, "stdout", stdout.String(), "stderr", stderr.String(), "output", outputErr)
			}
			return true
		})
	}
	execProbe := func(index, want int, command ...string) {
		t.Helper()
		execNativeProbe(inputs[index], ids[inputs[index].name], want, command...)
	}
	probe := func(index int, protocol, target string, port, local, want int) {
		t.Helper()
		execProbe(index, want, "/backend", "--route-probe", protocol, net.JoinHostPort(target, fmt.Sprint(port)), fmt.Sprint(local))
	}
	if !faults {
		// A healthy exact SOA on each workload's OWN gateway precedes the foreign
		// gateway check. Only a socket timeout (exit 2), not an invalid response,
		// refused listener or malformed CLI (exit 1), can establish this denial.
		for _, protocol := range []string{"udp", "tcp"} {
			for index, input := range inputs {
				execProbe(index, 0, "/backend", "--route-dns", protocol, net.JoinHostPort(input.gateway, "53"), input.network+".mydc.test.")
			}
			execProbe(0, 2, "/backend", "--route-dns", protocol, net.JoinHostPort(inputs[2].gateway, "53"), inputs[2].network+".mydc.test.")
		}
		// Both allowed and denied ports have a real responding application; a
		// refused/missing listener cannot manufacture a successful deny check.
		for i := range inputs {
			probe(i, "tcp", "127.0.0.1", 33100, 42000+i, 0)
			probe(i, "tcp", "127.0.0.1", 33101, 42010+i, 0)
			probe(i, "udp", "127.0.0.1", 53100, 42020+i, 0)
			probe(i, "udp", "127.0.0.1", 53101, 42030+i, 0)
		}
		probe(0, "tcp", inputs[2].address, 33100, 40001, 1)
		probe(0, "udp", inputs[2].address, 53100, 40002, 1)

	}

	type routeInput struct {
		id, network, node, protocol string
		number                      uint8
		port, sourcePort, target    int
	}
	routes := []routeInput{{"remote-tcp", "target", "node-b", "tcp", 6, 33100, 41001, 1}, {"remote-udp", "target", "node-b", "udp", 17, 53100, 41002, 1}, {"local-tcp", "near", "node-a", "tcp", 6, 33100, 41003, 2}, {"local-udp", "near", "node-a", "udp", 17, 53100, 41004, 2}}
	if faults {
		routes = []routeInput{routes[1]}
	}
	refs := func(id string) []services.ReferenceConsumer {
		p, err := policy.ProjectResources(read().State)
		if err != nil || p.NetworkAuthority == nil {
			t.Fatal(err)
		}
		var out []services.ReferenceConsumer
		for _, ref := range p.NetworkAuthority.RouteReferences() {
			if ref.Route.Policy.Source.Tenant == "tenant" && ref.Route.Policy.ID == id && ref.Closed == nil {
				out = append(out, ref)
			}
		}
		return out
	}
	ready := func(id string) {
		t.Helper()
		reported := map[[32]byte]string{}
		t.Log("awaiting original route IO/path plans", id)
		wait("both original route IO/path plans "+id, func() bool {
			current := refs(id)
			if len(current) != 2 {
				return false
			}
			for _, ref := range current {
				reply, err := a.callRouteFlow(ctx, ref, routeFlowRequest{Schema: 1, Reference: ref.ID})
				signed := ed25519.Verify(ed25519.PublicKey(ref.Local.Owner[:]), services.RouteNativeBytes(reply.Native), reply.Native.Signature)
				status := fmt.Sprintf("packet_ready=%t native_installed=%t signed=%t error=%v", reply.PacketReady, reply.Native.Installed, signed, err)
				if reported[ref.ID] != status {
					t.Logf("route %s owner %s: %s", id, ref.Local.Node, status)
					reported[ref.ID] = status
				}
				if err != nil || !reply.PacketReady || !reply.Native.Installed || !signed {
					return false
				}
			}
			return true
		})
	}
	approve := func(route routeInput, suffix string) {
		t.Helper()
		proposal := control.RouteProposal{ID: route.id, Source: control.RouteEndpoint{Tenant: "tenant", Network: "source", Node: "node-a", Pool: "pool"}, Destination: control.RouteEndpoint{Tenant: "other", Network: route.network, Node: route.node, Pool: "pool"}, Protocol: route.number, Ports: []tenancy.Ports{{First: uint16(route.port), Last: uint16(route.port)}}}
		if suffix == "" {
			proposePublicEndpoint(route.id, route.node, route.number, uint16(route.port))
		} else {
			change("route-propose/"+route.id+suffix, "propose-route", resources().Networks.Revision(), proposal)
		}
		current, _ := resources().Networks.Route("tenant", route.id)
		change("route-approve-source/"+route.id+suffix, "approve-route", current.Revision, control.RouteSelection{Tenant: "tenant", SourceTenant: "tenant", ID: route.id})
		if len(refs(route.id)) != 0 {
			t.Fatal("one approval reserved native route instances")
		}
		current, _ = resources().Networks.Route("tenant", route.id)
		change("route-approve-destination/"+route.id+suffix, "approve-route", current.Revision, control.RouteSelection{Tenant: "other", SourceTenant: "tenant", ID: route.id})
		ready(route.id)
	}
	for _, route := range routes {
		approve(route, "")
	}
	if !faults {
		for _, protocol := range []string{"udp", "tcp"} {
			execProbe(2, 0, "/backend", "--route-dns", protocol, net.JoinHostPort(inputs[2].gateway, "53"), inputs[2].network+".mydc.test.")
			execProbe(0, 2, "/backend", "--route-dns", protocol, net.JoinHostPort(inputs[2].gateway, "53"), inputs[2].network+".mydc.test.")
		}
		testRouteUnderlayIsolation(t, backend, inputs[0].cidr, inputs[0].gateway, inputs[0].address, inputs[0].network+".mydc.test.", run)
	}

	type originalFlow struct {
		ref   services.ReferenceConsumer
		flow  services.RouteFlow
		claim services.RouteFlowReceipt
		tuple services.RouteTuple
	}
	flows := map[string]originalFlow{}
	for _, route := range routes {
		probe(0, route.protocol, inputs[route.target].address, route.port, route.sourcePort, 0)
		target := inputs[route.target]
		logs, err := docker[target.engine].API.ContainerLogs(ctx, ids[target.name], client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "64"})
		if err != nil {
			t.Fatal("original target socket source evidence", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(logs, 64<<10))
		_ = logs.Close()
		wantPeer := fmt.Sprintf("route peer %s %s\n", route.protocol, net.JoinHostPort(inputs[0].address, fmt.Sprint(route.sourcePort)))
		if readErr != nil || !bytes.Contains(raw, []byte(wantPeer)) {
			t.Fatal("actual target did not observe original Book source address/port", route.id, readErr)
		}
		var ref services.ReferenceConsumer
		for _, candidate := range refs(route.id) {
			if candidate.Route.Side == "tenant" {
				ref = candidate
			}
		}
		projection, err := policy.ProjectResources(read().State)
		if err != nil || projection.NetworkAuthority == nil {
			t.Fatal(err)
		}
		book := projection.NetworkAuthority.AddressBook()
		sourceAllocation, sok := book.AllocationAt(netip.MustParseAddr(inputs[0].address))
		destinationAllocation, dok := book.AllocationAt(netip.MustParseAddr(inputs[route.target].address))
		if !sok || !dok {
			t.Fatal("actual app allocations missing from shared Book")
		}
		tuple := services.RouteTuple{Source: sourceAllocation, Destination: destinationAllocation, SourcePort: uint16(route.sourcePort), DestinationPort: uint16(route.port), Protocol: route.number}
		a.routeMu.Lock()
		record, found, loadErr := a.loadRouteOwner(ref)
		core, decodeErr := services.DecodeRouteRuntime(record.Core)
		flow, exists := core.OriginalFlow(tuple)
		claim, claimErr := a.storedRouteFlowReceipt(ref, flow)
		a.routeMu.Unlock()
		if loadErr != nil || decodeErr != nil || claimErr != nil || !found || !exists {
			t.Fatal("actual original route flow was not durable", loadErr, decodeErr, claimErr)
		}
		flows[route.id] = originalFlow{ref, flow, claim, tuple}
	}
	identityMode := len(identityChecks) == 1 && identityChecks[0] != nil
	if identityMode {
		// Read back only each original route's isolation rules, rather than
		// freezing unrelated rules in the same namespace. RETURN in the owned
		// in/out chains is the route exception ahead of cross-tenant default DROP.
		type isolationRouteNative struct {
			owner                 [32]byte
			table                 string
			policy, rules, device []byte
		}
		originalIsolationRefs := []services.ReferenceConsumer{}
		for _, route := range routes {
			originalIsolationRefs = append(originalIsolationRefs, refs(route.id)...)
		}
		isolationRoutes := func() map[[32]byte]isolationRouteNative {
			t.Helper()
			view := read()
			var nativeRules [2][]map[string]json.RawMessage
			for n := range nativeRules {
				raw, err := run(n, nil, "nft", "-j", "list", "ruleset")
				var value struct {
					Rules []map[string]json.RawMessage `json:"nftables"`
				}
				if err != nil || json.Unmarshal(raw, &value) != nil {
					t.Fatal("original route isolation readback", n, err)
				}
				nativeRules[n] = value.Rules
			}
			out := map[[32]byte]isolationRouteNative{}
			for _, ref := range originalIsolationRefs {
				n := 0
				if ref.Local.Node == "node-b" {
					n = 1
				} else if ref.Local.Node != "node-a" {
					t.Fatal("unexpected original isolation node", ref.Local.Node)
				}
				current := policy.ResourceWorkKey(view.State, ref.Local.Owner)
				work, err := policy.RouteWork(view.State, current, control.RouteWorkRequest{Reference: ref.ID})
				if err != nil || !work.PrepareAllowed || work.Reference.Local.Owner != ref.Local.Owner || work.Tunnel.RoutePolicy == nil {
					t.Fatal("original route isolation lost current authority or native owner", ref.Local.Node, err)
				}
				device, err := network.TunnelDeviceName(ref.RouteNativeKey(), ref.Generation, work.Tunnel)
				if err != nil {
					t.Fatal(err)
				}
				token, _ := json.Marshal(device)
				var selected []map[string]json.RawMessage
				table := ""
				in, outRule := false, false
				for _, row := range nativeRules[n] {
					var rule struct {
						Family, Table, Chain string
						Expr                 json.RawMessage
					}
					if len(row["rule"]) == 0 || json.Unmarshal(row["rule"], &rule) != nil || rule.Family != "inet" || !strings.HasPrefix(rule.Table, "mydc_i_") || !bytes.Contains(rule.Expr, token) {
						continue
					}
					if table != "" && table != rule.Table {
						t.Fatal("original route spans different isolation owners", ref.Local.Node, device)
					}
					table = rule.Table
					if bytes.Contains(rule.Expr, []byte(`"return"`)) {
						in = in || strings.HasPrefix(rule.Chain, "in_")
						outRule = outRule || strings.HasPrefix(rule.Chain, "out_")
					}
					selected = append(selected, row)
				}
				if table == "" || !in || !outRule {
					t.Fatal("original route missing isolation exception before default drop", ref.Local.Node, device, table, in, outRule)
				}
				nft, _ := json.Marshal(map[string]any{"nftables": selected})
				raw, _ := json.Marshal(map[string]json.RawMessage{"nft": nft})
				rules, err := routeSnapshotStructure(raw)
				if err != nil {
					t.Fatal("original route isolation structure", err)
				}
				link, err := run(n, nil, "ip", "-d", "-j", "link", "show", "dev", device)
				if err != nil {
					t.Fatal("original route isolation device", device, err)
				}
				routePolicy, _ := json.Marshal(work.Tunnel.RoutePolicy)
				out[ref.ID] = isolationRouteNative{ref.Local.Owner, table, routePolicy, rules, link}
			}
			return out
		}
		originalIsolation := isolationRoutes()
		original := flows["remote-udp"]
		var peer services.ReferenceConsumer
		for _, ref := range refs("remote-udp") {
			if ref.Route.Side == "other" {
				peer = ref
			}
		}
		before, err := a.callRouteFlow(ctx, peer, routeFlowRequest{Schema: 1, Reference: peer.ID, Tuple: &original.tuple})
		if err != nil || before.Flow == nil {
			t.Fatal("original route flow before identity replacement", err)
		}
		identityChecks[0](func() {
			for _, route := range routes {
				ready(route.id)
			}
			for id, after := range isolationRoutes() {
				before, found := originalIsolation[id]
				if !found || before.owner != after.owner || before.table != after.table || !bytes.Equal(before.policy, after.policy) || !bytes.Equal(before.rules, after.rules) || !sameRouteDevice(before.device, after.device) {
					t.Fatal("identity rotation changed original isolation route owner/table/policy/device", id, before.table, after.table)
				}
			}
			for _, route := range routes {
				probe(0, route.protocol, inputs[route.target].address, route.port, route.sourcePort, 0)
			}
			after, err := a.callRouteFlow(ctx, peer, routeFlowRequest{Schema: 1, Reference: peer.ID, Tuple: &original.tuple})
			if err != nil || after.Flow == nil || after.Flow.Pin != before.Flow.Pin || after.Flow.PeerPin != before.Flow.PeerPin {
				t.Fatal("identity rotation replaced original bilateral flow pins", err)
			}
			probe(0, "udp", inputs[1].address, 53101, 40012, 1)
			probe(1, "tcp", inputs[0].address, 33100, 40013, 1)
		})
		// One small explicit additional app avoids redeploying an existing
		// current-key generation. Original apps/flows remain unchanged; its new
		// Task borrows the exact original network under the installed key.
		target := inputs[1]
		target.name, target.address = "route-current", "198.19.84.19"
		key := deployment.ResourceKey("task", target.tenant, target.name, "endpoint")
		oldKey := deployment.ResourceKey("task", inputs[1].tenant, inputs[1].name, "endpoint")
		beforeState := read().State
		beforeProjection, err := policy.ProjectResources(beforeState)
		if err != nil || beforeProjection.NetworkAuthority == nil {
			t.Fatal("original endpoint projection before additional Task", err)
		}
		oldAllocation, exists := beforeProjection.NetworkAuthority.AddressBook().Allocation(oldKey + "/lan/0")
		oldGoal := beforeProjection.Goals[oldKey].Goal
		oldNative := ids[inputs[1].name]
		if !exists || oldNative == "" || beforeState.Object(key).Present {
			t.Fatal("additional Task lacks distinct original endpoint input")
		}
		group, err := resources().Networks.TUNSources(target.tenant, target.network)
		if err != nil || len(group) != 1 {
			t.Fatal("original target network source before additional Task", err)
		}
		nativeSourceKey := group[0].BridgeKey
		nativeSource := beforeState.Object(nativeSourceKey)
		path := filepath.Join(root, target.name+"-app.yaml")
		document := fmt.Sprintf("name: %s\nservices:\n endpoint:\n  image: %s\n  command: [/backend, --route-serve]\n  user: '10001:10001'\n  cpus: 0.1\n  mem_limit: 16m\n  healthcheck: {test: [CMD, /backend, --tcp-probe, '127.0.0.1:33100'], interval: 1s, timeout: 2s, retries: 3}\n  networks: {lan: {ipv4_address: %s, aliases: [current]}}\n  x-mydc: {node: %s}\nnetworks:\n lan: {external: true, name: %s}\n", target.name, registry.Reference, target.address, target.node, target.network)
		if err := os.WriteFile(path, []byte(document), 0600); err != nil {
			t.Fatal(err)
		}
		cli("compose", "up", "--tenant", target.tenant, "--operation", "up-"+target.name, "--file", path, "--no-input")
		cleanupInputs = append(append([]appInput(nil), inputs...), target)
		var newNative string
		// Observe the known original endpoint as well: before the new Task's
		// first Command exists its observation cannot expose owner-loop errors.
		// Only changed, bounded metadata is logged; this adds no retry or wait.
		var lastDiagnostic string
		diagnosticChanges := 0
		boundedDiagnostic := func(value string) string {
			if len(value) > 256 {
				return value[:256] + "..."
			}
			return value
		}
		diagnosticError := func(err error) string {
			if err == nil {
				return ""
			}
			return boundedDiagnostic(err.Error())
		}
		wait("current identity additional Task on original TUN and DNS", func() bool {
			apps, err := policy.Apps(read().State)
			if err != nil {
				return false
			}
			execution, found := apps.Execution(target.tenant, target.name)
			value, observeErr := observe(target.node, key)
			original, originalObserveErr := observe(target.node, oldKey)
			diagnostic := fmt.Sprintf("found=%t operation=%q status=%q ready=%t task-observe=%q original-observe=%q original-module=%q original-report=%q", found, execution.ActiveOperation(), execution.Status(), value.Ready, diagnosticError(observeErr), diagnosticError(originalObserveErr), boundedDiagnostic(original.ModuleError), boundedDiagnostic(original.ReportError))
			if diagnostic != lastDiagnostic {
				lastDiagnostic = diagnostic
				if diagnosticChanges < 16 {
					diagnosticChanges++
					t.Logf("additional route Task progress (%d/16): %s", diagnosticChanges, diagnostic)
				}
			}
			if found && execution.Status() == "Failed" {
				t.Fatalf("additional route Task execution failed: %s", diagnostic)
			}
			if !found || execution.ActiveOperation() != "up-"+target.name || execution.Status() != "Succeeded" || observeErr != nil || !value.Ready || value.NativeID == "" || value.NativeID == oldNative {
				return false
			}
			newNative = value.NativeID
			return true
		})
		afterState := read().State
		afterProjection, err := policy.ProjectResources(afterState)
		if err != nil || afterProjection.NetworkAuthority == nil {
			t.Fatal("additional Task projection", err)
		}
		newGoal := afterProjection.Goals[key].Goal
		newAllocation, exists := afterProjection.NetworkAuthority.AddressBook().Allocation(key + "/lan/0")
		originalAllocation, originalHeld := afterProjection.NetworkAuthority.AddressBook().Allocation(oldKey + "/lan/0")
		if !exists || !originalHeld || originalAllocation != oldAllocation || afterState.Object(oldKey) != beforeState.Object(oldKey) || newGoal.Owner == oldGoal.Owner || len(newGoal.ResourceKeys) < 2 || newAllocation.Owner != oldAllocation.Owner || newAllocation.Address.String() != target.address || newAllocation.Pool != oldAllocation.Pool || newAllocation.Endpoint == oldAllocation.Endpoint || afterState.Object(nativeSourceKey) != nativeSource {
			t.Fatal("additional Task rewrote original endpoint or native network owner")
		}
		for _, original := range inputs {
			value, err := observe(original.node, deployment.ResourceKey("task", original.tenant, original.name, "endpoint"))
			if err != nil || !value.Ready || value.NativeID != ids[original.name] {
				t.Fatal("additional Task recreated an existing original container", original.name, err)
			}
		}
		actual, err := docker[target.engine].API.ContainerInspect(ctx, newNative, client.ContainerInspectOptions{})
		if err != nil || actual.Container.State == nil || !actual.Container.State.Running || actual.Container.Config == nil || actual.Container.Config.Labels["org.mydc.owner"] != engine.Owner(policy.Cluster, newGoal.Owner) || actual.Container.NetworkSettings == nil || len(actual.Container.NetworkSettings.Networks) != 1 {
			t.Fatal("additional native Task did not belong to current installed identity", err)
		}
		for _, endpoint := range actual.Container.NetworkSettings.Networks {
			if endpoint == nil || endpoint.IPAddress.String() != target.address {
				t.Fatal("additional Task did not use its distinct declared network address")
			}
		}
		for _, protocol := range []string{"udp", "tcp"} {
			execNativeProbe(target, newNative, 0, "/backend", "--route-dns", protocol, net.JoinHostPort(target.gateway, "53"), target.network+".mydc.test.")
		}
		for _, route := range routes {
			ready(route.id)
		}
		probe(0, "tcp", target.address, 33100, 43001, 0)
		probe(0, "udp", target.address, 53100, 43002, 0)
		probe(0, "udp", target.address, 53101, 43003, 1)
		for _, route := range routes {
			probe(0, route.protocol, inputs[route.target].address, route.port, route.sourcePort, 0)
		}
		afterFlow, err := a.callRouteFlow(ctx, peer, routeFlowRequest{Schema: 1, Reference: peer.ID, Tuple: &original.tuple})
		if err != nil || afterFlow.Flow == nil || afterFlow.Flow.Pin != before.Flow.Pin || afterFlow.Flow.PeerPin != before.Flow.PeerPin {
			t.Fatal("additional Task replaced an original bilateral UDP receipt", err)
		}
	}
	if faults {
		original := flows["remote-udp"]
		var peer services.ReferenceConsumer
		for _, ref := range refs("remote-udp") {
			if ref.Route.Side == "other" {
				peer = ref
			}
		}
		testManagedRouteFaults(t, ctx, a, root, manifest, read, original.ref, peer, original.flow, original.claim, original.tuple, func() { probe(0, "udp", inputs[1].address, 53100, 41002, 0) }, func() { ready("remote-udp") }, stopB, startB)
	} else if !discoveryOnly && !identityMode {
		// UDP's original pin/receipt must survive a clean daemon cut in the same
		// kernel/DB/native. No missing reply is used as a process-stop observation.
		originalUDP := flows["remote-udp"]
		var peer services.ReferenceConsumer
		for _, ref := range refs("remote-udp") {
			if ref.Route.Side == "other" {
				peer = ref
			}
		}
		beforeReply, err := a.callRouteFlow(ctx, peer, routeFlowRequest{Schema: 1, Reference: peer.ID, Tuple: &originalUDP.tuple})
		if err != nil || beforeReply.Flow == nil {
			t.Fatal("original remote UDP pin before daemon stop", err)
		}
		spec, err := services.RouteTunnelDefinition(peer)
		if err != nil {
			t.Fatal(err)
		}
		device, err := network.TunnelDeviceName(peer.RouteNativeKey(), peer.Generation, spec)
		if err != nil {
			t.Fatal(err)
		}
		beforeDevice, err := run(1, nil, "ip", "-j", "link", "show", "dev", device)
		if err != nil {
			t.Fatal(err)
		}
		stopB()
		startB()
		ready("remote-udp")
		probe(0, "udp", inputs[1].address, 53100, 41002, 0)
		afterReply, err := a.callRouteFlow(ctx, peer, routeFlowRequest{Schema: 1, Reference: peer.ID, Tuple: &originalUDP.tuple})
		afterDevice, deviceErr := run(1, nil, "ip", "-j", "link", "show", "dev", device)
		sameDevice := sameRouteDevice(beforeDevice, afterDevice)
		restart := map[string]any{"before_device": json.RawMessage(beforeDevice), "after_device": json.RawMessage(afterDevice), "before_reply": beforeReply, "after_reply": afterReply, "same_device_identity": sameDevice, "same_raw_device_json": bytes.Equal(beforeDevice, afterDevice), "reply_error": fmt.Sprint(err), "device_error": fmt.Sprint(deviceErr)}
		if raw, evidenceErr := json.Marshal(restart); evidenceErr != nil {
			t.Fatal("restart evidence encoding", evidenceErr)
		} else if evidenceErr := os.WriteFile(filepath.Join(root, "route-restart.json"), raw, 0600); evidenceErr != nil {
			t.Fatal("restart original evidence", evidenceErr)
		}
		if err != nil || deviceErr != nil || afterReply.Flow == nil || afterReply.Flow.Pin != beforeReply.Flow.Pin || afterReply.Flow.PeerPin != beforeReply.Flow.PeerPin || !sameDevice {
			t.Fatal("same DB/native/UDP flow pin changed after actual daemon restart", err, deviceErr)
		}
		probe(0, "tcp", inputs[2].address, 33101, 40011, 1)
		probe(0, "udp", inputs[1].address, 53101, 40012, 1)
		probe(1, "tcp", inputs[0].address, 33100, 40013, 1)
		probe(2, "udp", inputs[0].address, 53100, 40014, 1)
		for _, original := range flows {
			wait("product normal flow collection "+original.ref.Name, func() bool {
				a.routeMu.Lock()
				defer a.routeMu.Unlock()
				record, found, err := a.loadRouteOwner(original.ref)
				if err != nil || !found {
					return false
				}
				core, err := services.DecodeRouteRuntime(record.Core)
				if err != nil {
					return false
				}
				_, exists := core.OriginalFlow(original.tuple)
				return !exists
			})
			p, err := policy.ProjectResources(read().State)
			if err != nil || p.NetworkAuthority == nil {
				t.Fatal(err)
			}
			peer, known := p.NetworkAuthority.ReferenceConsumer(original.claim.Peer.Consumer)
			if !known {
				t.Fatal("original peer reference disappeared")
			}
			reply, err := a.callRouteFlow(ctx, peer, routeFlowRequest{Schema: 1, Reference: peer.ID, Tuple: &original.tuple, Close: &original.claim, CloseQuery: true})
			if err != nil || reply.Closed == nil || !reply.Closed.Tombstoned || !ed25519.Verify(ed25519.PublicKey(peer.Local.Owner[:]), services.RoutePeerFlowCloseBytes(*reply.Closed), reply.Closed.Signature) {
				t.Fatal("normal source collection lacked actual peer tombstone", err)
			}
		}
		// Revocation is a real Catalog operation. It must close both remote
		// route instances while retaining the unrelated same-node policies.
		catalog, err = policy.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		other, _ = catalog.Tenant("other")
		change("route-revoke-target-node", "set-nodes", other.Revision, control.NodeAssignment{Tenant: "other", Nodes: []string{"node-a"}})
		wait("both remote route instance closures after node grant revocation", func() bool { return len(refs("remote-tcp")) == 0 && len(refs("remote-udp")) == 0 })
		probe(0, "tcp", inputs[1].address, 33100, 40021, 1)
		probe(0, "udp", inputs[2].address, 53100, 41024, 0)
		catalog, err = policy.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		other, _ = catalog.Tenant("other")
		change("route-restore-target-node", "set-nodes", other.Revision, control.NodeAssignment{Tenant: "other", Nodes: []string{"node-a", "node-b"}})
		if len(refs("remote-tcp")) != 0 || len(refs("remote-udp")) != 0 {
			t.Fatal("restored grant reopened old route instances")
		}
		approve(routes[0], "-new")
		probe(0, "tcp", inputs[1].address, 33100, 41031, 0)
	}
	for _, route := range routes {
		current, exists := resources().Networks.Route("tenant", route.id)
		if !exists {
			continue
		}
		change("route-withdraw/"+route.id, "withdraw-route", current.Revision, control.RouteSelection{Tenant: "other", SourceTenant: "tenant", ID: route.id})
	}
	wait("all original route native/flow/Bridge and shared closures", func() bool {
		p, err := policy.ProjectResources(read().State)
		if err != nil || p.NetworkAuthority == nil {
			return false
		}
		count := 0
		for _, ref := range p.NetworkAuthority.RouteReferences() {
			if ref.Route.Policy.Source.Tenant != "tenant" {
				continue
			}
			count++
			if ref.Closed == nil || ref.RouteClosed == nil {
				return false
			}
		}
		if faults {
			return count == 2
		}
		if discoveryOnly || identityMode {
			return count == 8 // Four original bilateral pairs, no unrelated replacement cycle.
		}
		return count == 10 // Four pairs, plus a deliberately new same-name TCP pair.
	})
	if faults {
		probe(0, "udp", inputs[1].address, 53100, 40031, 1)
	} else {
		probe(0, "tcp", inputs[2].address, 33100, 40031, 1)
	}
	for _, input := range cleanupInputs {
		cli("compose", "down", "--tenant", input.tenant, "-p", input.name, "--operation", "down-"+input.name)
	}
	wait("actual app Task/reference retirement", func() bool {
		shared := read().State
		apps, err := policy.Apps(shared)
		if err != nil {
			return false
		}
		for _, input := range cleanupInputs {
			inventory, ok := apps.Inventory(input.tenant, input.name)
			if !ok {
				return false
			}
			// FinishRetirement archives the original operation and removes the
			// transient target list. Wait for its durable terminal state instead
			// of requiring every app's short-lived closing phase simultaneously.
			summary, exists := inventory.Operation("up-" + input.name)
			if !exists || summary.Status != "Retired" || summary.CompletedAt == 0 || !inventory.Quiescent() {
				return false
			}
			claims := inventory.Claims()
			if len(claims) == 0 {
				return false
			}
			for _, claim := range claims {
				if !claim.Removed || shared.Object(claim.Step.Key).Present {
					return false
				}
			}
		}
		return true
	})
	// App down must leave management DNS alive until its separate explicit
	// disable. Wait for original signed closures before draining any Bridge.
	for _, input := range inputs {
		view := read()
		sources, err := policy.ManagedDNS(view.State)
		key := services.ManagedDNSKey(input.tenant, input.network)
		source, exists := sources[key]
		if err != nil || !exists || !source.Definition.Policy.Enabled {
			t.Fatal("original route DNS policy missing after app down", key, err)
		}
		source.Definition.Policy.Enabled = false
		change("route-disable-dns/"+input.network, "configure-network-dns", view.State.Object(key).Revision, source.Definition)
	}
	t.Log("awaiting signed DNS closures with original TTL before Bridge drain")
	wait("all original managed DNS closures before Bridge drain", func() bool {
		apps, err := policy.Apps(read().State)
		if err != nil {
			return false
		}
		count := 0
		for _, owner := range [][32]byte{a.Identity.Public, remoteIdentity.Public} {
			authority, rows, known := apps.NetworkDNS(owner)
			if !known {
				return false
			}
			for _, row := range rows {
				for _, input := range inputs {
					if row.Source.Key != services.ManagedDNSKey(input.tenant, input.network) {
						continue
					}
					ref, exists := authority.ReferenceConsumer(row.Reference)
					if !exists || ref.Closed == nil || row.Config.Enabled {
						return false
					}
					count++
				}
			}
		}
		return count == len(inputs)
	})
	for _, input := range inputs {
		group, err := resources().Networks.TUNSources(input.tenant, input.network)
		if err != nil || len(group) != 1 {
			t.Fatal("original one-member managed network", err)
		}
		row := group[0]
		original := row.Network
		target := original
		target.Generation, target.Revision, target.PendingChange = 0, 0, 0
		target.Owner = [32]byte{}
		id := "route-final-network-" + input.network
		change(id+"/plan", "plan-network-change", original.Revision, control.NetworkChangePlan{Tenant: input.tenant, ID: original.ID, Change: id, Target: target})
		change(id+"/drain", "drain-network", original.Revision, control.NetworkSelection{Tenant: input.tenant, ID: original.ID})
		var closed tenancy.NetworkClosure
		wait("actual managed Bridge closure "+input.network, func() bool {
			value, err := observe(input.node, row.BridgeKey)
			return err == nil && !value.Ready && len(value.Retirement) > 0 && json.Unmarshal(value.Retirement, &closed) == nil
		})
		pending, _ := resources().Networks.Change(input.tenant, original.ID)
		change(id+"/fence", "fence-network-change", pending.Revision, control.NetworkChangeFence{Tenant: input.tenant, ID: original.ID, Generation: pending.Generation, Closed: closed})
		pending, _ = resources().Networks.Change(input.tenant, original.ID)
		change(id+"/commit", "reconfigure-tun-network", resources().Networks.Revision(), control.NetworkReconfigure{Target: tenancy.TUNDefinition{Tenant: input.tenant, Name: input.network, Members: []tenancy.TUNNode{}}, Members: []tenancy.NetworkChangeVersion{{Tenant: input.tenant, ID: original.ID, Generation: pending.Generation, Revision: pending.Revision}}})
	}
	if len(resources().Networks.AllNetworks()) != 0 {
		t.Fatal("product retained original managed network definitions")
	}
	if faults {
		t.Log("actual two-owner route fault input: original same-tuple flow close/reuse, expired gate, authenticated old token and late claim rejection, bilateral packet pause/resume, original final route/app/DNS/network settlement")
	} else if identityMode {
		t.Log("RQ12 two consecutive current TLS identity rotations preserve original route native references, endpoint IDs and bilateral UDP pins; existing TCP/UDP positive and wrong-port/direction negative probes; current-identity additional Task borrows unchanged original TUN/DNS with a distinct endpoint, actual own-gateway DNS and routed TCP/UDP while all original natives/allocations/pins remain unchanged; original and successor app/route/DNS/network retirement and both namespace rollback; no new same-name route generation")
	} else if discoveryOnly {
		t.Log("RQ10 public route endpoints: source-only manager User/CLI discovery without receiver Read, original bilateral proposals/approvals, three containers/two tenants/two private Engines, remote and same-node TCP/UDP with exact source/port checks; original route/app/DNS TTL/Bridge closures and both namespace baselines; no restart/revocation/flow-GC claim")
	} else {
		t.Log("real CLI app.yaml; three containers/two tenants/two private Engines with Docker firewall enabled; own gateway authoritative DNS/foreign gateway timeout before and after route approval; remote and same-node TCP/UDP, exact ports/direction, same DB/native/UDP pin restart, product flow GC/peer tombstone, current node grant revocation, explicit new policy generation, management DNS closure before Bridge drain, both-owner retirement; rollback follows original journals")
	}
}

// The attacker is the OTHER owned node's underlay, not a host-local OUTPUT
// client that legitimately bypasses FORWARD. A temporary explicit route proves
// that lack of a route cannot manufacture the negative result.
func testRouteUnderlayIsolation(t *testing.T, backend, cidr, gateway, containerAddress, zone string, run func(int, []string, ...string) ([]byte, error)) {
	t.Helper()
	readRoute := func() ([]map[string]any, error) {
		raw, err := run(1, nil, "ip", "-j", "route", "show", "exact", cidr)
		var rows []map[string]any
		if err == nil {
			err = json.Unmarshal(raw, &rows)
		}
		return rows, err
	}
	before, err := readRoute()
	if err != nil || len(before) != 0 {
		t.Fatal("underlay route negative input has an existing foreign route", err)
	}
	// This exact selector is private to the fixture and cannot match a MyDC
	// route's separate policy table. Register cleanup BEFORE the first add.
	selector := []string{cidr, "via", "192.0.2.1", "proto", "static", "metric", "42701"}
	cleanup := func() {
		rows, err := readRoute()
		if err != nil {
			t.Error("underlay route rollback readback", err)
			return
		}
		if len(rows) == 0 {
			return
		}
		if len(rows) != 1 || rows[0]["dst"] != cidr || rows[0]["gateway"] != "192.0.2.1" || rows[0]["protocol"] != "static" || rows[0]["metric"] != float64(42701) {
			t.Error("underlay route identity changed; preserve foreign state")
			return
		}
		if raw, err := run(1, nil, append([]string{"ip", "route", "del"}, selector...)...); err != nil {
			t.Error("original underlay route rollback", err, string(raw))
			return
		}
		if rows, err := readRoute(); err != nil || len(rows) != 0 {
			t.Error("underlay route baseline not restored", err)
		}
	}
	t.Cleanup(cleanup)
	defer cleanup()
	if raw, err := run(1, nil, append([]string{"ip", "route", "add"}, selector...)...); err != nil {
		t.Fatal("explicit hostile underlay path", err, string(raw))
	}
	for _, protocol := range []string{"udp", "tcp"} {
		raw, err := run(1, nil, backend, "--route-dns", protocol, net.JoinHostPort(gateway, "53"), zone)
		var exited *exec.ExitError
		if !errors.As(err, &exited) || exited.ExitCode() != 2 {
			t.Fatal("untrusted underlay reached managed gateway or query failed before timeout", protocol, err, string(raw))
		}
	}
	raw, err := run(1, nil, backend, "--route-probe", "tcp", net.JoinHostPort(containerAddress, "33100"), "49101")
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 1 || !bytes.Contains(raw, []byte("route socket timeout:")) {
		t.Fatal("untrusted underlay reached private container or probe failed before socket timeout", err, string(raw))
	}
}
