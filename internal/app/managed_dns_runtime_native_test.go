// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
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

// Join only this process's socket FDs to its namespace's actual bound port53.
// Kernel socket inodes, rather than a metadata Ready flag, identify FD reuse.
func ownedDNSListeners(pid int) (map[string]string, error) {
	root := fmt.Sprintf("/proc/%d", pid)
	fds, err := os.ReadDir(root + "/fd")
	if err != nil {
		return nil, err
	}
	owned := map[string]bool{}
	for _, fd := range fds {
		target, _ := os.Readlink(root + "/fd/" + fd.Name())
		if strings.HasPrefix(target, "socket:[") {
			owned[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	out := map[string]string{}
	for _, protocol := range []string{"udp", "udp6", "tcp", "tcp6"} {
		raw, err := os.ReadFile(root + "/net/" + protocol)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 9 && strings.HasSuffix(fields[1], ":0035") && owned[fields[9]] && (strings.HasPrefix(protocol, "udp") || fields[3] == "0A") {
				out[protocol+"/"+fields[1]] = fields[9]
			}
		}
	}
	return out, nil
}

// The existing private two-owner fixture owns all processes/native rollback.
// This adds only the unverified logical-group DNS hot/query/closure inputs.
func testManagedDNSRuntime(t *testing.T, ctx context.Context, a *Runtime, root, products string, configs, sockets [2]string, manifest string, read func() cluster.View, change func(string, string, uint64, any), attempt func(string, string, uint64, any) state.Result, wait func(string, func() bool), pidB int, run func(int, []string, ...string) ([]byte, error)) {
	t.Helper()
	p := a.controlPolicy
	resource := func() control.Resources {
		t.Helper()
		r, err := p.Resources(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	backend := os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if !filepath.IsAbs(backend) {
		t.Fatal("prebuilt static backend required")
	}
	registry := registryfixture.OpenPreparedAt(t, backend, container.Config{Cmd: []string{"/backend"}, Env: []string{"SFC_DNS_FIXTURE=1"}, User: "10001:10001", Labels: map[string]string{"org.sfc.test.owner": os.Getenv("SFC_KERNEL_TEST_OWNER")}}, "192.0.2.1:0")
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	change("dns-runtime/trust", "set-trust", tenant.Revision, control.TrustChange{Tenant: "tenant", Add: []access.TrustRule{access.TrustRule{Registry: registry.Registry, Repository: "fixture"}}})
	public := sqlPublicFixture{Images: map[string]string{registry.Reference: registry.ConfigDigest}}
	var engines [2]*engine.Client
	var keys [2][32]byte
	for n, path := range configs {
		cfg, e := loadTestNode(path)
		if e != nil {
			t.Fatal(e)
		}
		id, e := identity.Load(cfg.Node.IdentityDir)
		if e != nil {
			t.Fatal(e)
		}
		keys[n] = id.Public
		clear(id.Private)
		engines[n], e = engine.Open(ctx, "unix://"+sockets[n], engine.Owner(p.Cluster, id.Public))
		if e != nil {
			t.Fatal(e)
		}
		defer engines[n].Close()
		info, e := engines[n].API.Info(ctx, client.InfoOptions{})
		if e != nil {
			t.Fatal(e)
		}
		public.EngineIDs[n] = info.Info.ID
	}
	if public.EngineIDs[0] == "" || public.EngineIDs[0] == public.EngineIDs[1] {
		t.Fatal("two private Engines required")
	}
	raw, _ := json.Marshal(public)
	if err = os.WriteFile(filepath.Join(root, "dns-fixture.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	remote := sfcp.Peer{ID: "node-b", Endpoint: "192.0.2.2:44101", Policy: sfcp.Policy{Key: sfcp.Identity(keys[1]), Member: true, Read: true, Respond: true}}
	observe := func(node, key string) (ModuleObservation, error) {
		var result ModuleObservation
		var raw []byte
		var e error
		if node == "node-b" {
			reply, callErr := cluster.CallManagement(ctx, a.Mesh, a.Identity, p.Cluster, remote, cluster.ManagementRequest{Method: "observe", Key: key, Latest: false})
			raw, e = reply.Data, callErr
		} else {
			raw, e = a.observeManaged(ctx, key, read())
		}
		if e == nil {
			e = json.Unmarshal(raw, &result)
		}
		return result, e
	}
	definition := tenancy.TUNDefinition{Tenant: "tenant", Name: "dns-runtime", GatewayMode: network.ManagedGatewayMode, Members: []tenancy.TUNNode{}}
	for n, node := range []string{"node-a", "node-b"} {
		definition.Members = append(definition.Members, tenancy.TUNNode{Node: node, Pools: []tenancy.Subnet{
			{ID: "v4", Prefix: netip.MustParsePrefix(fmt.Sprintf("198.19.86.%d/28", n*16)), Gateway: netip.MustParseAddr(fmt.Sprintf("198.19.86.%d", n*16+1)), MTU: 1280},
			{ID: "v6", Prefix: netip.MustParsePrefix(fmt.Sprintf("fd42:6d79:86:%x::/64", n+1)), Gateway: netip.MustParseAddr(fmt.Sprintf("fd42:6d79:86:%x::1", n+1)), MTU: 1280},
		}, Addresses: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("198.19.87.%d/32", n+1)), netip.MustParsePrefix(fmt.Sprintf("fd42:6d79:87::%x/128", n+1))}})
	}
	change("dns-runtime/network", "create-tun-network", resource().Networks.Revision(), definition)
	// An actual bounded upstream holds one original request per owner/pool.
	udp, err := net.ListenPacket("udp4", "192.0.2.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	type gate struct {
		entered, release chan struct{}
		once             sync.Once
		hits             atomic.Int32
	}
	gates := map[string]*gate{}
	for i := 0; i < 4; i++ {
		gates[fmt.Sprintf("hold%d.public.example.", i)] = &gate{entered: make(chan struct{}), release: make(chan struct{})}
	}
	var value atomic.Int32
	value.Store(9)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if len(q.Question) != 1 {
			return
		}
		original := byte(value.Load())
		if g := gates[q.Question[0].Name]; g != nil && g.hits.Add(1) == 1 {
			close(g.entered)
			select {
			case <-g.release:
			case <-ctx.Done():
				return
			}
		}
		answer := new(dns.Msg)
		answer.SetReply(q)
		answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(203, 0, 113, original)}}
		_ = w.WriteMsg(answer)
	})
	var servers []*dns.Server
	var serverDone []chan error

	var queryWorkers sync.WaitGroup
	t.Cleanup(func() {
		for _, g := range gates {
			g.once.Do(func() { close(g.release) })
		}
		queryWorkers.Wait()
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, s := range servers {
			if e := s.ShutdownContext(clean); e != nil {
				t.Error(e)
			}
		}
		for _, done := range serverDone {
			select {
			case e := <-done:
				if e != nil {
					t.Error(e)
				}
			case <-clean.Done():
				t.Error(clean.Err())
			}
		}
	})
	for _, s := range []*dns.Server{{PacketConn: udp, Handler: handler}, {Listener: tcp, Handler: handler}} {
		ready, done := make(chan struct{}), make(chan error, 1)
		s.NotifyStartedFunc = func() { close(ready) }
		servers, serverDone = append(servers, s), append(serverDone, done)
		go func() { done <- s.ActivateAndServe() }()
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	policy := services.ManagedDNSDefinition{Schema: 1, Tenant: "tenant", Network: "dns-runtime", Policy: services.ManagedDNSPolicy{Enabled: true, Zone: "dns-runtime.sfc.test.", TTL: 1, NegativeTTL: 1, Transports: []string{"udp", "tcp"}, Upstreams: []netip.AddrPort{netip.MustParseAddrPort(udp.LocalAddr().String())}, MaxQueries: 8, MaxCacheEntries: 8, MaxResponseBytes: 4096, MaxConnections: 8, RequestTimeoutMS: 15000}}
	policyKey := services.ManagedDNSKey("tenant", "dns-runtime")
	change("dns-runtime/enable", "configure-network-dns", 0, policy)
	profile, home := filepath.Join(root, "dns-client.yaml"), filepath.Join(root, "dns-home")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%s', endpoint: '192.0.2.1:44101', voter: true}\n", p.Cluster, a.Identity.Actor())), 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) {
		t.Helper()
		out, diagnostic, e := runManagedCLICommand(ctx, filepath.Join(products, "sfc"), home, profile, args, nil)
		if e != nil {
			t.Fatal(args, e, string(out), string(diagnostic))
		}
	}
	cli("wallet", "init")
	cli("login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin/key.pem"))
	app := "name: dns-clients\nservices:\n"
	for n, node := range []string{"node-a", "node-b"} {
		app += fmt.Sprintf(" client%d:\n  image: %s\n  command: [/backend]\n  environment: {SFC_DNS_FIXTURE: '1'}\n  user: '10001:10001'\n  cpus: 0.1\n  mem_limit: 16m\n  healthcheck: {test: [CMD, /backend, --tcp-probe, '127.0.0.1:8080'], interval: 1s, timeout: 2s, retries: 3}\n  networks: {lan: {ipv4_address: '198.19.86.%d', ipv6_address: 'fd42:6d79:86:%x::2'}}\n  x-sfc: {node: %s}\n", n, registry.Reference, n*16+2, n+1, node)
	}
	app += "networks:\n lan: {external: true, name: dns-runtime}\n"
	appPath := filepath.Join(root, "dns-app.yaml")
	if err = os.WriteFile(appPath, []byte(app), 0600); err != nil {
		t.Fatal(err)
	}
	cli("compose", "up", "--tenant", "tenant", "--operation", "dns-up", "--file", appPath, "--no-input")
	wait("DNS app and all four real owner/pool bindings", func() bool {
		apps, e := p.Apps(read().State)
		if e != nil {
			return false
		}
		ex, ok := apps.Execution("tenant", "dns-clients")
		if ok && (ex.Status() == "Failed" || ex.Status() == "Closed") {
			t.Fatal("DNS client deployment terminated before native queries", ex.Status())
		}
		if !ok || ex.Status() != "Succeeded" {
			return false
		}
		for _, node := range []string{"node-a", "node-b"} {
			o, e := observe(node, policyKey)
			if e != nil || !o.Ready || o.DNS == nil || o.DNS.Sockets != 2 || len(o.DNS.Resolvers) != 2 {
				return false
			}
		}
		return true
	})
	rows := func() []control.AppDNSOwner {
		t.Helper()
		apps, e := p.Apps(read().State)
		if e != nil {
			t.Fatal(e)
		}
		var out []control.AppDNSOwner
		for _, owner := range keys {
			_, list, ok := apps.NetworkDNS(owner)
			if !ok {
				t.Fatal("original shared DNS authority missing")
			}
			out = append(out, list...)
		}
		if len(out) != 4 {
			t.Fatal("four original DNS owner/pool instances required", len(out))
		}
		return out
	}
	original := rows()
	gateways := make([]netip.Addr, len(original))
	for i, row := range original {
		local, ok := resource().Networks.Network("tenant", row.Config.Network)
		if !ok {
			t.Fatal("original DNS network missing")
		}
		for _, pool := range local.Pools {
			if pool.ID == row.Config.Pool {
				gateways[i] = pool.Gateway
			}
		}
		if !gateways[i].IsValid() {
			t.Fatal("original DNS pool missing")
		}
	}
	before := [2]map[string]string{}
	for n, pid := range []int{os.Getpid(), pidB} {
		before[n], err = ownedDNSListeners(pid)
		if err != nil || len(before[n]) != 4 {
			t.Fatal("actual original DNS FDs", n, before[n], err)
		}
	}
	// Each HTTP request originates its DNS socket inside the actual nonroot
	// workload; curl itself remains in that node's owned namespace.
	query := func(index int, protocol, name string, kind uint16) (*dns.Msg, error) {
		row := original[index]
		node := 0
		if row.Managed.Node == "node-b" {
			node = 1
		}
		address := fmt.Sprintf("198.19.86.%d", node*16+2)
		q := new(dns.Msg)
		q.SetQuestion(name, kind)
		wire, e := q.Pack()
		if e != nil {
			return nil, e
		}
		path := filepath.Join(root, fmt.Sprintf("dns-wire-%d-%s-%d", index, protocol, q.Id))
		if e = os.WriteFile(path, wire, 0600); e != nil {
			return nil, e
		}
		defer os.Remove(path)
		values := url.Values{"server": {netip.AddrPortFrom(gateways[index], 53).String()}, "transport": {protocol}, "timeout_ms": {"15000"}}
		raw, e := run(node, nil, "curl", "--noproxy", "*", "--silent", "--show-error", "--fail-with-body", "--max-time", "16", "-H", "Content-Type: application/dns-message", "--data-binary", "@"+path, "http://"+address+":8080/dns-query?"+values.Encode())
		if e != nil {
			return nil, fmt.Errorf("actual workload DNS: %w: %s", e, raw)
		}
		answer := new(dns.Msg)
		if e = answer.Unpack(raw); e != nil {
			return nil, e
		}
		if answer.Id != q.Id || !answer.Response || len(answer.Question) != 1 || answer.Question[0] != q.Question[0] || answer.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("actual DNS answer differs from original question: %v", answer)
		}
		return answer, nil
	}
	soa := func(index int, protocol string, ttl uint32) {
		t.Helper()
		answer, e := query(index, protocol, policy.Policy.Zone, dns.TypeSOA)
		if e != nil || !answer.Authoritative || len(answer.Answer) != 1 {
			t.Fatal("actual authoritative DNS", index, protocol, answer, e)
		}
		record, ok := answer.Answer[0].(*dns.SOA)
		if !ok || record.Hdr.Ttl != ttl {
			t.Fatal("actual hot TTL", index, answer)
		}
	}
	for i := range original {
		soa(i, "udp", 1)
		soa(i, "tcp", 1)
	}
	type result struct {
		answer *dns.Msg
		err    error
	}
	var pending []chan result
	for i := range original {
		out := make(chan result, 1)
		pending = append(pending, out)
		queryWorkers.Add(1)
		go func() {
			defer queryWorkers.Done()
			answer, e := query(i, "tcp", fmt.Sprintf("hold%d.public.example.", i), dns.TypeA)
			out <- result{answer, e}
		}()
	}
	for i := range original {
		select {
		case <-gates[fmt.Sprintf("hold%d.public.example.", i)].entered:
		case result := <-pending[i]:
			t.Fatal("original query ended before reaching the owned upstream", i, result.answer, result.err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	oldRevision := read().State.Object(policyKey).Revision
	policy.Policy.TTL, policy.Policy.NegativeTTL = 2, 2
	change("dns-runtime/hot", "configure-network-dns", oldRevision, policy)
	value.Store(19)
	wait("all four DNS pools publish hot source without replacing lifetimes", func() bool {
		current := rows()
		for i, row := range current {
			if row.Reference != original[i].Reference || row.Config.Source <= original[i].Config.Source {
				return false
			}
		}
		for _, node := range []string{"node-a", "node-b"} {
			o, e := observe(node, policyKey)
			if e != nil || !o.Ready || o.DNS == nil || o.DNS.Queries != 2 {
				return false
			}
		}
		return true
	})
	for i := range original {
		soa(i, "udp", 2)
	}
	checkAddress := func(answer *dns.Msg, e error, want string) {
		t.Helper()
		if e != nil || answer == nil || len(answer.Answer) != 1 {
			t.Fatal("forwarded original query", answer, e)
		}
		record, ok := answer.Answer[0].(*dns.A)
		if !ok || record.A.String() != want {
			t.Fatal("old query/new cache result mixed", answer, want)
		}
	}
	for i := range original {
		answer, e := query(i, "udp", fmt.Sprintf("hold%d.public.example.", i), dns.TypeA)
		checkAddress(answer, e, "203.0.113.19")
	}
	for _, g := range gates {
		g.once.Do(func() { close(g.release) })
	}
	for _, out := range pending {
		select {
		case result := <-out:
			checkAddress(result.answer, result.err, "203.0.113.9")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	for i := range original {
		answer, e := query(i, "tcp", fmt.Sprintf("hold%d.public.example.", i), dns.TypeA)
		checkAddress(answer, e, "203.0.113.19")
	}
	// A rejected stale management CAS leaves the applied target and FDs intact.
	committed := read().State.Object(policyKey)
	if result := attempt("dns-runtime/stale", "configure-network-dns", oldRevision, policy); result.Code != state.ConditionFailed || read().State.Object(policyKey) != committed {
		t.Fatal("stale DNS management changed last known good", result)
	}
	for i := range original {
		soa(i, "tcp", 2)
	}
	for n, pid := range []int{os.Getpid(), pidB} {
		after, e := ownedDNSListeners(pid)
		if e != nil || !maps.Equal(before[n], after) {
			t.Fatal("hot/LKG replaced original process/listeners", n, before[n], after, e)
		}
	}
	cli("compose", "down", "--tenant", "tenant", "-p", "dns-clients", "--operation", "dns-down")
	wait("actual DNS app Tasks and original references Retired", func() bool {
		s := read().State
		apps, e := p.Apps(s)
		if e != nil {
			return false
		}
		inventory, ok := apps.Inventory("tenant", "dns-clients")
		if !ok || !inventory.Quiescent() {
			return false
		}
		op, ok := inventory.Operation("dns-up")
		if !ok || op.Status != "Retired" || op.CompletedAt == 0 {
			return false
		}
		for _, claim := range inventory.Claims() {
			if !claim.Removed || s.Object(claim.Step.Key).Present {
				return false
			}
		}
		return true
	})
	paused := false
	t.Cleanup(func() {
		if paused {
			_ = syscall.Kill(pidB, syscall.SIGCONT)
		}
	})
	if err = syscall.Kill(pidB, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	paused = true
	policy.Policy.Enabled = false
	change("dns-runtime/disable", "configure-network-dns", read().State.Object(policyKey).Revision, policy)
	counts := func() (int, int) {
		apps, e := p.Apps(read().State)
		if e != nil {
			t.Fatal(e)
		}
		closedA, closedB := 0, 0
		for n, owner := range keys {
			authority, list, ok := apps.NetworkDNS(owner)
			if !ok {
				t.Fatal("DNS original shared reference missing")
			}
			for _, row := range list {
				ref, ok := authority.ReferenceConsumer(row.Reference)
				if !ok {
					t.Fatal("original DNS instance disappeared")
				}
				if ref.Closed != nil {
					if n == 0 {
						closedA++
					} else {
						closedB++
					}
				}
			}
		}
		return closedA, closedB
	}
	wait("local two DNS closures with original peer process stopped", func() bool { local, remote := counts(); return local == 2 && remote == 0 })
	if !read().State.Object(policyKey).Present {
		t.Fatal("one owner erased the whole DNS policy/source")
	}
	if after, e := ownedDNSListeners(pidB); e != nil || !maps.Equal(before[1], after) {
		t.Fatal("stopped peer's sockets inferred Gone", after, e)
	}
	if err = syscall.Kill(pidB, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	paused = false
	wait("all four original signed DNS closures", func() bool { local, remote := counts(); return local == 2 && remote == 2 })
	retireDNSManagedGroup(t, p, read, change, wait, observe, "dns-runtime")
	report := map[string]any{"schema": 1, "original_rows": original, "pids": []int{os.Getpid(), pidB}, "listener_inodes": before, "hot_lifetimes_preserved": true, "old_query_answers": "203.0.113.9", "new_view_cache": "203.0.113.19", "stale_cas_lkg": true, "one_owner_cannot_close_peer": true, "four_signed_closures": true, "final_network_retired": true}
	raw, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var ownerManifest map[string]any
	existing, e := os.ReadFile(manifest)
	if e != nil || json.Unmarshal(existing, &ownerManifest) != nil {
		t.Fatal("original DNS public manifest", e)
	}
	ownerManifest["dns_runtime"] = json.RawMessage(raw)
	existing, _ = json.Marshal(ownerManifest)
	if e = os.WriteFile(manifest, existing, 0644); e != nil {
		t.Fatal(e)
	}
	t.Log("actual two-owner/four IPv4+IPv6 pool DNS: CLI app, UDP/TCP SOA, hot TTL with original lifetimes/PIDs/socket inodes, four held original TCP queries, new-view cache isolation, rejected CAS LKG, stopped peer retains original sockets/reference, all four signed closures and explicit managed network retirement")
}

func retireDNSManagedGroup(t *testing.T, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), observe func(string, string) (ModuleObservation, error), name string) {
	t.Helper()
	r, err := p.Resources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := r.Networks.TUNSources("tenant", name)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		target := row.Network
		target.Generation, target.Revision, target.PendingChange = 0, 0, 0
		target.Owner = [32]byte{}
		change("dns-retire/plan/"+row.Network.Node, "plan-network-change", row.Network.Revision, control.NetworkChangePlan{Tenant: "tenant", ID: row.Network.ID, Change: "dns-retire-" + row.Network.Node, Target: target})
	}
	for _, row := range rows {
		change("dns-retire/drain/"+row.Network.Node, "drain-network", row.Network.Revision, control.NetworkSelection{Tenant: "tenant", ID: row.Network.ID})
	}
	var versions []tenancy.NetworkChangeVersion
	for _, row := range rows {
		var proof tenancy.NetworkClosure
		wait("exact original DNS member native closure "+row.Network.Node, func() bool {
			current, e := p.Resources(read().State)
			if e != nil {
				return false
			}
			network, ok := current.Networks.Network("tenant", row.Network.ID)
			if !ok {
				return false
			}
			o, e := observe(row.Network.Node, row.BridgeKey)
			return e == nil && !o.Ready && len(o.Retirement) != 0 && json.Unmarshal(o.Retirement, &proof) == nil && proof.Generation == network.Generation && proof.Revision == network.Revision
		})
		current, e := p.Resources(read().State)
		if e != nil {
			t.Fatal(e)
		}
		candidate, _ := current.Networks.Change("tenant", row.Network.ID)
		change("dns-retire/fence/"+row.Network.Node, "fence-network-change", candidate.Revision, control.NetworkChangeFence{Tenant: "tenant", ID: row.Network.ID, Generation: candidate.Generation, Closed: proof})
		current, _ = p.Resources(read().State)
		candidate, _ = current.Networks.Change("tenant", row.Network.ID)
		versions = append(versions, tenancy.NetworkChangeVersion{Tenant: "tenant", ID: row.Network.ID, Generation: candidate.Generation, Revision: candidate.Revision})
	}
	r, _ = p.Resources(read().State)
	change("dns-retire/commit", "reconfigure-tun-network", r.Networks.Revision(), control.NetworkReconfigure{Target: tenancy.TUNDefinition{Tenant: "tenant", Name: name, Members: []tenancy.TUNNode{}}, Members: versions})
}
