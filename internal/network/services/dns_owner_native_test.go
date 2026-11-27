// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/enginefixture"
	"github.com/miekg/dns"
	"github.com/moby/moby/client"
)

type dnsNetworkReadKey struct{}
type dnsNetworkReadTransport struct {
	base  http.RoundTripper
	calls *atomic.Int64
}

func (d dnsNetworkReadTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Context().Value(dnsNetworkReadKey{}) == true && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/networks/") {
		d.calls.Add(1)
	}
	return d.base.RoundTrip(r)
}

func TestRealBoundaryDNSOwnerSingleNetworkReadPreservesEndpointProvenance(t *testing.T) {
	testRealDNSOwnerNative(t, false, false, false, false, false, false, true)
}

func TestRealBoundaryDNSOwnerSocketsQueriesOriginalDBAndRetirement(t *testing.T) {
	testRealDNSOwnerNative(t, false)
}
func TestRealBoundaryDNSOwnerProtocolAndInFlightReplacement(t *testing.T) {
	testRealDNSOwnerNative(t, true)
}
func TestRealBoundaryDNSOriginDoesNotProbeDependentReadiness(t *testing.T) {
	testRealDNSOwnerNative(t, false, true)
}
func TestRealBoundaryDNSOwnerReopensOnNewBridgeGeneration(t *testing.T) {
	testRealDNSOwnerNative(t, false, false, true)
}
func TestRealBoundaryDNSOwnerIndependentBridgeGeneration(t *testing.T) {
	testRealDNSOwnerNative(t, false, false, false, true)
}

func TestRealBoundaryDNSOwnerSameBootProcessCrashAndSocketRecovery(t *testing.T) {
	testRealDNSOwnerNative(t, false, false, false, false, true)
}

func TestRealBoundaryDNSOwnerPreviousBootJournalAndActualSocketRebind(t *testing.T) {
	testRealDNSOwnerNative(t, false, false, false, false, false, true)
}

func testRealDNSOwnerNative(t *testing.T, protocol bool, dependentReadiness ...bool) {
	dependent := len(dependentReadiness) >= 1 && dependentReadiness[0]
	redeploy := len(dependentReadiness) >= 2 && dependentReadiness[1]
	separateGenerations := len(dependentReadiness) >= 3 && dependentReadiness[2]
	crash := len(dependentReadiness) >= 4 && dependentReadiness[3]
	rebind := len(dependentReadiness) >= 5 && dependentReadiness[4]
	singleNetworkRead := len(dependentReadiness) >= 6 && dependentReadiness[5]
	owner, backend := os.Getenv("SFC_DOCKER_TEST_OWNER"), os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if owner == "" || backend == "" || os.Geteuid() != 0 {
		t.Skip("requires owned rollback prestate and user-prebuilt backend/test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	native := enginefixture.OpenPrepared(t, ctx, owner, owner, []string{`USER 10001:10001`, `ENV SFC_DNS_FIXTURE=1`}, backend)
	var networkReads atomic.Int64
	if singleNetworkRead {
		originalAPI := native.Client.API
		path := strings.TrimPrefix(originalAPI.DaemonHost(), "unix://")
		if !strings.HasPrefix(originalAPI.DaemonHost(), "unix://") {
			t.Fatal("owned local Engine required")
		}
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}
		api, err := client.New(client.WithHost(originalAPI.DaemonHost()), client.WithAPIVersion(originalAPI.ClientVersion()), client.WithHTTPClient(&http.Client{Transport: dnsNetworkReadTransport{transport, &networkReads}}))
		if err != nil {
			t.Fatal(err)
		}
		native.Client.API = api
		t.Cleanup(func() { _ = originalAPI.Close(); transport.CloseIdleConnections() })
	}

	root, err := os.MkdirTemp("", "sfc-dns-owner-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("preserved original DNS/network/workload journals: %s", root)
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	n, err := network.OpenManager(filepath.Join(root, "network.db"), native.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if n != nil {
			_ = n.Close()
		}
	}()
	w, err := workload.OpenManager(filepath.Join(root, "workload.db"), native.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if w != nil {
			_ = w.Close()
		}
	}()
	prefix := netip.MustParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	gateway := prefix.Addr().Next()
	bridgeKey, taskKey := "network/owner-dns", "workload/task/first/demo/web"
	bridge := network.BridgeSpec{Schema: 1, Network: "lan", Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "lan/pool", Network: "lan", Owner: owner, Prefix: prefix, Gateway: gateway, MTU: 1280}}}
	bridgeGeneration := uint64(1)
	if separateGenerations {
		bridgeGeneration = 7
	}
	if err = n.Desired(bridgeKey, 1, bridgeGeneration, &bridge, 8); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	f := fixture(t) // Pure committed policy input; this is not a Raft/CLI proof.
	networks, err := tenancy.New(f.n.Cluster())
	if err != nil {
		t.Fatal(err)
	}
	networks, err = networks.Create(f.c, "admin", networks.Revision(), tenancy.Network{Tenant: "first", ID: "lan", Node: "node-a", Owner: pub(f.key), Pools: []tenancy.Subnet{{ID: "pool", Prefix: prefix, Gateway: gateway, MTU: 1280}}})
	if err != nil {
		t.Fatal(err)
	}
	book, err := networks.AddressPlan(16)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority(networks.Cluster(), book)
	if err != nil {
		t.Fatal(err)
	}
	local, _ := source(networks, networks.Cluster(), "first", "lan", "pool")
	var allocation network.Allocation
	authority, allocation, err = authority.ReserveStatic(taskKey+"/lan/0", poolOwner(local), "first/lan", "first/lan/pool", 2, gateway.Next())
	if err != nil {
		t.Fatal(err)
	}
	cfg := DNSConfig{Tenant: "first", ID: "dns", Network: "lan", Pool: "pool", Source: 1, Serial: 1, Enabled: true, Zone: "app.sfc.test.", TTL: 1, NegativeTTL: 1, QuerySeconds: 2, MaxQueries: 4, MaxCacheEntries: 2, MaxResponseBytes: 4096, Names: []DNSName{{"probe", allocation.Endpoint, allocation.Generation}}}
	var upstream *dnsProtocolUpstream
	if protocol {
		upstream = openDNSProtocolUpstream(t, ctx)
		cfg.Reverse = true
		cfg.QuerySeconds = 3
		cfg.TTL = 3
		cfg.NegativeTTL = 2
		cfg.Upstreams = []netip.AddrPort{upstream.address}
	}
	authority, reference, err := authority.GrantDNSInstance(f.c, networks, "admin", 0, cfg)
	if err != nil {
		t.Fatal(err)
	}
	policy := DNSOwnerPolicy{Catalog: f.c, Networks: networks, Authority: authority, Actor: "admin", Config: cfg, Bridge: bridgeKey, BridgeGeneration: bridgeGeneration, MaxConnections: 4}
	if separateGenerations && reference.Local.NetworkGeneration == bridgeGeneration {
		t.Fatal("counterexample must use independent logical/native generations")
	}
	if protocol {
		policy.RequestTimeout = 2 * time.Second
	}
	var policyMu sync.Mutex
	var deny atomic.Bool
	deny.Store(true)
	options := DNSOwnerOptions{Cluster: networks.Cluster(), Key: f.key, Network: n, Workload: w, Roots: []string{"sfc.test."}, MaxViews: 16, MaxQueries: 8, MaxConnections: 4, IdleTimeout: time.Second,
		Current: func(_ context.Context, tenant, id string) (DNSOwnerPolicy, error) {
			policyMu.Lock()
			defer policyMu.Unlock()
			if tenant != "first" || id != "dns" {
				return DNSOwnerPolicy{}, ErrLease
			}
			return policy, nil
		},
		Permit: func(context.Context, DNSOwnerPolicy) error {
			if deny.Load() {
				return errors.New("current native permit denied")
			}
			return nil
		},
	}
	dbPath := filepath.Join(root, "dns.db")
	o, err := OpenDNSOwner(dbPath, options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if o != nil {
			if e := o.Close(); e != nil {
				t.Error(e)
			}
		}
	}()
	if err = o.Apply(ctx, "first", "dns"); err == nil {
		t.Fatal("missing permit accepted")
	}
	bridgeRecord, _ := n.View(bridgeKey)
	if len(bridgeRecord.Consumers) != 0 {
		t.Fatal("denied permit acquired a Bridge pin")
	}
	deny.Store(false)
	if separateGenerations {
		policyMu.Lock()
		policy.BridgeGeneration = bridgeGeneration + 1
		policyMu.Unlock()
		if err := o.Apply(ctx, "first", "dns"); err == nil {
			t.Fatal("wrong native generation accepted despite current logical authority")
		}
		row, err := n.View(bridgeKey)
		if err != nil || len(row.Consumers) != 0 || o.Status("first", "dns").Settings.Pending != 0 {
			t.Fatal("wrong native generation acquired a pin or dispatched DNS", err)
		}
		policyMu.Lock()
		policy.BridgeGeneration = bridgeGeneration
		policyMu.Unlock()
		t.Log("independent generations: logical", reference.Local.NetworkGeneration, "native", bridgeGeneration, "; wrong native generation refused without pin or dispatch")
	}
	// A real port conflict must keep the ORIGINAL dispatched operation and
	// close its partially prepared UDP FD. Nothing becomes Applied/Ready.
	conflict, err := net.Listen("tcp4", netip.AddrPortFrom(gateway, 53).String())
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Apply(ctx, "first", "dns"); err == nil {
		_ = conflict.Close()
		t.Fatal("port conflict became Ready")
	}
	if status := o.Status("first", "dns"); status.Ready || status.Settings.Pending != 1 || status.Settings.Applied != 0 {
		t.Fatal("conflict lost original journal", status, err)
	}
	if err = conflict.Close(); err != nil {
		t.Fatal(err)
	}
	if err = o.Apply(ctx, "first", "dns"); err != nil {
		t.Fatal("resume exact original preparation", err)
	}
	if status := o.Status("first", "dns"); !status.Ready || status.Settings.Pending != 0 || status.Settings.Applied != 1 || status.Settings.Observed != 1 {
		t.Fatal("native owner not ready", status)
	}
	var group uint64
	for id := range o.sockets {
		group = id
	}
	originalGroup := o.sockets[group]
	if o.settings.groups[group].State.LastID != 1 {
		t.Fatal("conflict generated a replacement operation")
	}
	image, err := native.Client.Image(ctx, native.Image, false)
	if err != nil {
		t.Fatal(err)
	}
	process, err := workload.ResolveImageProcess(image, workload.ProcessOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	spec := workload.ContainerSpec{Schema: 1, Node: owner, Image: native.Image, Bridge: bridgeKey, BridgeGeneration: bridgeGeneration, IPv4: allocation.Address, Memory: 32 << 20, NanoCPU: 100000000, Process: &process, Resolver: &workload.Resolver{Servers: []netip.Addr{gateway}, Search: []string{"app.sfc.test"}}}
	if dependent {
		spec.Readiness = &workload.HTTPReadiness{Path: "/resolve?name=probe", Port: 8080}
	}
	if err = w.Desired(taskKey, 2, 2, &spec, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	status, err := w.Status(ctx, taskKey)
	if err != nil || !status.Running {
		t.Fatal(status, err)
	}
	originalNative := status.NativeID
	httpClient := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer httpClient.CloseIdleConnections()
	query := func(protocol string) {
		t.Helper()
		for {
			req, e := http.NewRequestWithContext(ctx, "GET", "http://"+allocation.Address.String()+":8080/resolve?name=probe&transport="+protocol, nil)
			if e != nil {
				t.Fatal(e)
			}
			response, e := httpClient.Do(req)
			if e == nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 128))
				_ = response.Body.Close()
				if readErr != nil || response.StatusCode != 200 || string(body) != allocation.Address.String() {
					t.Fatal("actual owner DNS lookup", protocol, response.StatusCode, string(body), readErr)
				}
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	query("udp")
	query("tcp")
	if dependent {
		nativeID, running, err := w.NativeIdentity(ctx, taskKey)
		if err != nil || !running || nativeID != originalNative {
			t.Fatal("original identity without application readiness", nativeID, running, err)
		}
		status, err := w.Status(ctx, taskKey)
		if err != nil || !status.HTTPConfigured || !status.HTTPReady || !status.Ready {
			t.Fatal("readiness that consumes DNS must complete without recursive admission", status, err)
		}
		t.Log("actual HTTP readiness performs DNS/search; DNS admission checks native identity/attachment without invoking HTTP; original Status still probes and becomes Ready")
	}
	waitSettled := func() {
		t.Helper()
		for o.Status("first", "dns").Queries != 0 {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		if s := o.Status("first", "dns"); s.Failed || s.Settings.Users != 0 {
			t.Fatal("original query pin not returned", s)
		}
	}
	waitSettled()
	if singleNetworkRead {
		binding := originalGroup.binding
		lease := binding.Lease()
		before, err := n.View(bridgeKey)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			native  string
			address netip.Addr
			success bool
		}{
			{originalNative, allocation.Address, true},
			{"foreign-native", allocation.Address, false},
			{originalNative, allocation.Address.Next(), false},
		} {
			networkReads.Store(0)
			err := binding.HasEndpoint(context.WithValue(ctx, dnsNetworkReadKey{}, true), tc.native, tc.address)
			if (err == nil) != tc.success || networkReads.Load() != 1 {
				t.Fatal("endpoint provenance or single SDK read lost", tc.success, networkReads.Load(), err)
			}
		}
		after, err := n.View(bridgeKey)
		if err != nil || before.Consumers[lease.Consumer] != lease.Pin || after.Consumers[lease.Consumer] != lease.Pin || len(before.Consumers) != len(after.Consumers) {
			t.Fatal("endpoint checks changed original pins", err)
		}
		t.Log("one actual NetworkInspect per endpoint check; original Bridge/kernel/namespace and endpoint accepted, foreign native/address denied, pins unchanged")
	}
	if protocol {
		current := func() DNSOwnerPolicy { policyMu.Lock(); defer policyMu.Unlock(); return policy }
		replace := func(next DNSConfig) {
			policyMu.Lock()
			defer policyMu.Unlock()
			cfg = ownDNSConfig(next)
			policy.Config = cfg
			var e error
			policy.Authority, _, e = policy.Authority.GrantDNSInstance(f.c, networks, "admin", reference.Generation, cfg)
			if e != nil {
				t.Fatal(e)
			}
		}
		protect := func(zones []string) {
			policyMu.Lock()
			defer policyMu.Unlock()
			policy.ProtectedZones = append([]string(nil), zones...)
		}
		deadline := func(d time.Duration) { policyMu.Lock(); defer policyMu.Unlock(); policy.RequestTimeout = d }
		verifyDNSNativeProtocol(t, ctx, o, upstream, gateway, allocation.Address, current, replace, protect, deadline)
		waitSettled()
	}
	outside := new(dns.Msg)
	outside.SetQuestion("probe.app.sfc.test.", dns.TypeA)
	if response, _, e := (&dns.Client{Net: "udp4", Timeout: 150 * time.Millisecond}).ExchangeContext(ctx, outside, netip.AddrPortFrom(gateway, 53).String()); e == nil && response != nil {
		t.Fatal("host query outside the approved endpoint received an answer")
	}
	// Actual source origin is derived from the owning workload journal plus
	// Engine endpoint, not accepted from packet source IP alone.
	if _, err = o.origin(ctx, policy, originalGroup.binding, gateway); err == nil {
		t.Fatal("unallocated host origin accepted")
	}
	bad := policy
	bad.Authority, err = NewAuthority(networks.Cluster(), book)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.origin(ctx, bad, originalGroup.binding, allocation.Address); err == nil {
		t.Fatal("Engine IP without original committed allocation accepted")
	}
	borrowed := originalGroup.binding.Lease()
	borrowed.Spec.Pools[0].Gateway = netip.MustParseAddr("192.0.2.99")
	if originalGroup.binding.Lease().Spec.Pools[0].Gateway != gateway {
		t.Fatal("binding leaked mutable provenance")
	}
	policyMu.Lock()
	cfg.Source++
	cfg.Serial++
	cfg.TTL = 5
	policy.Config = cfg
	policy.Authority, _, err = policy.Authority.GrantDNSInstance(f.c, networks, "admin", reference.Generation, cfg)
	policyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Apply(ctx, "first", "dns"); err != nil {
		t.Fatal("hot source", err)
	}
	if o.sockets[group] != originalGroup || o.settings.groups[group].State.LastID != 1 {
		t.Fatal("hot change rebound original socket")
	}
	query("udp")
	waitSettled()
	originalSwitchID := o.settings.scopes["dns/first/dns"].Switch.LastID
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(dbPath, dbPath+".saved"); err != nil {
		t.Fatal(err)
	}
	if fresh, e := OpenDNSOwner(dbPath, options); e == nil {
		_ = fresh.Close()
		t.Fatal("lost owner DB reset native journal")
	}
	if err = os.Rename(dbPath+".saved", dbPath); err != nil {
		t.Fatal(err)
	}
	if rebind {
		injectDNSPreviousBootJournal(t, dbPath, options)
	}
	if crash {
		o = crashNativeDNSOwner(t, ctx, root, dbPath, native.Client, &n, &w, &options, func() { query("udp"); query("tcp") })
	} else {
		o, err = OpenDNSOwner(dbPath, options)
	}
	if err != nil {
		t.Fatal("same DB reopen", err)
	}
	if o.Status("first", "dns").Ready {
		t.Fatal("stored metadata claimed live socket")
	}
	if crash || rebind {
		deny.Store(true)
		if err := o.Apply(ctx, "first", "dns"); err == nil || o.Status("first", "dns").Ready || len(o.sockets) != 0 {
			t.Fatal("recovery bypassed current native permit", err)
		}
		deny.Store(false)
	}
	if err = o.Apply(ctx, "first", "dns"); err != nil {
		t.Fatal("original DB/socket resume", err)
	}
	if len(o.sockets) != 1 || o.settings.groups[group].State.LastID != 1 || o.settings.scopes["dns/first/dns"].Switch.LastID != originalSwitchID {
		t.Fatal("reopen resubmitted native operation")
	}
	if rebind {
		b := o.bridges[group]
		actual := o.sockets[group].binding
		if b.Boot != o.boot || b.Namespace != actual.Namespace() || b.Interface != actual.Interface() || b.Index != actual.Index() || !sameDNSBridgeLease(b.Lease, actual.Lease()) {
			t.Fatal("rebind did not join actual kernel scope to original lease")
		}
		t.Log("injected previous-boot journal; actual UDP/TCP bind/read-back, unchanged original operations/Task/Bridge pin; not a physical kernel reboot")
	}
	current, err := w.Status(ctx, taskKey)
	if err != nil || current.NativeID != originalNative {
		t.Fatal("original native Task replaced", err)
	}
	query("tcp")
	waitSettled()
	// Stop admission while the original TTL still pins this lifetime. A new
	// explicit enabled target must recover the original group after Stop/Wait,
	// never attest Serving for the old closed file descriptors.
	policyMu.Lock()
	cfg.Source++
	cfg.Serial++
	cfg.Enabled = false
	policy.Config = cfg
	policy.Authority, _, err = policy.Authority.GrantDNSInstance(f.c, networks, "admin", reference.Generation, cfg)
	policyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if proof, e := o.Retire(ctx, "first", "dns"); !errors.Is(e, reconcile.ErrPending) || proof != nil || o.Status("first", "dns").Ready {
		t.Fatal("TTL retirement should retain original lifetime with native stopped", proof, e)
	}
	stoppedGroup := o.sockets[group]
	policyMu.Lock()
	cfg.Source++
	cfg.Serial++
	cfg.Enabled = true
	policy.Config = cfg
	policy.Authority, _, err = policy.Authority.GrantDNSInstance(f.c, networks, "admin", reference.Generation, cfg)
	policyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Apply(ctx, "first", "dns"); err != nil {
		t.Fatal("explicit reactivation after joined sockets", err)
	}
	if !o.Status("first", "dns").Ready || o.sockets[group] == stoppedGroup || o.settings.groups[group].State.LastID != 1 {
		t.Fatal("reactivation lost original prepare identity or reused closed sockets")
	}
	query("udp")
	waitSettled()
	if err = w.Desired(taskKey, 3, 2, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	if gone, e := w.Gone(ctx, taskKey, 3, 2); e != nil || !gone {
		t.Fatal("original Task not gone", gone, e)
	}
	policyMu.Lock()
	cfg.Source++
	cfg.Serial++
	cfg.Enabled = false
	policy.Config = cfg
	policy.Authority, _, err = policy.Authority.GrantDNSInstance(f.c, networks, "admin", reference.Generation, cfg)
	policyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var closed *ReferenceClose
	retireStarted := time.Now()
	for {
		closed, err = o.Retire(ctx, "first", "dns")
		if err == nil {
			break
		}
		if !errors.Is(err, reconcile.ErrPending) {
			t.Fatal("retire original owner", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	if o.Status("first", "dns").Ready || len(o.sockets) != 0 || len(o.dns.Views()) != 0 || len(o.dns.Queries()) != 0 {
		t.Fatal("retirement retained native work")
	}
	if protocol && time.Since(retireStarted) < time.Duration(cfg.TTL)*time.Second {
		t.Fatal("whole-second clock returned original lifetime before actual TTL elapsed", time.Since(retireStarted), cfg.TTL)
	}
	policy.Authority, err = policy.Authority.ObserveReferenceClose(*closed, time.Now().Unix())
	if err != nil {
		t.Fatal("original signed A3 closure", err)
	}
	ref, known := policy.Authority.ReferenceConsumer(reference.ID)
	if !known || ref.Closed == nil || ref.Lifetime != reference.Lifetime {
		t.Fatal("original shared lifetime not settled")
	}
	bridgeRecord, err = n.View(bridgeKey)
	if err != nil || len(bridgeRecord.Consumers) != 0 {
		t.Fatal("original Bridge pin retained", err)
	}
	if !redeploy {
		if err = o.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err = n.Desired(bridgeKey, 4, bridgeGeneration, nil, 8); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	if gone, e := n.Gone(ctx, bridgeKey, 4, bridgeGeneration, bridge); e != nil || !gone {
		t.Fatal("original Bridge not gone", gone, e)
	}
	if redeploy {
		o, policy = verifyDNSOwnerRecreatedBridge(t, ctx, o, n, policy, bridge, bridgeKey, allocation, closed, originalNative, f.key, func(next DNSOwnerPolicy) { policyMu.Lock(); policy = next; policyMu.Unlock() })
	}
	if path := os.Getenv("SFC_NATIVE_MANIFEST"); path != "" {
		raw, _ := json.Marshal(map[string]any{"schema": 1, "udp_tcp": true, "same_db_native_id": originalNative, "original_group": group, "original_prepare_id": 1, "hot_rebinds": 0, "retired": true, "shared_reference": reference.ID, "bridge_consumers": 0})
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("actual product DNS owner: UDP/TCP + native endpoint provenance + original conflict operation + hot FD reuse + atomic query/Settings DB + clean same-DB resume + explicit deactivate/reactivate after Stop/Wait with original preparation + original TTL and signed lifetime/Bridge settlement; committed policy/permit are fixtures, not CLI/Raft/multi-owner proof")
}
