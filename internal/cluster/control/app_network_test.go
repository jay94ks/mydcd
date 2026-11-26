// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"

	"github.com/hashicorp/raft"
)

// Native observations and the accepted graph are explicit fixtures here.
// Reports, committed Goal generations, MYDCP, Raft, DB and Snapshot are real.
func TestRealAppDNSProjectionReportSerialAndSnapshotSameDB(t *testing.T) {
	testRealAppDNSProjection(t, false)
}

func TestRealAppDNSProjectionPreservesArchivedSerialFloor(t *testing.T) {
	testRealAppDNSProjection(t, true)
}

func testRealAppDNSProjection(t *testing.T, archived bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	p, _, oldApps, c := appHistoryFixture(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{101}, 32))
	self, err := identity.FromSeed(bytes.Repeat([]byte{101}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	peer := mydcp.Peer{ID: "source", Policy: mydcp.Policy{Key: mydcp.Identity(p.TrustRoot), Member: true, Read: true, Snapshot: true, Respond: true}}
	lookup := func(key mydcp.Identity) (mydcp.Peer, bool) { return peer, key == peer.Key }
	server, err := mydcp.NewTransport(self, p.Cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	peer.Endpoint, p.Genesis.Endpoint = server.Addr().String(), server.Addr().String()
	caller, err := mydcp.NewTransport(self, p.Cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = caller.Close() }()
	seeds := map[string]map[string][]byte{}
	options := cluster.Options{ID: "source", Root: filepath.Join(t.TempDir(), "node"), Admin: "legacy-admin", Cluster: p.Cluster, Mesh: server, Bootstrap: true, ModuleID: p.ID(), Validate: p.ValidateManaged, AdmitModule: p.AdmitModule, AdmitMutation: p.AdmitAppMutation, AdmitModulePatch: p.AdmitAppPatch}
	options.Servers = []raft.Server{{ID: "source", Address: raft.ServerAddress(peer.Endpoint), Suffrage: raft.Voter}}
	options.Resolve = func(id raft.ServerID, address raft.ServerAddress) (mydcp.Peer, bool) {
		return peer, id == "source" && string(address) == peer.Endpoint
	}
	options.Reduce = func(s state.State, command state.Command) (map[string][]byte, state.Code) {
		if writes, seeded := seeds[command.RequestID]; seeded && (command.Actor == "legacy-admin" && command.Value == "fixture" || command.RequestID == "fixture-accept") {
			return writes, state.Applied
		}
		return p.Reduce(s, command)
	}
	options.CommandModule = func(method, actor string, raw []byte, v cluster.View) (state.Command, error) {
		decoded, err := hex.DecodeString(actor)
		if err != nil || len(decoded) != 32 {
			return state.Command{}, ErrCatalog
		}
		var key [32]byte
		copy(key[:], decoded)
		return p.ResolveAppCommand(v.State, method, key, raw)
	}
	var engine *cluster.Engine
	defer func() {
		if engine != nil {
			_ = engine.Close()
		}
	}()
	open := func() {
		t.Helper()
		engine, err = cluster.Open(options)
		if err != nil {
			t.Fatal(err)
		}
		if err = engine.ServeManagement(); err != nil {
			t.Fatal(err)
		}
		for {
			if _, err = engine.Read(ctx, true); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(15 * time.Millisecond):
			}
		}
	}
	open()
	view := func() state.State {
		t.Helper()
		v, err := engine.Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		return v.State
	}
	commit := func(command state.Command, want state.Code) state.Result {
		t.Helper()
		result, err := engine.Submit(ctx, command)
		if err != nil || result.Result.Code != want {
			t.Fatal("commit", command.Key, command.RequestID, result, want, err)
		}
		return result.Result
	}
	seed := func(root, id string, writes map[string][]byte) {
		t.Helper()
		seeds[id] = writes
		commit(state.Command{Kind: state.Module, Actor: "legacy-admin", Epoch: 1, RequestID: id, Key: root, Expected: view().Object(root).Revision, Value: "fixture"}, state.Applied)
	}
	tenant, _ := c.Tenant("tenant")
	c, err = c.SetNodes("admin", "tenant", tenant.Revision, []string{"source"})
	if err != nil {
		t.Fatal(err)
	}
	writes, _ := p.checkpoint(view(), c)
	seed(CatalogKey, "seed-catalog", writes)
	resources, err := p.Resources(view())
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"", "tenant"} {
		resources.Quotas, err = resources.Quotas.Set(c, "admin", 0, tenancy.NodeLimit{Tenant: tenant, Node: "source", Owner: p.TrustRoot, Capacity: workload.Resources{CPU: 1e9, Memory: 256 << 20}, Networks: 4, MaxConsumers: 8}, resources.Networks)
		if err != nil {
			t.Fatal(err)
		}
	}
	resources.Revision = resources.Quotas.Revision()
	writes, _ = p.resourceCheckpoint(view(), resources)
	seed(ResourcesKey, "seed-quota", writes)
	document := fmt.Sprintf("name: app\nservices:\n  db:\n    image: docker.io/library/php@sha256:%s\n    cpus: 0.1\n    mem_limit: 16m\n    networks: {lan: {ipv4_address: 10.78.0.10}}\n    x-mydc: {node: source}\nnetworks:\n  lan:\n    x-mydc:\n      mtu: 1280\n      pools: {source: {cidr: 10.78.0.0/24, gateway: 10.78.0.1}}\n      dns:\n        enabled: true\n        zone: app.mydc.test.\n        ttl_seconds: 30\n        negative_ttl_seconds: 5\n        transports: [udp, tcp]\n        limits: {cache_entries: 8, queries_inflight: 8, tcp_connections: 4, request_timeout_ms: 2000}\n", string(bytes.Repeat([]byte{'a'}, 64)))
	input, err := deployment.ParseCompose([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	planning, err := p.AppPlanning(view(), "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	// The preaccepted graph fixture enables this declaration core only. The
	// public runtime capability remains off until the native DNS owner connects.
	planning.Features["network-services"] = true
	planning.Project, planning.Deployment = "app", "deploy"
	blueprint, err := deployment.Compile(input, c, planning)
	if err != nil {
		t.Fatal(err)
	}
	origin := oldApps.entries[appKey("tenant", "app")].Origin
	user, _ := c.User("admin")
	origin.Session.AccountRevision = user.Revision
	origin.Session.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.Deploy, access.ManageNetwork, access.ManageServices}}}
	origin.Session.Signature = ed25519.Sign(private, access.SessionBytes(origin.Session))
	origin.RequestID, origin.RootRevision = "fixture-accept", view().Object(AppsKey).Revision
	origin.Change.Expected = 0
	origin.Change.Payload, _ = json.Marshal(AppBegin{Tenant: "tenant", App: "app", Deployment: "deploy", Upload: "fixture", Operation: "operation"})
	origin.Signature = ed25519.Sign(private, OperationBytes(origin))
	command, _ := origin.Command()
	inventory, _ := deployment.NewInventory(p.Cluster, "tenant", "app", "deploy")
	inventory, err = inventory.Begin(inventory.Revision(), c, planning, blueprint, "operation", command.Actor, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	apps, _ := p.Apps(view())
	var serialFloor uint32
	if archived {
		// An archived group holds no owner/native authority. It retains the
		// last public serial for this stable tenant/app/network scope only.
		projection, err := p.ProjectResources(view())
		if err != nil {
			t.Fatal(err)
		}
		authority, err := services.NewAuthority(p.Cluster, projection.Addresses)
		if err != nil {
			t.Fatal(err)
		}
		serialFloor = 17
		group := appDNSGroup{Tenant: "tenant", App: "app", Network: "lan", Source: 9, Serial: serialFloor}
		group.Digest = appDNSDigest(group.Owners)
		apps.network = &appNetworkState{Revision: 9, Authority: authority, Groups: []appDNSGroup{group}}
		encoded, err := apps.network.encode()
		if err != nil {
			t.Fatal("archived serial floor checkpoint", err)
		}
		apps.network, err = decodeAppNetwork(encoded, p.Cluster)
		if err != nil {
			t.Fatal("archived serial floor decode", err)
		}
	}
	apps.entries[appKey("tenant", "app")] = appEntry{Inventory: inventory, Origin: origin}
	writes, _ = p.appsCheckpoint(view(), apps)
	seeds[command.RequestID] = writes
	commit(command, state.Applied)
	report := func(action, key string, observation *deployment.Observation, want state.Code) state.Result {
		t.Helper()
		s := view()
		a, err := p.Apps(s)
		if err != nil {
			t.Fatal(err)
		}
		i, _ := a.Inventory("tenant", "app")
		r := AppProgress{Schema: 1, Cluster: p.Cluster, Reporter: p.TrustRoot, Tenant: "tenant", App: "app", Operation: "operation", Key: key, Action: action, Expected: i.Revision(), At: 10, Epoch: 1, RootRevision: s.Object(AppsKey).Revision, RequestID: fmt.Sprintf("dns/%d/%s", s.Index(), action), Observation: observation}
		if StageReport(r.Action) {
			r.Stage = p.StageDigest(s, r.Tenant, r.App, r.Key)
		}
		r.Signature = ed25519.Sign(private, AppProgressBytes(r))
		raw, _ := json.Marshal(r)
		response, err := cluster.CallManagement(ctx, caller, self, p.Cluster, peer, cluster.ManagementRequest{Method: "app-progress", Latest: true, Input: raw})
		if err != nil || response.Committed == nil || response.Committed.Result.Code != want {
			t.Fatal("report", action, response, want, err)
		}
		return response.Committed.Result
	}
	needed := func(key string, want bool) {
		t.Helper()
		s := view()
		a, err := p.Apps(s)
		if err != nil {
			t.Fatal(err)
		}
		projection, err := p.ProjectResources(s)
		if err != nil {
			t.Fatal(err)
		}
		changed, err := a.DNSProjectionNeeded(s, projection, "tenant", "app", key)
		if err != nil || changed != want {
			t.Fatal("controller repeated/omitted projection", changed, want, err)
		}
	}
	step := func(key string, observe bool) {
		t.Helper()
		report("prepare", key, nil, state.Applied)
		report("send", key, nil, state.Applied)
		a, _ := p.Apps(view())
		e, _ := a.Execution("tenant", "app")
		stage, _ := e.Stage(key)
		result := commit(*stage.Command, state.Applied)
		report("collect", key, nil, state.Applied)
		if observe {
			o := deployment.Observation{Cluster: p.Cluster, Plan: blueprint.Digest(), Operation: "operation", Key: key, Native: "fixture-native", Owner: p.TrustRoot, Command: state.Digest(*stage.Command), Generation: result.Generation, Revision: result.Revision, Sequence: 1, At: 10, Applied: true}
			o.Signature = ed25519.Sign(private, deployment.ObservationBytes(o))
			report("observe", key, &o, state.Applied)
		}
	}
	bridge := deployment.ResourceKey("bridge", "tenant", "app", "lan/source")
	dnsKey := deployment.ResourceKey("dns", "tenant", "app", "lan/source")
	task := deployment.ResourceKey("task", "tenant", "app", "db")
	step(bridge, true)
	step(dnsKey, false)
	needed(dnsKey, true)
	report("project-dns", dnsKey, nil, state.Applied)
	needed(dnsKey, false)
	a, err := p.Apps(view())
	if err != nil {
		t.Fatal(err)
	}
	_, owners, ok := a.NetworkDNS(p.TrustRoot)
	if !ok || len(owners) != 1 || len(owners[0].Config.Names) != 0 || owners[0].Config.Serial != serialFloor+1 {
		t.Fatal("predicted future task", owners)
	}
	original := owners[0]
	step(task, false)
	needed(dnsKey, true)
	report("project-dns", dnsKey, nil, state.Applied)
	needed(dnsKey, false)
	a, err = p.Apps(view())
	if err != nil {
		t.Fatal(err)
	}
	authority, owners, ok := a.NetworkDNS(p.TrustRoot)
	if !ok || len(owners) != 1 || len(owners[0].Config.Names) != 1 || owners[0].Config.Serial != serialFloor+2 || owners[0].Reference != original.Reference {
		t.Fatal("new serial lost original DNS lifetime", owners)
	}
	name := owners[0].Config.Names[0]
	allocation, held := authority.AddressBook().Allocation(name.Endpoint)
	if !held || name.Generation != view().Object(task).Generation || allocation.Generation != name.Generation || name.Name != "db" || a.Quiescent() {
		t.Fatal("non-authoritative address/fence", name)
	}
	if _, err = authority.WithCommittedStaticAllocation(allocation, "foreign-network"); err == nil {
		t.Fatal("old allocation accepted a foreign network")
	}
	changedAllocation := allocation
	changedAllocation.Generation++
	pool, _ := authority.AddressBook().Pool(allocation.Pool)
	if _, err = authority.WithCommittedStaticAllocation(changedAllocation, pool.Network); err == nil {
		t.Fatal("old allocation rebound to a new generation")
	}
	raw, err := a.network.encode()
	if err != nil {
		t.Fatal(err)
	}
	var damaged appNetworkDisk
	_ = json.Unmarshal(raw, &damaged)
	damaged.Groups[0].Owners[0].Config.Names[0].Name = "forged"
	forged, _ := json.Marshal(damaged)
	if _, err = decodeAppNetwork(forged, p.Cluster); err == nil {
		t.Fatal("changed committed name escaped digest validation")
	}
	report("project-dns", task, nil, state.Forbidden)
	e, _ := a.Execution("tenant", "app")
	if e.ActivationReady(task) {
		t.Fatal("projection manufactured native DNS Applied")
	}
	owners[0].Config.Names[0].Name = "forged"
	_, owned, _ := a.NetworkDNS(p.TrustRoot)
	if owned[0].Config.Names[0].Name != "db" {
		t.Fatal("public owner view aliases checkpoint")
	}
	report("project-dns", dnsKey, nil, state.ConditionFailed)
	before := view()
	if err = engine.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	engine = nil
	if err = caller.Close(); err != nil {
		t.Fatal(err)
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	server, err = mydcp.NewTransport(self, p.Cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Listen(peer.Endpoint); err != nil {
		t.Fatal(err)
	}
	caller, err = mydcp.NewTransport(self, p.Cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	options.Mesh = server
	open()
	restored, err := p.Apps(view())
	if err != nil || !reflect.DeepEqual(a, restored) || before.Index() != view().Index() {
		t.Fatal("same DB changed authority/source/lifetime", err)
	}
	// Simulate a missing desired row in a copied state only. No native absence
	// is asserted and no production bypass or physical resource is used.
	missing, result, err := state.Apply(before, before.Index()+1, state.Command{Actor: "legacy-admin", Epoch: 1, RequestID: "missing-goal", Key: task, Expected: before.Object(task).Revision, Delete: true})
	if err != nil || result.Code != state.Applied {
		t.Fatal(err, result)
	}
	projection, err := p.ProjectResources(missing)
	retained, found := projection.Addresses.Allocation(name.Endpoint)
	if err != nil || !found || retained != allocation || projection.AddressSources[allocation.Address.String()].Revision != 0 {
		t.Fatal("missing Goal released original address", err)
	}
	t.Log("real signed member report/MYDCP/N1 Raft/bbolt: empty pre-task view -> exact committed task/serial2 -> original A3 lifetime and Book hold -> no native Applied -> duplicate denial/Snapshot/same DB; accepted graph/Bridge observation are fixtures, no DNS socket or CLI acceptance claimed")
}
