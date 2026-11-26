// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"

	"github.com/hashicorp/raft"
)

type controlBoundary struct {
	t            *testing.T
	ctx          context.Context
	node, client *identity.Identity
	server, cli  *mydcp.Transport
	engine       *Engine
	policy       control.Policy
	options      Options
	mu           sync.RWMutex
	peers        map[mydcp.Identity]mydcp.Peer
}

func newControlBoundary(t *testing.T, configure ...func(*controlBoundary)) *controlBoundary {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	f := &controlBoundary{t: t, ctx: ctx, peers: map[mydcp.Identity]mydcp.Peer{}}
	t.Cleanup(cancel)
	var err error
	f.node, err = identity.Create(filepath.Join(t.TempDir(), "node-key"))
	if err != nil {
		t.Fatal(err)
	}
	f.client, err = identity.Create(filepath.Join(t.TempDir(), "admin-key"))
	if err != nil {
		t.Fatal(err)
	}
	f.policy = control.Policy{Cluster: [32]byte{71}, BootstrapKey: f.client.Public}
	for i, key := range [][32]byte{f.node.Public, f.client.Public} {
		peer := mydcp.Peer{ID: []string{"node", "client"}[i], Policy: mydcp.Policy{Key: mydcp.Identity(key), Member: i == 0, Snapshot: i == 0, Respond: true, Read: true, Manage: i == 1}}
		f.peers[peer.Key] = peer
	}
	f.options = Options{ID: "node", Root: t.TempDir(), Admin: f.client.Actor(), Cluster: f.policy.Cluster, Bootstrap: true, Validate: f.policy.Validate, Reduce: f.policy.Reduce, ModuleID: f.policy.ID()}
	f.options.Resolve = func(id raft.ServerID, address raft.ServerAddress) (mydcp.Peer, bool) {
		p, ok := f.lookup(mydcp.Identity(f.node.Public))
		return p, ok && p.ID == string(id) && p.Endpoint == string(address)
	}
	t.Cleanup(f.close)
	managedBoundary(f)
	for _, change := range configure {
		change(f)
	}
	f.start()
	return f
}

// managedBoundary pins the node's advertised endpoint and installs the managed
// catalog policy rooted at the node identity, as init does.
func managedBoundary(f *controlBoundary) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	address := socket.LocalAddr().String()
	_ = socket.Close()
	peer := f.peers[mydcp.Identity(f.node.Public)]
	peer.Endpoint = address
	f.peers[peer.Key] = peer
	f.policy.TrustRoot, f.policy.Genesis = f.node.Public, config.Peer{ID: "node", Key: f.node.Actor(), Endpoint: address, Voter: true}
	f.options.Validate, f.options.Reduce, f.options.AdmitModule, f.options.ModuleID = f.policy.Validate, f.policy.Reduce, f.policy.AdmitModule, f.policy.ID()
	f.options.TrackConfiguration = true
	f.options.Resolve = func(id raft.ServerID, address raft.ServerAddress) (mydcp.Peer, bool) {
		f.mu.RLock()
		defer f.mu.RUnlock()
		for _, p := range f.peers {
			if p.ID == string(id) && p.Endpoint == string(address) {
				return p, true
			}
		}
		return mydcp.Peer{}, false
	}
}

func (f *controlBoundary) lookup(key mydcp.Identity) (mydcp.Peer, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	p, ok := f.peers[key]
	return p, ok
}

func (f *controlBoundary) start() {
	f.startUnready()
	f.wait(func() bool {
		_, err := f.engine.Read(f.ctx, false)
		return err == nil && f.engine.IsLeader()
	})
}

func (f *controlBoundary) startUnready() {
	f.t.Helper()
	for i, id := range []*identity.Identity{f.node, f.client} {
		mesh, err := mydcp.NewTransport(id, f.policy.Cluster, f.lookup)
		if err != nil {
			f.t.Fatal(err)
		}
		if i == 0 {
			f.server = mesh
		} else {
			f.cli = mesh
		}
		peer, _ := f.lookup(mydcp.Identity(id.Public))
		address := peer.Endpoint
		if address == "" {
			address = "127.0.0.1:0"
		}
		if err = mesh.Listen(address); err != nil {
			f.t.Fatal(err)
		}
		peer.Endpoint = mesh.Addr().String()
		f.mu.Lock()
		f.peers[peer.Key] = peer
		f.mu.Unlock()
	}
	peer, _ := f.lookup(mydcp.Identity(f.node.Public))
	f.options.Mesh = f.server
	f.options.Servers = []raft.Server{{ID: "node", Address: raft.ServerAddress(peer.Endpoint), Suffrage: raft.Voter}}
	var err error
	f.engine, err = Open(f.options)
	if err != nil {
		f.t.Fatal(err)
	}
	if err = f.engine.ServeManagement(); err != nil {
		f.t.Fatal(err)
	}
}

func (f *controlBoundary) wait(check func() bool) {
	f.t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for !check() {
		select {
		case <-f.ctx.Done():
			f.t.Fatal(f.ctx.Err())
		case <-ticker.C:
		}
	}
}

func (f *controlBoundary) close() {
	if f.cli != nil {
		_ = f.cli.Close()
		f.cli = nil
	}
	if f.engine != nil {
		_ = f.engine.Close()
		f.engine = nil
	}
	if f.server != nil {
		_ = f.server.Close()
		f.server = nil
	}
}

func (f *controlBoundary) view() View {
	f.t.Helper()
	v, err := f.engine.Read(f.ctx, true)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *controlBoundary) catalog() access.Catalog {
	f.t.Helper()
	c, err := f.policy.Catalog(f.view().State)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *controlBoundary) command(id, action, principal string, expected uint64, payload any) state.Command {
	f.t.Helper()
	b, err := control.ChangeBytes(action, principal, expected, payload)
	if err != nil {
		f.t.Fatal(err)
	}
	return state.Command{Kind: state.Module, Actor: f.client.Actor(), Epoch: 1, RequestID: id, Key: control.CatalogKey, Expected: f.view().State.Object(control.CatalogKey).Revision, Value: string(b)}
}

func (f *controlBoundary) call(c state.Command) Committed {
	f.t.Helper()
	raw, err := state.EncodeCommand(c)
	if err != nil {
		f.t.Fatal(err)
	}
	peer, _ := f.lookup(mydcp.Identity(f.node.Public))
	r, err := CallManagement(f.ctx, f.cli, f.client, f.policy.Cluster, peer, ManagementRequest{Method: "submit", Latest: true, Command: raw})
	if err != nil || r.Committed == nil {
		f.t.Fatal("authenticated MYDCP management boundary", r.Code, err)
	}
	return *r.Committed
}

func (f *controlBoundary) enroll() state.Command {
	f.t.Helper()
	c := f.command("enroll", "enroll", "", 0, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: f.client.Public, Enabled: true}}})
	if result := f.call(c); result.Result.Code != state.Applied {
		f.t.Fatal("explicit bootstrap enrollment", result)
	}
	return c
}

func TestRealControlCatalogMYDCPCASRevocationAndSnapshot(t *testing.T) {
	f := newControlBoundary(t)
	initial := f.catalog()
	if !initial.AwaitingAdmin() || initial.Revision() != 0 || len(initial.VisibleTenants("admin")) != 0 {
		t.Fatal("initial catalog was not blank")
	}
	enroll := f.enroll()
	create := f.command("tenant", "create-tenant", "admin", 0, control.TenantID{ID: "demo"})
	applied := f.call(create)
	if applied.Result.Code != state.Applied || applied.RaftIndex <= applied.Result.Index {
		t.Fatal(applied)
	}
	tenant, ok := f.catalog().Tenant("demo")
	if !ok || len(tenant.ImageSources) != 1 || tenant.ImageSources[0] != (access.TrustRule{Registry: "docker.io", Repository: "**"}) || f.catalog().AwaitingAdmin() {
		t.Fatal("tenant default/bootstrap anchor", tenant)
	}
	stale := f.command("stale", "set-nodes", "admin", tenant.Revision, control.NodeAssignment{Tenant: "demo", Nodes: []string{"node"}})
	trust := f.command("trust", "set-trust", "admin", tenant.Revision, control.TrustAssignment{Tenant: "demo", Rules: []access.TrustRule{}})
	if f.call(trust).Result.Code != state.Applied {
		t.Fatal("explicit trust removal")
	}
	rejected := f.call(stale)
	if rejected.Result.Code != state.ConditionFailed {
		t.Fatal("stale common root accepted", rejected)
	}
	forged := f.command("forged", "create-tenant", "other-user", 0, control.TenantID{ID: "foreign"})
	if f.call(forged).Result.Code != state.Forbidden {
		t.Fatal("unverified principal/legacy admin granted tenant rights")
	}
	if err := f.engine.Snapshot(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.close()
	f.start()
	if f.call(create).Result != applied.Result || f.call(stale).Result != rejected.Result {
		t.Fatal("same DB/snapshot lost original success or CAS rejection")
	}
	if tenant, ok := f.catalog().Tenant("demo"); !ok || len(tenant.ImageSources) != 0 {
		t.Fatal("restart silently reinserted Docker Hub", tenant)
	}
	if f.call(enroll).Result.Code != state.Applied || f.catalog().AwaitingAdmin() {
		t.Fatal("duplicate enrollment did not return original receipt")
	}
	changed := create
	changed.Value = strings.Replace(changed.Value, "demo", "other", 1)
	if f.call(changed).Result.Code != state.RequestConflict {
		t.Fatal("same ID/different command was admitted")
	}
	// Current account policy wins even for the old genesis/node administrator.
	u, _ := f.catalog().User("admin")
	u.Revision = 0
	u.Credentials = []access.Credential{{ID: "password", Method: access.Password, VerifierRef: "provider/admin-password", Enabled: true}}
	// The account has its own revision, independent of tenant/catalog changes.
	old, _ := f.catalog().User("admin")
	revoke := f.command("remove-key", "put-user", "admin", old.Revision, u)
	if f.call(revoke).Result.Code != state.Applied {
		t.Fatal("current credential replacement")
	}
	if f.call(f.command("revoked", "create-tenant", "admin", 0, control.TenantID{ID: "after"})).Result.Code != state.Forbidden {
		t.Fatal("revoked key retained legacy admin user authority")
	}
}

func TestRealControlCatalogLargeCheckpointUsesBoundedRows(t *testing.T) {
	f := newControlBoundary(t)
	f.enroll()
	for i := 0; i < 9; i++ {
		u := access.User{ID: fmt.Sprintf("user-%d", i), Username: fmt.Sprintf("user-%d", i), Enabled: true}
		for j := 0; j < 48; j++ {
			u.Credentials = append(u.Credentials, access.Credential{ID: fmt.Sprintf("pass-%d", j), Method: access.Password, VerifierRef: "provider/" + strings.Repeat("a", 220) + fmt.Sprintf("-%d-%d", i, j), Enabled: true})
		}
		c := f.command(fmt.Sprintf("user-%d", i), "put-user", "admin", 0, u)
		if len(c.Value) > 64<<10 || f.call(c).Result.Code != state.Applied {
			t.Fatal("bounded per-user management command")
		}
	}
	before, err := f.catalog().Encode()
	if err != nil || len(before) <= 64<<10 {
		t.Fatal("fixture did not cross command value boundary", len(before), err)
	}
	v := f.view()
	for key, object := range v.State.Objects(control.CatalogKey + "/") {
		if object.Present && (len(object.Value) > 32<<10 || object.Revision != v.State.Object(control.CatalogKey).Revision) {
			t.Fatal("unbounded/unpublished checkpoint part", key)
		}
	}
	if err = f.engine.Snapshot(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.close()
	f.start()
	after, err := f.catalog().Encode()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("multi-row catalog snapshot/replay changed metadata", err)
	}
	// Neither a missing reducer nor a changed bootstrap/policy can reopen this root.
	f.close()
	mesh, err := mydcp.NewTransport(f.node, f.policy.Cluster, f.lookup)
	if err != nil {
		t.Fatal(err)
	}
	f.server = mesh
	p, _ := f.lookup(mydcp.Identity(f.node.Public))
	if err = mesh.Listen(p.Endpoint); err != nil {
		t.Fatal(err)
	}
	o := f.options
	o.Mesh, o.Reduce, o.Validate, o.ModuleID = mesh, nil, nil, [32]byte{}
	engine, err := Open(o)
	if err == nil {
		_ = engine.Close()
		t.Fatal("root reopened after silently disabling module authority")
	}
	changed := f.policy
	changed.BootstrapKey = [32]byte{99}
	o = f.options
	o.Mesh, o.Reduce, o.Validate, o.ModuleID = mesh, changed.Reduce, changed.Validate, changed.ID()
	engine, err = Open(o)
	if err == nil {
		_ = engine.Close()
		t.Fatal("root reopened after changing bootstrap policy")
	}
}

func TestRealControlCatalogCommitSyncFailurePreservesOriginalOnReplay(t *testing.T) {
	f := newControlBoundary(t)
	f.enroll()
	c := f.command("uncertain-tenant", "create-tenant", "admin", 0, control.TenantID{ID: "uncertain"})
	before := f.view()
	if err := f.engine.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.engine.Submit(f.ctx, c); !errors.Is(err, ErrUnknown) {
		t.Fatal("failed atomic sync claimed success/nonexecution", err)
	}
	select {
	case failure := <-f.engine.Failure():
		if failure == nil {
			t.Fatal("missing terminal storage failure")
		}
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	if _, err := f.engine.Read(f.ctx, false); err == nil {
		t.Fatal("failed catalog checkpoint published")
	}
	f.close()
	f.start()
	v := f.view()
	result, found := v.State.LookupResult(c)
	_, exists := f.catalog().Tenant("uncertain")
	if !found || !exists || result.Code != state.Applied || result.Index != before.State.Index()+1 || v.State.Index() != result.Index {
		t.Fatal("original command/catalog replay lost or re-executed", found, exists, result)
	}
	if f.call(c).Result != result {
		t.Fatal("recovery changed original request receipt")
	}
}

func TestRealManagedMutationPolicyUpgradePreservesCheckpointAndReceipt(t *testing.T) {
	f := newControlBoundary(t, func(f *controlBoundary) {
		p, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		address := p.LocalAddr().String()
		_ = p.Close()
		peer := f.peers[mydcp.Identity(f.node.Public)]
		peer.Endpoint = address
		f.peers[peer.Key] = peer
		f.policy.TrustRoot = f.node.Public
		f.policy.Genesis = config.Peer{ID: "node", Key: f.node.Actor(), Endpoint: address, Voter: true}
		f.options.ModuleID = f.policy.ID()
		f.options.Validate = f.policy.Validate
		f.options.Reduce = f.policy.Reduce
		f.options.AdmitModule = f.policy.AdmitModule
	})
	f.enroll()
	command := f.command("tenant-upgrade", "create-tenant", "admin", 0, control.TenantID{ID: "demo"})
	original := f.call(command)
	if original.Result.Code != state.Applied {
		t.Fatal(original)
	}
	before := f.view().State
	encoded, _ := state.Encode(before)
	if err := f.engine.Snapshot(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.close()
	f.options.AdmitMutation = f.policy.AdmitAppMutation
	f.options.AllowMutationUpgrade = true
	f.start()
	after := f.view().State
	round, _ := state.Encode(after)
	if !bytes.Equal(encoded, round) {
		t.Fatal("policy capability upgrade rewrote state/IDs/receipts")
	}
	if result, ok := after.LookupResult(command); !ok || result != original.Result {
		t.Fatal("original ACK lost")
	}
	marker, err := f.engine.db.Get("mutation-policy-upgrade-1")
	var evidence struct {
		Original, Current []byte
		CommandIndex      uint64
	}
	if err != nil || json.Unmarshal(marker, &evidence) != nil || !bytes.HasSuffix(evidence.Current, []byte("/delegated-mutations-1")) || !bytes.Equal(evidence.Original, bytes.TrimSuffix(evidence.Current, []byte("/delegated-mutations-1"))) || evidence.CommandIndex != before.Index() {
		t.Fatal("upgrade evidence", err)
	}
	// The actual bound module/identity and old-root check still prevent downgrade.
	f.close()
	f.options.AllowMutationUpgrade = false
	f.start()
	if round, _ := state.Encode(f.view().State); !bytes.Equal(encoded, round) {
		t.Fatal("reopen lost upgraded root")
	}
	// The related-control patch capability is separately bound. Merely adding
	// a callback cannot silently rewrite an established root's capabilities.
	f.close()
	refuseOpen := func(options Options) {
		t.Helper()
		mesh, e := mydcp.NewTransport(f.node, f.policy.Cluster, f.lookup)
		if e != nil {
			t.Fatal(e)
		}
		defer mesh.Close()
		peer, _ := f.lookup(mydcp.Identity(f.node.Public))
		if e = mesh.Listen(peer.Endpoint); e != nil {
			t.Fatal(e)
		}
		options.Mesh = mesh
		if unexpected, e := Open(options); e == nil {
			_ = unexpected.Close()
			t.Fatal("unexpected root capability accepted")
		} else if e.Error() != "state root identity/cluster mismatch" {
			t.Fatal("capability refusal failed for another reason", e)
		}
	}
	f.options.AdmitModulePatch = f.policy.AdmitAppPatch
	refuseOpen(f.options)
	f.options.AllowPatchUpgrade = true
	f.start()
	if round, _ := state.Encode(f.view().State); !bytes.Equal(encoded, round) {
		t.Fatal("related patch upgrade changed state/receipts")
	}
	marker, err = f.engine.db.Get("module-patch-policy-upgrade-1")
	if err != nil || json.Unmarshal(marker, &evidence) != nil || !bytes.Equal(evidence.Original, bytes.TrimSuffix(evidence.Current, []byte("/related-control-patches-1"))) || evidence.CommandIndex != before.Index() {
		t.Fatal("related patch marker", err)
	}
	if result, ok := f.view().State.LookupResult(command); !ok || result != original.Result {
		t.Fatal("patch upgrade lost original ACK")
	}
	f.close()
	f.options.AdmitModulePatch = nil
	f.options.AllowPatchUpgrade = false
	refuseOpen(f.options)
	f.options.AdmitModulePatch = f.policy.AdmitAppPatch
	f.start()
	if round, _ := state.Encode(f.view().State); !bytes.Equal(encoded, round) {
		t.Fatal("related patch root reopen lost state")
	}
}
