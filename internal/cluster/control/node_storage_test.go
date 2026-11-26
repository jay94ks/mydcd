// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// This fixture tests the actual shared reducer, signatures and checkpoint
// invariants. Directory observations are simulated, not native filesystem proof.
type nodeStorageFixture struct {
	t                    *testing.T
	p                    Policy
	s                    state.State
	users                access.Catalog
	node, admin, manager ed25519.PrivateKey
	sessions             map[string]access.Session
	next                 int
}

func newNodeStorageFixture(t *testing.T) *nodeStorageFixture {
	t.Helper()
	key := func(n byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
	f := &nodeStorageFixture{t: t, node: key(101), admin: key(102), manager: key(103), sessions: map[string]access.Session{}}
	n, a := [32]byte(f.node.Public().(ed25519.PublicKey)), [32]byte(f.admin.Public().(ed25519.PublicKey))
	f.p = Policy{Cluster: [32]byte{104}, BootstrapKey: a, TrustRoot: n, Genesis: config.Peer{ID: "node-a", Key: hex.EncodeToString(n[:]), Endpoint: "127.0.0.1:8010", Voter: true}}
	c, _ := access.New(a)
	var err error
	c, err = c.Enroll(a, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: a, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.CreateTenant("admin", "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	c, err = c.SetNodes("admin", "tenant", tenant.Revision, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.PutUser("admin", 0, access.User{ID: "manager", Username: "manager", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(f.manager.Public().(ed25519.PublicKey)), Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.SetMembership("admin", 0, access.Membership{Tenant: "tenant", User: "manager", Role: access.Manager, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	f.users = c
	f.s, _ = state.New("anchor")
	writes, code := f.p.checkpoint(f.s, c)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.checkpoint(CatalogKey, writes)
	for name, private := range map[string]ed25519.PrivateKey{"admin": f.admin, "manager": f.manager} {
		u, _ := c.User(name)
		s := access.Session{Schema: 1, ID: "session-" + name, Cluster: f.p.Cluster, User: name, Credential: "key", AccountRevision: u.Revision, Key: [32]byte(private.Public().(ed25519.PublicKey)), Issuer: n, IssuerEpoch: 1, IssuedAt: 1, ExpiresAt: 1001, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read, access.ManageCluster, access.ManageVolumes}}}}
		s.Signature = ed25519.Sign(f.node, access.SessionBytes(s))
		f.sessions[name] = s
	}
	return f
}

func (f *nodeStorageFixture) checkpoint(key string, writes map[string][]byte) {
	f.t.Helper()
	f.next++
	cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: fmt.Sprintf("fixture-%d", f.next), Key: key, Expected: f.s.Object(key).Revision, Value: "fixed-fixture"}
	n, r, err := state.ApplyReduced(f.s, f.s.Index()+1, cmd, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || r.Code != state.Applied {
		f.t.Fatal("fixture checkpoint", r, err)
	}
	f.s = n
}

func (f *nodeStorageFixture) apply(actor, action string, expected uint64, payload any, want state.Code) state.Command {
	f.t.Helper()
	f.next++
	raw, err := ChangeBytes(action, actor, expected, payload)
	if err != nil {
		f.t.Fatal(err)
	}
	var change Change
	if err = json.Unmarshal(raw, &change); err != nil {
		f.t.Fatal(err)
	}
	op := UserOperation{Schema: 1, Session: f.sessions[actor], At: 2, Epoch: 1, RequestID: fmt.Sprintf("user-%d", f.next), RootRevision: f.s.Object(CommandKey(action)).Revision, Change: change}
	private := f.admin
	if actor == "manager" {
		private = f.manager
	}
	op.Signature = ed25519.Sign(private, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil {
		f.t.Fatal(err)
	}
	n, r, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || r.Code != want {
		f.t.Fatal(action, r.Code, want, err)
	}
	f.s = n
	return cmd
}

func (f *nodeStorageFixture) root() nodestorage.Root {
	f.t.Helper()
	c, err := f.p.NodeStorage(f.s)
	if err != nil {
		f.t.Fatal(err)
	}
	r, ok := c.Root("node-a", "hdd")
	if !ok {
		f.t.Fatal("missing root")
	}
	return r
}

func (f *nodeStorageFixture) report(r NodeStorageReport, private ed25519.PrivateKey, want state.Code) {
	f.t.Helper()
	f.next++
	r.Schema, r.Cluster, r.Reporter, r.Epoch, r.RootRevision = 1, f.p.Cluster, [32]byte(private.Public().(ed25519.PublicKey)), 1, f.s.Object(NodeStorageKey).Revision
	r.Index = f.s.Index()
	r.Signature = ed25519.Sign(private, NodeStorageReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		f.t.Fatal(err)
	}
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		f.t.Fatal("native report", r.Action, result.Code, want, err)
	}
	f.s = n
}

func (f *nodeStorageFixture) observe() {
	f.t.Helper()
	r := f.root()
	fact := nodestorage.RootFact{Schema: 1, Root: r.Reference(f.p.Cluster), Directory: nodestorage.Directory{Filesystem: "ext4", FilesystemPath: "/tenant-data", UUID: [16]byte{1}, HandleType: 1, Handle: bytes.Repeat([]byte{5}, 8), Inode: 5, DeviceMajor: 8, DeviceMinor: 1, Boot: [32]byte{1}, Namespace: [32]byte{2}, MountID: 3}}
	fact.Signature = ed25519.Sign(f.node, nodestorage.RootFactBytes(fact))
	f.report(NodeStorageReport{Action: "registered", Expected: r.Revision, Ready: &fact}, f.manager, state.Forbidden)
	f.report(NodeStorageReport{Action: "registered", Expected: r.Revision + 1, Ready: &fact}, f.node, state.ConditionFailed)
	f.report(NodeStorageReport{Action: "registered", Expected: r.Revision, Ready: &fact}, f.node, state.Applied)
}

func TestNodeStorageSharedAuthorityFactsDrainAndSnapshotFloor(t *testing.T) {
	f := newNodeStorageFixture(t)
	d := nodestorage.Definition{Node: "node-a", ID: "hdd", Path: "/mnt/hdd", MaxVolumes: 2, Tenants: []string{"tenant"}}
	f.apply("manager", "add-node-storage", 0, d, state.Forbidden)
	wrong := d
	wrong.Key = [32]byte{9}
	f.apply("admin", "add-node-storage", 0, wrong, state.Forbidden)
	wrong = d
	wrong.Node = "uninstalled"
	f.apply("admin", "add-node-storage", 0, wrong, state.Forbidden)
	cmd := f.apply("admin", "add-node-storage", 0, d, state.Applied)
	if f.root().Attestation != nil || f.p.storageQuiescent(f.s) {
		t.Fatal("definition fabricated native Ready/quiescence")
	}
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != state.Applied {
		t.Fatal("original request replay", result, err)
	}
	f.s = n
	f.observe()
	r := f.root()
	if r.Definition.Key != f.p.TrustRoot {
		t.Fatal("node key did not come from current membership")
	}
	if _, err := f.p.NodeStoragePermit(f.s, [32]byte(f.manager.Public().(ed25519.PublicKey)), NodeStorageSelection{"node-a", "hdd"}); err == nil {
		t.Fatal("non-owner key obtained native root permit")
	}
	if _, err := f.p.NodeStorageRead(f.s, f.sessions["manager"], 2, NodeStorageSelection{"node-a", "hdd"}); err == nil {
		t.Fatal("tenant manager obtained host-root observation")
	}
	if _, _, err := f.p.NodeStoragePage(f.s, f.users, "manager", "", ""); err == nil {
		t.Fatal("tenant manager listed system root paths/ACLs")
	}
	if root, err := f.p.NodeStorageRead(f.s, f.sessions["admin"], 2, NodeStorageSelection{"node-a", "hdd"}); err != nil || root.Reference(f.p.Cluster) != r.Reference(f.p.Cluster) {
		t.Fatal("current system authority native read", err)
	}
	data, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if restored := f.root(); restored.Generation != r.Generation || restored.Attestation.Verify() != nil {
		t.Fatal("Snapshot lost original registration")
	}
	selection := NodeStorageSelection{"node-a", "hdd"}
	f.apply("admin", "remove-node-storage", r.Revision, selection, state.ConditionFailed)
	f.apply("admin", "drain-node-storage", r.Revision, selection, state.Applied)
	r = f.root()
	f.apply("admin", "remove-node-storage", r.Revision, selection, state.ConditionFailed)
	closed := nodestorage.RootClosed{Schema: 1, Root: r.Reference(f.p.Cluster), NoUsers: true, NoPending: true}
	closed.Signature = ed25519.Sign(f.node, nodestorage.RootClosedBytes(closed))
	f.report(NodeStorageReport{Action: "closed", Expected: r.Revision, Closed: &closed}, f.node, state.Applied)
	r = f.root()
	f.apply("admin", "remove-node-storage", r.Revision, selection, state.Applied)
	f.apply("admin", "add-node-storage", 0, d, state.Applied)
	if f.root().Generation <= r.Generation || f.root().Attestation != nil {
		t.Fatal("same-name registration reused old floor/Ready")
	}
	f.report(NodeStorageReport{Action: "closed", Expected: f.root().Revision, Closed: &closed}, f.node, state.ConditionFailed)
}

func TestNodeStorageTypedInputRejectsCounterfeitCountsAndUnknownPolicy(t *testing.T) {
	good := []byte(`{"schema":1,"action":"add-node-storage","payload":{"Node":"node-a","ID":"hdd","Path":"/mnt/hdd","Tenants":[],"MaxVolumes":2}}`)
	change, err := InputChange(good, "admin")
	if err != nil || CommandKey(change.Action) != NodeStorageKey {
		t.Fatal("typed node-storage input", err)
	}
	for _, raw := range []string{
		`{"schema":1,"action":"remove-node-storage","payload":{"Node":"node-a","ID":"hdd","Registered":0}}`,
		`{"schema":1,"action":"set-node-storage-policy","payload":{"Node":"node-a","ID":"hdd","MaxVolumes":2,"AllowAll":true}}`,
		`{"schema":1,"action":"node-storage-ready","payload":{}}`,
	} {
		if _, err := InputChange([]byte(raw), "admin"); err == nil {
			t.Fatal("unsafe management input", raw)
		}
	}
}

func TestNodeStorageFixedDirectoryCapacityAndCurrentStartPolicy(t *testing.T) {
	f := newNodeStorageFixture(t)
	f.apply("admin", "add-node-storage", 0, nodestorage.Definition{Node: "node-a", ID: "hdd", Path: "/mnt/hdd", MaxVolumes: 2, Tenants: []string{"tenant"}}, state.Applied)
	f.observe()
	r := f.root()
	v, err := f.p.Volumes(f.s)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		id := fmt.Sprintf("data-%d", i)
		scope := volumes.Scope{Cluster: f.p.Cluster, Tenant: "tenant", ID: id, Generation: uint64(i)}
		directory := r.Attestation.Directory
		directory.Handle = bytes.Repeat([]byte{byte(i + 10)}, 8)
		directory.Inode = uint64(i + 10)
		directory.FilesystemPath += "/" + id
		fixed := &nodestorage.FixedDirectory{Root: *r.Attestation, RootDirectory: r.Attestation.Directory, Path: r.Definition.Path + "/" + id, Directory: directory}
		digest := fixed.Selection().Digest()
		ready := volumes.NativeReady{Schema: 1, Spec: volumes.NativeSpec{Schema: 1, Scope: scope, Node: "node-a", NodeKey: f.p.TrustRoot, Retain: true, Kind: "node-fixed", FixedDigest: hex.EncodeToString(digest[:])}, Generation: scope.Generation, Owner: volumes.Owner{Node: "node-a", Key: f.p.TrustRoot, Native: volumes.FixedNativeName(scope)}, Fixed: fixed}
		ready.Signature = ed25519.Sign(f.node, volumes.NativeReadyBytes(ready))
		if ready.Verify() != nil {
			t.Fatal("simulated fixed native binding")
		}
		core, err := volumes.NewFixed(f.users, "admin", scope, ready.Owner, 2)
		if err != nil {
			t.Fatal(err)
		}
		v.entries[scope.Key()] = registeredVolume{Native: ready, State: core}
	}
	writes, code := f.p.volumeCheckpoint(f.s, v)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.checkpoint(VolumesKey, writes)
	f.apply("admin", "set-node-storage-policy", r.Revision, NodeStoragePolicy{Node: "node-a", ID: "hdd", Tenants: []string{"tenant"}, MaxVolumes: 1}, state.ConditionFailed)
	scope := volumes.Scope{Cluster: f.p.Cluster, Tenant: "tenant", ID: "data-1", Generation: 1}
	f.apply("manager", "acquire-volume", 1, VolumeAcquire{scope, "writer", 1, true}, state.Applied)
	v, err = f.p.Volumes(f.s)
	if err != nil {
		t.Fatal(err)
	}
	core, _ := v.Volume(scope)
	request := volumes.StartRequest{Scope: scope, Consumer: core.Consumers()[0], Boot: [32]byte{1}, Challenge: [32]byte{2}, Sequence: 1}
	if _, err = f.p.VolumePermit(f.s, f.p.TrustRoot, request); err != nil {
		t.Fatal("current fixed Start authority", err)
	}
	f.apply("admin", "drain-node-storage", r.Revision, NodeStorageSelection{"node-a", "hdd"}, state.Applied)
	if _, err = f.p.VolumePermit(f.s, f.p.TrustRoot, request); err == nil {
		t.Fatal("drained root admitted Start")
	}
	r = f.root()
	closed := nodestorage.RootClosed{Schema: 1, Root: r.Reference(f.p.Cluster), NoUsers: true, NoPending: true}
	closed.Signature = ed25519.Sign(f.node, nodestorage.RootClosedBytes(closed))
	f.report(NodeStorageReport{Action: "closed", Expected: r.Revision, Closed: &closed}, f.node, state.ConditionFailed)
	f.apply("admin", "remove-node-storage", r.Revision, NodeStorageSelection{"node-a", "hdd"}, state.ConditionFailed)
	v, err = f.p.Volumes(f.s)
	after, _ := v.Volume(scope)
	if err != nil || len(after.Consumers()) != 1 {
		t.Fatal("Drain/rejected closure erased writer", err)
	}
}
