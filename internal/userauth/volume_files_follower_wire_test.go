// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Real loopback TLS/MYDCP, SDK Raft and bbolt command publication. Transport
// membership and signed native Volume facts are declared fixture inputs; the
// runner records I/O calls and claims no Docker/file publication or native Gone.
type volumeFileWireFixture struct {
	t       *testing.T
	ctx     context.Context
	policy  control.Policy
	user    *identity.Identity
	nodes   [3]*identity.Identity
	peers   [3]mydcp.Peer
	engines [3]*cluster.Engine
	meshes  [3]*mydcp.Transport
	client  Client
	session access.Session
	service Service
	blocked atomic.Bool
	serial  int
	job     control.VolumeFileJob
}

func newVolumeFileWireFixture(t *testing.T) *volumeFileWireFixture {
	t.Helper()
	f := &volumeFileWireFixture{t: t}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	f.ctx = ctx
	t.Cleanup(cancel)
	key := func() *identity.Identity {
		k, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(k.Private) })
		return k
	}
	f.user = key()
	for i := range f.nodes {
		f.nodes[i] = key()
		f.peers[i] = mydcp.Peer{ID: fmt.Sprintf("node-%c", 'a'+i), Policy: mydcp.Policy{Key: mydcp.Identity(f.nodes[i].Public), Member: true, Manage: true, Read: true, Respond: true, Snapshot: true}}
	}
	clusterID := [32]byte{218}
	lookup := func(k mydcp.Identity) (mydcp.Peer, bool) {
		if k == mydcp.Identity(f.user.Public) {
			return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: k, UserAuth: true}}, true
		}
		for _, peer := range f.peers {
			if k == peer.Key {
				return peer, true
			}
		}
		return mydcp.Peer{}, false
	}
	for i := range f.nodes {
		mesh, err := mydcp.NewTransportWithPurposeLookup(f.nodes[i], clusterID, func(k mydcp.Identity, purpose mydcp.Purpose) (mydcp.Peer, bool) {
			if f.blocked.Load() && (i == 0 || k == f.peers[0].Key) && (purpose == mydcp.Raft || purpose == mydcp.Snapshot) {
				return mydcp.Peer{}, false
			}
			return lookup(k)
		})
		if err != nil {
			t.Fatal(err)
		}
		f.meshes[i] = mesh
		t.Cleanup(func() { _ = mesh.Close() })
		if err = mesh.Listen("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		f.peers[i].Endpoint = mesh.Addr().String()
	}
	f.policy = control.Policy{Cluster: clusterID, BootstrapKey: f.user.Public, TrustRoot: f.nodes[0].Public, Genesis: config.Peer{ID: f.peers[0].ID, Key: hex.EncodeToString(f.nodes[0].Public[:]), Endpoint: f.peers[0].Endpoint, Voter: true}}
	servers := make([]raft.Server, len(f.nodes))
	for i, peer := range f.peers {
		servers[i] = raft.Server{ID: raft.ServerID(peer.ID), Address: raft.ServerAddress(peer.Endpoint), Suffrage: raft.Voter}
	}
	root := t.TempDir()
	for i := range f.nodes {
		e, err := cluster.Open(cluster.Options{ID: f.peers[i].ID, Root: filepath.Join(root, f.peers[i].ID), Admin: f.user.Actor(), Cluster: clusterID, Mesh: f.meshes[i], Bootstrap: i == 0, Servers: servers,
			Resolve: func(id raft.ServerID, _ raft.ServerAddress) (mydcp.Peer, bool) {
				for _, peer := range f.peers {
					if peer.ID == string(id) {
						return peer, true
					}
				}
				return mydcp.Peer{}, false
			}, ModuleID: f.policy.ID(), Validate: f.policy.ValidateManaged, Reduce: f.policy.Reduce, AdmitModule: f.policy.AdmitModule, AdmitMutation: f.policy.AdmitAppMutation, AdmitModulePatch: f.policy.AdmitAppPatch})
		if err != nil {
			t.Fatal(err)
		}
		f.engines[i] = e
		t.Cleanup(func() { _ = e.Close() })
		if err = e.ServeManagement(); err != nil {
			t.Fatal(err)
		}
	}
	f.wait(func() bool {
		for i, e := range f.engines {
			if e.IsLeader() {
				if i != 1 {
					_ = e.TransferLeadership(ctx, f.peers[1].ID, f.peers[1].Endpoint)
				}
				return f.engines[1].IsLeader()
			}
		}
		return false
	})
	enroll, err := (control.Enrollment{Schema: 1, RequestID: "file-wire-enroll", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: f.user.Public, Enabled: true}}}}).Command(f.user.Public)
	if err != nil {
		t.Fatal(err)
	}
	f.submit(enroll)
	f.refreshSession()
	f.change("create-tenant", 0, control.TenantID{ID: "tenant"})
	catalog, err := f.policy.Catalog(f.read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	f.change("set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{f.peers[0].ID}})
	scope := volumes.Scope{Cluster: clusterID, Tenant: "tenant", App: "app", ID: "data", Generation: 1}
	spec := volumes.NativeSpec{Schema: 1, Scope: scope, Node: f.peers[0].ID, NodeKey: f.nodes[0].Public, Materialization: "initial", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
	raw, _ := json.Marshal(spec)
	nativeClient := engine.Client{Owner: engine.Owner(clusterID, f.nodes[0].Public)}
	nativeID, err := nativeClient.Identity("volume", volumes.NativeKey(spec), reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	native := volumes.NativeReady{Schema: 1, Spec: spec, Generation: 1, Owner: volumes.Owner{Node: spec.Node, Key: spec.NodeKey, Native: nativeID.Name}}
	native.Signature = ed25519.Sign(f.nodes[0].Private, volumes.NativeReadyBytes(native))
	f.change("create-volume", 0, native)
	f.change("volume-file-get", 1, control.VolumeFileChange{Scope: scope, Path: "backups/original.bin", MaxBytes: 128 << 10})
	book, err := f.policy.Volumes(f.read().State)
	if err != nil || len(book.VolumeFiles()) != 1 {
		t.Fatal("accepted file fixture", err)
	}
	f.job = book.VolumeFiles()[0]
	f.service = Service{Engine: f.engines[0], Mesh: f.meshes[0], Self: f.nodes[0], Policy: f.policy}
	mesh, err := mydcp.NewTransport(f.user, clusterID, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mesh.Close() })
	f.client = Client{Mesh: mesh, Self: f.user, Cluster: clusterID, Peers: []mydcp.Peer{f.peers[0]}}
	f.wait(func() bool {
		view, err := f.engines[0].Read(ctx, false)
		return err == nil && view.State.Index() >= f.read().State.Index()
	})
	return f
}

func (f *volumeFileWireFixture) wait(ready func() bool) {
	f.t.Helper()
	for !ready() {
		select {
		case <-f.ctx.Done():
			f.t.Fatal(f.ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func (f *volumeFileWireFixture) read() cluster.View {
	f.t.Helper()
	v, err := f.engines[1].Read(f.ctx, true)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}
func (f *volumeFileWireFixture) submit(cmd state.Command) {
	f.t.Helper()
	out, err := f.engines[1].Submit(f.ctx, cmd)
	if err != nil || out.Result.Code != state.Applied {
		f.t.Fatal("original control command", out.Result.Code, err)
	}
}
func (f *volumeFileWireFixture) refreshSession() {
	f.t.Helper()
	catalog, err := f.policy.Catalog(f.read().State)
	if err != nil {
		f.t.Fatal(err)
	}
	u, _ := catalog.User("admin")
	now := time.Now().Unix()
	f.session = access.Session{Schema: 1, ID: "file-session", Cluster: f.policy.Cluster, User: u.ID, Credential: "key", AccountRevision: u.Revision, Key: f.user.Public, Issuer: f.nodes[0].Public, IssuerEpoch: 1, IssuedAt: now, ExpiresAt: now + 600, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read, access.ManageVolumes, access.ManageCluster}}}}
	f.session.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(f.session))
}
func (f *volumeFileWireFixture) change(action string, expected uint64, value any) {
	f.t.Helper()
	raw, err := control.ChangeBytes(action, f.session.User, expected, value)
	if err != nil {
		f.t.Fatal(err)
	}
	var change control.Change
	if err = json.Unmarshal(raw, &change); err != nil {
		f.t.Fatal(err)
	}
	v := f.read()
	f.serial++
	op := control.UserOperation{Schema: 1, Session: f.session, At: time.Now().Unix(), Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.CommandKey(action)).Revision, RequestID: fmt.Sprintf("file-wire-%d", f.serial), Change: change}
	op.Signature = ed25519.Sign(f.user.Private, control.OperationBytes(op))
	cmd, err := op.Command()
	if err != nil {
		f.t.Fatal(err)
	}
	f.submit(cmd)
}
func (f *volumeFileWireFixture) revoke() {
	f.t.Helper()
	c, err := f.policy.Catalog(f.read().State)
	if err != nil {
		f.t.Fatal(err)
	}
	u, _ := c.User("admin")
	u.Credentials[0].Label = "revoked-old-session-revision"
	expected := u.Revision
	u.Revision = 0
	f.change("put-user", expected, u)
}

func TestVolumeFileActualFollowerOwnerQuorumAndCurrentUserGates(t *testing.T) {
	for _, mode := range []string{"ok", "pre-io-denied", "mid-io-revoked", "post-io-revoked", "prefix-not-received", "node-relay-without-user-proof"} {
		t.Run(mode, func(t *testing.T) {
			f := newVolumeFileWireFixture(t)
			var calls atomic.Int32
			body := bytes.Repeat([]byte("private-file-data"), 4000)
			f.service.VolumeFiles = func(ctx context.Context, session access.Session, job control.VolumeFileJob, boundary VolumeFileIO) (VolumeFileReply, error) {
				calls.Add(1)
				if job.ID != f.job.ID || job.Consumer != f.job.Consumer || !sameSession(session, f.session) || job.Native.Owner.Key != f.nodes[0].Public || f.engines[0].IsLeader() || boundary.Epoch == 0 {
					return VolumeFileReply{}, mydcp.ErrAdmission
				}
				for offset := 0; offset < len(body); offset += 24 << 10 {
					if mode == "mid-io-revoked" && offset > 0 {
						f.revoke()
					}
					if err := boundary.Write(body[offset:min(offset+(24<<10), len(body))]); err != nil {
						return VolumeFileReply{}, err
					}
				}
				if mode == "post-io-revoked" {
					f.revoke()
				}
				return VolumeFileReply{Schema: 1, ID: job.ID, Code: "ok", Result: &volumes.FileResult{Path: job.Request.Path, Size: int64(len(body)), Digest: sha256.Sum256(body)}}, nil
			}
			if err := f.meshes[0].OnManagement(mydcp.VolumeFile, f.service.handleVolumeFile); err != nil {
				t.Fatal(err)
			}
			if mode == "pre-io-denied" {
				f.revoke()
			}
			callCtx := f.ctx
			if mode == "prefix-not-received" {
				f.blocked.Store(true)
				defer f.blocked.Store(false)
				f.change("create-tenant", 0, control.TenantID{ID: "after-owner-prefix"})
				local, err := f.engines[0].Read(f.ctx, false)
				if err != nil || local.State.Index() >= f.read().State.Index() {
					t.Fatal("fixture failed to hold original follower prefix", err)
				}
				var cancel context.CancelFunc
				callCtx, cancel = context.WithTimeout(f.ctx, 100*time.Millisecond)
				defer cancel()
			}
			var received bytes.Buffer
			var got VolumeFileReply
			var err error
			if mode == "node-relay-without-user-proof" {
				relay := Client{Mesh: f.meshes[1], Self: f.nodes[1], Cluster: f.policy.Cluster}
				q := VolumeFileRequest{Schema: 1, ID: f.job.ID, ExpiresAt: time.Now().Add(time.Minute).Unix(), Nonce: [32]byte{1}}
				got, err = relay.volumeFileExchange(callCtx, f.peers[0], q, f.job, nil, &received, 3, func(conn *mydcp.Session, body []byte) (Envelope, error) {
					e := Envelope{Body: body, Session: &f.session}
					e.Relay = &Relay{Node: f.nodes[1].Public, Target: f.nodes[0].Public, Caller: f.user.Public, Challenge: [32]byte{2}, Connection: conn.PeerChallenge()}
					// A correctly signed node attestation must not mint the
					// missing original user's request approval.
					e.Signature = ed25519.Sign(f.nodes[1].Private, access.RequestBytes(f.session, e.Relay.Challenge, body))
					e.Relay.Signature = ed25519.Sign(f.nodes[1].Private, RelayBytes(f.policy.Cluster, e))
					return e, nil
				})
			} else {
				got, err = f.client.VolumeFile(callCtx, f.peers[0], f.session, f.job, nil, &received)
			}
			if mode == "ok" {
				if err != nil || got.Code != "ok" || !bytes.Equal(received.Bytes(), body) || calls.Load() != 1 {
					t.Fatal("follower owner did not consume quorum original", got.Code, calls.Load(), err)
				}
			} else {
				if err == nil {
					t.Fatal("denied/revoked/unpublished request succeeded", mode)
				}
				if (mode == "pre-io-denied" || mode == "prefix-not-received" || mode == "node-relay-without-user-proof") && (calls.Load() != 0 || received.Len() != 0) {
					t.Fatal("I/O entered before current prefix/authority", mode, calls.Load(), received.Len())
				}
				if mode == "mid-io-revoked" && received.Len() > 24<<10 {
					t.Fatal("revoked stream consumed another chunk")
				}
			}
			f.blocked.Store(false)
			// This wire runner never claims native closure. A denied response or
			// revocation must leave the exact accepted consumer and original ID.
			book, err := f.policy.Volumes(f.read().State)
			if err != nil {
				t.Fatal(err)
			}
			retained, ok := book.VolumeFile(f.job.ID)
			if !ok || retained.Phase != "Reserved" || retained.Consumer != f.job.Consumer || !bytes.Equal(control.OperationBytes(retained.Origin), control.OperationBytes(f.job.Origin)) {
				t.Fatal("wire failure forged close or replaced original operation")
			}
		})
	}
}

func TestVolumeFileCurrentViewRejectsEpochNativeAndRelaySubstitution(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	v, err := f.service.authenticationView(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{Session: &f.session}
	if _, err := f.service.volumeFileAt(v, e, f.job.ID, v.State.ModuleEpoch(), &f.job); err != nil {
		t.Fatal("consumed follower view denied", err)
	}
	if _, err := f.service.volumeFileAt(v, e, f.job.ID, v.State.ModuleEpoch()+1, &f.job); err == nil {
		t.Fatal("stream crossed its accepted epoch")
	}
	wrong := f.job
	wrong.Native.Generation++
	if _, err := f.service.volumeFileAt(v, e, f.job.ID, v.State.ModuleEpoch(), &wrong); err == nil {
		t.Fatal("substituted native generation admitted")
	}
	e.Relay = &Relay{Node: [32]byte{99}}
	if _, err := f.service.volumeFileAt(v, e, f.job.ID, v.State.ModuleEpoch(), &f.job); err == nil {
		t.Fatal("unknown relay obtained original user authority")
	}
}

// A buffered chunk is not an authority cache: revocation before its delivery
// or the final EOF is consumed must prevent further native input reads.
func TestVolumeFileBufferedInputRechecksAuthorityBeforeDelivery(t *testing.T) {
	denied := errors.New("current grant revoked")
	r := volumeFileReader{pending: []byte("original-input"), authorize: func() error { return denied }}
	if n, err := r.Read(make([]byte, 32)); n != 0 || !errors.Is(err, denied) || string(r.pending) != "original-input" {
		t.Fatal("buffered input bypassed current authority", n, err)
	}
	r.pending, r.done = nil, true
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, denied) || errors.Is(err, io.EOF) {
		t.Fatal("revoked EOF reported as authorized completion", err)
	}
}
