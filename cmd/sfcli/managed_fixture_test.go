// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// managedNode is one initialized single-node cluster for CLI tests. The
// bootstrap admin key enrolls the first system administrator; every later
// catalog change is a signed user operation, as in a real installation.
type managedNode struct {
	t       *testing.T
	ctx     context.Context
	Config  config.Node
	Runtime *app.Runtime
	Address string
	Cluster [32]byte
	Policy  control.Policy
	Peer    sfcp.Peer
	Admin   *identity.Identity
	client  *userauth.Client
	session *access.Session
	user    string
}

func newManagedNode(t *testing.T, ctx context.Context, root, nodeID string, admin *identity.Identity) *managedNode {
	t.Helper()
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	if err = probe.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Node{Version: 1, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = nodeID, address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node-key")
	initialized, err := app.Initialize(ctx, cfg, admin.Public, "init-"+nodeID)
	if err != nil {
		t.Fatal(err)
	}
	m := &managedNode{t: t, ctx: ctx, Config: cfg, Address: address, Admin: admin}
	m.Open()
	t.Cleanup(func() {
		if m.Runtime != nil {
			_ = m.Runtime.Close()
		}
		if m.client != nil {
			_ = m.client.Mesh.Close()
			clear(m.client.Self.Private)
		}
	})
	m.Cluster = initialized.Installation.Root.Cluster
	m.Policy = control.Policy{Cluster: m.Cluster, BootstrapKey: admin.Public, TrustRoot: m.Runtime.Identity.Public, Genesis: initialized.Installation.Genesis}
	m.Peer = sfcp.Peer{ID: nodeID, Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(m.Runtime.Identity.Public), Respond: true}}
	return m
}

// Open starts (or restarts on the same state root) the node runtime.
func (m *managedNode) Open() {
	m.t.Helper()
	if m.client != nil {
		// Sessions bind the client connection key; log in again after a restart.
		_ = m.client.Mesh.Close()
		clear(m.client.Self.Private)
		m.client, m.session = nil, nil
	}
	runtime, err := app.Open(m.Config)
	if err != nil {
		m.t.Fatal(err)
	}
	m.Runtime = runtime
	if _, err = runtime.InstallConfiguration(m.ctx); err != nil {
		m.t.Fatal(err)
	}
}

// Close stops the runtime; Open may then reopen the same state root.
func (m *managedNode) Close() {
	m.t.Helper()
	if err := m.Runtime.Close(); err != nil {
		m.t.Fatal(err)
	}
	m.Runtime = nil
}

// Node is the installation identity of the node; tests use it to forge or
// re-sign session fixtures.
func (m *managedNode) Node() *identity.Identity { return m.Runtime.Identity }

// ClientProfile is a user client profile for this node.
func (m *managedNode) ClientProfile() string {
	return fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n  - {id: %s, key: '%s', endpoint: '%s', voter: true}\n", m.Cluster, m.Peer.ID, m.Runtime.Identity.Actor(), m.Address)
}

// SaveContext saves context name (made current) for this node in home.
func (m *managedNode) SaveContext(home, name, user string) {
	m.t.Helper()
	saveTestContext(m.t, home, name, user, "sfcp://"+m.Address, m.Cluster, m.Peer.ID, m.Runtime.Identity.Public)
}

// saveTestContext saves context name (made current) in home for one node,
// trusting its key out of band. New-frame commands read it.
func saveTestContext(t *testing.T, home, name, user, endpoint string, cluster [32]byte, node string, key [32]byte) {
	t.Helper()
	e, err := cliprofile.ParseEndpoint(endpoint, false)
	if err != nil {
		t.Fatal(err)
	}
	store, err := cliprofile.OpenStore(home, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := hex.EncodeToString(cluster[:])
	trust, err := cliprofile.TrustNode(cliprofile.Trust{Version: 1, Cluster: id}, cliprofile.PeerIdentity{Cluster: cluster, Key: key, ID: node, Endpoint: e}, "out-of-band", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SaveTrust(trust); err != nil {
		t.Fatal(err)
	}
	c := cliprofile.Config{Version: 1, Current: name, Contexts: map[string]cliprofile.Context{name: {Endpoint: e.URI, Cluster: id, User: user}}}
	if err = store.Save(c); err != nil {
		t.Fatal(err)
	}
}

// Catalog reads the current user catalog.
func (m *managedNode) Catalog() access.Catalog {
	m.t.Helper()
	v, err := m.Runtime.Engine().Read(m.ctx, true)
	if err != nil {
		m.t.Fatal(err)
	}
	c, err := m.Policy.Catalog(v.State)
	if err != nil {
		m.t.Fatal(err)
	}
	return c
}

// EnrollAdmin registers user as the first system administrator. The user's
// private-key credential must be the bootstrap admin key.
func (m *managedNode) EnrollAdmin(user access.User) {
	m.t.Helper()
	reply, err := m.adminClient().Enroll(m.ctx, m.Peer, control.Enrollment{Schema: 1, RequestID: "enroll-" + user.ID, User: user}, m.Admin.Private)
	if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
		m.t.Fatal("enroll admin", reply.Code, err)
	}
	m.user = user.Username
}

// Change applies one catalog change as the enrolled administrator.
func (m *managedNode) Change(id, action string, expected uint64, payload any) state.Result {
	m.t.Helper()
	c := m.adminClient()
	if m.session == nil {
		session, err := c.Login(m.ctx, m.Peer, m.user, m.Admin.Private)
		if err != nil {
			m.t.Fatal("admin login", err)
		}
		m.session = &session
	}
	raw, err := control.ChangeBytes(action, m.session.User, expected, payload)
	if err != nil {
		m.t.Fatal(err)
	}
	var change control.Change
	if err = json.Unmarshal(raw, &change); err != nil {
		m.t.Fatal(err)
	}
	op, err := c.Prepare(m.ctx, m.Peer, *m.session, id, change)
	if err != nil {
		m.t.Fatal("prepare", id, err)
	}
	reply, err := c.Operation(m.ctx, m.Peer, op, false)
	if err != nil || reply.Result == nil {
		m.t.Fatal("apply", id, reply.Code, err)
	}
	return *reply.Result
}

func (m *managedNode) adminClient() *userauth.Client {
	m.t.Helper()
	if m.client != nil {
		return m.client
	}
	self, err := identity.Ephemeral()
	if err != nil {
		m.t.Fatal(err)
	}
	peer := m.Peer
	mesh, err := sfcp.NewTransport(self, m.Cluster, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		m.t.Fatal(err)
	}
	m.client = &userauth.Client{Mesh: mesh, Self: self, Cluster: m.Cluster, Peers: []sfcp.Peer{peer}}
	return m.client
}
