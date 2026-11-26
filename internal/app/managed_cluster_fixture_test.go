// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// managedVoters is an initialized managed cluster whose first node ran
// init and whose other nodes joined by invitation and were promoted to
// voters. The bootstrap admin is enrolled as user "admin".
type managedVoters struct {
	t       *testing.T
	ctx     context.Context
	Configs []config.Node
	Nodes   []*Runtime
	Peers   []config.Peer
	Cluster [32]byte
	Policy  control.Policy
	admin   *identity.Identity
	client  userauth.Client
	session access.Session
	mu      sync.RWMutex
	known   map[mydcp.Identity]mydcp.Peer
}

func newManagedVoters(t *testing.T, ctx context.Context, root string, admin *identity.Identity, count int) *managedVoters {
	t.Helper()
	m := &managedVoters{t: t, ctx: ctx, admin: admin, known: map[mydcp.Identity]mydcp.Peer{}}
	t.Cleanup(func() {
		for _, n := range m.Nodes {
			if n != nil {
				_ = n.Close()
			}
		}
	})
	nodeConfig := func(id string) config.Node {
		probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := probe.LocalAddr().String()
		_ = probe.Close()
		c := config.Node{Version: 1, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
		c.Node.ID, c.Node.Listen = id, address
		c.Node.StateDir, c.Node.IdentityDir = filepath.Join(root, id+"-state"), filepath.Join(root, id)
		return c
	}
	first := nodeConfig("node-0")
	initialized, err := Initialize(ctx, first, admin.Public, "init-voters")
	if err != nil {
		t.Fatal(err)
	}
	source, err := Open(first)
	if err != nil {
		t.Fatal(err)
	}
	m.Configs, m.Nodes = append(m.Configs, first), append(m.Nodes, source)
	if _, err = source.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	m.Cluster = initialized.Installation.Root.Cluster
	m.Policy = control.Policy{Cluster: m.Cluster, BootstrapKey: admin.Public, TrustRoot: source.Identity.Public, Genesis: initialized.Installation.Genesis}
	m.addPeer(initialized.Installation.Genesis)
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	m.client = userauth.Client{Self: self, Cluster: m.Cluster, Peers: []mydcp.Peer{m.Peer(0)}}
	m.client.Mesh, err = mydcp.NewTransport(self, m.Cluster, m.lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.client.Mesh.Close(); clear(self.Private) })
	entry := m.Peer(0)
	enrolled, err := m.client.Enroll(ctx, entry, control.Enrollment{Schema: 1, RequestID: "enroll-admin", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}, admin.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", enrolled.Code, err)
	}
	if m.session, err = m.client.Login(ctx, entry, "admin", admin.Private); err != nil {
		t.Fatal("admin login", err)
	}
	for i := 1; i < count; i++ {
		id := fmt.Sprintf("node-%d", i)
		cfg := nodeConfig(id)
		key, err := identity.Create(cfg.Node.IdentityDir)
		if err != nil {
			t.Fatal(err)
		}
		clear(key.Private)
		target := config.Peer{ID: id, Key: key.Actor(), Endpoint: cfg.Node.Listen}
		m.Change(0, "invite-"+id, "invite-node", 0, control.NodeInvitation{Peer: target, JoinID: "join-" + id})
		var inv membership.Invitation
		m.wait("invitation "+id, func() bool {
			inv, err = m.client.NodeInvitation(ctx, entry, m.session, id)
			return err == nil
		})
		runtime, _, err := Join(ctx, cfg, inv, m.Cluster, source.Identity.Public)
		if err != nil {
			t.Fatal("join", id, err)
		}
		m.Configs, m.Nodes = append(m.Configs, cfg), append(m.Nodes, runtime)
		m.addPeer(target)
		m.client.Peers = append(m.client.Peers, m.Peer(i))
		m.wait("member ready "+id, func() bool { e, ok := m.directory(runtime).Entry(id); return ok && e.Phase == membership.Ready })
		e, _ := m.directory(source).Entry(id)
		m.Change(0, "promote-"+id, "promote-node", e.Revision, control.NodeSelection{ID: id})
		m.wait("voter "+id, func() bool {
			e, ok := m.directory(source).Entry(id)
			return ok && e.Phase == membership.Active && e.Peer.Voter && e.Job.Pending == nil
		})
	}
	for i := range m.Nodes {
		m.Peers[i].Voter = true
	}
	return m
}

func (m *managedVoters) addPeer(p config.Peer) {
	k, _ := identity.ParseKey(p.Key)
	m.mu.Lock()
	m.known[mydcp.Identity(k)] = mydcp.Peer{ID: p.ID, Endpoint: p.Endpoint, Policy: mydcp.Policy{Key: mydcp.Identity(k), Respond: true}}
	m.mu.Unlock()
	m.Peers = append(m.Peers, p)
}

func (m *managedVoters) lookup(k mydcp.Identity) (mydcp.Peer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.known[k]
	return p, ok
}

// Peer is node i as a client target.
func (m *managedVoters) Peer(i int) mydcp.Peer {
	k, _ := identity.ParseKey(m.Peers[i].Key)
	p, _ := m.lookup(mydcp.Identity(k))
	return p
}

// Change applies one catalog change as "admin", entering through node i.
func (m *managedVoters) Change(i int, id, action string, expected uint64, payload any) {
	m.t.Helper()
	raw, err := control.ChangeBytes(action, "admin", expected, payload)
	if err != nil {
		m.t.Fatal(err)
	}
	var change control.Change
	if err = json.Unmarshal(raw, &change); err != nil {
		m.t.Fatal(err)
	}
	// A prepared operation pins the target root's revision. Node reports can
	// move that root before it commits, so a ConditionFailed is prepared again
	// under a new request ID; a stale explicit expected keeps failing.
	for attempt := 0; ; attempt++ {
		request := id
		if attempt > 0 {
			request = fmt.Sprintf("%s-%d", id, attempt)
		}
		op, err := m.client.Prepare(m.ctx, m.Peer(i), m.session, request, change)
		if err != nil {
			m.t.Fatal("prepare", action, err)
		}
		// Resubmitting the same signed operation is idempotent, so a transient
		// unavailable reply under load is retried with the original request.
		var reply userauth.Reply
		m.wait("change "+action, func() bool {
			reply, err = m.client.Operation(m.ctx, m.Peer(i), op, false)
			return err == nil && reply.Result != nil
		})
		if reply.Result.Code == state.Applied {
			return
		}
		if reply.Result.Code != state.ConditionFailed || attempt == 4 {
			m.t.Fatal("change", request, action, reply.Code, reply.Result)
		}
	}
}

func (m *managedVoters) directory(r *Runtime) membership.Directory {
	m.t.Helper()
	view, err := r.Engine().Read(m.ctx, false)
	if err != nil {
		m.t.Fatal(err)
	}
	d, err := m.Policy.Members(view.State)
	if err != nil {
		m.t.Fatal(err)
	}
	return d
}

func (m *managedVoters) wait(label string, check func() bool) {
	m.t.Helper()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !check() {
		select {
		case <-m.ctx.Done():
			m.t.Fatal(label, m.ctx.Err())
		case <-tick.C:
		}
	}
}
