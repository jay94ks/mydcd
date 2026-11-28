// SPDX-License-Identifier: Apache-2.0

// Package clusterfixture runs a managed sfcd cluster of real nodes for
// tests (devel/refactor/16). Each node has its own state, SFCP endpoint,
// management socket and fake Docker engine (tests/enginefake); only host
// work is fake. New runs every node in the test process on loopback;
// NewIsolated runs node-1 onward as child processes, each in its own
// network namespace, for networks that span servers. Product packages
// never import it.
package clusterfixture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/tests/enginefake"
)

// Node is one sfcd of the cluster.
type Node struct {
	ID      string
	Config  config.Node
	Runtime *app.Runtime
	Engine  *enginefake.Engine
	// Socket is the node's management socket (what sfc-web mounts).
	Socket string
	// Key is the node identity key a client pins.
	Key [32]byte
	// child runs the node in its own network namespace (NewIsolated);
	// Runtime is then nil.
	child *exec.Cmd
	stdin io.Closer
}

// Cluster is an initialized managed cluster: node-0 ran init, the others
// joined by invitation and were promoted to voters. The bootstrap key is
// enrolled as system administrator "admin" (user ID "u-admin").
type Cluster struct {
	t     *testing.T
	ctx   context.Context
	Nodes []*Node
	ID    [32]byte
	// Policy verifies the cluster's operations (bootstrap key, trust root).
	Policy control.Policy
	Admin  *identity.Identity

	client  userauth.Client
	session access.Session
	mu      sync.RWMutex
	known   map[sfcp.Identity]sfcp.Peer
	// net is the bridge joining the nodes' namespaces (NewIsolated).
	net  *hostNet
	opts []Option
	root string
}

// An Option changes a node's configuration before the node opens (for
// example its Vault backends).
type Option func(*Node)

// New starts a cluster of count nodes named node-0 … node-(count-1), all
// in the test process.
func New(t *testing.T, ctx context.Context, count int, opts ...Option) *Cluster {
	t.Helper()
	return newCluster(t, ctx, count, false, opts)
}

// NewIsolated starts a cluster like New, but node-1 onward each run as a
// child process in its own network namespace, joined to node-0 (in the
// test's namespace) by a bridge: their routes, TUN devices and container
// namespaces cannot collide. It needs root, and the test package's TestMain
// must call Main. A child node's Runtime is nil.
func NewIsolated(t *testing.T, ctx context.Context, count int, opts ...Option) *Cluster {
	t.Helper()
	return newCluster(t, ctx, count, true, opts)
}

func newCluster(t *testing.T, ctx context.Context, count int, isolated bool, opts []Option) *Cluster {
	t.Helper()
	// Unix socket paths are limited to 107 bytes; t.TempDir can be longer.
	root, err := os.MkdirTemp("", "cf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c := &Cluster{t: t, ctx: ctx, Admin: admin, known: map[sfcp.Identity]sfcp.Peer{}, opts: opts, root: root}
	if isolated {
		if c.net, err = newHostNet(); err != nil {
			t.Fatal("host network", err)
		}
		t.Cleanup(c.net.close)
	}
	// Cleanups run last-in first-out: nodes close before their engines.
	t.Cleanup(func() {
		for _, n := range c.Nodes {
			if n.Runtime != nil {
				_ = n.Runtime.Close()
			}
			if n.child != nil {
				stopChild(n)
			}
		}
	})

	first := c.node(root, "node-0")
	initialized, err := app.Initialize(ctx, first.Config, admin.Public, "init-cluster")
	if err != nil {
		t.Fatal("init", err)
	}
	if first.Runtime, err = app.Open(first.Config); err != nil {
		t.Fatal("open", err)
	}
	if _, err = first.Runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	c.serve(first)
	c.ID = initialized.Installation.Root.Cluster
	c.Policy = control.Policy{Cluster: c.ID, BootstrapKey: admin.Public, TrustRoot: first.Runtime.Identity.Public, Genesis: initialized.Installation.Genesis}

	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c.client = userauth.Client{Self: self, Cluster: c.ID, Peers: []sfcp.Peer{c.Peer(0)}}
	if c.client.Mesh, err = sfcp.NewTransport(self, c.ID, c.lookup); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.client.Mesh.Close(); clear(self.Private) })
	c.Enroll(access.User{ID: "u-admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}})
	if c.session, err = c.client.Login(ctx, c.Peer(0), "admin", admin.Private); err != nil {
		t.Fatal("admin login", err)
	}

	for i := 1; i < count; i++ {
		n, target := c.Prepare(fmt.Sprintf("node-%d", i))
		c.Change(0, "invite-"+n.ID, "invite-node", 0, control.NodeInvitation{Peer: target, JoinID: "join-" + n.ID})
		var inv membership.Invitation
		c.Wait("invitation "+n.ID, func() bool {
			inv, err = c.client.NodeInvitation(ctx, c.Peer(0), c.session, n.ID)
			return err == nil
		})
		if isolated {
			c.startChild(n, i, inv)
			c.client.Peers = append(c.client.Peers, c.Peer(i))
		} else {
			c.Join(n, inv)
		}
		c.Wait("member ready "+n.ID, func() bool { e, ok := c.directory(first.Runtime).Entry(n.ID); return ok && e.Phase == membership.Ready })
		e, _ := c.directory(first.Runtime).Entry(n.ID)
		c.Change(0, "promote-"+n.ID, "promote-node", e.Revision, control.NodeSelection{ID: n.ID})
		c.Wait("voter "+n.ID, func() bool {
			e, ok := c.directory(first.Runtime).Entry(n.ID)
			return ok && e.Phase == membership.Active && e.Peer.Voter && e.Job.Pending == nil
		})
	}
	return c
}

// Prepare makes the next node (its directories, engine and identity key)
// without joining it: the caller invites it (target is its peer) and then
// calls Join with the invitation. Not for NewIsolated clusters.
func (c *Cluster) Prepare(id string) (*Node, config.Peer) {
	c.t.Helper()
	n := c.node(c.root, id)
	key, err := identity.Create(n.Config.Node.IdentityDir)
	if err != nil {
		c.t.Fatal(err)
	}
	clear(key.Private)
	return n, config.Peer{ID: n.ID, Key: key.Actor(), Endpoint: n.Config.Node.Listen}
}

// Join starts a prepared node with its invitation; it then waits as a
// learner until promoted.
func (c *Cluster) Join(n *Node, inv membership.Invitation) {
	c.t.Helper()
	var err error
	if n.Runtime, _, err = app.Join(c.ctx, n.Config, inv, c.ID, c.Nodes[0].Runtime.Identity.Public); err != nil {
		c.t.Fatal("join", n.ID, err)
	}
	c.serve(n)
	c.client.Peers = append(c.client.Peers, c.Peer(slices.Index(c.Nodes, n)))
}

// node prepares a node's directories, SFCP endpoint (loopback, or the
// bridge address of NewIsolated) and fake engine.
func (c *Cluster) node(root, id string) *Node {
	c.t.Helper()
	host := "127.0.0.1"
	if c.net != nil {
		host = c.net.address(len(c.Nodes)).String()
	}
	address := net.JoinHostPort(host, childPort)
	if len(c.Nodes) == 0 || c.net == nil {
		probe, err := net.ListenPacket("udp4", net.JoinHostPort(host, "0"))
		if err != nil {
			c.t.Fatal(err)
		}
		address = probe.LocalAddr().String()
		_ = probe.Close()
	}
	dir := filepath.Join(root, id)
	engine, err := enginefake.Start(filepath.Join(dir, "docker"))
	if err != nil {
		c.t.Fatal(err)
	}
	// Bridge networks get real kernel bridges and running containers their
	// own network namespaces, as Docker makes, when the test can (root in
	// the cloud test container).
	if os.Geteuid() == 0 {
		engine.UseHost("")
	}
	c.t.Cleanup(func() {
		_ = engine.Close()
		if u := engine.Unknown(); len(u) > 0 {
			c.t.Errorf("%s: Docker calls the fake engine does not know: %v", id, u)
		}
	})
	n := &Node{ID: id, Engine: engine, Socket: filepath.Join(dir, "sfcdp.sock")}
	n.Config = engine.Node()
	n.Config.Node.ID, n.Config.Node.Listen, n.Config.Node.ManagementSocket = id, address, n.Socket
	n.Config.Node.StateDir, n.Config.Node.IdentityDir = filepath.Join(dir, "state"), filepath.Join(dir, "node-key")
	for _, opt := range c.opts {
		opt(n)
	}
	c.Nodes = append(c.Nodes, n)
	return n
}

// serve opens the node's management socket and makes it a known peer.
func (c *Cluster) serve(n *Node) {
	c.t.Helper()
	if err := n.Runtime.Mesh.ListenUnix(n.Socket); err != nil {
		c.t.Fatal(err)
	}
	if socket, ok := listenEngine(n.Runtime, filepath.Dir(n.Socket)); ok {
		n.Engine.ConnectSFCD(socket)
	}
	n.Key = n.Runtime.Identity.Public
	c.register(n)
}

// register makes n (with its Key) a known peer.
func (c *Cluster) register(n *Node) {
	k := sfcp.Identity(n.Key)
	c.mu.Lock()
	c.known[k] = sfcp.Peer{ID: n.ID, Endpoint: n.Config.Node.Listen, Policy: sfcp.Policy{Key: k, Respond: true}}
	c.mu.Unlock()
}

func (c *Cluster) lookup(k sfcp.Identity) (sfcp.Peer, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.known[k]
	return p, ok
}

// Peer is node i as a SFCP client target.
func (c *Cluster) Peer(i int) sfcp.Peer {
	p, _ := c.lookup(sfcp.Identity(c.Nodes[i].Key))
	return p
}

// Enroll adds a user with the bootstrap key, as a real installation's first
// administrator does.
func (c *Cluster) Enroll(user access.User) {
	c.t.Helper()
	reply, err := c.client.Enroll(c.ctx, c.Peer(0), control.Enrollment{Schema: 1, RequestID: "enroll-" + user.ID, User: user}, c.Admin.Private)
	if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
		c.t.Fatal("enroll", user.ID, reply.Code, err)
	}
}

// Change applies one catalog change as "admin", entering through node i.
// A ConditionFailed (a node report moved the root after prepare) is
// prepared again under a new request ID, at most four times.
func (c *Cluster) Change(i int, id, action string, expected uint64, payload any) {
	c.t.Helper()
	raw, err := control.ChangeBytes(action, "u-admin", expected, payload)
	if err != nil {
		c.t.Fatal(err)
	}
	var change control.Change
	if err = json.Unmarshal(raw, &change); err != nil {
		c.t.Fatal(err)
	}
	for attempt := 0; ; attempt++ {
		request := id
		if attempt > 0 {
			request = fmt.Sprintf("%s-%d", id, attempt)
		}
		op, err := c.client.Prepare(c.ctx, c.Peer(i), c.session, request, change)
		if err != nil {
			c.t.Fatal("prepare", action, err)
		}
		var reply userauth.Reply
		c.Wait("change "+action, func() bool {
			reply, err = c.client.Operation(c.ctx, c.Peer(i), op, false)
			return err == nil && reply.Result != nil
		})
		if reply.Result.Code == state.Applied {
			return
		}
		if reply.Result.Code != state.ConditionFailed || attempt == 4 {
			c.t.Fatal("change", request, action, reply.Code, reply.Result)
		}
	}
}

// State is node-0's latest committed state (for expected revisions).
func (c *Cluster) State() state.State {
	c.t.Helper()
	view, err := c.Nodes[0].Runtime.Engine().Read(c.ctx, true)
	if err != nil {
		c.t.Fatal(err)
	}
	return view.State
}

func (c *Cluster) directory(r *app.Runtime) membership.Directory {
	c.t.Helper()
	view, err := r.Engine().Read(c.ctx, false)
	if err != nil {
		c.t.Fatal(err)
	}
	d, err := c.Policy.Members(view.State)
	if err != nil {
		c.t.Fatal(err)
	}
	return d
}

// Wait polls check every 20ms until it holds or the context ends.
func (c *Cluster) Wait(label string, check func() bool) {
	c.t.Helper()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !check() {
		select {
		case <-c.ctx.Done():
			c.t.Fatal(label, c.ctx.Err())
		case <-tick.C:
		}
	}
}

// listenEngine opens r's engine socket in dir for the fake engine, as sfcd
// does for sfed: event feed (32) and log queue (33, 34) travel there. The
// socket admits only root peers, so without root there is none and the
// node sees no engine events or logs.
func listenEngine(r *app.Runtime, dir string) (string, bool) {
	if os.Geteuid() != 0 {
		return "", false
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil || r.Mesh.AllowEnginePeer(exe) != nil {
		return "", false
	}
	socket := filepath.Join(dir, "sfcd-engine.sock")
	if err := r.ListenEngine(socket); err != nil {
		return "", false
	}
	return socket, true
}

// PlanApp is sfcd's planned artifact for an app.yaml, as "admin", entering
// through node i (what `sfcli app up` uploads).
func (c *Cluster) PlanApp(i int, tenant string, q control.AppPlanRequest) []byte {
	c.t.Helper()
	artifact, err := c.client.StreamAppPlan(c.ctx, c.Peer(i), c.session, tenant, q)
	if err != nil {
		c.t.Fatal("plan app", err)
	}
	return artifact
}
