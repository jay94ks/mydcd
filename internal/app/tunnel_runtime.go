// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/desired"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/observability"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
)

// One journal/FD owner, one isolated path/packet plane per logical network.
type tunnelRuntime struct {
	r         *Runtime
	manager   *network.TunnelManager
	mu        sync.Mutex
	instances map[[16]byte]*tunnelInstance
	routes    map[[32]byte]*tunnelInstance
	closed    bool
	// refusals is the last path refusal reason logged for each peer.
	refusals map[mydcp.Identity]pathRefusal
}

func journalTunnelNetwork(record reconcile.Record) (string, bool, error) {
	resources := []reconcile.Resource{record.State.Desired.Resource, record.State.Applied}
	if record.State.Pending != nil {
		resources = append(resources, record.State.Pending.Target)
	}
	name := ""
	for _, r := range resources {
		if !r.Present {
			continue
		}
		spec, err := network.DecodeTunnel(r.Spec)
		if err != nil || name != "" && name != spec.Network {
			return "", false, network.ErrPolicy
		}
		name = spec.Network
	}
	if name == "" && len(record.Consumers) > 0 {
		return "", false, reconcile.ErrLease
	}
	return name, name != "", nil
}

func openTunnelRuntime(r *Runtime, path string) (*tunnelRuntime, error) {
	var m *network.TunnelManager
	var err error

	m, err = network.OpenTunnelManagerWithAdmission(path, r.owner, r.network)

	if err != nil {
		return nil, err
	}
	t := &tunnelRuntime{r: r, manager: m, instances: map[[16]byte]*tunnelInstance{}}
	// Retained native journals share the current transport. Their serving
	// planes are selected by this transport's single exact-owner dispatcher.
	if r.historicalOwner {
		return t, nil
	}
	if err = r.Mesh.OnPath(t.authorize, t.acceptPath); err != nil {
		_ = m.Close()
		return nil, err
	}
	if err = r.Mesh.OnPacket(func(s *mydcp.Session, f mydcp.Frame) error {
		r.life.RLock()
		defer r.life.RUnlock()
		if r.closed || r.ctx.Err() != nil || len(f.Fields) < 2 || len(f.Fields[1].Value) != 16 {
			return mydcp.ErrAdmission
		}
		var selected *tunnelInstance
		for _, owner := range r.physicalOwners() {
			candidate := t
			if owner != r {
				candidate = owner.tunnel
			}
			if candidate == nil {
				continue
			}
			for _, instance := range candidate.packetInstances() {
				plane := instance.serving.Load()
				if plane == nil || !plane.Accepts(s, f) {
					continue
				}
				if selected != nil {
					return mydcp.ErrAdmission
				}
				selected = instance
			}
		}
		if selected == nil {
			return errTunnelPending
		}
		return selected.receive(s, f)
	}); err != nil {
		_ = m.Close()
		return nil, err
	}
	return t, nil
}
func (t *tunnelRuntime) instance(name string) (*tunnelInstance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errTunnelPending
	}
	id := network.NetworkID(t.r.policy.Cluster, name)
	for _, route := range t.routes {
		if network.NetworkID(t.r.policy.Cluster, route.network) == id {
			return nil, network.ErrPolicy
		}
	}
	i := t.instances[id]
	if i == nil {
		i = &tunnelInstance{r: t.r, manager: t.manager, network: name, paths: map[[32]byte]tunnelPath{}}
		t.instances[id] = i
	} else if i.network != name {
		return nil, network.ErrPolicy
	}
	return i, nil
}
func (t *tunnelRuntime) scoped(v cluster.View, scope []byte) (string, tunnelView, error) {
	var empty tunnelView
	decoded, err := schema.Decode[tunnelScope](scope)
	if err != nil {
		return "", empty, err
	}
	views, err := t.r.tunnelViews(v.State)
	if err != nil {
		return "", empty, err
	}
	for name, view := range views {
		id := network.NetworkID(t.r.policy.Cluster, name)
		if decoded.Network == hex.EncodeToString(id[:]) {
			return name, view, nil
		}
	}
	return "", empty, errTunnelPending
}

// A shared transport routes by the exact original scope/packet owner. A
// network ID alone is insufficient after several installed-key generations.
func (t *tunnelRuntime) packetInstances() []*tunnelInstance {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	out := make([]*tunnelInstance, 0, len(t.instances)+len(t.routes))
	for _, i := range t.instances {
		out = append(out, i)
	}
	for _, i := range t.routes {
		out = append(out, i)
	}
	return out
}
func (t *tunnelRuntime) pathOwner(v cluster.View, s *mydcp.Session, scope []byte, mtu int) (*tunnelRuntime, error) {
	var selected *tunnelRuntime
	var refused error = pathRefused("no local owner has a TUN runtime")
	for _, owner := range t.r.physicalOwners() {
		candidate := t
		if owner != t.r {
			candidate = owner.tunnel
		}
		if candidate == nil {
			continue
		}
		if err := candidate.authorizeLocal(v, s, scope, mtu); err != nil {
			refused = err
			continue
		}
		if selected != nil {
			return nil, mydcp.ErrAdmission
		}
		selected = candidate
	}
	if selected == nil {
		t.logRefusal(s.Peer().Key, refused)
		return nil, refused
	}
	t.mu.Lock()
	delete(t.refusals, s.Peer().Key)
	t.mu.Unlock()
	return selected, nil
}

// pathRefusal is why this server refused a peer's TUN path control. It is
// still mydcp.ErrAdmission to the peer; the reason is a fixed local string
// for this server's log.
type pathRefusal string

func pathRefused(reason string) error      { return pathRefusal(reason) }
func (p pathRefusal) Error() string        { return "managed TUN path refused: " + string(p) }
func (p pathRefusal) Is(target error) bool { return target == mydcp.ErrAdmission }

// logRefusal logs a refusal reason once per peer until it changes.
func (t *tunnelRuntime) logRefusal(peer mydcp.Identity, err error) {
	var reason pathRefusal
	if !errors.As(err, &reason) {
		return
	}
	t.mu.Lock()
	if t.refusals == nil {
		t.refusals = map[mydcp.Identity]pathRefusal{}
	}
	same := t.refusals[peer] == reason
	t.refusals[peer] = reason
	t.mu.Unlock()
	if !same {
		log.Printf("managed TUN path from peer=%s refused: %s", hex.EncodeToString(peer[:]), reason)
	}
}
func (t *tunnelRuntime) authorize(ctx context.Context, s *mydcp.Session, scope []byte, mtu int) error {
	v, err := t.r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	_, err = t.pathOwner(v, s, scope, mtu)
	return err
}
func (t *tunnelRuntime) scopedRemote(v cluster.View, view tunnelView, scope []byte, mtu int, peer [32]byte) (string, [32]byte, error) {
	var selected string
	var original [32]byte
	for remote, owner := range view.Owners {
		wire, err := t.r.tunnelWireKey(v.State, owner)
		if err != nil || wire != peer || remote == t.r.owner {
			continue
		}
		want, required, err := pathScope(t.r.policy.Cluster, v, view, t.r.owner, remote)
		if err != nil || required != mtu || !bytes.Equal(want, scope) {
			continue
		}
		if selected != "" {
			return "", [32]byte{}, mydcp.ErrAdmission
		}
		selected, original = remote, owner
	}
	if selected == "" {
		return "", original, mydcp.ErrAdmission
	}
	return selected, original, nil
}
func (t *tunnelRuntime) authorizeLocal(v cluster.View, s *mydcp.Session, scope []byte, mtu int) error {
	r := t.r
	peer := [32]byte(s.Peer().Key)
	wire, err := r.localTunnelWireKey(v)
	if err != nil {
		return pathRefused("this server's key is not its current work key")
	}
	if r.ctx.Err() != nil {
		return mydcp.ErrAdmission
	}
	if bytes.Compare(peer[:], wire[:]) >= 0 {
		return pathRefused("the peer key does not sort before this server's key (the other side starts the path)")
	}
	if work, found, err := t.routePathWork(v, scope); found || err != nil {
		if err != nil {
			return err
		}
		peerWire, keyErr := r.tunnelWireKey(v.State, work.Peer.Local.Owner)
		want, required, err := routePathScope(work)
		if err != nil || keyErr != nil || peerWire != peer || required != mtu || !bytes.Equal(want, scope) {
			return pathRefused("route path scope, MTU or peer key differs")
		}
		_, err = currentRoute(s, work.Tunnel, mtu)
		return err
	}
	_, view, err := t.scoped(v, scope)
	if err != nil {
		return pathRefused("no managed TUN network on this server matches the path scope")
	}
	if _, _, err = t.scopedRemote(v, view, scope, mtu, peer); err != nil {
		return pathRefused("no member of the network has the peer's current work key with the same scope and MTU")
	}
	_, spec, _ := tunnelFor(view.Topology.Tunnels, r.owner)
	_, err = currentRoute(s, spec, mtu)
	return err
}
func (t *tunnelRuntime) acceptPath(s *mydcp.Session, pair mydcp.PathPair) error {
	local, _ := pair.Samples()
	ctx, cancel := context.WithTimeout(t.r.ctx, 5*time.Second)
	defer cancel()
	v, err := t.r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	selected, err := t.pathOwner(v, s, local.Scope, pair.MTU())
	if err != nil {
		return err
	}
	return selected.acceptPathLocal(v, s, pair)
}
func (t *tunnelRuntime) acceptPathLocal(v cluster.View, s *mydcp.Session, p mydcp.PathPair) error {
	local, other := p.Samples()
	var i *tunnelInstance
	var original [32]byte
	var spec network.TunnelSpec
	if work, found, err := t.routePathWork(v, local.Scope); found || err != nil {
		if err != nil {
			return err
		}
		original, spec = work.Peer.Local.Owner, work.Tunnel
		i, err = t.routeInstance(work.Reference.ID, spec.Network)
		if err != nil {
			return err
		}
	} else {
		name, view, err := t.scoped(v, local.Scope)
		if err != nil {
			return err
		}
		_, original, err = t.scopedRemote(v, view, local.Scope, p.MTU(), [32]byte(s.Peer().Key))
		if err != nil {
			return err
		}
		_, spec, _ = tunnelFor(view.Topology.Tunnels, t.r.owner)
		i, err = t.instance(name)
		if err != nil {
			return err
		}
	}
	route, err := currentRoute(s, spec, p.MTU())
	if err != nil {
		return err
	}
	if err = admitPair(p, local, other); err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed || t.r.ctx.Err() != nil {
		return mydcp.ErrAdmission
	}
	prior, exists := i.paths[original]
	oldLocal, oldRemote := prior.Path.Samples()
	if i.plane != nil && (!exists || prior.Session != s || prior.route != route || prior.scope != string(local.Scope) || oldLocal.Budget != local.Budget || oldRemote.Budget != other.Budget || prior.Path.MTU() != p.MTU()) {
		if err = i.stopPlane(); err != nil {
			return err
		}
	}
	i.paths[original] = tunnelPath{PacketPeer: network.PacketPeer{WireKey: [32]byte(s.Peer().Key), Session: s, Path: p}, route: route, scope: string(local.Scope)}
	return nil
}
func (t *tunnelRuntime) reconcile(v cluster.View, views map[string]tunnelView) error {
	for _, key := range t.manager.Keys() {
		record, err := t.manager.View(key)
		if err != nil {
			return err
		}
		name, held, err := journalTunnelNetwork(record)
		if err != nil {
			return err
		}
		if held {
			view, ok := views[name]
			if !ok {
				return fmt.Errorf("unbound native TUN journal %s", key)
			}
			if _, ok = view.Topology.Tunnels[key]; !ok {
				return fmt.Errorf("unbound native TUN source %s", key)
			}
		}
	}
	var failed error
	for _, name := range desired.Sorted(views) {
		view := views[name]
		_, _, local := tunnelFor(view.Topology.Tunnels, t.r.owner)
		if !local {
			continue
		}
		i, err := t.instance(name)
		if err != nil {
			return err
		}
		if err = i.Reconcile(v, view); err != nil {
			failed = errors.Join(failed, fmt.Errorf("%s: %w", name, err))
		}
	}
	return failed
}
func (t *tunnelRuntime) ReconcileManaged(v cluster.View) error {
	views, err := t.r.tunnelViews(v.State)
	if err != nil {
		return err
	}
	return t.reconcile(v, views)
}
func (t *tunnelRuntime) Close() error {
	t.mu.Lock()
	t.closed = true
	instances := make([]*tunnelInstance, 0, len(t.instances))
	for _, i := range t.instances {
		instances = append(instances, i)
	}
	for _, i := range t.routes {
		instances = append(instances, i)
	}
	t.mu.Unlock()
	var failed error
	for _, i := range instances {
		i.mu.Lock()
		i.closed = true
		failed = errors.Join(failed, i.stopPlane())
		i.mu.Unlock()
	}
	return errors.Join(failed, t.manager.Close())
}
func (t *tunnelRuntime) Observe(key string) (TunnelObservation, error) {
	t.mu.Lock()
	instances := make([]*tunnelInstance, 0, len(t.instances))
	for _, i := range t.instances {
		instances = append(instances, i)
	}
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return TunnelObservation{}, errTunnelPending
	}
	for _, i := range instances {
		i.mu.Lock()
		matches := i.key == key
		i.mu.Unlock()
		if matches {
			return i.Observe(key)
		}
	}
	return TunnelObservation{Connections: map[string][32]byte{}}, errTunnelPending
}
func (t *tunnelRuntime) Ready(key string) error { _, err := t.Observe(key); return err }

// Drain first revokes new borrows, then joins packet IO and returns its exact
// durable pin. Dependency consumers remain until their own positive closure.
func (t *tunnelRuntime) Drain(ctx context.Context, key string, revision, generation uint64, spec network.TunnelSpec) (bool, error) {
	i, err := t.instance(spec.Network)
	if err != nil {
		return false, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.key == key {
		// A confirmed drain must revoke packet serving before any journal I/O.
		// If that I/O fails, retain the original lease/key for reconciliation.
		if err = i.stopPlane(); err != nil {
			return false, err
		}
	}
	row, err := t.manager.View(key)
	if err != nil {
		return false, err
	}
	if err = t.manager.Desired(key, revision, generation, nil, row.Capacity); err != nil {
		return false, err
	}
	if i.key == key {
		i.key = ""
		i.lease = network.TunnelLease{}
	}
	for consumer, pin := range row.Consumers {
		if consumer != "packet-plane" {
			continue
		}
		if pin.Generation != generation {
			return false, reconcile.ErrLease
		}
		if err = t.manager.Return(network.TunnelLease{Key: key, Consumer: consumer, Pin: pin}); err != nil {
			return false, err
		}
	}
	if err = t.manager.Step(ctx, key); err != nil {
		return false, err
	}
	return t.manager.Gone(ctx, key, revision, generation, spec)
}

// Waits reports the managed TUN networks whose path is not open, for the
// node's host observation. Only errTunnelPending reasons are reported; their
// text is produced here (MTU and path state), never by a peer.
func (t *tunnelRuntime) Waits() []observability.TunnelWait {
	t.mu.Lock()
	instances := make([]*tunnelInstance, 0, len(t.instances))
	for _, i := range t.instances {
		instances = append(instances, i)
	}
	t.mu.Unlock()
	var out []observability.TunnelWait
	for _, i := range instances {
		i.mu.Lock()
		name, err := i.network, i.lastError
		i.mu.Unlock()
		tenant, netName, ok := managedTunnelName(name)
		if !ok || err == nil || !errors.Is(err, errTunnelPending) || len(out) == 32 {
			continue
		}
		reason := "waiting for the path to the other servers"
		if text := err.Error(); strings.Contains(text, "underlay MTU=") {
			reason = text[strings.Index(text, "underlay MTU="):]
		}
		if len(reason) > 256 || strings.ContainsAny(reason, "\x00\r\n") {
			reason = "waiting for the path to the other servers"
		}
		out = append(out, observability.TunnelWait{Tenant: tenant, Network: netName, Reason: reason})
	}
	slices.SortFunc(out, func(a, b observability.TunnelWait) int {
		return strings.Compare(a.Tenant+"/"+a.Network, b.Tenant+"/"+b.Network)
	})
	return out
}

// managedTunnelName splits "tenant/T/network/N".
func managedTunnelName(name string) (string, string, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 4 || parts[0] != "tenant" || parts[2] != "network" || !lifecycle.ValidID(parts[1]) || !lifecycle.ValidID(parts[3]) {
		return "", "", false
	}
	return parts[1], parts[3], true
}
