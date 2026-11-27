// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/vishvananda/netlink"
	"slices"
)

var errTunnelPending = errors.New("TUN dependencies or current bilateral path unavailable")

type tunnelAnchor struct {
	Key, Spec            string
	Revision, Generation uint64
}
type tunnelScope struct {
	Schema  uint8
	Network string
	A, B    tunnelAnchor
}
type tunnelPath struct {
	network.PacketPeer
	route routeStamp
	scope string
}
type routeStamp struct {
	Link, MTU       int
	Source, Gateway string
}
type tunnelInstance struct {
	network      string
	r            *Runtime
	manager      *network.TunnelManager
	mu           sync.Mutex
	paths        map[[32]byte]tunnelPath
	plane        *network.PacketPlane
	serving      atomic.Pointer[network.PacketPlane]
	configSource [32]byte
	// wires, limits and plan are what the serving plane was built or last
	// retargeted with: a member joining or leaving keeps the plane.
	wires        map[string][32]byte
	limits       [2]int
	plan         network.PacketPlan
	lease        network.TunnelLease
	key          string
	source       [32]byte
	lastError    error
	closed       bool
	routeReading atomic.Bool
}

func tunnelFor(tunnels map[string]network.TunnelSpec, owner string) (string, network.TunnelSpec, bool) {
	for _, key := range desired.Sorted(tunnels) {
		t := tunnels[key]
		if t.Owner == owner && !t.Lifecycle.Released() {
			return key, t, true
		}
	}
	return "", network.TunnelSpec{}, false
}
func anchor(s state.State, key string) tunnelAnchor {
	o := s.Object(key)
	k, v := sha256.Sum256([]byte(key)), sha256.Sum256([]byte(o.Value))
	return tunnelAnchor{Key: hex.EncodeToString(k[:]), Spec: hex.EncodeToString(v[:]), Revision: o.Revision, Generation: o.Generation}
}
func pathScope(cluster [32]byte, v cluster.View, g tunnelView, a, b string) ([]byte, int, error) {
	ak, at, yes := tunnelFor(g.Topology.Tunnels, a)
	bk, bt, other := tunnelFor(g.Topology.Tunnels, b)
	if !yes || !other || at.Lifecycle.Drain || bt.Lifecycle.Drain || at.Network != bt.Network {
		return nil, 0, errTunnelPending
	}
	for key, owner := range map[string]string{ak: b, bk: a} {
		peers, err := g.Topology.Peers(key)
		if err != nil {
			return nil, 0, err
		}
		found := false
		for _, peer := range peers {
			found = found || peer == owner
		}
		if !found {
			return nil, 0, errTunnelPending
		}
	}
	aa, ba := anchor(v.State, ak), anchor(v.State, bk)
	if a > b {
		aa, ba = ba, aa
	}
	n := network.NetworkID(cluster, at.Network)
	binary, err := json.Marshal(tunnelScope{Schema: 1, Network: hex.EncodeToString(n[:]), A: aa, B: ba})
	return binary, max(at.MTU, bt.MTU), err
}

// RouteGet is read-only and resolves the actual connection destination. An
// underlay endpoint inside an overlay route would route SFCP into itself.
func currentRoute(s *sfcp.Session, spec network.TunnelSpec, mtu int) (routeStamp, error) {
	remote, ok := s.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return routeStamp{}, errTunnelPending
	}
	return routeTo(remote.AddrPort().Addr(), spec, mtu)
}

func routeTo(a netip.Addr, spec network.TunnelSpec, mtu int) (routeStamp, error) {
	a = a.Unmap()
	for _, p := range spec.Routes {
		if p.Contains(a) {
			return routeStamp{}, errors.New("SFCP underlay endpoint overlaps TUN route")
		}
	}
	routes, err := netlink.RouteGet(net.IP(a.AsSlice()))
	if err != nil || len(routes) != 1 {
		return routeStamp{}, errors.Join(err, errTunnelPending)
	}
	route := routes[0]
	link, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil || link.Attrs().Flags&net.FlagUp == 0 {
		return routeStamp{}, errors.Join(err, errTunnelPending)
	}
	limit := link.Attrs().MTU
	if route.MTU > 0 {
		limit = min(limit, route.MTU)
	}
	stamp := routeStamp{Link: route.LinkIndex, MTU: limit, Source: route.Src.String(), Gateway: route.Gw.String()}
	header := 28
	if a.Is6() {
		header = 48
	}
	// This is the minimum possible native payload cost. The negotiated CID,
	// remote limit and actual ACK-based limit are checked by PathPair as well.
	if limit < mtu+header+sfcp.PacketFrameOverhead+37 {
		return stamp, fmt.Errorf("%w: underlay MTU=%d cannot carry TUN MTU=%d", errTunnelPending, limit, mtu)
	}
	return stamp, nil
}

func admitPair(p sfcp.PathPair, a, b sfcp.PathSample) error {
	scope, err := schema.Decode[tunnelScope](a.Scope)
	if err != nil || !bytes.Equal(a.Scope, b.Scope) {
		return errTunnelPending
	}
	obs := func(s sfcp.PathSample) network.MTUObservation {
		return network.MTUObservation{From: hex.EncodeToString(s.From[:]), To: hex.EncodeToString(s.To[:]), Source: scope.A.Revision, Generation: scope.A.Generation, At: uint64(s.At), PathMTU: s.Budget.UDPBytes, Overhead: s.Budget.UDPBytes - s.Budget.IPBytes}
	}
	return network.AdmitMTU(p.MTU(), scope.A.Revision, scope.A.Generation, uint64(time.Now().UnixMilli()), 30_000, obs(a), obs(b))
}

func (t *tunnelInstance) receive(s *sfcp.Session, f sfcp.Frame) error {
	plane := t.serving.Load()
	if plane == nil {
		return errTunnelPending
	}
	peer, known := t.r.Mesh.Peer(s.Peer().Key)
	if !known || !peer.Tunnel {
		return sfcp.ErrAdmission
	}
	return plane.Receive(s, f)
}

func (t *tunnelInstance) stopPlane() error {
	// Revoke admission before joining the old IO owner. A receiver that
	// already loaded it is synchronized by PacketPlane.Receive/Stop itself.
	t.serving.Store(nil)
	if t.plane == nil {
		return nil
	}
	err := t.plane.Stop()
	t.routeReading.Store(false)
	t.plane = nil
	t.source = [32]byte{}
	t.configSource = [32]byte{}
	t.wires, t.limits, t.plan = nil, [2]int{}, network.PacketPlan{}
	return err
}

// retainedPlan keeps the peers whose original owner is still a member under
// the same wire key: the ones that left lose admission at once.
func retainedPlan(plan network.PacketPlan, owners, wires map[string][32]byte) network.PacketPlan {
	out := plan
	out.Peers = map[[32]byte]network.PacketPeer{}
	for owner, pub := range owners {
		if peer, ok := plan.Peers[pub]; ok && peer.WireKey == wires[owner] {
			out.Peers[pub] = peer
		}
	}
	return out
}

func (t *tunnelInstance) Reconcile(v cluster.View, g tunnelView) (result error) {
	t.mu.Lock()
	defer func() { t.lastError = result; t.mu.Unlock() }()
	if t.closed {
		return errTunnelPending
	}
	r := t.r
	wire, wireErr := r.localTunnelWireKey(v)
	if wireErr != nil {
		return errors.Join(wireErr, t.stopPlane())
	}
	wireOwners := map[string][32]byte{}
	for owner, original := range g.Owners {
		key, err := r.tunnelWireKey(v.State, original)
		if err != nil {
			return errors.Join(err, t.stopPlane())
		}
		wireOwners[owner] = key
	}
	limits := g.Budgets[r.owner].Packets
	configBytes, _ := json.Marshal(struct {
		Rows           map[string]state.Object
		Wire           map[string][32]byte
		Packets, Bytes int
	}{g.Rows, wireOwners, limits.QueuePackets, limits.QueueBytes})
	configSource := sha256.Sum256(configBytes)
	// An unchanged inspection may run concurrently with packet admission.
	// Changed authority/budgets revoke the old plane BEFORE native I/O. A
	// member joining or leaving (same budgets, same keys for the members that
	// stay) only revokes the members that left; the plane keeps serving.
	keep := t.plane != nil && t.plane.Retargetable() && t.limits == [2]int{limits.QueuePackets, limits.QueueBytes}
	for owner, key := range t.wires {
		if now, stays := wireOwners[owner]; keep && stays && now != key {
			keep = false
		}
	}
	if t.plane != nil && t.configSource != configSource {
		if !keep {
			if err := t.stopPlane(); err != nil {
				return err
			}
		} else {
			t.plan = retainedPlan(t.plan, g.Owners, wireOwners)
			t.plane.SetPlan(t.plan)
		}
	}
	keys := map[string]bool{}
	for _, key := range t.manager.Keys() {
		record, err := t.manager.View(key)
		if err != nil {
			return err
		}
		name, held, err := journalTunnelNetwork(record)
		if err != nil {
			return err
		}
		if held && name == t.network {
			keys[key] = true
		}
	}
	for key, spec := range g.Topology.Tunnels {
		if spec.Owner == r.owner && !spec.Lifecycle.Released() {
			keys[key] = true
		}
	}
	active := ""
	for _, key := range desired.Sorted(keys) {
		o := v.State.Object(key)
		spec, known := g.Topology.Tunnels[key]
		if o.Revision == 0 || known && spec.Owner != r.owner {
			return fmt.Errorf("unbound TUN journal %s", key)
		}
		var target *network.TunnelSpec
		if known && !spec.Lifecycle.Drain {
			if active != "" {
				return network.ErrPolicy
			}
			copy := spec
			copy.Lifecycle = schema.Lifecycle{}
			target = &copy
			active = key
		}
		budget := g.Budgets[r.owner]
		capacity := budget.Consumers
		if target != nil {
			record, recordErr := t.manager.View(key)
			known := slices.Contains(t.manager.Keys(), key)
			if known && recordErr != nil {
				return recordErr
			}
			if !known || record.State.Pending == nil && !record.State.Applied.Present || record.State.Pending != nil && record.State.Pending.Phase == reconcile.Prepared {
				raw, _ := json.Marshal(control.NativeRequest{Source: deployment.ObjectRef{Key: key, Revision: o.Revision, Generation: o.Generation}})
				reply, err := r.appCall(r.ctx, "app-native-permit", raw)
				if err != nil {
					_ = t.stopPlane()
					return err
				}
				permit, err := schema.Decode[control.NativePermit](reply.Data)
				native, _ := json.Marshal(target)
				if err != nil || permit.Source.Key != key || permit.Source.Revision != o.Revision || permit.Source.Generation != o.Generation || permit.Owner != r.Identity.Public || permit.Kind != "tunnel" || permit.Spec != sha256.Sum256(native) || permit.PacketLimits == nil || *permit.PacketLimits != budget.Packets {
					return network.ErrPolicy
				}
				capacity = permit.MaxConsumers
			}
		}
		if target != nil && (budget.Packets.QueuePackets < 1 || budget.Packets.QueueBytes < spec.MTU) {
			_ = t.stopPlane()
			return network.ErrPolicy
		}
		if capacity < 1 {
			old, err := t.manager.View(key)
			if err != nil {
				return err
			}
			capacity = old.Capacity
		}
		if target != nil && strings.HasPrefix(key, tenancy.ManagedNetworkSourcePrefix) && target.Network != tenancy.PacketNamespace("", tenancy.SystemNetwork) {
			// The committed source routes remote server addresses like pools;
			// sfc-system owns their main-table /32, so this server keeps them
			// in the TUN's own host table, looked up only from its pools.
			var pools []netip.Prefix
			for _, p := range g.Topology.Pools {
				if p.Network == target.Network && p.Owner == target.Owner {
					pools = append(pools, p.Prefix)
				}
			}
			local := network.LocalHostRoutes(*target, pools)
			target = &local
		}
		if err := t.manager.Desired(key, o.Revision, o.Generation, target, capacity); err != nil {
			return err
		}
		if target != nil {
			continue
		}
		if t.key == key {
			if err := t.stopPlane(); err != nil {
				result = errors.Join(result, err)
			}
			t.lease = network.TunnelLease{}
			t.key = ""
		}
		record, err := t.manager.View(key)
		if err != nil {
			return err
		}
		for consumer, pin := range record.Consumers {
			if strings.HasPrefix(consumer, "ingress/") || strings.HasPrefix(consumer, "network-reference/") {
				continue
			}
			if consumer != "packet-plane" || pin.Generation != o.Generation {
				return reconcile.ErrLease
			}
			if err = t.manager.Return(network.TunnelLease{Key: key, Consumer: consumer, Pin: pin}); err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
		err = t.manager.Step(ctx, key)
		cancel()
		if err != nil && !errors.Is(err, reconcile.ErrPending) {
			result = errors.Join(result, err)
		}
	}
	if active == "" {
		return errors.Join(result, t.stopPlane())
	}
	spec := g.Topology.Tunnels[active]
	owners, err := g.Topology.Peers(active)
	if err != nil {
		_ = t.stopPlane()
		return err
	}
	wanted := map[[32]byte]bool{}
	for _, owner := range owners {
		wanted[g.Owners[owner]] = true
	}
	for pub := range t.paths {
		if !wanted[pub] {
			delete(t.paths, pub)
		}
	}
	plan := network.PacketPlan{WireKey: wire, Peers: map[[32]byte]network.PacketPeer{}}
	plan.Policy = g.Packets
	for _, owner := range owners {
		pub := g.Owners[owner]
		peerWire := wireOwners[owner]
		if peerWire == wire {
			return errors.Join(sfcp.ErrAdmission, t.stopPlane())
		}
		scope, mtu, e := pathScope(r.policy.Cluster, v, g, r.owner, owner)
		if e != nil {
			_ = t.stopPlane()
			return e
		}
		path, ok := t.paths[pub]
		if ok {
			route, routeErr := currentRoute(path.Session, spec, mtu)
			if route != path.route || [32]byte(path.Session.Peer().Key) != peerWire {
				_ = path.Session.RetirePath()
				delete(t.paths, pub)
				ok = false
			}
			if routeErr != nil {
				_ = t.stopPlane()
				return routeErr
			}
			ok = ok && path.scope == string(scope) && path.Session.PathCurrent(path.Path)
		}
		if !ok {
			if !keep {
				_ = t.stopPlane()
			}
			if bytes.Compare(wire[:], peerWire[:]) > 0 {
				return errTunnelPending
			}
			peer, known := r.Mesh.Peer(sfcp.Identity(peerWire))
			if !known {
				return sfcp.ErrAdmission
			}
			ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
			host, _, e := net.SplitHostPort(peer.Endpoint)
			if e == nil {
				var addresses []netip.Addr
				if a, err := netip.ParseAddr(host); err == nil {
					addresses = []netip.Addr{a}
				} else {
					addresses, e = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				}
				if e == nil && len(addresses) == 0 {
					e = errTunnelPending
				}
				if e == nil {
					_, e = routeTo(addresses[0], spec, mtu)
				}
			}
			if e != nil {
				cancel()
				return e
			}
			s, e := r.Mesh.Dial(ctx, peer)
			if e == nil {
				current, err := s.NativeRouteCurrent()
				if err != nil || !current {
					_ = s.RetirePath()
					e = errors.Join(err, errTunnelPending)
				}
			}
			var pair sfcp.PathPair
			var route routeStamp
			if e == nil {
				route, e = currentRoute(s, spec, mtu)
			}
			if e == nil {
				pair, e = s.ObservePath(ctx, scope, mtu)
			}
			cancel()
			if e != nil {
				return e
			}
			a, b := pair.Samples()
			if e = admitPair(pair, a, b); e != nil {
				return e
			}
			path = tunnelPath{PacketPeer: network.PacketPeer{WireKey: peerWire, Session: s, Path: pair}, route: route, scope: string(scope)}
			t.paths[pub] = path
		}
		path.WireKey = peerWire
		plan.Peers[pub] = path.PacketPeer
	}
	// An admitted operation retains its original target if a newer source
	// arrives during its native effect. The next pass processes that source.
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	err = t.manager.Step(ctx, active)
	cancel()
	if err != nil {
		_ = t.stopPlane()
		return err
	}
	if _, err = t.manager.Inspect(r.ctx, active); err != nil {
		_ = t.stopPlane()
		return err
	}
	n := g.Budgets[r.owner].Packets
	encoded := configBytes
	for _, owner := range owners {
		path := t.paths[g.Owners[owner]]
		a, b := path.Path.Samples()
		bits, _ := json.Marshal([]sfcp.PacketBudget{a.Budget, b.Budget})
		encoded = append(encoded, bits...)
	}
	source := sha256.Sum256(encoded)
	if t.plane != nil && t.source == source && t.plane.Err() == nil {
		return result
	}
	if keep && t.plane != nil && t.plane.Retarget(spec, plan) == nil {
		t.source, t.configSource, t.wires, t.plan = source, configSource, wireOwners, plan
		return result
	}
	if err = t.stopPlane(); err != nil {
		result = errors.Join(result, err)
	}
	lease, err := t.manager.AcquireContext(r.ctx, active, "packet-plane", v.State.Object(active).Generation)
	if err != nil {
		return err
	}
	t.lease, t.key = lease, active
	plane, err := network.NewPacketPlane(r.ctx, r.Identity.Public, network.NetworkID(r.policy.Cluster, spec.Network), spec, lease.IO, network.PacketLimits{QueuePackets: n.QueuePackets, QueueBytes: n.QueueBytes}, plan)
	if err != nil {
		return err
	}
	t.plane, t.source = plane, source
	t.configSource = configSource
	t.wires, t.limits, t.plan = wireOwners, [2]int{n.QueuePackets, n.QueueBytes}, plan
	t.serving.Store(plane)
	return result
}

type TunnelObservation struct {
	PacketUsers    int
	Connections    map[string][32]byte
	TransportDrops *sfcp.PacketDropStats `json:",omitempty"`
}

func (t *tunnelInstance) Ready(key string) error { _, err := t.Observe(key); return err }
func (t *tunnelInstance) Observe(key string) (TunnelObservation, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	status := TunnelObservation{Connections: map[string][32]byte{}}
	drops := t.r.Mesh.PacketDropCounts()
	status.TransportDrops = &drops
	if t.plane != nil {
		status.PacketUsers = 1
	}
	for pub, path := range t.paths {
		a, _ := path.Path.Samples()
		status.Connections[hex.EncodeToString(pub[:])] = sha256.Sum256(a.Budget.Connection[:])
	}
	if t.closed || t.plane == nil || t.key != key {
		return status, errors.Join(t.lastError, errTunnelPending)
	}
	if err := t.plane.Err(); err != nil {
		return status, err
	}
	record, err := t.manager.View(key)
	if err != nil {
		return status, err
	}
	spec, err := network.DecodeTunnel(record.State.Applied.Spec)
	if err != nil {
		return status, err
	}
	for _, path := range t.paths {
		if !path.Session.PathCurrent(path.Path) {
			return status, errTunnelPending
		}
		route, err := currentRoute(path.Session, spec, path.Path.MTU())
		if err != nil || route != path.route {
			return status, errors.Join(err, errTunnelPending)
		}
	}
	return status, nil
}
