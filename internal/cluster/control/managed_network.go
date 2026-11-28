// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func (p Policy) managedNetworkNativePermit(s state.State, caller [32]byte, request NativeRequest, view ResourceProjection, source ManagedNetworkSource) (NativePermit, error) {
	n := source.Network
	if !p.ownsResource(s, caller, n.Owner) {
		return NativePermit{}, catalogReason("the caller does not own network %s/%s", n.Tenant, n.ID)
	}
	caller = n.Owner
	owner, err := p.workNodeOwner(s, n.Node)
	catalog, e := p.Catalog(s)
	tenant, exists := catalog.Tenant(n.Tenant)
	switch {
	case err != nil || e != nil || !p.ownsResource(s, owner, caller) || n.Owner != caller:
		return NativePermit{}, catalogReason("server %s no longer owns network %s/%s", n.Node, n.Tenant, n.ID)
	case n.Draining || n.PendingChange != 0:
		return NativePermit{}, catalogReason("network %s/%s has a change in progress", n.Tenant, n.ID)
	case n.System:
		// The system network has no tenant: only the server's own current
		// membership and its server-wide limit apply.
		if !slices.ContainsFunc(view.Resources.Networks.SystemMembers(), func(m tenancy.Network) bool {
			return m.Node == n.Node && m.ID == n.ID && m.Generation == n.Generation && m.Revision == n.Revision && !m.Draining
		}) {
			return NativePermit{}, catalogReason("server %s is no longer a member of %s", n.Node, tenancy.SystemNetwork)
		}
	case !exists || !tenant.Enabled || tenant.Phase != access.TenantActive:
		return NativePermit{}, catalogReason("tenant %s is not active", n.Tenant)
	case !slices.Contains(tenant.AllowedNodes, n.Node):
		return NativePermit{}, catalogReason("tenant %s may not use server %s", n.Tenant, n.Node)
	}
	if n.Logical != "" && !n.System {
		if current, ok := view.Resources.Networks.NamedNetwork(n.Tenant, n.Logical, n.Node); !ok || current.Generation != n.Generation || current.Revision != n.Revision {
			return NativePermit{}, catalogReason("network %s/%s was replaced", n.Tenant, n.Logical)
		}
	}
	global, gok := view.Resources.Quotas.Limit("", n.Node)
	scoped, sok := view.Resources.Quotas.Limit(n.Tenant, n.Node)
	if err := checkNativeLimits(n.Tenant, n.Node, caller, view.Resources.Quotas, global, gok, scoped, sok); err != nil {
		return NativePermit{}, err
	}
	capacity := min(global.MaxConsumers, scoped.MaxConsumers)
	// A tenant's projected consumers are admitted against its own and the
	// server-wide limit. The system network has no tenant limit; its
	// consumers count against the server-wide budget (Consumers below).
	if !n.System {
		if err := admitIngressConsumers(view, deployment.GoalResources{Goal: deployment.GoalCommand{Tenant: n.Tenant, Node: n.Node, Owner: caller}}); err != nil {
			return NativePermit{}, err
		}
	}
	permit := NativePermit{Source: request.Source, Owner: caller, MaxConsumers: capacity, Consumers: p.nativeConsumerBudget(n.Scope(), n.Node, caller, global, scoped)}
	var spec any
	if source.Bridge != nil {
		permit.Kind, spec = "bridge", *source.Bridge
	} else if source.Tunnel != nil {
		permit.Kind, spec = "tunnel", *source.Tunnel
		limits, err := checkPacketLimits(n.Tenant, n.Node, global, scoped, source.Tunnel.MTU)
		if err != nil {
			return NativePermit{}, err
		}
		permit.PacketLimits = &limits
	} else {
		return NativePermit{}, catalogReason("network %s/%s has no bridge or TUN source", n.Tenant, n.ID)
	}
	raw, _ := json.Marshal(spec)
	permit.Spec = sha256.Sum256(raw)
	return permit, nil
}

func checkProjectedNetworkReferences(cluster [32]byte, s state.State, view ResourceProjection) error {
	ctx := deployment.PlanningContext{Cluster: cluster, Networks: view.Resources.Networks, Nodes: map[string]deployment.PlanningNode{}, Current: s.Objects("")}
	for _, goal := range view.Goals {
		if goal.Goal.Kind != "network-ref" || goal.Goal.Lifecycle != nil && goal.Goal.Lifecycle.Drain {
			continue
		}
		var ref deployment.NetworkReference
		if canonical(goal.Goal.Config, &ref) != nil || ref.Tenant != goal.Goal.Tenant || ref.Node != goal.Goal.Node || ref.Owner != goal.Goal.Owner {
			return ErrCatalog
		}
		ctx.Nodes[ref.Node] = deployment.PlanningNode{Key: ref.Owner}
		if ref.CheckRetained(ctx) != nil {
			return ErrCatalog
		}
	}
	return nil
}

// Called only at a fresh native/Start authority edge. Stored projection and
// original-result settlement use CheckRetained instead of manufacturing a new
// grant from an already accepted app reference.
func checkCurrentNetworkReference(cluster [32]byte, s state.State, view ResourceProjection, goal deployment.GoalResources) error {
	var ref deployment.NetworkReference
	if goal.Goal.Kind != "network-ref" || canonical(goal.Goal.Config, &ref) != nil || ref.Tenant != goal.Goal.Tenant || ref.Node != goal.Goal.Node || ref.Owner != goal.Goal.Owner {
		return ErrCatalog
	}
	ctx := deployment.PlanningContext{Cluster: cluster, Networks: view.Resources.Networks, Current: s.Objects(""), Nodes: map[string]deployment.PlanningNode{ref.Node: {Key: ref.Owner}}}
	return ref.Check(ctx)
}

// ManagedNetworkSource is a read-only projection of the existing reservation
// and its exact FSM source row. It is not an app Goal or another catalog.
type ManagedNetworkSource struct {
	Network tenancy.Network
	Bridge  *network.BridgeSpec
	Tunnel  *network.TunnelSpec
	// Closed is derived only from a fenced change and source tombstones. The
	// retained specs describe the old native identity, never active admission.
	Closed *tenancy.NetworkClosure
}

func newManagedNetworkSources(s state.State, networks tenancy.Networks, tenant, name string) (map[string][]byte, error) {
	rows, err := networks.TUNSources(tenant, name)
	if err != nil {
		return nil, err
	}
	writes := map[string][]byte{}
	for _, row := range rows {
		if s.Object(row.BridgeKey).Present || row.Tunnel != nil && s.Object(row.TunnelKey).Present {
			return nil, ErrCatalog
		}
		writes[row.BridgeKey], _ = json.Marshal(row.Bridge)
		if row.Tunnel != nil {
			writes[row.TunnelKey], _ = json.Marshal(row.Tunnel)
		}
	}
	return writes, nil
}

// Only the signed typed resource operation may atomically publish its exact
// related control source rows. The FSM's native/legacy namespace prohibition
// remains intact; apps cannot publish these rows or acquire their ownership.
func (p Policy) admitManagedNetworkPatch(s state.State, cmd state.Command, keys []string) bool {
	var writes map[string][]byte
	code := state.Forbidden
	switch {
	case cmd.Key != ResourcesKey:
	case cmd.Kind == state.Module && strings.HasPrefix(cmd.Actor, "user/"):
		writes, code = p.reduceResources(s, cmd)
	case cmd.Kind == state.ModuleReport && strings.HasPrefix(cmd.Actor, "node/"):
		// a server's own system network step or workspace network leave
		writes, code = p.reduceNodeResourceReport(s, cmd)
	}
	if code != state.Applied {
		return false
	}
	expected := map[string]bool{}
	for key := range writes {
		if managedSourceKey(key) || key == AppsKey || strings.HasPrefix(key, AppsKey+"/") {
			expected[key] = true
		}
	}
	if len(expected) == 0 || len(expected) != len(keys) {
		return false
	}
	for _, key := range keys {
		if !expected[key] {
			return false
		}
	}
	return true
}

func managedSourceMatches(actual, expected any) bool {
	a, _ := json.Marshal(actual)
	b, _ := json.Marshal(expected)
	return bytes.Equal(a, b)
}

func projectManagedNetworkSources(s state.State, networks tenancy.Networks, retired []services.RetiredNetwork) (map[string]ManagedNetworkSource, error) {
	out := map[string]ManagedNetworkSource{}
	groups := map[string]bool{}
	for _, v := range networks.AllNetworks() {
		if v.Logical == "" || groups[v.Tenant+"/"+v.Logical] {
			continue
		}
		groups[v.Tenant+"/"+v.Logical] = true
		rows, err := networks.TUNSources(v.Tenant, v.Logical)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			o := s.Object(row.BridgeKey)
			if !o.Present {
				change, found := networks.Change(row.Network.Tenant, row.Network.ID)
				proof := change.SourceClosed
				if !found || change.Phase != tenancy.ChangeFenced || proof == nil || !row.Network.Draining || proof.Generation != row.Network.Generation || proof.Revision != row.Network.Revision || o.Generation == 0 || o.Revision <= o.Generation {
					return nil, ErrCatalog
				}
				out[row.BridgeKey] = ManagedNetworkSource{Network: row.Network, Bridge: &row.Bridge, Closed: proof}
				if row.Tunnel != nil {
					tombstone := s.Object(row.TunnelKey)
					if tombstone.Present || tombstone.Generation == 0 || tombstone.Revision != o.Revision {
						return nil, ErrCatalog
					}
					out[row.TunnelKey] = ManagedNetworkSource{Network: row.Network, Tunnel: row.Tunnel, Closed: proof}
				}
				continue
			}
			b, err := network.DecodeBridge(o.Value)
			if err != nil || !o.Present || o.Generation == 0 || o.Revision < o.Generation || b.Lifecycle.Drain != row.Network.Draining {
				return nil, ErrCatalog
			}
			active := b
			active.Lifecycle = schema.Lifecycle{}
			if !managedSourceMatches(active, row.Bridge) {
				return nil, ErrCatalog
			}
			out[row.BridgeKey] = ManagedNetworkSource{Network: row.Network, Bridge: &b}
			if row.Tunnel == nil {
				continue
			}
			o = s.Object(row.TunnelKey)
			t, err := network.DecodeTunnel(o.Value)
			if err != nil || !o.Present || o.Generation == 0 || o.Revision < o.Generation || t.Lifecycle.Drain != row.Network.Draining {
				return nil, ErrCatalog
			}
			activeTUN := t
			activeTUN.Lifecycle = schema.Lifecycle{}
			if !managedSourceMatches(activeTUN, *row.Tunnel) {
				return nil, ErrCatalog
			}
			out[row.TunnelKey] = ManagedNetworkSource{Network: row.Network, Tunnel: &t}
		}
	}
	for _, archive := range retired {
		for _, source := range archive.Sources {
			if _, current := out[source.Key]; current {
				continue
			}
			object := s.Object(source.Key)
			if !object.Present && object.Generation == source.Generation && object.Revision >= source.Revision {
				proof := archive.Closed
				out[source.Key] = ManagedNetworkSource{Network: archive.Network, Bridge: source.Bridge, Tunnel: source.Tunnel, Closed: &proof}
			}
		}
	}
	for key, o := range s.Objects(tenancy.ManagedNetworkSourcePrefix) {
		if o.Present {
			if _, exists := out[key]; !exists {
				return nil, ErrCatalog
			}
		}
	}
	return out, nil
}

func drainManagedNetworkSources(s state.State, networks tenancy.Networks, tenant, id string, cmd state.Command) (map[string][]byte, error) {
	n, ok := networks.Network(tenant, id)
	if !ok || n.Logical == "" {
		return nil, nil
	}
	rows, err := networks.TUNSources(tenant, n.Logical)
	if err != nil {
		return nil, err
	}
	writes := map[string][]byte{}
	digest := sha256.Sum256(append([]byte("sfc-managed-network-drain-1\x00"), []byte(cmd.Value)...))
	var nonce [16]byte
	copy(nonce[:], digest[:16])
	if nonce == ([16]byte{}) {
		nonce[0] = 1
	}
	for _, row := range rows {
		if row.Network.ID != id {
			continue
		}
		b, e := network.DecodeBridge(s.Object(row.BridgeKey).Value)
		if e != nil {
			return nil, e
		}
		if !b.Lifecycle.Drain {
			b.Lifecycle = schema.Lifecycle{Drain: true, Nonce: nonce}
			writes[row.BridgeKey], _ = json.Marshal(b)
		}
		if row.Tunnel != nil {
			t, e := network.DecodeTunnel(s.Object(row.TunnelKey).Value)
			if e != nil {
				return nil, e
			}
			if !t.Lifecycle.Drain {
				t.Lifecycle = schema.Lifecycle{Drain: true, Nonce: nonce}
				writes[row.TunnelKey], _ = json.Marshal(t)
			}
		}
	}
	return writes, nil
}

// catalogReason keeps errors.Is(err, ErrCatalog) while naming the failed
// check. The text crosses the management reply, so it never holds secrets.
func catalogReason(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCatalog, fmt.Sprintf(format, args...))
}

func checkNativeLimits(tenant, node string, caller [32]byte, quotas tenancy.Quotas, global tenancy.NodeLimit, gok bool, scoped tenancy.NodeLimit, sok bool) error {
	switch {
	case !gok:
		return catalogReason("server %s has no node-wide limit", node)
	case !sok:
		return catalogReason("tenant %s has no limit on server %s", tenant, node)
	case !quotas.SameOwner(node, global.Owner, caller) || !quotas.SameOwner(node, scoped.Owner, caller):
		return catalogReason("the limits on server %s belong to another owner", node)
	case global.MaxConsumers < 1:
		return catalogReason("server %s allows no connections (max consumers 0)", node)
	case scoped.MaxConsumers < 1:
		return catalogReason("tenant %s allows no connections on server %s (max consumers 0)", tenant, node)
	}
	return nil
}

func checkPacketLimits(tenant, node string, global, scoped tenancy.NodeLimit, mtu int) (network.PacketLimits, error) {
	limits := network.PacketLimits{QueuePackets: min(global.PacketQueuePackets, scoped.PacketQueuePackets), QueueBytes: min(global.PacketQueueBytes, scoped.PacketQueueBytes)}
	if limits.QueuePackets >= 1 && limits.QueueBytes >= mtu+120 {
		return limits, nil
	}
	if global.PacketQueuePackets < 1 || global.PacketQueueBytes < mtu+120 {
		return limits, catalogReason("server %s packet queue (%d packets, %d bytes) is below one %d-byte TUN packet", node, global.PacketQueuePackets, global.PacketQueueBytes, mtu+120)
	}
	return limits, catalogReason("tenant %s packet queue on server %s (%d packets, %d bytes) is below one %d-byte TUN packet", tenant, node, scoped.PacketQueuePackets, scoped.PacketQueueBytes, mtu+120)
}
