// SPDX-License-Identifier: Apache-2.0

// Package desired validates typed shared module state inside committed apply.
// It has no clocks, sockets, Docker or OS effects.
package desired

import (
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload"
	"math"
	"net/netip"
	"sort"
	"strings"
)

const NodePrefix = "network/node/"
const BridgePrefix = "network/bridge/"
const TunnelPrefix = "network/tunnel/"
const TaskPrefix = "workload/task/"
const IngressPrefix = "ingress/app/"

var ErrPolicy = errors.New("shared module policy or resource dependency conflict")

type NodeSpec struct {
	Schema                                                uint8
	Owner                                                 string
	CPU, Memory                                           uint64
	MaxBridges, MaxContainers, MaxEndpoints, MaxConsumers int
	PacketQueuePackets                                    int `json:",omitempty"`
	PacketQueueBytes                                      int `json:",omitempty"`
	Labels                                                map[string]string
	MaxIngressInstances, MaxIngressListeners              int `json:",omitempty"`
	MaxIngressRequests, MaxIngressConnections             int `json:",omitempty"`
	IngressBufferBytes                                    int `json:",omitempty"`
}
type Graph struct {
	Nodes       map[string]NodeSpec
	Bridges     map[string]network.BridgeSpec
	Tunnels     map[string]network.TunnelSpec
	Tasks       map[string]workload.ContainerSpec
	Ingress     map[string]ingress.Spec
	IPAM        network.Book
	nodeObjects map[string]state.Object
}
type Policy struct {
	Cluster [32]byte
	Owners  map[string][32]byte
}

// DecodeNode is shared by original Desired admission and explicit retirement
// of its historical policy metadata. It does not authorize a physical node.
func DecodeNode(value string) (NodeSpec, error) {
	n, err := schema.Decode[NodeSpec]([]byte(value))
	if err != nil || n.Schema != 1 || n.Owner == "" || n.CPU > math.MaxInt64 || n.Memory > math.MaxInt64 || n.MaxBridges < 0 || n.MaxContainers < 0 || n.MaxEndpoints < 0 || n.MaxConsumers < 1 || n.PacketQueuePackets < 0 || n.PacketQueuePackets > 65536 || n.PacketQueueBytes < 0 || n.PacketQueueBytes > 64<<20 || len(n.Labels) > 128 {
		return n, ErrPolicy
	}
	for k, v := range n.Labels {
		if k == "" || len(k) > 256 || len(v) > 256 || strings.ContainsRune(k+v, 0) {
			return n, ErrPolicy
		}
	}
	return n, nil
}

// Owner binds native resources to both the cluster and the complete node key.
func Owner(cluster, key [32]byte) string {
	return engine.Owner(cluster, key)
}

func Sorted[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func kind(key string) string {
	for _, prefix := range []string{NodePrefix, BridgePrefix, TunnelPrefix, TaskPrefix, IngressPrefix} {
		if strings.HasPrefix(key, prefix) && len(key) > len(prefix) {
			return prefix
		}
	}
	return ""
}

func lifecycle(key, value string) (schema.Lifecycle, string, []byte, []byte, error) {
	var life schema.Lifecycle
	var owner string
	var native, proof []byte
	switch kind(key) {
	case IngressPrefix:
		s, err := ingress.DecodeSpec(value)
		if err != nil {
			return life, "", nil, nil, err
		}
		life, owner = s.Lifecycle, s.Owner
		s.Lifecycle.Proof = nil
		proof, _ = json.Marshal(s)
		s.Lifecycle = schema.Lifecycle{}
		native, _ = json.Marshal(s)
	case TunnelPrefix:
		s, err := network.DecodeTunnel(value)
		if err != nil {
			return life, "", nil, nil, err
		}
		life, owner = s.Lifecycle, s.Owner
		s.Lifecycle.Proof = nil
		proof, _ = json.Marshal(s)
		s.Lifecycle = schema.Lifecycle{}
		native, _ = json.Marshal(s)
	case BridgePrefix:
		s, err := network.DecodeBridge(value)
		if err != nil {
			return life, "", nil, nil, err
		}
		life, owner = s.Lifecycle, s.Owner
		s.Lifecycle.Proof = nil
		proof, _ = json.Marshal(s)
		s.Lifecycle = schema.Lifecycle{}
		native, _ = json.Marshal(s)
	case TaskPrefix:
		s, err := workload.DecodeContainer(value)
		if err != nil {
			return life, "", nil, nil, err
		}
		life, owner = s.Lifecycle, s.Node
		s.Lifecycle.Proof = nil
		proof, _ = json.Marshal(s)
		s.Lifecycle = schema.Lifecycle{}
		native, _ = json.Marshal(s)
	default:
		return life, "", nil, nil, ErrPolicy
	}
	return life, owner, native, proof, nil
}

// RetirementBytes binds the local terminal-absence proof to the original shared
// generation and canonical Drain intent. Proof bytes themselves are excluded.
func (p Policy) RetirementBytes(key string, o state.Object) ([]byte, error) {
	l, _, _, b, err := lifecycle(key, o.Value)
	if err != nil || !o.Present || !l.Drain || !l.Valid() {
		return nil, ErrPolicy
	}
	return schema.GoneBytes(p.Cluster, key, o.Generation, b), nil
}

// NativeLifecycle describes the same original spec consumed by the existing
// native managers. Native omits Lifecycle; proofInput retains Drain/Nonce but
// omits the signature. It grants no execution or terminal absence.
func NativeLifecycle(key, value string) (schema.Lifecycle, string, []byte, []byte, error) {
	return lifecycle(key, value)
}

// WithLifecycle changes only the existing lifecycle envelope. Decode through
// the native contract before and after; caller policy still authorizes changes.
func WithLifecycle(key, value string, next schema.Lifecycle) (string, error) {
	if !next.Valid() {
		return "", ErrPolicy
	}
	var spec any
	var life *schema.Lifecycle
	switch kind(key) {
	case BridgePrefix:
		v, err := network.DecodeBridge(value)
		if err != nil {
			return "", err
		}
		spec, life = &v, &v.Lifecycle
	case TunnelPrefix:
		v, err := network.DecodeTunnel(value)
		if err != nil {
			return "", err
		}
		spec, life = &v, &v.Lifecycle
	case TaskPrefix:
		v, err := workload.DecodeContainer(value)
		if err != nil {
			return "", err
		}
		spec, life = &v, &v.Lifecycle
	case IngressPrefix:
		v, err := ingress.DecodeSpec(value)
		if err != nil {
			return "", err
		}
		spec, life = &v, &v.Lifecycle
	default:
		return "", ErrPolicy
	}
	*life = next
	raw, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	if _, _, _, _, err = lifecycle(key, string(raw)); err != nil {
		return "", err
	}
	return string(raw), nil
}

// ValidateLifecycle is the original native lifecycle transition predicate,
// shared by legacy ownership cleanup and the standalone Desired policy.
func ValidateLifecycle(key string, old, next state.Object) error {
	if old.Present {
		ol, _, on, _, err := lifecycle(key, old.Value)
		if err != nil {
			return err
		}
		if !next.Present {
			if !ol.Released() {
				return ErrPolicy
			}
		} else {
			nl, _, nn, _, err := lifecycle(key, next.Value)
			if err != nil || string(on) != string(nn) || ol.Drain && (!nl.Drain || ol.Nonce != nl.Nonce) || ol.Released() && string(ol.Proof) != string(nl.Proof) {
				return ErrPolicy
			}
		}
	} else if next.Present {
		nl, _, _, _, err := lifecycle(key, next.Value)
		if err != nil || nl.Drain {
			return ErrPolicy
		}
	}
	return nil
}

func (p Policy) Validate(before, after state.State, c state.Command) error {
	k := kind(c.Key)
	if k == BridgePrefix || k == TunnelPrefix || k == TaskPrefix || k == IngressPrefix {
		if err := ValidateLifecycle(c.Key, before.Object(c.Key), after.Object(c.Key)); err != nil {
			return err
		}
	}
	if k == NodePrefix && before.Object(c.Key).Present && after.Object(c.Key).Present {
		old, err := schema.Decode[NodeSpec]([]byte(before.Object(c.Key).Value))
		if err != nil {
			return err
		}
		next, err := schema.Decode[NodeSpec]([]byte(after.Object(c.Key).Value))
		if err != nil {
			return err
		}
		if old.Owner != next.Owner {
			return ErrPolicy
		}
	}
	_, err := p.Project(after)
	return err
}

// Project rebuilds the deterministic allocation policy from per-object rows,
// never from a single growing value or a stale pre-proposal cache.
func (p Policy) Project(s state.State) (Graph, error) {
	g := Graph{Nodes: map[string]NodeSpec{}, Bridges: map[string]network.BridgeSpec{}, Tunnels: map[string]network.TunnelSpec{}, Tasks: map[string]workload.ContainerSpec{}, Ingress: map[string]ingress.Spec{}, nodeObjects: map[string]state.Object{}}
	objects := s.Objects("")
	for _, key := range Sorted(objects) {
		o := objects[key]
		if !o.Present {
			continue
		}
		switch kind(key) {
		case IngressPrefix:
			v, err := ingress.DecodeSpec(o.Value)
			if err != nil {
				return g, err
			}
			if _, ok := p.Owners[v.Owner]; !ok {
				return g, ErrPolicy
			}
			g.Ingress[key] = v
		case NodePrefix:
			n, err := DecodeNode(o.Value)
			if err != nil {
				return g, ErrPolicy
			}
			if _, known := p.Owners[n.Owner]; !known {
				return g, ErrPolicy
			}
			if _, duplicate := g.Nodes[n.Owner]; duplicate {
				return g, ErrPolicy
			}
			g.Nodes[n.Owner] = n
			g.nodeObjects[n.Owner] = o
		case BridgePrefix:
			b, err := network.DecodeBridge(o.Value)
			if err != nil {
				return g, err
			}
			g.Bridges[key] = b
		case TaskPrefix:
			t, err := workload.DecodeContainer(o.Value)
			if err != nil {
				return g, err
			}
			g.Tasks[key] = t
		case TunnelPrefix:
			t, err := network.DecodeTunnel(o.Value)
			if err != nil {
				return g, err
			}
			g.Tunnels[key] = t
		}
		if kind(key) == BridgePrefix || kind(key) == TunnelPrefix || kind(key) == TaskPrefix || kind(key) == IngressPrefix {
			life, owner, _, proof, err := lifecycle(key, o.Value)
			if err != nil {
				return g, err
			}
			pub, known := p.Owners[owner]
			if !known {
				return g, ErrPolicy
			}
			if life.Released() && schema.VerifyGone(pub, p.Cluster, key, o.Generation, proof, life.Proof) != nil {
				return g, ErrPolicy
			}
		}
	}
	g.IPAM, _ = network.NewBook(len(g.Tasks)*2 + 1)
	bridgeCount, taskCount, addressCount := map[string]int{}, map[string]int{}, map[string]int{}
	cpu, memory := map[string]uint64{}, map[string]uint64{}
	poolIDs := map[string]bool{}
	for _, key := range Sorted(g.Bridges) {
		b := g.Bridges[key]
		if b.Lifecycle.Released() {
			continue
		}
		n, known := g.Nodes[b.Owner]
		if !known {
			return g, ErrPolicy
		}
		bridgeCount[b.Owner]++
		if bridgeCount[b.Owner] > n.MaxBridges {
			return g, ErrPolicy
		}
		for _, pool := range b.Pools {
			if poolIDs[pool.ID] {
				return g, ErrPolicy
			}
			poolIDs[pool.ID] = true
			var err error
			g.IPAM, err = g.IPAM.AddPool(pool)
			if err != nil {
				return g, err
			}
		}
	}
	for _, key := range Sorted(g.Tasks) {
		t := g.Tasks[key]
		if t.Lifecycle.Released() {
			continue
		}
		n, known := g.Nodes[t.Node]
		if !known {
			return g, ErrPolicy
		}
		b, known := g.Bridges[t.Bridge]
		if !known || b.Owner != t.Node || b.Lifecycle.Released() || b.Lifecycle.Drain && !t.Lifecycle.Drain || s.Object(t.Bridge).Generation != t.BridgeGeneration {
			return g, ErrPolicy
		}
		taskCount[t.Node]++
		if taskCount[t.Node] > n.MaxContainers || uint64(t.NanoCPU) > n.CPU-cpu[t.Node] || uint64(t.Memory) > n.Memory-memory[t.Node] {
			return g, ErrPolicy
		}
		cpu[t.Node] += uint64(t.NanoCPU)
		memory[t.Node] += uint64(t.Memory)
		for i, address := range []netip.Addr{t.IPv4, t.IPv6} {
			if !address.IsValid() {
				continue
			}
			poolID := ""
			for _, pool := range b.Pools {
				if pool.Prefix.Contains(address) {
					poolID = pool.ID
				}
			}
			if poolID == "" {
				return g, ErrPolicy
			}
			var err error
			family := "/4"
			if i == 1 {
				family = "/6"
			}
			g.IPAM, _, err = g.IPAM.Reserve(key+family, t.Node, b.Network, poolID, s.Object(key).Generation, address)
			if err != nil {
				return g, err
			}
			addressCount[t.Node]++
			if addressCount[t.Node] > n.MaxEndpoints {
				return g, ErrPolicy
			}
		}
	}
	if err := g.validateTunnels(addressCount); err != nil {
		return g, err
	}
	if err := g.validateIngress(s); err != nil {
		return g, err
	}
	return g, nil
}

// Eligibility binds observations to the current node incarnation and every
// relevant committed resource change, rather than unrelated command traffic.
func (g Graph) Eligibility(s state.State) map[string]workload.Eligibility {
	e := map[string]workload.Eligibility{}
	for owner, o := range g.nodeObjects {
		e[owner] = workload.Eligibility{Generation: o.Generation, MinRevision: o.Revision}
	}
	for key, spec := range g.Ingress {
		if !spec.Lifecycle.Released() {
			n := e[spec.Owner]
			n.MinRevision = max(n.MinRevision, s.Object(key).Revision)
			e[spec.Owner] = n
		}
	}
	for key, b := range g.Bridges {
		if !b.Lifecycle.Released() {
			n := e[b.Owner]
			n.MinRevision = max(n.MinRevision, s.Object(key).Revision)
			e[b.Owner] = n
		}
	}
	for key, t := range g.Tasks {
		if !t.Lifecycle.Released() {
			n := e[t.Node]
			n.MinRevision = max(n.MinRevision, s.Object(key).Revision)
			e[t.Node] = n
		}
	}
	for key, t := range g.Tunnels {
		if !t.Lifecycle.Released() {
			n := e[t.Owner]
			n.MinRevision = max(n.MinRevision, s.Object(key).Revision)
			e[t.Owner] = n
		}
	}
	return e
}
