// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// TaskMaterial is public, original committed metadata supplied by the app
// controller. It is not an authorization/commit receipt or a host path.
// Providers recheck current permissions and original native refs at use time.
type TaskMaterial struct {
	Binding    Binding
	Projection *workload.InputRef
	Volumes    []volumes.NativeReady
	Network    ObjectRef
	Bridge     network.BridgeSpec
}

func (b Blueprint) taskRecipe(service string, m TaskMaterial, owner string) (ComposeService, workload.ContainerSpec, error) {
	s, logical, inputErr := b.taskInput(service)
	bound := m.Binding
	if inputErr != nil || !validBinding(bound) || bound.d.Cluster != b.d.Cluster || owner != engine.Owner(b.d.Cluster, bound.d.Needs.Use.NodeKey) {
		return s, workload.ContainerSpec{}, ErrInputs
	}
	want, err := b.Inputs(service, bound.d.Needs.Consumer, bound.d.Needs.Generation, bound.d.Needs.Use.RequesterKey)
	if err != nil || !sameNeeds(want, bound.d.Needs) {
		return s, workload.ContainerSpec{}, ErrInputs
	}
	s, err = b.frozenTask(logical, s)
	if err != nil || s.CheckLifecycleNeeds(want) != nil {
		return s, workload.ContainerSpec{}, ErrInputs
	}
	// Each mismatch names its part, so a stuck Task says which material
	// differs from its binding.
	switch {
	case want.HasSources() != (m.Projection != nil):
		return s, workload.ContainerSpec{}, inputError("TASK_MATERIAL_MISMATCH", fmt.Sprintf("%s.projection (sources=%d, projection=%t)", service, len(want.ApprovalSources()), m.Projection != nil))
	case m.Projection != nil && *m.Projection != projectionReference(bound):
		return s, workload.ContainerSpec{}, inputError("TASK_MATERIAL_MISMATCH", service+".projection (reference differs from the binding)")
	case len(m.Volumes) != len(bound.d.Pins):
		return s, workload.ContainerSpec{}, inputError("TASK_MATERIAL_MISMATCH", fmt.Sprintf("%s.volumes (ready=%d, pinned=%d)", service, len(m.Volumes), len(bound.d.Pins)))
	case len(s.Networks) != 1:
		return s, workload.ContainerSpec{}, inputError("TASK_MATERIAL_MISMATCH", fmt.Sprintf("%s.networks (%d, want 1)", service, len(s.Networks)))
	}
	n := b.d.Nodes[s.MyDC.Node]
	if s.Memory == "" {
		s.Memory = strconv.FormatUint(n.DefaultMemory, 10)
	}
	memory, err := byteSize(s.Memory)
	if err != nil || memory < 16<<20 || memory > math.MaxInt64 {
		return s, workload.ContainerSpec{}, workload.ErrProcess
	}
	cpu, err := nanoCPU(s.CPUs)
	if s.CPUs == "" {
		cpu = n.DefaultCPU
	}
	if err != nil || cpu == 0 || cpu > math.MaxInt64 {
		return s, workload.ContainerSpec{}, workload.ErrProcess
	}
	result := workload.ContainerSpec{ResourceKeys: lifecycle.OwnIdentityTransitions(n.ResourceKeys), Writable: s.Standalone && s.ReadOnly != nil && !*s.ReadOnly, TTY: s.TTY, StdinOpen: s.StdinOpen, Schema: 1, Node: owner, Image: s.Image, Memory: int64(memory), NanoCPU: int64(cpu), Bridge: m.Network.Key, BridgeGeneration: m.Network.Generation}
	result.Logging = s.Logging.Clone()
	result.Ports = slices.Clone(s.Ports)
	result.Stop, err = engine.ParseStopPolicy(s.StopGracePeriod, s.StopSignal)
	if err != nil {
		return s, result, err
	}
	result.Resolver, err = s.resolverSpec()
	if err != nil {
		return s, result, err
	}
	if m.Projection != nil {
		p := *m.Projection
		result.Inputs = &p
	}
	ready := map[string]volumes.NativeReady{}
	for _, r := range m.Volumes {
		key := VolumeKey(r.Spec.Scope)
		if r.Verify() != nil || r.Spec.Scope.Cluster != b.d.Cluster || r.Owner.Node != s.MyDC.Node || !n.resourceIdentity(b.d.Cluster, s.MyDC.Node, r.Owner.Key) {
			return s, result, ErrInputs
		}
		if _, exists := ready[key]; exists {
			return s, result, ErrInputs
		}
		ready[key] = r
	}
	for i, declared := range s.Volumes {
		pin := bound.d.Pins[i]
		r, ok := ready[pin.Key]
		definition := b.d.Input.Volumes[declared.Source]
		v := definition.MyDC
		if !ok || pin.Scope != r.Spec.Scope || pin.Consumer.Owner != r.Owner || pin.Key != b.volumeKey(declared.Source) || pin.Consumer.Writable == declared.ReadOnly || v.Node != r.Owner.Node || v.Retain == nil || !*v.Retain || v.Quota != "observe" {
			return s, result, ErrInputs
		}
		binding := ""
		if ref, fixed := b.d.FixedVolumes[declared.Source]; fixed {
			if !fixedVolumePolicy(definition) || !ref.Matches(r) || bound.d.Needs.FixedVolumes[pin.Key] != ref {
				return s, result, ErrInputs
			}
			binding = hex.EncodeToString(ref.Native[:])
		} else if r.Fixed != nil || v.UID != 0 && v.UID != r.Spec.UID || v.GID != 0 && v.GID != r.Spec.GID {
			return s, result, ErrInputs
		}
		if binding == "" && v.Mode != "" {
			mode, err := strconv.ParseUint(v.Mode, 8, 32)
			if err != nil || uint32(mode) != r.Spec.Mode {
				return s, result, ErrInputs
			}
		}
		result.Volumes = append(result.Volumes, workload.VolumeMount{Scope: pin.Scope, Consumer: pin.Consumer, NativeKey: volumes.NativeKey(r.Spec), NativeGeneration: r.Generation, Target: declared.Target, NativeBinding: binding})
	}
	result.Tmpfs, err = s.TmpfsMounts(result.Memory)
	if err != nil {
		return s, result, err
	}
	if r := s.MyDC.Readiness; r != nil && r.Kind == "http" {
		result.Readiness, err = r.httpProbe()
		if err != nil {
			return s, result, workload.ErrProcess
		}
	}
	if err = b.taskNetwork(service, s, m, &result); err != nil {
		return s, result, err
	}
	return s, result, nil
}

// The parser and immutable native recipe consume the same deadline contract.
// Zero preserves the original one-second default, including its JSON shape.
func (r Readiness) httpProbe() (*workload.HTTPReadiness, error) {
	p := &workload.HTTPReadiness{Path: r.Path, Port: r.Port}
	if r.Kind != "http" {
		return nil, workload.ErrProcess
	}
	if r.Timeout != "" {
		d, err := time.ParseDuration(r.Timeout)
		if err != nil || d < time.Millisecond || d > 30*time.Second || d%time.Millisecond != 0 {
			return nil, workload.ErrProcess
		}
		p.TimeoutMS = int(d / time.Millisecond)
	}
	if !p.Valid() {
		return nil, workload.ErrProcess
	}
	return p, nil
}

func (b Blueprint) taskNetwork(service string, s ComposeService, m TaskMaterial, result *workload.ContainerSpec) error {
	raw, _ := json.Marshal(m.Bridge)
	bridge, err := network.DecodeBridge(string(raw))
	if err != nil || !b.d.Nodes[s.MyDC.Node].resourceIdentity(b.d.Cluster, s.MyDC.Node, ownerKey(bridge.Owner, b.d.Cluster)) || bridge.Lifecycle.Drain || m.Network.Generation == 0 || m.Network.Revision < m.Network.Generation {
		return ErrInputs
	}
	if bridge.Owner != result.Node {
		result.BridgeOwner = bridge.Owner
	}
	for alias, attachment := range s.Networks {
		declared := b.d.Input.Networks[alias]
		if declared.External {
			var ref NetworkReference
			found := false
			for _, step := range b.d.Steps {
				if step.Key == ResourceKey("network-ref", b.d.Tenant, b.d.App, alias+"/"+s.MyDC.Node) && json.Unmarshal(step.Goal, &ref) == nil {
					found = true
					break
				}
			}
			if !found || ref.Schema != 1 || ref.Tenant != b.d.Tenant || ref.Node != s.MyDC.Node || !ref.RetainSource || !scopedBridgeKey(ref.Source.Key, b.d.Tenant) || ref.Source != m.Network || ref.Owner != ownerKey(bridge.Owner, b.d.Cluster) || ref.Network != bridge.Network || len(ref.Pools) != len(bridge.Pools) {
				return ErrInputs
			}
			for _, p := range bridge.Pools {
				if !slices.ContainsFunc(ref.Pools, func(q tenancy.Subnet) bool {
					return q.Prefix == p.Prefix && q.Gateway == p.Gateway && q.MTU == p.MTU && q.IPAM == p.IPAM
				}) {
					return ErrInputs
				}
			}
			for _, destination := range ref.Routes {
				if destination.Addr().Is4() && attachment.IPv4 == "" || destination.Addr().Is6() && attachment.IPv6 == "" {
					continue
				}
				gateway := netip.Addr{}
				for _, p := range bridge.Pools {
					if p.Prefix.Addr().Is4() == destination.Addr().Is4() {
						if gateway.IsValid() && gateway != p.Gateway {
							return ErrInputs
						}
						gateway = p.Gateway
					}
				}
				if !gateway.IsValid() {
					return ErrInputs
				}
				result.Routes = append(result.Routes, workload.ContainerRoute{Destination: destination, Gateway: gateway})
			}
		} else {
			pool := declared.MyDC.Pools[s.MyDC.Node]
			if m.Network.Key != ResourceKey("bridge", b.d.Tenant, b.d.App, alias+"/"+s.MyDC.Node) || bridge.Network != PoolID(b.d.Tenant, b.d.App, alias, s.MyDC.Node) || bridge.MTU != declared.MyDC.MTU || len(bridge.Pools) != 1 || bridge.Pools[0].Prefix != mustPrefix(pool.CIDR) || bridge.Pools[0].Gateway != mustAddr(pool.Gateway) {
				return ErrInputs
			}
			for node, remote := range declared.MyDC.Pools {
				if node == s.MyDC.Node {
					continue
				}
				prefix := mustPrefix(remote.CIDR)
				if prefix.Addr().Is4() && attachment.IPv4 == "" || prefix.Addr().Is6() && attachment.IPv6 == "" {
					continue
				}
				result.Routes = append(result.Routes, workload.ContainerRoute{Destination: prefix, Gateway: mustAddr(pool.Gateway)})
			}
			// A remote node's Ingress originates backend connections from its
			// TUN host address, not from a container pool. The return route is
			// part of the same overlay contract as its remote container routes.
			for node, address := range declared.MyDC.TunnelAddresses {
				if node == s.MyDC.Node {
					continue
				}
				prefix := mustPrefix(address)
				if prefix.Addr().Is4() && attachment.IPv4 == "" || prefix.Addr().Is6() && attachment.IPv6 == "" {
					continue
				}
				result.Routes = append(result.Routes, workload.ContainerRoute{Destination: prefix, Gateway: mustAddr(pool.Gateway)})
			}
		}
		if attachment.IPv4 != "" {
			result.IPv4, err = netip.ParseAddr(attachment.IPv4)
			if err != nil {
				return err
			}
		}
		if attachment.IPv6 != "" {
			result.IPv6, err = netip.ParseAddr(attachment.IPv6)
			if err != nil {
				return err
			}
		}
	}
	slices.SortFunc(result.Routes, func(a, b workload.ContainerRoute) int {
		return strings.Compare(a.Destination.String(), b.Destination.String())
	})
	if err := workload.ValidateContainerRoutes(*result, bridge); err != nil {
		return err
	}
	if !result.IPv4.IsValid() && !result.IPv6.IsValid() {
		return inputError("STATIC_ADDRESS_REQUIRED", service)
	}
	book, _ := network.NewBook(2)
	for _, p := range bridge.Pools {
		book, err = book.AddPool(p)
		if err != nil {
			return err
		}
	}
	for family, address := range []netip.Addr{result.IPv4, result.IPv6} {
		if address.IsValid() {
			book, _, err = book.Reserve(service+"/"+strconv.Itoa(family), bridge.Owner, bridge.Network, "", m.Binding.d.Needs.Generation, address)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// ResolveTask maps the exact frozen single-file declaration and original
// binding to the same native ContainerSpec used by the daemon's A2 adapter.
// It inspects/pulls an image only after all metadata correspondence checks.
func (b Blueprint) ResolveTask(ctx context.Context, service string, material TaskMaterial, catalog access.Catalog, docker *engine.Client, pull bool, credentials ...engine.RegistryAuth) (workload.ContainerSpec, error) {
	if docker == nil {
		return workload.ContainerSpec{}, ErrInputs
	}
	s, result, err := b.taskRecipe(service, material, docker.Owner)
	if err != nil {
		return workload.ContainerSpec{}, err
	}
	var targets []string
	for _, f := range material.Binding.d.Needs.Files {
		if f.Kind != "env" {
			targets = append(targets, f.Target)
		}
	}
	process, err := s.resolveProcess(ctx, docker, catalog, b.d.Actor, b.d.Tenant, s.MyDC.Node, pull, targets, len(s.MyDC.SecretEnv), result.Volumes, result.Resolver, credentials...)
	if err != nil {
		return workload.ContainerSpec{}, err
	}
	result.Process, result.Pull = &process, pull
	raw, _ := json.Marshal(result)
	return workload.DecodeContainer(string(raw))
}

func (e Execution) ResolveTask(ctx context.Context, service string, material TaskMaterial, catalog access.Catalog, docker *engine.Client, pull bool, credentials ...engine.RegistryAuth) (workload.ContainerSpec, error) {
	if old, held := e.heldExecution(ResourceKey("task", e.d.Plan.Tenant, e.d.Plan.App, service)); held {
		return old.ResolveTask(ctx, service, material, catalog, docker, pull, credentials...)
	}
	stage, ok := e.Stage(ResourceKey("task", e.d.Plan.Tenant, e.d.Plan.App, service))
	if !ok || stage.Result == nil || stage.Result.Code != state.Applied || stage.Result.Generation != material.Binding.Needs().Generation {
		return workload.ContainerSpec{}, ErrInputs
	}
	return (Blueprint{e.d.Plan}).ResolveTask(ctx, service, material, catalog, docker, pull, credentials...)
}

// MatchesTaskRecipe checks the immutable public recipe without image/network
// effects. A recovered native journal keeps its ORIGINAL resolved image config.
func (e Execution) MatchesTaskRecipe(service string, material TaskMaterial, spec workload.ContainerSpec) bool {
	if old, held := e.heldExecution(ResourceKey("task", e.d.Plan.Tenant, e.d.Plan.App, service)); held {
		return old.MatchesTaskRecipe(service, material, spec)
	}
	_, expected, err := (Blueprint{e.d.Plan}).taskRecipe(service, material, spec.Node)
	if err != nil || spec.Process == nil {
		return false
	}
	actual := spec
	actual.Process = nil
	actual.Pull = false
	left, _ := json.Marshal(expected)
	right, _ := json.Marshal(actual)
	return bytes.Equal(left, right)
}
