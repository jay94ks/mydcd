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

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// TaskMaterial is public, original committed metadata supplied by the app
// controller. It is not an authorization/commit receipt or a host path.
// Providers recheck current permissions and original native refs at use time.
type TaskMaterial struct {
	Binding    Binding
	Projection *workload.InputRef
	Volumes    []volumes.NativeReady
	Network    ObjectRef // primary (first alias) network source
	Bridge     network.BridgeSpec
	Extra      []TaskNetworkBinding `json:",omitempty"` // the other networks, in alias order
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
	}
	n := b.d.Nodes[s.Sfc.Node]
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
	remoteHome := map[string][32]byte{} // Volume key → home's current key
	for _, r := range m.Volumes {
		key := VolumeKey(r.Spec.Scope)
		if r.Verify() != nil || r.Spec.Scope.Cluster != b.d.Cluster {
			return s, result, ErrInputs
		}
		if r.Owner.Node != s.Sfc.Node {
			// A shared Volume whose home is another server; the pin below
			// must be this server's remote consumer of it.
			home, ok := b.d.Nodes[r.Owner.Node]
			if !ok || !home.resourceIdentity(b.d.Cluster, r.Owner.Node, r.Owner.Key) {
				return s, result, ErrInputs
			}
			remoteHome[key] = home.Key
		} else if !n.resourceIdentity(b.d.Cluster, s.Sfc.Node, r.Owner.Key) {
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
		v := definition.Sfc
		if !ok || pin.Scope != r.Spec.Scope || pin.Consumer.Owner != r.Owner || pin.Key != b.volumeKey(declared.Source) || pin.Consumer.Writable == declared.ReadOnly || v.Node != r.Owner.Node || v.Retain == nil || !*v.Retain || v.Quota != "observe" {
			return s, result, ErrInputs
		}
		if home, remote := remoteHome[pin.Key]; remote || pin.Consumer.Remote() {
			ref, fixed := b.d.FixedVolumes[declared.Source]
			runner, valid := pin.Consumer.GoneKey()
			if !remote || !fixed || ref.Share == "" || !fixedVolumePolicy(definition) || !ref.Matches(r) || bound.d.Needs.FixedVolumes[pin.Key] != ref || pin.Consumer.Runner != s.Sfc.Node || !valid || !n.resourceIdentity(b.d.Cluster, s.Sfc.Node, runner) {
				return s, result, ErrInputs
			}
			result.RemoteVolumes = append(result.RemoteVolumes, workload.RemoteVolumeMount{Scope: pin.Scope, Consumer: pin.Consumer, Home: home, Target: declared.Target})
			continue
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
	if r := s.Sfc.Readiness; r != nil && r.Kind == "http" {
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

// TaskNetworkBinding is one more network of a Task beyond its primary one in
// TaskMaterial.Network/Bridge: the alias it is declared under and its exact
// committed source, as ResolveTaskNetwork returns it.
type TaskNetworkBinding struct {
	Alias   string
	Network ObjectRef
	Bridge  network.BridgeSpec
}

// taskNetwork binds every declared network, in alias order. The first alias is
// the primary attachment in the recipe's own Bridge fields; the rest go to
// Attachments in the same order, so one-network recipes keep their bytes.
func (b Blueprint) taskNetwork(service string, s ComposeService, m TaskMaterial, result *workload.ContainerSpec) error {
	aliases := mapKeys(s.Networks)
	if len(aliases) == 0 || len(aliases) > workload.MaxTaskNetworks || len(m.Extra) != len(aliases)-1 {
		return inputError("TASK_MATERIAL_MISMATCH", fmt.Sprintf("%s.networks (%d, material %d)", service, len(aliases), 1+len(m.Extra)))
	}
	var bridges []network.BridgeSpec
	for i, alias := range aliases {
		n := TaskNetworkBinding{Alias: aliases[0], Network: m.Network, Bridge: m.Bridge}
		if i > 0 {
			n = m.Extra[i-1]
		}
		if n.Alias != alias {
			return ErrInputs
		}
		a, routes, bridge, err := b.taskAttachment(service, s, alias, s.Networks[alias], n, result.Node, m.Binding.d.Needs.Generation)
		if err != nil {
			return err
		}
		slices.SortFunc(routes, func(a, b workload.ContainerRoute) int {
			return strings.Compare(a.Destination.String(), b.Destination.String())
		})
		if i == 0 {
			result.Bridge, result.BridgeGeneration, result.BridgeOwner, result.IPv4, result.IPv6, result.Routes = a.Bridge, a.BridgeGeneration, a.BridgeOwner, a.IPv4, a.IPv6, routes
		} else {
			a.Routes = routes
			result.Attachments = append(result.Attachments, a)
		}
		bridges = append(bridges, bridge)
	}
	return workload.ValidateContainerRoutes(*result, bridges...)
}

func (b Blueprint) taskAttachment(service string, s ComposeService, alias string, attachment Attachment, n TaskNetworkBinding, owner string, generation uint64) (workload.TaskAttachment, []workload.ContainerRoute, network.BridgeSpec, error) {
	out := workload.TaskAttachment{Bridge: n.Network.Key, BridgeGeneration: n.Network.Generation}
	var routes []workload.ContainerRoute
	raw, _ := json.Marshal(n.Bridge)
	bridge, err := network.DecodeBridge(string(raw))
	if err != nil || !b.d.Nodes[s.Sfc.Node].resourceIdentity(b.d.Cluster, s.Sfc.Node, ownerKey(bridge.Owner, b.d.Cluster)) || bridge.Lifecycle.Drain || n.Network.Generation == 0 || n.Network.Revision < n.Network.Generation {
		return out, nil, bridge, ErrInputs
	}
	if bridge.Owner != owner {
		out.BridgeOwner = bridge.Owner
	}
	declared := b.d.Input.Networks[alias]
	if declared.External {
		var ref NetworkReference
		found := false
		for _, step := range b.d.Steps {
			if step.Key == ResourceKey("network-ref", b.d.Tenant, b.d.App, alias+"/"+s.Sfc.Node) && json.Unmarshal(step.Goal, &ref) == nil {
				found = true
				break
			}
		}
		if !found || ref.Schema != 1 || ref.Tenant != b.d.Tenant || ref.Node != s.Sfc.Node || !ref.RetainSource || !scopedBridgeKey(ref.Source.Key, b.d.Tenant) || ref.Source != n.Network || ref.Owner != ownerKey(bridge.Owner, b.d.Cluster) || ref.Network != bridge.Network || len(ref.Pools) != len(bridge.Pools) {
			return out, nil, bridge, ErrInputs
		}
		for _, p := range bridge.Pools {
			if !slices.ContainsFunc(ref.Pools, func(q tenancy.Subnet) bool {
				return q.Prefix == p.Prefix && q.Gateway == p.Gateway && q.MTU == p.MTU && q.IPAM == p.IPAM
			}) {
				return out, nil, bridge, ErrInputs
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
						return out, nil, bridge, ErrInputs
					}
					gateway = p.Gateway
				}
			}
			if !gateway.IsValid() {
				return out, nil, bridge, ErrInputs
			}
			routes = append(routes, workload.ContainerRoute{Destination: destination, Gateway: gateway})
		}
	} else {
		pool := declared.Sfc.Pools[s.Sfc.Node]
		if n.Network.Key != ResourceKey("bridge", b.d.Tenant, b.d.App, alias+"/"+s.Sfc.Node) || bridge.Network != PoolID(b.d.Tenant, b.d.App, alias, s.Sfc.Node) || bridge.MTU != declared.Sfc.MTU || len(bridge.Pools) != 1 || bridge.Pools[0].Prefix != mustPrefix(pool.CIDR) || bridge.Pools[0].Gateway != mustAddr(pool.Gateway) {
			return out, nil, bridge, ErrInputs
		}
		for node, remote := range declared.Sfc.Pools {
			if node == s.Sfc.Node {
				continue
			}
			prefix := mustPrefix(remote.CIDR)
			if prefix.Addr().Is4() && attachment.IPv4 == "" || prefix.Addr().Is6() && attachment.IPv6 == "" {
				continue
			}
			routes = append(routes, workload.ContainerRoute{Destination: prefix, Gateway: mustAddr(pool.Gateway)})
		}
		// A remote node's Ingress originates backend connections from its
		// TUN host address, not from a container pool. The return route is
		// part of the same overlay contract as its remote container routes.
		for node, address := range declared.Sfc.TunnelAddresses {
			if node == s.Sfc.Node {
				continue
			}
			prefix := mustPrefix(address)
			if prefix.Addr().Is4() && attachment.IPv4 == "" || prefix.Addr().Is6() && attachment.IPv6 == "" {
				continue
			}
			routes = append(routes, workload.ContainerRoute{Destination: prefix, Gateway: mustAddr(pool.Gateway)})
		}
	}
	if attachment.IPv4 != "" {
		out.IPv4, err = netip.ParseAddr(attachment.IPv4)
		if err != nil {
			return out, nil, bridge, err
		}
	}
	if attachment.IPv6 != "" {
		out.IPv6, err = netip.ParseAddr(attachment.IPv6)
		if err != nil {
			return out, nil, bridge, err
		}
	}
	if !out.IPv4.IsValid() && !out.IPv6.IsValid() {
		return out, nil, bridge, inputError("STATIC_ADDRESS_REQUIRED", service)
	}
	book, _ := network.NewBook(2)
	for _, p := range bridge.Pools {
		book, err = book.AddPool(p)
		if err != nil {
			return out, nil, bridge, err
		}
	}
	for family, address := range []netip.Addr{out.IPv4, out.IPv6} {
		if address.IsValid() {
			book, _, err = book.Reserve(service+"/"+alias+"/"+strconv.Itoa(family), bridge.Owner, bridge.Network, "", generation, address)
			if err != nil {
				return out, nil, bridge, err
			}
		}
	}
	return out, routes, bridge, nil
}

// ResolveTask maps the exact frozen single-file declaration and original
// binding to the same native ContainerSpec used by the daemon's A2 adapter.
// It inspects/pulls an image only after all metadata correspondence checks.
func (b Blueprint) ResolveTask(ctx context.Context, service string, material TaskMaterial, catalog access.Catalog, docker *engine.Client, pull bool, image TaskImage, credentials ...engine.RegistryAuth) (workload.ContainerSpec, error) {
	if docker == nil {
		return workload.ContainerSpec{}, ErrInputs
	}
	s, result, err := b.taskRecipe(service, material, docker.Owner)
	if err != nil {
		return workload.ContainerSpec{}, err
	}
	if image.Digest != "" {
		// A tag: the container is made from the digest the deploy resolved
		// (or this server's copy); the recipe keeps the tag.
		s.Image = image.Digest
		result.ImageDigest, result.ImageSource = image.Digest, image.Source
	}
	var targets []string
	for _, f := range material.Binding.d.Needs.Files {
		if f.Kind != "env" {
			targets = append(targets, f.Target)
		}
	}
	process, err := s.resolveProcess(ctx, docker, catalog, b.d.Actor, b.d.Tenant, s.Sfc.Node, pull, targets, len(s.Sfc.SecretEnv), result.Volumes, result.Resolver, credentials...)
	if err != nil {
		return workload.ContainerSpec{}, err
	}
	result.Process, result.Pull = &process, pull
	raw, _ := json.Marshal(result)
	return workload.DecodeContainer(string(raw))
}

func (e Execution) ResolveTask(ctx context.Context, service string, material TaskMaterial, catalog access.Catalog, docker *engine.Client, pull bool, image TaskImage, credentials ...engine.RegistryAuth) (workload.ContainerSpec, error) {
	if old, held := e.heldExecution(ResourceKey("task", e.d.Plan.Tenant, e.d.Plan.App, service)); held {
		return old.ResolveTask(ctx, service, material, catalog, docker, pull, image, credentials...)
	}
	stage, ok := e.Stage(ResourceKey("task", e.d.Plan.Tenant, e.d.Plan.App, service))
	if !ok || stage.Result == nil || stage.Result.Code != state.Applied || stage.Result.Generation != material.Binding.Needs().Generation {
		return workload.ContainerSpec{}, ErrInputs
	}
	return (Blueprint{e.d.Plan}).ResolveTask(ctx, service, material, catalog, docker, pull, image, credentials...)
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
	if actual.ImageDigest != "" && !e.TagAllows(actual.Image, actual.ImageDigest) {
		return false
	}
	actual.ImageDigest, actual.ImageSource = "", ""
	left, _ := json.Marshal(expected)
	right, _ := json.Marshal(actual)
	return bytes.Equal(left, right)
}
