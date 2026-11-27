// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"math/big"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type Condition string

const (
	Committed Condition = "Committed"
	Applied   Condition = "Applied"
	Healthy   Condition = "Healthy"
	Completed Condition = "Completed"
	Released  Condition = "Released"
)

type Dependency struct {
	Key       string
	Condition Condition
}
type Step struct {
	StableDNS       []ObjectRef  `json:",omitempty"`
	Identity        []string     `json:",omitempty"`
	Activation      []Dependency `json:",omitempty"`
	Base            ObjectRef
	BasePresent     bool
	Key, Kind, Node string
	Owner           [32]byte
	Goal            json.RawMessage // canonical declaration metadata, not a native command
	Dependencies    []Dependency
	Completion      Condition
	Retain          bool
}

// Bridge goals contain the owned CIDR and Docker IPAM configuration.
type bridgeDeclaration struct {
	Network string          `yaml:"network"`
	MTU     int             `yaml:"mtu"`
	Pool    PoolDeclaration `yaml:"pool"`
}
type PlanningNode struct {
	ResourceKeys              []lifecycle.IdentityTransition `json:",omitempty"`
	Key                       [32]byte
	Generation, Revision      uint64
	Underlay                  string
	Voter, Draining           bool
	Capacity, Used            workload.Resources
	DefaultCPU, DefaultMemory uint64
}
type PlanningContext struct {
	HostPorts                                       []HostPortUse // same committed accepted/held resources, not an allocator
	ExternalRegistries                              []imagesource.Definition
	Planned                                         []PlannedResource                    // committed pending intents; never native sources
	Addresses                                       map[string]ObjectRef                 // canonical static IP -> committed source, or retained hold with Revision=0
	ExternalNetworks                                map[string]map[string]NetworkBinding // declaration alias -> owner node -> current managed source
	Cluster                                         [32]byte
	Actor, Tenant, Project, Deployment, DefaultNode string
	Nodes                                           map[string]PlanningNode // committed admission, never YAML node hints
	Networks                                        tenancy.Networks        // complete shared catalog, including other tenants
	Volumes                                         map[string]volumes.State
	FixedVolumes                                    map[string]volumes.NativeReady // current permitted signed registrations; never caller-supplied app paths
	Shares                                          map[string]VolumeShare         // volume key -> committed volume-shares record
	Checkers                                        checker.Catalog
	CheckerPrograms                                 map[AppScope]checker.FrozenProgram // exact accepted app programs, not current authority
	CheckerProviders                                map[[32]byte]bool                  // exact source owners served by current installed members in this committed view; never authentication
	CheckerSources                                  map[string]checker.SourceFact      // actually staged inline facts supplied separately from app.yaml
	Features                                        map[string]bool                    // verified adapter capability set, not YAML grants
	Current                                         map[string]state.Object            // same committed view used by the plan
	Reserved                                        map[string]workload.Resources      // per-resource desired reservation already counted in Nodes.Used
}
type blueprintRecord struct {
	RegistrySources                  map[string][]Source `json:",omitempty"`
	SecretEnvRequiresNewGeneration   []string            `json:",omitempty"`
	Document                         *AppDocument        `json:",omitempty"`
	InputKind                        string              `json:",omitempty"`
	DefaultNode                      string              `json:",omitempty"`
	Schema                           uint8
	Cluster                          [32]byte
	Actor, Tenant, App, Deployment   string
	Input                            Compose
	Steps                            []Step
	CatalogRevision, NetworkRevision uint64
	Nodes                            map[string]PlanningNode
	FixedVolumes                     map[string]VolumeReference `json:",omitempty"` // declaration alias -> immutable borrowed registration
	Checkers                         *checker.FrozenProgram     `json:",omitempty"`
}

// Blueprint is a self-contained declaration/graph artifact. It is not a receipt
// of reservation, command commit, provider readiness or native health. A later
// executor binds exact command bytes from these goals and committed results.
type Blueprint struct{ d blueprintRecord }

// Only deterministic metadata validation of these exact encoded bytes is
// reused. Current catalog, authority and native readiness are never cached.
var validatedBlueprintMetadataBytes deliveryValidationCache

func (b Blueprint) Encode() ([]byte, error) {
	if b.d.Schema != 1 {
		return nil, ErrInputs
	}
	raw, e := json.Marshal(b.d)
	if e != nil {
		return raw, e
	}
	if !validatedBlueprintMetadataBytes.contains(raw) {
		if !validCheckerPlan(b.d) || !validPlanTaskMetadata(b.d) || !validBlueprintDocument(b) {
			return nil, ErrInputs
		}
		validatedBlueprintMetadataBytes.remember(raw)
	}
	if len(raw) > 4<<20 {
		return nil, inputError("PLAN_BUDGET", "plan")
	}
	return raw, e
}
func (b Blueprint) Digest() [32]byte { raw, _ := b.Encode(); return sha256.Sum256(raw) }
func (b Blueprint) Steps() []Step {
	out := slices.Clone(b.d.Steps)
	for i := range out {
		out[i].StableDNS = slices.Clone(out[i].StableDNS)
		out[i].Goal = bytes.Clone(out[i].Goal)
		out[i].Dependencies = slices.Clone(out[i].Dependencies)
		out[i].Activation = slices.Clone(out[i].Activation)
		out[i].Identity = slices.Clone(out[i].Identity)
	}
	return out
}

// SecretEnvironmentServices names services whose values are resolved only at
// native create. Changing a value or projection requires a new Task generation.
func (b Blueprint) SecretEnvironmentServices() []string {
	return slices.Clone(b.d.SecretEnvRequiresNewGeneration)
}

// ReleaseOrder preserves retained objects. Removing their consumers does not
// authorize provider/volume destruction. Native closure remains required.
func (b Blueprint) ReleaseOrder() []Step {
	steps := map[string]Step{}
	for _, s := range b.Steps() {
		s.Dependencies = lifetimeDependencies(s)
		steps[s.Key] = s
	}
	ordered, err := orderSteps(steps)
	if err != nil {
		return nil
	}
	slices.Reverse(ordered)
	return ordered
}
func goal(v any) json.RawMessage { raw, _ := json.Marshal(v); return raw }
func ResourceKey(kind, tenant, app, id string) string {
	prefix := map[string]string{"bridge": "network/bridge/", "network-ref": "network/reference/", "tunnel": "network/tun/", "dns": "network/dns/", "route": "network/route/", "volume": "workload/volume/", "namespace": "workload/vault/", "inputs": "workload/inputs/", "task": "workload/task/", "registry": "workload/registry/", "delivery": "workload/cd/", "ingress": "ingress/app/"}[kind]
	if prefix == "" || !identifier(tenant) || !identifier(app) {
		return ""
	}
	for _, part := range strings.Split(id, "/") {
		if !identifier(part) {
			return ""
		}
	}
	return prefix + tenant + "/" + app + "/" + id
}

// PoolID is stable without truncating tenant/app names or reusing another
// network's ID. Object generations are supplied by actual committed results.
func PoolID(tenant, app, network, node string) string {
	h := sha256.Sum256([]byte(tenant + "/" + app + "/" + network + "/" + node))
	return "n" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:]))
}

func Compile(c Compose, policy access.Catalog, ctx PlanningContext) (Blueprint, error) {
	return compile(c, policy, ctx, nil, "")
}

func compile(c Compose, policy access.Catalog, ctx PlanningContext, move *VolumeMovePlacement, inputKind string) (Blueprint, error) {
	if c.Standalone != (inputKind == "standalone") {
		return Blueprint{}, ErrInputs
	}
	if inputKind != "" && inputKind != "app" && inputKind != "standalone" {
		return Blueprint{}, ErrInputs
	}
	if inputKind == "app" || inputKind == "standalone" {
		if err := c.validateApp(inputKind == "standalone"); err != nil {
			return Blueprint{}, err
		}
	}
	if e := c.validate(); e != nil {
		return Blueprint{}, e
	}
	if c.hasLifecycle() && !ctx.Features["lifecycle"] {
		// The live adapter must advertise this only after its real runner and
		// source/cache preparation consume the frozen Task program.
		return Blueprint{}, inputError("FEATURE_UNAVAILABLE", "lifecycle")
	}
	// Clone the caller's declaration before applying explicit CLI placement.
	raw, _ := json.Marshal(c)
	var input Compose
	if json.Unmarshal(raw, &input) != nil {
		return Blueprint{}, ErrInputs
	}
	c = input
	if c.Name == "" {
		c.Name = ctx.Project
	} else if ctx.Project != "" && ctx.Project != c.Name {
		return Blueprint{}, inputError("PROJECT_CONFLICT", "name")
	}
	if !identifier(c.Name) {
		return Blueprint{}, inputError("PROJECT_NAME_REQUIRED", "name")
	}
	if c.Sfc.Tenant == "" {
		c.Sfc.Tenant = ctx.Tenant
	} else if ctx.Tenant != "" && ctx.Tenant != c.Sfc.Tenant {
		return Blueprint{}, inputError("TENANT_CONFLICT", "x-sfc.tenant")
	}
	if c.Sfc.Deployment == "" {
		// The deployment of an app is named after it unless the caller
		// keeps an existing one (ctx.Deployment).
		c.Sfc.Deployment = ctx.Deployment
		if c.Sfc.Deployment == "" {
			c.Sfc.Deployment = c.Name
		}
	} else if ctx.Deployment != "" && ctx.Deployment != c.Sfc.Deployment {
		return Blueprint{}, inputError("DEPLOYMENT_CONFLICT", "x-sfc.deployment_id")
	}
	if ctx.Cluster == ([32]byte{}) || !identifier(c.Sfc.Tenant) || !identifier(c.Sfc.Deployment) || policy.Authorize(ctx.Actor, c.Sfc.Tenant, access.Deploy, "") != nil {
		return Blueprint{}, inputError("APP_SCOPE_REQUIRED", "x-sfc")
	}
	if _, e := ctx.Networks.Encode(); e != nil {
		return Blueprint{}, inputError("COMPLETE_NETWORK_VIEW_REQUIRED", "context")
	}
	b := Blueprint{blueprintRecord{InputKind: inputKind, Schema: 1, Cluster: ctx.Cluster, Actor: ctx.Actor, Tenant: c.Sfc.Tenant, App: c.Name, Deployment: c.Sfc.Deployment, CatalogRevision: policy.Revision(), NetworkRevision: ctx.Networks.Revision(), Nodes: map[string]PlanningNode{}}}
	if err := b.freezeRegistrySources(c, ctx.ExternalRegistries); err != nil {
		return Blueprint{}, err
	}
	if inputKind == "app" && c.Sfc.Delivery != nil && c.Sfc.Delivery.Enabled {
		if ctx.DefaultNode != "" && !identifier(ctx.DefaultNode) {
			return Blueprint{}, inputError("INVALID_DEFAULT_NODE", "context")
		}
		b.d.DefaultNode = ctx.DefaultNode
	}
	if c.hasLifecycle() {
		frozen, err := freezeCheckerPlan(c, ctx)
		if err != nil {
			return Blueprint{}, err
		}
		b.d.Checkers = &frozen
	}
	placements, placementErr := planServicePlacements(c, ctx.DefaultNode)
	if placementErr != nil {
		return Blueprint{}, placementErr
	}
	key := func(kind, id string) string { return ResourceKey(kind, b.d.Tenant, b.d.App, id) }
	known := map[string]Step{}
	add := func(s Step) error {
		if s.Key == "" || len(known) >= 1024 {
			return inputError("PLAN_BUDGET", "steps")
		}
		if _, ok := known[s.Key]; ok {
			return inputError("DUPLICATE_RESOURCE", s.Key)
		}
		base := ctx.Current[s.Key]
		if base.Generation > base.Revision || base.Present && (base.Generation == 0 || base.Revision == 0) {
			return inputError("INVALID_RESOURCE_VIEW", s.Key)
		}
		if base.Present {
			var current GoalCommand
			if json.Unmarshal([]byte(base.Value), &current) != nil || current.Schema != 1 || current.Cluster != b.d.Cluster || current.Tenant != b.d.Tenant || current.App != b.d.App || current.Deployment != b.d.Deployment || current.Kind != s.Kind {
				return inputError("FOREIGN_RESOURCE", s.Key)
			}
			// These app-owned native services keep their journal/listener owner
			// across a key rotation. Tasks and their private inputs are new
			// current-key generations; network and Volume owners are resolved
			// from their exact retained sources elsewhere in the compiler.
			if move == nil && current.Node == s.Node && (s.Kind == "ingress" || s.Kind == "registry") {
				n := ctx.Nodes[s.Node]
				if n.resourceIdentity(ctx.Cluster, s.Node, current.Owner) && n.resourceIdentity(ctx.Cluster, s.Node, s.Owner) {
					s.Owner = current.Owner
				}
			}
			if move == nil && (current.Node != s.Node || current.Owner != s.Owner) && s.Kind != "task" && s.Kind != "inputs" && !committedVolumeGoal(current, s, ctx.Volumes) {
				return inputError("FOREIGN_RESOURCE", s.Key)
			}
			if current.Lifecycle != nil && current.Lifecycle.Drain {
				return inputError("RESOURCE_DRAINING", s.Key)
			}
		}
		s.Base = ObjectRef{s.Key, base.Revision, base.Generation}
		s.BasePresent = base.Present
		known[s.Key] = s
		return nil
	}
	node := func(id string, action access.Action) (PlanningNode, error) {
		n, ok := ctx.Nodes[id]
		if !ok || !n.resourceIdentity(ctx.Cluster, id, n.Key) || n.Generation == 0 || n.Revision == 0 || n.Draining || policy.Authorize(ctx.Actor, b.d.Tenant, action, id) != nil {
			return n, inputError("NODE_ADMISSION_REQUIRED", id)
		}
		n.ResourceKeys = lifecycle.OwnIdentityTransitions(n.ResourceKeys)
		b.d.Nodes[id] = n
		return n, nil
	}
	require := func(feature string) error {
		if !ctx.Features[feature] {
			return inputError("FEATURE_UNAVAILABLE", feature)
		}
		return nil
	}
	if e := require("core"); e != nil {
		return Blueprint{}, e
	}
	for id, h := range c.Sfc.Nodes {
		n, ok := ctx.Nodes[id]
		if !ok || n.Underlay != h.Underlay || n.Voter != h.Voter {
			return Blueprint{}, inputError("NODE_HINT_CONFLICT", "x-sfc.nodes."+id)
		}
	}

	// Use the existing global CIDR/ownership algorithm for an uncommitted plan.
	// The candidate generations/revisions are deliberately NOT exported as
	// actual future reservation/commit locations.
	borrowed := map[string]NetworkReference{}
	for _, alias := range mapKeys(c.Networks) {
		definition := c.Networks[alias]
		if !definition.External {
			continue
		}
		if e := require("network-reference"); e != nil {
			return Blueprint{}, e
		}
		if definition.Sfc.DNS != nil || definition.Sfc.RuntimeChanges != nil || len(definition.Sfc.TunnelAddresses) > 0 {
			return Blueprint{}, inputError("EXTERNAL_NETWORK_NOT_MUTABLE", alias)
		}
		name := definition.Name
		if name == "" {
			name = alias
		}
		owners := map[string]bool{}
		for name, service := range c.Services {
			if _, uses := service.Networks[alias]; uses {
				for _, instance := range placements[name] {
					owners[instance.Node] = true
				}
			}
		}
		for _, registry := range c.Sfc.Registries {
			if registry.Enabled && registry.Network == alias {
				owners[registry.Node] = true
			}
		}
		if ingress := c.Sfc.Ingress; ingress != nil {
			for _, route := range IngressRoutes(*ingress) {
				backend, exists := c.Services[route.Service]
				if !exists {
					return Blueprint{}, inputError("INGRESS_BACKEND_REQUIRED", route.Service)
				}
				network, err := ingressNetwork(ingressForRoute(*ingress, route), backend)
				if err != nil {
					return Blueprint{}, err
				}
				if network == alias {
					owners[ingress.Node] = true
				}
			}
		}
		for _, owner := range mapKeys(owners) {
			_, e := node(owner, access.ManageNetwork)
			if e != nil {
				return Blueprint{}, e
			}
			binding, ok := ctx.ExternalNetworks[alias][owner]
			if !ok && (inputKind == "app" || inputKind == "standalone") {
				binding, e = currentNetworkBinding(ctx, b.d.Tenant, owner, name)
				if e != nil {
					return Blueprint{}, e
				}
				ok = true
			}
			if !ok {
				return Blueprint{}, inputError("EXTERNAL_NETWORK_BINDING_REQUIRED", alias)
			}
			ref, e := resolveNetworkReference(ctx, b.d.Tenant, owner, name, binding)
			if e != nil {
				return Blueprint{}, e
			}
			referenceKey := key("network-ref", alias+"/"+owner)
			borrowed[referenceKey] = ref
			if e = add(Step{Key: referenceKey, Kind: "network-ref", Node: owner, Owner: ref.Owner, Goal: goal(ref), Completion: Applied}); e != nil {
				return Blueprint{}, e
			}
		}
	}
	projected := ctx.Networks
	for _, id := range mapKeys(c.Networks) {
		net := c.Networks[id]
		if net.External {
			continue
		}
		if len(net.Sfc.Pools) == 0 {
			return Blueprint{}, inputError("NETWORK_BINDING_REQUIRED", "networks."+id)
		}
		for _, owner := range mapKeys(net.Sfc.Pools) {
			pool := net.Sfc.Pools[owner]
			n, e := node(owner, access.ManageNetwork)
			if e != nil {
				return Blueprint{}, e
			}
			mtu := net.Sfc.MTU
			if mtu == 0 {
				mtu = 1280
			}
			wanted := tenancy.Network{Tenant: b.d.Tenant, ID: PoolID(b.d.Tenant, b.d.App, id, owner), Node: owner, Owner: n.Key, Pools: []tenancy.Subnet{{ID: "pool", Prefix: mustPrefix(pool.CIDR), Gateway: mustAddr(pool.Gateway), MTU: mtu}}}
			if existing, ok := projected.Network(wanted.Tenant, wanted.ID); ok && n.resourceIdentity(ctx.Cluster, owner, existing.Owner) {
				wanted.Owner = existing.Owner
			}
			if !plannedNetworkAllowed(b, ctx, wanted) {
				return Blueprint{}, inputError("GLOBAL_CIDR_CONFLICT", id)
			}
			if existing, ok := projected.Network(wanted.Tenant, wanted.ID); ok {
				if existing.Draining || existing.Node != owner || !n.resourceIdentity(ctx.Cluster, owner, existing.Owner) || !slices.Equal(existing.Pools, wanted.Pools) {
					return Blueprint{}, inputError("NETWORK_TRANSITION_REQUIRED", id)
				}
			} else {
				projected, e = projected.Create(policy, ctx.Actor, projected.Revision(), wanted)
				if e != nil {
					return Blueprint{}, inputError("GLOBAL_CIDR_CONFLICT", id)
				}
			}
			resourceOwner := wanted.Owner
			bridge := key("bridge", id+"/"+owner)
			bridgePool := pool
			if e = add(Step{Key: bridge, Kind: "bridge", Node: owner, Owner: resourceOwner, Goal: goal(bridgeDeclaration{id, mtu, bridgePool}), Completion: Applied}); e != nil {
				return Blueprint{}, e
			}
			if len(net.Sfc.Pools) > 1 {
				var deps []Dependency
				for _, other := range mapKeys(net.Sfc.Pools) {
					deps = append(deps, Dependency{key("bridge", id+"/"+other), Applied})
				}
				if e = add(Step{Key: key("tunnel", id+"/"+owner), Kind: "tunnel", Node: owner, Owner: resourceOwner, Goal: goal(net.Sfc.TunnelAddresses), Dependencies: deps, Completion: Applied}); e != nil {
					return Blueprint{}, e
				}
			}
			if net.Sfc.DNS != nil && net.Sfc.DNS.Enabled {
				feature := "network-dns"
				if ctx.Features["network-services"] {
					feature = "network-services"
				}
				if e = require(feature); e != nil {
					return Blueprint{}, e
				}
				if e = add(Step{Key: key("dns", id+"/"+owner), Kind: "dns", Node: owner, Owner: resourceOwner, Goal: goal(net.Sfc.DNS), Dependencies: []Dependency{{bridge, Applied}}, Completion: Applied}); e != nil {
					return Blueprint{}, e
				}
			}
		}
	}
	if c.Sfc.Vault != nil {
		if e := require("inputs"); e != nil {
			return Blueprint{}, e
		}
		if policy.Authorize(ctx.Actor, b.d.Tenant, access.ManageSecrets, "") != nil {
			return Blueprint{}, access.ErrDenied
		}
		if e := add(Step{Key: key("namespace", "root"), Kind: "namespace", Goal: goal(c.Sfc.Vault), Completion: Committed, Retain: true}); e != nil {
			return Blueprint{}, e
		}
	}
	volumeOwners := map[string]string{}
	for id, service := range c.Services {
		if len(service.Sfc.Nodes) == 0 {
			service.Sfc.Node = placements[id][0].Node
			c.Services[id] = service
		}
		for _, instance := range placements[id] {
			for _, mount := range service.Volumes {
				ref, fixed, err := resolveFixedVolume(mount.Source, b.d.Tenant, c.Volumes[mount.Source], ctx)
				if err != nil {
					return Blueprint{}, err
				}
				if fixed && ref.Share != "" {
					// A shared Volume stays on its owner; tasks on other
					// servers reach it over VolumeFS.
					continue
				}
				if len(placements[id]) > 1 && fixed {
					return Blueprint{}, inputError("REPLICA_FIXED_VOLUME_FORBIDDEN", mount.Source)
				}
				if old := volumeOwners[mount.Source]; old != "" && old != instance.Node {
					return Blueprint{}, inputError("VOLUME_MOVE_REQUIRED", mount.Source)
				}
				volumeOwners[mount.Source] = instance.Node
			}
		}
	}
	for _, r := range c.Sfc.Registries {
		if r.Enabled {
			if old := volumeOwners[r.Volume]; old != "" && old != r.Node {
				return Blueprint{}, inputError("VOLUME_MOVE_REQUIRED", r.Volume)
			}
			volumeOwners[r.Volume] = r.Node
		}
	}
	for _, id := range mapKeys(c.Volumes) {
		v := c.Volumes[id]
		if e := require("volumes"); e != nil {
			return Blueprint{}, e
		}
		ref, fixed, resolveErr := resolveFixedVolume(id, b.d.Tenant, v, ctx)
		if resolveErr != nil {
			return Blueprint{}, resolveErr
		}
		owner := v.Sfc.Node
		if owner == "" {
			owner = volumeOwners[id]
		}
		if owner == "" && fixed {
			owner = ref.Owner.Node
		}
		if owner == "" {
			owner = ctx.DefaultNode
		}
		if !identifier(owner) {
			return Blueprint{}, inputError("PLACEMENT_REQUIRED", "volumes."+id)
		}
		if used := volumeOwners[id]; used != "" && used != owner {
			return Blueprint{}, inputError("VOLUME_MOVE_REQUIRED", id)
		}
		n, e := node(owner, access.ManageVolumes)
		if e != nil {
			return Blueprint{}, e
		}
		if v.Sfc.Quota == "hard" {
			if e = require("hard-quota"); e != nil {
				return Blueprint{}, e
			}
		}
		volumeOwners[id] = owner
		v.Sfc.Node = owner
		c.Volumes[id] = v
		if fixed {
			if e := require("fixed-volumes"); e != nil {
				return Blueprint{}, e
			}
			if ref.Owner.Node != owner || !n.resourceIdentity(ctx.Cluster, owner, ref.Owner.Key) {
				return Blueprint{}, inputError("VOLUME_NOT_MOVABLE", id)
			}
			if b.d.FixedVolumes == nil {
				b.d.FixedVolumes = map[string]VolumeReference{}
			}
			b.d.FixedVolumes[id] = ref
			continue // no app-owned creation/native report or deletion claim
		}
		vk := b.d.Tenant + "/" + b.d.App + "/" + id
		if v.Name != "" && v.Name != id {
			return Blueprint{}, inputError("MANAGED_VOLUME_NAME_MAPPING_REQUIRED", id)
		}
		resourceOwner := n.Key
		if existing, ok := ctx.Volumes[vk]; ok {
			scope := existing.Scope()
			actual, _ := existing.Owner()
			placement, selected := selectedVolumeMove(move, scope)
			moving := selected && placement.Target.Node == owner && placement.Target.Key == n.Key
			if scope.Cluster != ctx.Cluster || scope.Tenant != b.d.Tenant || scope.App != b.d.App || scope.ID != id || !moving && (actual.Node != owner || !n.resourceIdentity(ctx.Cluster, owner, actual.Key)) {
				return Blueprint{}, inputError("VOLUME_MOVE_REQUIRED", id)
			}
			if !moving {
				resourceOwner = actual.Key
			}
		} else if v.External {
			return Blueprint{}, inputError("MANAGED_VOLUME_REQUIRED", id)
		}
		if e = add(Step{Key: key("volume", id), Kind: "volume", Node: owner, Owner: resourceOwner, Goal: goal(v), Completion: Applied, Retain: true}); e != nil {
			return Blueprint{}, e
		}
	}
	addresses := map[string]bool{}
	writers := map[string]int{}
	readers := map[string]int{}
	for _, logical := range mapKeys(c.Services) {
		for _, instance := range placements[logical] {
			id := instance.ResourceID()
			s, materializeErr := materializeTaskInstance(c.Services[logical], instance)
			if materializeErr != nil {
				return Blueprint{}, materializeErr
			}
			n, e := node(s.Sfc.Node, access.Deploy)
			if e != nil {
				return Blueprint{}, e
			}
			if _, e = policy.CheckImage(ctx.Actor, b.d.Tenant, s.Sfc.Node, s.Image); e != nil {
				return Blueprint{}, imageCheckError(policy, ctx.Actor, b.d.Tenant, s.Sfc.Node, e, "services."+logical+".image")
			}
			cpu, _ := nanoCPU(s.CPUs)
			memory, _ := byteSize(s.Memory)
			if cpu == 0 {
				cpu = n.DefaultCPU
			}
			if memory == 0 {
				memory = n.DefaultMemory
			}
			if _, err := s.TmpfsMounts(int64(memory)); err != nil {
				return Blueprint{}, inputError("INVALID_TMPFS", id)
			}
			if cpu == 0 || memory == 0 || n.Used.CPU > n.Capacity.CPU || n.Used.Memory > n.Capacity.Memory {
				return Blueprint{}, inputError("RESOURCE_BUDGET_REQUIRED", id)
			}

			s.CPUs = new(big.Rat).SetFrac(new(big.Int).SetUint64(cpu), big.NewInt(1e9)).FloatString(9)
			s.CPUs = strings.TrimRight(strings.TrimRight(s.CPUs, "0"), ".")
			s.Memory = new(big.Int).SetUint64(memory).String()
			s, e = replicaAddresses(b, ctx, instance, s, c.Networks, borrowed, addresses)
			if e != nil {
				return Blueprint{}, e
			}
			s = resolveServiceDNS(s, c.Networks)
			s, e = resolveReplicaDNS(b, ctx, instance, s, c.Networks, borrowed)
			if e != nil {
				return Blueprint{}, e
			}
			if instance.Ordinal == 0 {
				c.Services[logical] = singletonDeclaredAddresses(c.Services[logical], s)
			}
			taskConfig, err := b.frozenTask(logical, s)
			if err != nil {
				return Blueprint{}, err
			}
			if len(s.Networks) == 0 {
				return Blueprint{}, inputError("NETWORK_BINDING_REQUIRED", id)
			}
			var activation []Dependency
			var deps []Dependency
			for _, netID := range mapKeys(s.Networks) {
				net := c.Networks[netID]
				if len(s.Networks[netID].Aliases) > 0 {
					if !net.External {
						return Blueprint{}, inputError("MANAGED_NETWORK_REFERENCE_REQUIRED", netID)
					}
					if e := require("managed-dns"); e != nil {
						return Blueprint{}, e
					}
				}
				pool, ok := net.Sfc.Pools[s.Sfc.Node]
				if net.External {
					referenceKey := key("network-ref", netID+"/"+s.Sfc.Node)
					ref, exists := borrowed[referenceKey]
					if !exists {
						return Blueprint{}, inputError("EXTERNAL_NETWORK_BINDING_REQUIRED", netID)
					}
					if len(s.Networks[netID].Aliases) > 0 && ref.ManagedName == "" {
						return Blueprint{}, inputError("MANAGED_DNS_BINDING_REQUIRED", netID)
					}
					for _, address := range []string{s.Networks[netID].IPv4, s.Networks[netID].IPv6} {
						if address != "" && !acceptsReferenceAddress(ref, address) {
							return Blueprint{}, inputError("ADDRESS_OUTSIDE_POOL", id)
						}
					}
					deps = append(deps, Dependency{referenceKey, Applied})
					continue
				}
				if !ok {
					return Blueprint{}, inputError("NETWORK_BINDING_REQUIRED", id)
				}
				prefix := mustPrefix(pool.CIDR)
				for _, address := range []string{s.Networks[netID].IPv4, s.Networks[netID].IPv6} {
					if address != "" && !prefix.Contains(mustAddr(address)) {
						return Blueprint{}, inputError("ADDRESS_OUTSIDE_POOL", id)
					}
				}
				deps = append(deps, Dependency{key("bridge", netID+"/"+s.Sfc.Node), Applied})
				if len(net.Sfc.Pools) > 1 {
					deps = append(deps, Dependency{key("tunnel", netID+"/"+s.Sfc.Node), Applied})
				}
				if net.Sfc.DNS != nil && net.Sfc.DNS.Enabled {
					// Publish the task's exact address/generation before DNS native
					// readiness, which itself consumes those committed addresses.
					// Native Create/Start remains gated by the same DNS observation.
					dns := key("dns", netID+"/"+s.Sfc.Node)
					deps = append(deps, Dependency{dns, Committed})
					activation = append(activation, Dependency{dns, Applied})
				}
			}
			for netID, a := range s.Networks {
				for _, ip := range []string{a.IPv4, a.IPv6} {
					if ip == "" {
						continue
					}
					canonical := mustAddr(ip).String()
					wanted := Step{Key: key("task", id), Kind: "task", Node: s.Sfc.Node, Owner: n.Key, Goal: goal(taskConfig)}
					if !plannedAddressAllowed(b, ctx, wanted, mustAddr(ip)) {
						return Blueprint{}, inputError("ADDRESS_CONFLICT", id)
					}
					if held, ok := ctx.Addresses[canonical]; ok && (held.Generation == 0 || held.Revision < held.Generation || !ctx.Current[held.Key].Present || held.Key != key("task", id) || held.Generation != ctx.Current[held.Key].Generation || held.Revision != ctx.Current[held.Key].Revision) {
						return Blueprint{}, inputError("ADDRESS_CONFLICT", id)
					}
					addressKey := s.Sfc.Node + "/" + canonical
					if addresses[addressKey] || canonical == c.Networks[netID].Sfc.Pools[s.Sfc.Node].Gateway {
						return Blueprint{}, inputError("ADDRESS_CONFLICT", id)
					}
					addresses[addressKey] = true
				}
			}
			mounted := map[string]bool{}
			for _, mount := range s.Volumes {
				volumeKey := b.volumeKey(mount.Source)
				if mounted[volumeKey] {
					return Blueprint{}, inputError("DUPLICATE_VOLUME_REFERENCE", mount.Source)
				}
				mounted[volumeKey] = true
				if mount.ReadOnly {
					readers[volumeKey]++
				} else {
					writers[volumeKey]++
				}
				share := b.d.FixedVolumes[mount.Source].Share
				if share == "" && (writers[volumeKey] > 1 || writers[volumeKey] > 0 && readers[volumeKey] > 0) || share == volumes.ShareSingleWriter && writers[volumeKey] > 1 {
					return Blueprint{}, inputError("VOLUME_WRITER_CONFLICT", mount.Source)
				}
				if _, fixed := b.d.FixedVolumes[mount.Source]; !fixed {
					deps = append(deps, Dependency{key("volume", mount.Source), Applied})
				}
			}
			if len(s.Secrets) > 0 || len(s.Sfc.Sources) > 0 || len(s.Sfc.SecretEnv) > 0 || len(b.d.RegistrySources[logical]) > 0 {
				if e = require("inputs"); e != nil {
					return Blueprint{}, e
				}
				inputDeps := []Dependency{{Key: key("task", id), Condition: Committed}}
				if c.Sfc.Vault != nil {
					inputDeps = append(inputDeps, Dependency{key("namespace", "root"), Committed})
				}
				for _, mount := range s.Volumes {
					if _, fixed := b.d.FixedVolumes[mount.Source]; !fixed {
						inputDeps = append(inputDeps, Dependency{key("volume", mount.Source), Applied})
					}
				}
				if e = add(Step{Key: key("inputs", id), Kind: "inputs", Identity: []string{key("task", id)}, Node: s.Sfc.Node, Owner: n.Key, Goal: goal(struct {
					Sources         []Selector
					Mounts          SecretMounts
					Environment     []SecretEnvironment `json:",omitempty"`
					RegistrySources []Source            `json:",omitempty"`
				}{Sources: s.Sfc.Sources, Mounts: s.Secrets, Environment: s.Sfc.SecretEnv, RegistrySources: b.d.RegistrySources[logical]}), Dependencies: inputDeps, Completion: Applied}); e != nil {
					return Blueprint{}, e
				}
				activation = append(activation, Dependency{Key: key("inputs", id), Condition: Applied})
			}
			for _, dep := range mapKeys(s.DependsOn) {
				when, err := dependencyCondition(s.DependsOn[dep].Condition)
				if err != nil {
					return Blueprint{}, err
				}
				for _, dependency := range placements[dep] {
					deps = append(deps, Dependency{key("task", dependency.ResourceID()), when})
				}
			}
			completion := Applied
			if s.hasReadiness() || instance.Ordinal != 0 {
				completion = Healthy
			}
			if b.d.Checkers != nil {
				deps, e = mergeCheckerDependencies(deps, b.d.Checkers.Program.Services[logical], key)
				if e != nil {
					return Blueprint{}, e
				}
			}
			deps = expandReplicaDependencies(deps, placements, b.d.Tenant, b.d.App)
			if e = add(Step{Key: key("task", id), Kind: "task", Node: s.Sfc.Node, Owner: n.Key, Goal: goal(taskConfig), Dependencies: deps, Activation: activation, Completion: completion}); e != nil {
				return Blueprint{}, e
			}
		}
	}
	if i := c.Sfc.Ingress; i != nil {
		n, e := node(i.Node, access.Deploy)
		if e != nil {
			return Blueprint{}, e
		}
		var deps []Dependency
		var identity []string
		declaration := *i
		resolvedRoutes := IngressRoutes(*i)
		for routeAt, route := range resolvedRoutes {
			when := Applied
			backend := c.Services[route.Service]
			if backend.hasReadiness() {
				when = Healthy
			}
			alias, e := ingressNetwork(ingressForRoute(*i, route), backend)
			if e != nil {
				return Blueprint{}, e
			}
			for _, instance := range placements[route.Service] {
				condition := when
				if instance.Ordinal != 0 {
					condition = Healthy
					identity = append(identity, key("task", instance.ResourceID()))
				}
				deps = append(deps, Dependency{key("task", instance.ResourceID()), condition})
			}
			if c.Networks[alias].External {
				localKey := key("network-ref", alias+"/"+i.Node)
				local, localOK := borrowed[localKey]
				if !localOK {
					return Blueprint{}, inputError("INGRESS_REMOTE_NETWORK_REQUIRED", alias)
				}
				for _, instance := range placements[route.Service] {
					remote, remoteOK := borrowed[key("network-ref", alias+"/"+instance.Node)]
					if !remoteOK || instance.Node != i.Node && (local.PacketNetwork == "" || local.PacketNetwork != remote.PacketNetwork || len(local.Routes) == 0 || len(remote.Routes) == 0) {
						return Blueprint{}, inputError("INGRESS_REMOTE_NETWORK_REQUIRED", alias)
					}
				}
				deps = append(deps, Dependency{localKey, Applied})
			} else {
				seen := map[string]bool{}
				for _, instance := range placements[route.Service] {
					if instance.Node == i.Node {
						if len(identity) != 0 && !seen["bridge"] {
							deps = append(deps, Dependency{key("bridge", alias+"/"+i.Node), Applied})
							seen["bridge"] = true
						}
						continue
					}
					if c.Networks[alias].Sfc.Pools[i.Node].CIDR == "" {
						return Blueprint{}, inputError("INGRESS_REMOTE_NETWORK_REQUIRED", alias)
					}
					for _, owner := range []string{i.Node, instance.Node} {
						if !seen[owner] {
							deps = append(deps, Dependency{key("tunnel", alias+"/"+owner), Applied})
							seen[owner] = true
						}
					}
				}
			}
			resolvedRoutes[routeAt].Network = alias
		}
		depSet := map[Dependency]bool{}
		uniqueDeps := deps[:0]
		for _, dependency := range deps {
			if !depSet[dependency] {
				depSet[dependency] = true
				uniqueDeps = append(uniqueDeps, dependency)
			}
		}
		deps = uniqueDeps
		slices.Sort(identity)
		identity = slices.Compact(identity)
		if len(i.Routes) > 0 {
			declaration.Routes = resolvedRoutes
		} else {
			declaration.Backend.Network = resolvedRoutes[0].Network
		}
		if e = add(Step{Key: key("ingress", "http"), Kind: "ingress", Identity: identity, Node: i.Node, Owner: n.Key, Goal: goal(declaration), Dependencies: deps, Completion: Healthy}); e != nil {
			return Blueprint{}, e
		}
	}
	for _, id := range mapKeys(c.Sfc.Registries) {
		r := c.Sfc.Registries[id]
		if !r.Enabled {
			continue
		}
		if e := require("registry"); e != nil {
			return Blueprint{}, e
		}
		n, e := node(r.Node, access.ManageRegistry)
		if e != nil {
			return Blueprint{}, e
		}
		if _, e = policy.CheckImage(ctx.Actor, b.d.Tenant, r.Node, r.Image); e != nil {
			return Blueprint{}, imageCheckError(policy, ctx.Actor, b.d.Tenant, r.Node, e, "x-sfc.registries."+id+".image")
		}
		if volumeOwners[r.Volume] != r.Node {
			return Blueprint{}, inputError("REGISTRY_VOLUME_REQUIRED", id)
		}
		bridge := key("bridge", r.Network+"/"+r.Node)
		if c.Networks[r.Network].External {
			bridge = key("network-ref", r.Network+"/"+r.Node)
		}
		if _, ok := known[bridge]; !ok {
			return Blueprint{}, inputError("REGISTRY_NETWORK_REQUIRED", id)
		}
		volumeKey := b.volumeKey(r.Volume)
		if _, fixed := b.d.FixedVolumes[r.Volume]; fixed {
			return Blueprint{}, inputError("FIXED_VOLUME_REQUIRES_TENANT_REGISTRY", r.Volume)
		}
		writers[volumeKey]++
		if writers[volumeKey] > 1 || readers[volumeKey] > 0 {
			return Blueprint{}, inputError("VOLUME_WRITER_CONFLICT", r.Volume)
		}
		cpu, e := nanoCPU(r.Resources.CPUs)
		if e != nil || cpu == 0 || r.Resources.Memory == 0 {
			return Blueprint{}, inputError("RESOURCE_BUDGET_REQUIRED", id)
		}

		if e = add(Step{Key: key("registry", id), Kind: "registry", Node: r.Node, Owner: n.Key, Goal: goal(r), Dependencies: []Dependency{{bridge, Applied}, {key("volume", r.Volume), Applied}}, Completion: Healthy}); e != nil {
			return Blueprint{}, e
		}
	}
	if c.Sfc.Delivery != nil && c.Sfc.Delivery.Enabled {
		if e := require("git-cd"); e != nil {
			return Blueprint{}, e
		}
		if policy.Authorize(ctx.Actor, b.d.Tenant, access.ManageCD, "") != nil {
			return Blueprint{}, access.ErrDenied
		}
		if e := add(Step{Key: key("delivery", "source"), Kind: "delivery", Goal: goal(c.Sfc.Delivery), Completion: Committed}); e != nil {
			return Blueprint{}, e
		}
	}
	if c.Sfc.Routing != nil && len(c.Sfc.Routing.Routes) > 0 {
		if e := require("routes"); e != nil {
			return Blueprint{}, e
		}
		for _, r := range c.Sfc.Routing.Routes {
			if e := add(Step{Key: key("route", r.ID), Kind: "route", Goal: goal(r), Completion: Applied}); e != nil {
				return Blueprint{}, e
			}
		}
	}
	if e := requireJobCompletion(known); e != nil {
		return Blueprint{}, e
	}
	steps, e := orderSteps(known)
	if e != nil {
		return Blueprint{}, e
	}
	b.d.Input = c
	for _, service := range mapKeys(c.Services) {
		if len(c.Services[service].Sfc.SecretEnv) != 0 {
			b.d.SecretEnvRequiresNewGeneration = append(b.d.SecretEnvRequiresNewGeneration, service)
		}
	}
	b.d.Steps = steps
	if e = b.checkPublishedPorts(ctx); e != nil {
		return Blueprint{}, e
	}
	annotateDNSBindings(&b, ctx)
	if e = validateLifetimes(steps); e != nil {
		return Blueprint{}, e
	}
	if e = validatePlanBudget(b, ctx); e != nil {
		return Blueprint{}, e
	}
	if _, e = b.Encode(); e != nil {
		return Blueprint{}, e
	}
	return b, nil
}
func mapKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
func orderSteps(steps map[string]Step) ([]Step, error) {
	var out []Step
	seen := map[string]uint8{}
	var visit func(string) error
	visit = func(k string) error {
		if seen[k] == 1 {
			return inputError("DEPENDENCY_CYCLE", k)
		}
		if seen[k] == 2 {
			return nil
		}
		s, ok := steps[k]
		if !ok {
			return inputError("MISSING_DEPENDENCY", k)
		}
		seen[k] = 1
		slices.SortFunc(s.Dependencies, func(a, b Dependency) int { return strings.Compare(a.Key, b.Key) })
		previous := ""
		for _, d := range s.Dependencies {
			if d.Key == previous || d.Condition != Committed && d.Condition != Applied && d.Condition != Healthy && d.Condition != Completed && d.Condition != Released || d.Condition == Completed && steps[d.Key].Kind != "task" {
				return inputError("INVALID_DEPENDENCY", k)
			}
			previous = d.Key
			if e := visit(d.Key); e != nil {
				return e
			}
		}
		seen[k] = 2
		out = append(out, s)
		return nil
	}
	for _, k := range mapKeys(steps) {
		if e := visit(k); e != nil {
			return nil, e
		}
	}
	return out, nil
}

func mustPrefix(s string) netip.Prefix { p, _ := netip.ParsePrefix(s); return p }
func mustAddr(s string) netip.Addr     { a, _ := netip.ParseAddr(s); return a }

// imageCheckError names why an image was refused. CheckImage also denies
// an actor without Deploy on the node; only when that passes is the denial
// the tenant's missing trust rule. Any other denial stays unnamed.
func imageCheckError(policy access.Catalog, actor, tenant, node string, err error, path string) error {
	if errors.Is(err, access.ErrDenied) && policy.Authorize(actor, tenant, access.Deploy, node) == nil {
		return inputError("IMAGE_NOT_TRUSTED", path)
	}
	return err
}
