// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"strings"
)

// VolumeMoveResourceRead is public preparation metadata, never native Desired,
// a future generation, or a reservation/Ready receipt. Full rows stay local to
// the same committed replica; only the enclosing read-set digest is on wire.
type VolumeMoveResourceRead struct {
	Key, Kind, Node  string
	Owner            [32]byte
	Source           deployment.ObjectRef
	Spec             [32]byte
	Volume           *volumes.NativeSpec            `json:",omitempty"`
	VolumeGeneration uint64                         `json:",omitempty"`
	Bridge           *tenancy.Network               `json:",omitempty"`
	Ingress          *deployment.IngressDeclaration `json:",omitempty"`
}

func (p Policy) moveResourceReads(s state.State, j VolumeMove) ([]VolumeMoveResourceRead, error) {
	apps, err := p.Apps(s)
	if err != nil {
		return nil, err
	}
	var q VolumeMoveBegin
	if moveBeginForJob(j, &q) != nil {
		return nil, ErrCatalog
	}
	b, err := p.frozenMoveBlueprint(apps, j.Origin, q)
	if err != nil {
		return nil, err
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return nil, err
	}
	demands, err := b.ResourceDemands()
	if err != nil {
		return nil, err
	}
	registry, err := p.Volumes(s)
	if err != nil {
		return nil, err
	}
	targets, err := moveVolumeTargets(registry, j, b.Scope())
	if err != nil {
		return nil, err
	}
	definitions, err := p.ManagedDNS(s)
	if err != nil {
		return nil, err
	}
	byKey := map[string]deployment.ResourceDemand{}
	for _, d := range demands {
		byKey[d.Key] = d
	}
	rows := map[string]VolumeMoveResourceRead{}
	add := func(row VolumeMoveResourceRead) error {
		if row.Node == "" || row.Owner == ([32]byte{}) || row.Key == "" || row.Kind == "" {
			return ErrCatalog
		}
		id := row.Node + "/" + row.Kind + "/" + row.Key
		if old, ok := rows[id]; ok {
			a, _ := json.Marshal(old)
			z, _ := json.Marshal(row)
			if string(a) != string(z) {
				return ErrCatalog
			}
		}
		rows[id] = row
		return nil
	}
	addNative := func(kind, node string, owner [32]byte, source deployment.ObjectRef, spec [32]byte) error {
		o := s.Object(source.Key)
		if !o.Present || source.Generation == 0 || o.Generation != source.Generation || o.Revision != source.Revision || spec != sha256.Sum256([]byte(o.Value)) {
			return ErrCatalog
		}
		return add(VolumeMoveResourceRead{Key: source.Key, Kind: kind, Node: node, Owner: owner, Source: source, Spec: spec})
	}
	for _, step := range b.Steps() {
		if step.Owner == ([32]byte{}) {
			continue
		}
		row := VolumeMoveResourceRead{Key: step.Key, Kind: step.Kind, Node: step.Node, Owner: step.Owner}
		o := s.Object(step.Key)
		current, exists := projection.Goals[step.Key]
		sameOwner := exists && current.Goal.Node == step.Node && current.Goal.Owner == step.Owner && current.Goal.Tenant == b.Scope().Tenant && current.Goal.App == b.Scope().App && current.Goal.Deployment == b.Scope().Deployment
		source := deployment.ObjectRef{Key: step.Key, Generation: o.Generation, Revision: o.Revision}
		switch step.Kind {
		case "network-ref":
			var ref deployment.NetworkReference
			if canonical(step.Goal, &ref) != nil {
				return nil, ErrCatalog
			}
			if err := addNative("native-bridge", ref.Node, ref.Owner, ref.Source, ref.Spec); err != nil {
				return nil, err
			}
			for _, dependency := range ref.ManagedSources {
				identity, e := tenancy.ParseSourceIdentity(dependency.Source.Key)
				managed, found := projection.ManagedSources[dependency.Source.Key]
				if e != nil || !found || managed.Network.Tenant != b.Scope().Tenant || managed.Network.Node != identity.Node {
					return nil, ErrCatalog
				}
				kind := "native-bridge"
				if identity.Kind == "tun" {
					kind = "native-tunnel"
				}
				if err := addNative(kind, identity.Node, managed.Network.Owner, dependency.Source, dependency.Spec); err != nil {
					return nil, err
				}
			}
			if ref.ManagedName != "" {
				dnsKey := services.ManagedDNSKey(ref.Tenant, ref.ManagedName)
				if definition, found := definitions[dnsKey]; found && definition.Definition.Policy.Enabled {
					dns := s.Object(dnsKey)
					if err := addNative("native-dns", ref.Node, ref.Owner, deployment.ObjectRef{Key: dnsKey, Generation: dns.Generation, Revision: dns.Revision}, sha256.Sum256([]byte(dns.Value))); err != nil {
						return nil, err
					}
				}
			}
			continue
		case "bridge", "tunnel":
			if sameOwner && current.Goal.Kind == step.Kind && sha256.Sum256(step.Goal) == sha256.Sum256(current.Goal.Config) {
				if err := addNative("native-"+step.Kind, step.Node, step.Owner, source, sha256.Sum256([]byte(o.Value))); err != nil {
					return nil, err
				}
				continue
			}
			if step.Kind == "bridge" {
				row.Bridge = byKey[step.Key].Network
				if row.Bridge == nil {
					return nil, ErrCatalog
				}
			}
		case "ingress":
			row.Ingress = byKey[step.Key].Ingress
			if row.Ingress == nil {
				return nil, ErrCatalog
			}
			if sameOwner && o.Present {
				row.Source = source
				row.Spec = sha256.Sum256([]byte(o.Value))
			}
		case "volume":
			if spec, found := targets[step.Key]; found {
				if spec.Node != step.Node || spec.NodeKey != step.Owner {
					return nil, ErrCatalog
				}
				row.Volume = &spec
				row.VolumeGeneration = 1
			} else {
				id := step.Key[strings.LastIndexByte(step.Key, '/')+1:]
				ready, found := registry.Native(b.Scope().Tenant, b.Scope().App, id)
				if !found || ready.Spec.Node != step.Node || ready.Spec.NodeKey != step.Owner {
					return nil, ErrCatalog
				}
				row.Volume = &ready.Spec
				row.VolumeGeneration = ready.Generation
			}
		case "task", "inputs", "dns", "registry":
		default:
			return nil, ErrCatalog
		}
		if err := add(row); err != nil {
			return nil, err
		}
	}
	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make([]VolumeMoveResourceRead, 0, len(rows))
	for _, id := range ids {
		out = append(out, rows[id])
	}
	return out, nil
}

func moveVolumeTargets(registry Volumes, j VolumeMove, scope deployment.AppScope) (map[string]volumes.NativeSpec, error) {
	group, err := drainMoveGroup(registry, j)
	if err != nil {
		return nil, err
	}
	// All children of the original signed drain must prepare before any owner
	// is committed. Their exact accepted targets are preparation inputs, never
	// inferred current Native/Ready facts for their still-live source owners.
	targets := map[string]volumes.NativeSpec{}
	for _, child := range group {
		childScope := child.Binding.Scope
		if childScope.Cluster != scope.Cluster || childScope.Tenant != scope.Tenant || childScope.App != scope.App || child.Target.Scope != childScope || child.Target.Node != child.Binding.Target.Node || child.Target.NodeKey != child.Binding.Target.Key || child.Target.Validate() != nil {
			return nil, ErrCatalog
		}
		key := deployment.ResourceKey("volume", childScope.Tenant, childScope.App, childScope.ID)
		if prior, found := targets[key]; found && prior != child.Target {
			return nil, ErrCatalog
		}
		targets[key] = child.Target
	}
	return targets, nil
}
