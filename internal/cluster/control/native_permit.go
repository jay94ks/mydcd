// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/tenancy"
	"strings"
)

type NativeRequest struct {
	Source deployment.ObjectRef
	DNS    string `json:",omitempty"`
}
type NativePermit struct {
	Native       string `json:",omitempty"`
	DNS          string `json:",omitempty"`
	Source       deployment.ObjectRef
	Owner        [32]byte
	Kind         string
	Spec         [32]byte
	MaxConsumers int
	Consumers    *network.ConsumerBudget `json:",omitempty"`
	PacketLimits *network.PacketLimits   `json:",omitempty"`
}

func (p Policy) NativePermit(s state.State, caller [32]byte, r NativeRequest) (NativePermit, error) {
	if !strings.HasPrefix(r.Source.Key, "network/bridge/") && !strings.HasPrefix(r.Source.Key, "network/tun/") && !strings.HasPrefix(r.Source.Key, "network/dns/") && !strings.HasPrefix(r.Source.Key, "network/reference/") && !strings.HasPrefix(r.Source.Key, tenancy.ManagedNetworkSourcePrefix) && !strings.HasPrefix(r.Source.Key, services.ManagedDNSPrefix) && !strings.HasPrefix(r.Source.Key, "workload/volume/") && !strings.HasPrefix(r.Source.Key, "workload/task/") && !strings.HasPrefix(r.Source.Key, "ingress/app/") {
		return NativePermit{}, ErrCatalog
	}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(caller) {
		return NativePermit{}, ErrCatalog
	}
	o := s.Object(r.Source.Key)
	if !o.Present || r.Source.Generation != o.Generation || r.Source.Revision != o.Revision {
		return NativePermit{}, ErrCatalog
	}
	if strings.HasPrefix(r.Source.Key, services.ManagedDNSPrefix) {
		return p.managedDNSNativePermit(s, caller, r)
	}
	if r.DNS != "" {
		return NativePermit{}, ErrCatalog
	}
	projected, err := p.ProjectResources(s)
	if err != nil {
		return NativePermit{}, err
	}
	if source, exists := projected.ManagedSources[r.Source.Key]; exists {
		return p.managedNetworkNativePermit(s, caller, r, projected, source)
	}
	goal, ok := projected.Goals[r.Source.Key]
	if !ok || goal.Bridge == nil && goal.Tunnel == nil && goal.Ingress == nil && goal.Goal.Kind != "volume" && goal.Goal.Kind != "dns" && goal.Goal.Kind != "network-ref" || !members.OwnsResource(caller, goal.Goal.Owner) || goal.Goal.Lifecycle != nil && goal.Goal.Lifecycle.Drain {
		return NativePermit{}, ErrCatalog
	}
	caller = goal.Goal.Owner
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return NativePermit{}, err
	}
	entry, ok := apps.entries[appKey(goal.Goal.Tenant, goal.Goal.App)]
	if !ok {
		return NativePermit{}, ErrCatalog
	}
	if wave, retiring := entry.Inventory.Retirement(); retiring && !(goal.Ingress != nil && goal.Ingress.DynamicBackends && wave.Preserves(r.Source.Key)) {
		return NativePermit{}, ErrCatalog
	}
	e, ok := entry.Inventory.Execution()
	if !ok || e.Status() == "Paused" || e.Status() == "Stopping" || e.Status() == "Closed" {
		return NativePermit{}, ErrCatalog
	}
	stage, ok := e.Stage(r.Source.Key)
	if !ok {
		return NativePermit{}, ErrCatalog
	}
	var result state.Result
	found := false
	if stage.Command != nil && stage.Command.Value == o.Value {
		result, found = s.LookupResult(*stage.Command)
		if stage.Result != nil {
			result, found = *stage.Result, true
		}
	} else if goal.Ingress != nil && goal.Ingress.DynamicBackends {
		// A new rollout may not yet have collected its unchanged listener
		// Noop. Its exact retained source remains governed by the new accepted
		// plan/grant, without forging that Noop's result or another command.
		for _, claim := range entry.Inventory.Claims() {
			if claim.Removed || claim.Step.Key != r.Source.Key || claim.Command.Value != o.Value {
				continue
			}
			for _, step := range e.Steps() {
				if step.Key == r.Source.Key && step.Node == claim.Step.Node && step.Owner == claim.Step.Owner && string(step.Goal) == string(goal.Goal.Config) && strings.Join(step.Identity, "\x00") == strings.Join(goal.Goal.Follow, "\x00") {
					result, found = claim.Result, true
				}
			}
		}
	}
	if !found || result.Code != state.Applied || result.Revision != o.Revision || result.Generation != o.Generation {
		return NativePermit{}, ErrCatalog
	}
	catalog, err := p.Catalog(s)
	if err != nil || p.authorizeAppStep(s, catalog, entry, e, r.Source.Key) != nil {
		return NativePermit{}, ErrCatalog
	}
	global, gok := projected.Resources.Quotas.Limit("", goal.Goal.Node)
	scoped, sok := projected.Resources.Quotas.Limit(goal.Goal.Tenant, goal.Goal.Node)
	if err := checkNativeLimits(goal.Goal.Tenant, goal.Goal.Node, caller, projected.Resources.Quotas, global, gok, scoped, sok); err != nil {
		return NativePermit{}, err
	}
	capacity := min(global.MaxConsumers, scoped.MaxConsumers)
	if goal.Goal.Kind == "network-ref" {
		if err := checkCurrentNetworkReference(p.Cluster, s, projected, goal); err != nil {
			return NativePermit{}, err
		}
		if err := admitIngressConsumers(projected, goal); err != nil {
			return NativePermit{}, err
		}
		return NativePermit{Source: r.Source, Owner: caller, Kind: "network-ref", Spec: sha256.Sum256(goal.Goal.Config), MaxConsumers: capacity}, nil
	}
	if goal.Goal.Kind == "dns" {
		_, rows, known := apps.NetworkDNS(caller)
		for _, row := range rows {
			if known && row.Source == r.Source && row.Config.Enabled {
				return NativePermit{Source: r.Source, Owner: caller, Kind: "dns", Spec: AppDNSNativeDigest(row), MaxConsumers: capacity}, nil
			}
		}
		return NativePermit{}, ErrCatalog
	}
	if goal.Ingress != nil {
		var declared deployment.IngressDeclaration
		if json.Unmarshal(goal.Goal.Config, &declared) != nil || p.admitIngressDeclaration(s, goal.Goal.Tenant, entry.Origin.Session.User, declared) != nil {
			return NativePermit{}, access.ErrDenied
		}
		if err := admitIngressConsumers(projected, goal); err != nil {
			return NativePermit{}, err
		}
		if goal.Ingress.DynamicBackends {
			for _, service := range goal.Ingress.Services {
				for _, backend := range service.Backends {
					if backend.Suspended || backend.Draining {
						continue
					}
					ref := deployment.ObjectRef{Key: backend.Task, Generation: backend.Generation, Revision: backend.Revision}
					binding, exists := apps.Binding(ref)
					if !exists {
						return NativePermit{}, ErrCatalog
					}
					source, exists := apps.BindingSource(binding.Digest())
					if !exists {
						return NativePermit{}, ErrCatalog
					}
					accepted := entry
					accepted.Origin, accepted.Sync = source.Origin, source.Sync
					execution := e
					if old, held := e.HeldExecution(backend.Task); held {
						execution = old
					}
					if p.authorizeAppSourceStep(s, catalog, accepted, execution, backend.Task) != nil {
						return NativePermit{}, ErrCatalog
					}
					if source.Sync != nil && source.Sync.Local != nil {
						var input deployment.ComposeService
						if json.Unmarshal(projected.Goals[backend.Task].Goal.Config, &input) != nil || p.authorizeLocalNeeds(s, catalog, source.Sync.Local, binding.Needs(), input) != nil {
							return NativePermit{}, ErrCatalog
						}
					}
				}
			}
		}
		spec := *goal.Ingress
		spec.Lifecycle = schema.Lifecycle{}
		native := ingress.ManagedNativeID(r.Source.Key, r.Source.Generation, spec)
		for _, claim := range entry.Inventory.Claims() {
			if claim.Removed || claim.Step.Key != r.Source.Key || claim.Native == "" {
				continue
			}
			if current, ok := deployment.CurrentIngressNative(claim, r.Source, o.Value); ok {
				native = current
				break
			}
			matched := false
			if stage.Command != nil {
				for _, step := range e.Steps() {
					if step.Key == r.Source.Key {
						if retained, ok := deployment.RetainedIngressNative(claim, step, *stage.Command, result); ok {
							native = retained
							matched = true
							break
						}
					}
				}
			}
			if claim.Result.Generation == r.Source.Generation && !matched {
				return NativePermit{}, ErrCatalog
			}
		}
		return NativePermit{Native: native, Source: r.Source, Owner: caller, Kind: "ingress", Spec: ingress.SpecDigest(spec), MaxConsumers: capacity}, nil
	}
	if goal.Goal.Kind == "volume" {
		material, err := p.AppVolumeMaterial(s, r.Source)
		if err != nil {
			return NativePermit{}, err
		}
		raw, _ := json.Marshal(material)
		return NativePermit{Source: r.Source, Owner: caller, Kind: "volume", Spec: sha256.Sum256(raw), MaxConsumers: capacity}, nil
	}
	if goal.Bridge != nil || goal.Tunnel != nil {
		if err := admitIngressConsumers(projected, goal); err != nil {
			return NativePermit{}, err
		}
	}
	if goal.Tunnel != nil {
		spec := *goal.Tunnel
		spec.Lifecycle = schema.Lifecycle{}
		limits, err := checkPacketLimits(goal.Goal.Tenant, goal.Goal.Node, global, scoped, spec.MTU)
		if err != nil {
			return NativePermit{}, err
		}
		raw, _ := json.Marshal(spec)
		return NativePermit{Source: r.Source, Owner: caller, Kind: "tunnel", Spec: sha256.Sum256(raw), MaxConsumers: capacity, PacketLimits: &limits, Consumers: p.nativeConsumerBudget(goal.Goal.Tenant, goal.Goal.Node, caller, global, scoped)}, nil
	}
	spec := *goal.Bridge
	spec.Lifecycle = schema.Lifecycle{}
	raw, _ := json.Marshal(spec)
	return NativePermit{Source: r.Source, Owner: caller, Kind: "bridge", Spec: sha256.Sum256(raw), MaxConsumers: capacity, Consumers: p.nativeConsumerBudget(goal.Goal.Tenant, goal.Goal.Node, caller, global, scoped)}, nil
}
