// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

type isolationRecord struct {
	Schema uint8
	Owner  string
	Boot   [32]byte
	Source [32]byte
	State  reconcile.State
}

func isolationRecordKey(boot [32]byte) string {
	return "network-isolation/" + hex.EncodeToString(boot[:])
}

func decodeIsolationRecord(raw []byte, owner string, boot [32]byte) (isolationRecord, error) {
	r, err := schema.Decode[isolationRecord](raw)
	if err != nil || r.Schema != 1 || r.Owner != owner || r.Boot != boot || boot == ([32]byte{}) || r.Source == ([32]byte{}) || reconcile.Validate(r.State) != nil {
		return r, errors.New("invalid original node isolation record")
	}
	resources := []reconcile.Resource{r.State.Desired.Resource, r.State.Applied}
	if r.State.Pending != nil {
		resources = append(resources, r.State.Pending.Target)
	}
	for _, resource := range resources {
		if !resource.Present {
			continue
		}
		spec, err := network.DecodeIsolation(resource.Spec)
		if err != nil || spec.Owner != owner {
			return r, errors.New("node isolation source/owner changed")
		}
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return r, errors.New("noncanonical node isolation record")
	}
	return r, nil
}

func (r *Runtime) saveIsolation(record isolationRecord) error {
	if r.reports == nil || r.isolationFailed {
		return errors.New("original isolation store requires reopening")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if _, err := decodeIsolationRecord(raw, r.owner, record.Boot); err != nil {
		return err
	}
	if err := r.reports.Write(map[string][]byte{isolationRecordKey(record.Boot): raw}); err != nil {
		r.isolationFailed = true
		return err
	}
	return nil
}

func (r *Runtime) isolationSpec(v cluster.View, projection control.ResourceProjection) (network.IsolationSpec, error) {
	return r.buildIsolationSpec(v, projection, true)
}

func (r *Runtime) isolationSharedHash(v cluster.View, projection control.ResourceProjection) ([32]byte, error) {
	spec, err := r.buildIsolationSpec(v, projection, false)
	if err != nil {
		return [32]byte{}, err
	}
	raw, _ := json.Marshal(spec)
	return sha256.Sum256(raw), nil
}

func (r *Runtime) buildIsolationSpec(v cluster.View, projection control.ResourceProjection, includeOriginal bool) (network.IsolationSpec, error) {
	spec := network.IsolationSpec{Schema: 1, Owner: r.owner}
	if r.Identity == nil {
		return spec, network.ErrPolicy
	}
	for _, definition := range projection.Resources.Networks.AllNetworks() {
		for _, pool := range definition.Pools {
			spec.Prefixes = append(spec.Prefixes, network.TenantPrefix{Tenant: definition.Tenant, Prefix: pool.Prefix})
		}
		for _, address := range definition.TunnelAddresses {
			spec.Prefixes = append(spec.Prefixes, network.TenantPrefix{Tenant: definition.Tenant, Prefix: address})
		}
	}
	addBridge := func(tenant, key string, generation uint64, native reconcile.Resource) error {
		bridge, err := network.DecodeBridge(native.Spec)
		if err != nil || bridge.Owner != r.owner || generation == 0 || tenant == "" {
			return errors.New("isolation Bridge lost its original source ownership")
		}
		device, err := network.BridgeDeviceName(r.owner, key, generation, sha256.Sum256([]byte(native.Spec)))
		if err != nil {
			return err
		}
		binding := network.IsolationBridge{Tenant: tenant, Device: device, Managed: bridge.GatewayMode == network.ManagedGatewayMode}
		for _, pool := range bridge.Pools {
			spec.Prefixes = append(spec.Prefixes, network.TenantPrefix{Tenant: tenant, Prefix: pool.Prefix})
			binding.Prefixes = append(binding.Prefixes, pool.Prefix)
		}
		spec.Bridges = append(spec.Bridges, binding)
		return nil
	}
	addDesired := func(tenant, key string, bridge network.BridgeSpec) error {
		raw, err := json.Marshal(bridge)
		if err != nil {
			return err
		}
		object := v.State.Object(key)
		return addBridge(tenant, key, object.Generation, reconcile.Resource{Generation: object.Generation, Present: true, Spec: string(raw)})
	}
	addTunnel := func(tenant, key string, native reconcile.Resource) error {
		tunnel, err := network.DecodeTunnel(native.Spec)
		if err != nil || tunnel.Owner != r.owner || native.Generation == 0 || tenant == "" {
			return errors.New("isolation TUN lost its original source ownership")
		}
		if tunnel.RoutePolicy != nil {
			return nil // Bilateral route exceptions use their own exact contract.
		}
		device, err := network.TunnelDeviceName(key, native.Generation, tunnel)
		if err != nil {
			return err
		}
		spec.Tunnels = append(spec.Tunnels, network.IsolationTunnel{Tenant: tenant, Device: device, Prefixes: tunnel.Routes})
		for _, prefix := range append(tunnel.Clone().Routes, tunnel.Addresses...) {
			spec.Prefixes = append(spec.Prefixes, network.TenantPrefix{Tenant: tenant, Prefix: prefix})
		}
		return nil
	}
	for key, source := range projection.ManagedSources {
		if source.Tunnel != nil && source.Network.Owner == r.Identity.Public && source.Closed == nil && !source.Network.Draining {
			tunnel := source.Tunnel.Clone()
			tunnel.Lifecycle = schema.Lifecycle{}
			raw, _ := json.Marshal(tunnel)
			object := v.State.Object(key)
			if err := addTunnel(source.Network.Tenant, key, reconcile.Resource{Generation: object.Generation, Present: true, Spec: string(raw)}); err != nil {
				return spec, err
			}
		}
		if source.Bridge == nil || source.Network.Owner != r.Identity.Public || source.Closed != nil || source.Network.Draining {
			continue
		}
		bridge := *source.Bridge
		bridge.Lifecycle = schema.Lifecycle{}
		if err := addDesired(source.Network.Tenant, key, bridge); err != nil {
			return spec, err
		}
	}
	for key, goal := range projection.Goals {
		if goal.Bridge != nil && goal.Goal.Owner == r.Identity.Public && !goal.Bridge.Lifecycle.Drain {
			if err := addDesired(goal.Goal.Tenant, key, *goal.Bridge); err != nil {
				return spec, err
			}
		}
		if goal.Tunnel != nil && goal.Goal.Owner == r.Identity.Public && !goal.Tunnel.Lifecycle.Drain {
			raw, _ := json.Marshal(goal.Tunnel)
			object := v.State.Object(key)
			if err := addTunnel(goal.Goal.Tenant, key, reconcile.Resource{Generation: object.Generation, Present: true, Spec: string(raw)}); err != nil {
				return spec, err
			}
		}
	}
	if includeOriginal && r.tunnel != nil && r.tunnel.manager != nil {
		for _, key := range r.tunnel.manager.Keys() {
			row, err := r.tunnel.manager.View(key)
			if err != nil {
				return spec, err
			}
			tenant := row.Scope.Tenant
			if source, exists := projection.ManagedSources[key]; exists {
				if tenant != "" && tenant != source.Network.Tenant {
					return spec, errors.New("original isolation TUN tenant changed")
				}
				tenant = source.Network.Tenant
			} else if goal, exists := projection.Goals[key]; exists {
				if tenant != "" && tenant != goal.Goal.Tenant {
					return spec, errors.New("original app TUN tenant changed")
				}
				tenant = goal.Goal.Tenant
			}
			resources := []reconcile.Resource{row.State.Desired.Resource, row.State.Applied}
			if row.State.Pending != nil {
				resources = append(resources, row.State.Pending.Target)
			}
			for _, native := range resources {
				if native.Present {
					if err := addTunnel(tenant, key, native); err != nil {
						return spec, err
					}
				}
			}
		}
	}
	// Historical Applied/pending resources stay protected until their actual
	// journal closes. A new source cannot silently erase the old native Bridge.
	if includeOriginal && r.network != nil {
		for _, key := range r.network.Keys() {
			row, err := r.network.View(key)
			if err != nil {
				return spec, err
			}
			tenant := row.Scope.Tenant
			if source, ok := projection.ManagedSources[key]; ok {
				if tenant != "" && tenant != source.Network.Tenant {
					return spec, errors.New("isolation Bridge tenant changed")
				}
				tenant = source.Network.Tenant
			} else if goal, ok := projection.Goals[key]; ok {
				if tenant != "" && tenant != goal.Goal.Tenant {
					return spec, errors.New("isolation app Bridge tenant changed")
				}
				tenant = goal.Goal.Tenant
			}
			resources := []reconcile.Resource{row.State.Desired.Resource, row.State.Applied}
			if row.State.Pending != nil {
				resources = append(resources, row.State.Pending.Target)
			}
			for _, native := range resources {
				if native.Present {
					if err := addBridge(tenant, key, native.Generation, native); err != nil {
						return spec, err
					}
				}
			}
		}
	}
	if projection.NetworkAuthority != nil {
		for _, ref := range projection.NetworkAuthority.RouteReferences() {
			if ref.Native == nil || ref.Local.Owner != r.Identity.Public || ref.Closed != nil {
				continue
			}
			work, err := r.controlPolicy.RouteWork(v.State, r.commandIdentity().Public, control.RouteWorkRequest{Reference: ref.ID})
			if err != nil || !work.PrepareAllowed || ref.Dispatch == nil || work.Peer.Dispatch == nil || work.Tunnel.RoutePolicy == nil || work.Tunnel.RoutePolicy.Bridge == "" {
				continue
			}
			device, err := network.TunnelDeviceName(ref.RouteNativeKey(), ref.Generation, work.Tunnel)
			if err != nil {
				return spec, err
			}
			spec.Routes = append(spec.Routes, network.IsolationRoute{Device: device, Policy: *work.Tunnel.RoutePolicy})
		}
	}
	return network.NormalizeIsolation(spec)
}

func (r *Runtime) reconcileTenantIsolation(ctx context.Context, v cluster.View, projection control.ResourceProjection) error {
	r.isolationMu.Lock()
	defer r.isolationMu.Unlock()
	spec, err := r.isolationSpec(v, projection)
	if err != nil {
		return err
	}
	if r.reports == nil && len(spec.Bridges) == 0 {
		return nil
	}
	if r.reports == nil || r.isolationFailed {
		return errors.New("original isolation store requires reopening")
	}
	boot, err := services.NativeBootID()
	if err != nil {
		return err
	}
	key := isolationRecordKey(boot)
	raw, err := r.reports.GetBounded(key, 100<<20)
	var record isolationRecord
	if errors.Is(err, storage.ErrMissing) {
		if len(spec.Bridges) == 0 {
			return nil
		} // Blank node has no native policy.
		if present, err := network.IsolationExists(r.owner); err != nil || present {
			return errors.Join(err, errors.New("native isolation has no original kernel-boot journal"))
		}
		record = isolationRecord{Schema: 1, Owner: r.owner, Boot: boot}
	} else if err != nil {
		return err
	} else {
		record, err = decodeIsolationRecord(raw, r.owner, boot)
		if err != nil {
			return err
		}
	}
	wanted := reconcile.Desired{Revision: v.State.Index()}
	record.Source, err = r.isolationSharedHash(v, projection)
	if err != nil {
		return err
	}
	if len(spec.Bridges) != 0 {
		generation := record.State.GenerationFloor
		if generation == 0 || !record.State.Desired.Present {
			if generation == ^uint64(0) {
				return reconcile.ErrDesired
			}
			generation++
		}
		value, _ := json.Marshal(spec)
		wanted.Resource = reconcile.Resource{Generation: generation, Present: true, Spec: string(value)}
	} else {
		wanted.Retiring = record.State.GenerationFloor
	}
	record.State, err = reconcile.SetDesired(record.State, wanted)
	if err != nil {
		return err
	}
	if err := r.saveIsolation(record); err != nil {
		return err
	}
	operation := record.State.Pending
	if operation == nil {
		record.State, operation, err = reconcile.Plan(record.State)
		if err != nil {
			return err
		}
		if operation == nil {
			if !record.State.Applied.Present {
				return nil
			}
			applied, err := network.DecodeIsolation(record.State.Applied.Spec)
			if err != nil {
				return err
			}
			present, err := network.InspectIsolation(applied)
			if err != nil || !present {
				return errors.Join(err, network.ErrKernelOwnership)
			}
			return nil
		}
		if err := r.saveIsolation(record); err != nil {
			return err
		}
	}
	first := operation.Phase == reconcile.Prepared
	if first {
		record.State, err = reconcile.Dispatch(record.State, operation.ID)
		if err != nil {
			return err
		}
		if err := r.saveIsolation(record); err != nil {
			return err
		}
	}
	target, err := network.DecodeIsolation(operation.Target.Spec)
	if err != nil {
		return err
	}
	var effectErr error
	if operation.Kind == reconcile.Remove {
		effectErr = network.RemoveIsolation(ctx, target)
	} else {
		var previous *network.IsolationSpec
		if record.State.Applied.Present {
			old, err := network.DecodeIsolation(record.State.Applied.Spec)
			if err != nil {
				return err
			}
			previous = &old
		}
		effectErr = network.ApplyIsolation(ctx, previous, target, first)
	}
	outcome := reconcile.EffectApplied
	if effectErr != nil {
		outcome = reconcile.EffectUnknown
	}
	record.State, err = reconcile.Settle(record.State, operation.ID, outcome)
	if err != nil {
		return errors.Join(effectErr, err)
	}
	if err := r.saveIsolation(record); err != nil {
		return errors.Join(effectErr, err)
	}
	if effectErr != nil {
		return effectErr
	}
	if record.State.Applied != record.State.Desired.Resource {
		return reconcile.ErrPending
	}
	return nil
}

// New route admission cannot use an uninstalled/stale baseline. Existing gate
// reads remain readonly; this native readback runs on the owner/RPC IO path.
func (r *Runtime) tenantIsolationReady(v cluster.View, projection control.ResourceProjection) error {
	r.isolationMu.Lock()
	defer r.isolationMu.Unlock()
	if r.reports == nil || r.isolationFailed {
		return errors.New("isolation store is unavailable")
	}
	spec, err := r.isolationSpec(v, projection)
	if err != nil {
		return err
	}
	boot, err := services.NativeBootID()
	if err != nil {
		return err
	}
	raw, err := r.reports.GetBounded(isolationRecordKey(boot), 100<<20)
	if err != nil {
		return err
	}
	record, err := decodeIsolationRecord(raw, r.owner, boot)
	if err != nil {
		return err
	}
	wanted, _ := json.Marshal(spec)
	if record.State.Pending != nil || !record.State.Applied.Present || record.State.Applied != record.State.Desired.Resource || record.State.Applied.Spec != string(wanted) {
		return reconcile.ErrPending
	}
	present, err := network.InspectIsolation(spec)
	if err != nil || !present {
		return errors.Join(err, network.ErrKernelOwnership)
	}
	return nil
}

// Manager's consumer callback must never reenter Manager/View. Its read-set
// digest covers committed sources; the applied spec additionally retains all
// original native resources. Unrelated app progress does not renew this digest.
func (r *Runtime) tenantIsolationAdmissionReady(v cluster.View, projection control.ResourceProjection) error {
	r.isolationMu.Lock()
	defer r.isolationMu.Unlock()
	if r.reports == nil || r.isolationFailed {
		return errors.New("isolation store is unavailable")
	}
	source, err := r.isolationSharedHash(v, projection)
	if err != nil {
		return err
	}
	boot, err := services.NativeBootID()
	if err != nil {
		return err
	}
	raw, err := r.reports.GetBounded(isolationRecordKey(boot), 100<<20)
	if err != nil {
		return err
	}
	record, err := decodeIsolationRecord(raw, r.owner, boot)
	if err != nil {
		return err
	}
	if record.Source != source || record.State.Pending != nil || !record.State.Applied.Present || record.State.Applied != record.State.Desired.Resource {
		return reconcile.ErrPending
	}
	spec, err := network.DecodeIsolation(record.State.Applied.Spec)
	if err != nil {
		return err
	}
	present, err := network.InspectIsolation(spec)
	if err != nil || !present {
		return errors.Join(err, network.ErrKernelOwnership)
	}
	return nil
}
