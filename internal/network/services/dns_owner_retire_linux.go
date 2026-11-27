// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

// Retire requires an explicit current disabled configuration. It stops actual
// I/O, retains old views until their ORIGINAL TTL holds expire, then settles
// Settings groups and Bridge pins. The returned signed receipt still needs the
// shared authority's commit; no local mutation pretends to commit that result.
func (o *DNSOwner) Retire(ctx context.Context, tenant, id string) (*ReferenceClose, error) {
	o.effects.Lock()
	defer o.effects.Unlock()
	p, err := o.options.Current(ctx, tenant, id)
	if err != nil {
		return nil, err
	}
	if p.Config.Enabled || p.Config.Tenant != tenant || p.Config.ID != id {
		return nil, ErrLease
	}
	o.mu.Lock()
	if o.closed || o.failed {
		o.mu.Unlock()
		return nil, errors.Join(ErrLease, o.lastErr)
	}
	key := "dns/" + dnsKey(tenant, id)
	scope, ok := o.settings.scopes[key]
	if !ok {
		proof, err := o.retireUndispatched(p)
		o.mu.Unlock()
		return proof, err
	}
	target, err := DNSSettings(p.Catalog, p.Networks, p.Authority, p.Actor, p.Config, scope.Desired.binding.Native)
	if err != nil {
		o.mu.Unlock()
		return nil, err
	}
	m, err := o.settings.Desired(p.Catalog, p.Networks, p.Authority, p.Actor, scope.Desired.revision, target)
	if err == nil {
		m, _, err = m.Stage(p.Catalog, p.Networks, p.Authority, key)
	}
	d := o.dns
	if err == nil && d.Applied(tenant, id) != 0 {
		d, err = d.RetireCurrent(tenant, id, d.Applied(tenant, id), o.holdClock())
	}
	if err == nil {
		err = o.save(m, d, false)
	}
	if err != nil {
		o.mu.Unlock()
		return nil, err
	}
	var groups []*dnsSocketGroup
	for id, g := range o.sockets {
		if o.settings.groups[id].Key == key {
			groups = append(groups, g)
		}
	}
	o.mu.Unlock()
	// No lock is held while joining handlers: their positive original query
	// release must sync through the same owner before native Remove can settle.
	for _, g := range groups {
		if err = g.close(); err != nil {
			return nil, err
		}
	}
	current, err := o.options.Current(ctx, tenant, id)
	if err != nil || current.Config.Enabled || current.Config.Source != p.Config.Source || current.Authority.Revision() != p.Authority.Revision() || current.Networks.Revision() != p.Networks.Revision() || current.Catalog.Revision() != p.Catalog.Revision() {
		return nil, errors.Join(err, ErrLease)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.failed {
		return nil, errors.Join(ErrLease, o.lastErr)
	}
	var op *reconcile.Operation
	scope = o.settings.scopes[key]
	if scope.Switch.Pending != nil {
		op = scope.Switch.Pending
	} else {
		m, op, err = o.settings.PlanSwitch(p.Catalog, p.Networks, p.Authority, key)
		if err == nil {
			err = o.save(m, o.dns, false)
		}
		if err != nil {
			return nil, err
		}
	}
	if op != nil {
		if op.Kind != reconcile.Remove {
			return nil, reconcile.ErrPending
		}
		step := SettingsStep{SettingsActivate, key, 0, *op}
		if op.Phase == reconcile.Prepared {
			m, err = o.settings.Dispatch(p.Catalog, p.Networks, p.Authority, step)
			if err == nil {
				err = o.save(m, o.dns, false)
			}
			if err != nil {
				return nil, err
			}
		}
		m, err = o.settings.Observe(o.proof(step))
		if err == nil {
			err = o.save(m, o.dns, false)
		}
		if err != nil {
			return nil, err
		}
	}
	m, err = o.settings.Publish(p.Catalog, p.Networks, p.Authority, key)
	if err == nil {
		err = o.save(m, o.dns, false)
	}
	if err != nil {
		return nil, err
	}
	for _, v := range o.dns.Views() {
		if v.Tenant != tenant || v.Service != id {
			continue
		}
		d, err = o.dns.Collect(v.ID, o.clock())
		if err != nil {
			// Native Stop/Wait above positively ended all original I/O. An
			// uncertain elapsed clock starts a NEW full original TTL; it is
			// neither immediate expiry nor permission to discard a live pin.
			if rebased, e := o.dns.RebaseHold(v.ID, o.holdClock()); e == nil {
				if e = o.save(o.settings, rebased, false); e != nil {
					return nil, e
				}
			}
			return nil, reconcile.ErrPending
		}
		if err = o.save(o.settings, d, false); err != nil {
			return nil, err
		}
	}
	for slot, s := range o.settings.slots {
		if s.Target.key != key || !s.Retired {
			continue
		}
		m, err = o.settings.CollectSlot(slot)
		if err != nil {
			return nil, err
		}
		if err = o.save(m, o.dns, false); err != nil {
			return nil, err
		}
	}
	for group, g := range o.settings.groups {
		if g.Key != key {
			continue
		}
		if g.State.Pending != nil {
			op = g.State.Pending
		} else {
			m, op, err = o.settings.PlanGroup(group)
			if err == nil {
				err = o.save(m, o.dns, false)
			}
			if err != nil {
				return nil, err
			}
		}
		if op != nil {
			if op.Kind != reconcile.Remove {
				return nil, reconcile.ErrPending
			}
			step := SettingsStep{SettingsPrepare, key, group, *op}
			if op.Phase == reconcile.Prepared {
				m, err = o.settings.Dispatch(p.Catalog, p.Networks, p.Authority, step)
				if err == nil {
					err = o.save(m, o.dns, false)
				}
				if err != nil {
					return nil, err
				}
			}
			if socket := o.sockets[group]; socket != nil {
				socket.mu.Lock()
				closed := socket.closed
				socket.mu.Unlock()
				if !closed {
					return nil, ErrLease
				}
			}
			m, err = o.settings.Observe(o.proof(step))
			if err == nil {
				err = o.save(m, o.dns, false)
			}
			if err != nil {
				return nil, err
			}
		}
		b, known := o.bridges[group]
		if !known {
			return nil, ErrLease
		}
		if err = o.options.Network.ReturnConsumer(b.Lease.Key, b.Lease.Consumer, b.Lease.Pin.Generation); err != nil {
			return nil, err
		}
		m, err = o.settings.DropGroup(group)
		if err != nil {
			return nil, err
		}
		delete(o.bridges, group)
		delete(o.sockets, group)
		if err = o.save(m, o.dns, false); err != nil {
			return nil, err
		}
	}
	local, ok := retainedSource(p.Networks, o.options.Cluster, tenant, p.Config.Network, p.Config.Pool)
	if !ok {
		return nil, ErrLease
	}
	ref, ok := p.Authority.DNSReference(tenant, id, local)
	if !ok {
		return nil, ErrLease
	}
	d, err = o.dns.MarkReferenceClosed(p.Authority, ref.ID)
	if err == nil {
		err = o.save(o.settings, d, false)
	}
	if err != nil {
		return nil, err
	}
	proof, err := o.dns.ReferenceFacts(p.Authority, ref.ID, [32]byte{}, o.clock())
	if err != nil {
		return nil, err
	}
	proof.Settled = true
	proof.Signature = ed25519.Sign(o.options.Key, ReferenceCloseBytes(proof))
	return &proof, nil
}

// Requires the original owner's effects/mu locks. Socket effects can only be
// dispatched after a Settings scope/slot/group is synced to this SAME DB. An
// undecided/unclean/lost journal fails in OpenDNSOwner and never reaches here.
// A Bridge consumer acquired before that first Settings sync is recovered from
// its original Network journal and returned with positive durable read-back.
func (o *DNSOwner) retireUndispatched(p DNSOwnerPolicy) (*ReferenceClose, error) {
	key := "dns/" + dnsKey(p.Config.Tenant, p.Config.ID)
	if p.Config.Enabled || o.dns.scopeInUse(dnsKey(p.Config.Tenant, p.Config.ID)) {
		return nil, ErrLease
	}
	if _, exists := o.settings.scopes[key]; exists {
		return nil, ErrLease
	}
	for _, slot := range o.settings.slots {
		if slot.Target.key == key {
			return nil, ErrLease
		}
	}
	for _, group := range o.settings.groups {
		if group.Key == key {
			return nil, ErrLease
		}
	}
	for _, group := range o.sockets {
		if group.tenant == p.Config.Tenant && group.id == p.Config.ID {
			return nil, ErrLease
		}
	}
	projection, err := buildRetiringDNS(p.Catalog, p.Networks, p.Authority, p.Actor, p.Config)
	if err != nil {
		return nil, err
	}
	ref, exists := referenceForProjection(p.Authority, projection)
	if !exists || ref.Local.Owner != o.settings.owner || ref.DesiredSource != p.Config.Source || ref.DesiredHash != projectionHash(projection) || ref.Serial != p.Config.Serial || p.Bridge == "" || p.BridgeGeneration != ref.Local.NetworkGeneration {
		return nil, ErrLease
	}
	consumer := "dns/" + hex.EncodeToString(ref.ID[:])
	err = o.options.Network.ReturnConsumer(p.Bridge, consumer, p.BridgeGeneration)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return nil, err
	}
	record, err := o.options.Network.View(p.Bridge)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return nil, err
	}
	if _, held := record.Consumers[consumer]; held {
		return nil, reconcile.ErrPending
	}
	d, err := o.dns.MarkReferenceClosed(p.Authority, ref.ID)
	if err == nil {
		err = o.save(o.settings, d, false)
	}
	if err != nil {
		return nil, err
	}
	proof, err := o.dns.ReferenceFacts(p.Authority, ref.ID, [32]byte{}, o.clock())
	if err != nil {
		return nil, err
	}
	proof.Settled = true
	proof.Signature = ed25519.Sign(o.options.Key, ReferenceCloseBytes(proof))
	return &proof, nil
}
