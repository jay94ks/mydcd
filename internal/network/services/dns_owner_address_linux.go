// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

// collectRetiredDNS requires effects and mu. Query handlers retain the SAME
// Settings/DNS pins until their upstream work and actual response write end.
// Thus the existing Collect gates include real completion and original TTL,
// rather than a timeout or an observation that a socket currently looks idle.
func (o *DNSOwner) collectRetiredDNS(tenant, id string) error {
	for _, view := range o.dns.Views() {
		if view.Tenant != tenant || view.Service != id || !view.Retired || view.Queries != 0 {
			continue
		}
		d, err := o.dns.Collect(view.ID, o.clock())
		if err != nil {
			// The core only permits rebasing an uncertain elapsed clock after
			// all original query pins return. A valid unexpired deadline stays.
			if rebased, e := o.dns.RebaseHold(view.ID, o.holdClock()); e == nil {
				if e = o.save(o.settings, rebased, false); e != nil {
					return e
				}
			}
			continue
		}
		if err = o.save(o.settings, d, false); err != nil {
			return err
		}
	}
	key := "dns/" + dnsKey(tenant, id)
	for slot, original := range o.settings.slots {
		if original.Target.key != key || !original.Retired || len(original.Users) != 0 {
			continue
		}
		m, err := o.settings.CollectSlot(slot)
		if errors.Is(err, reconcile.ErrPending) {
			continue
		}
		if err != nil {
			return err
		}
		if err = o.save(m, o.dns, false); err != nil {
			return err
		}
	}
	return nil
}

// Collect retains the active instance/socket and reclaims only retired local
// views/slots whose original completion/TTL gates have already been satisfied.
func (o *DNSOwner) Collect(tenant, id string) error {
	o.effects.Lock()
	defer o.effects.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.failed {
		return errors.Join(ErrLease, o.lastErr)
	}
	return o.collectRetiredDNS(tenant, id)
}

// RetireAddress permanently fences one ORIGINAL allocation while the managed
// server continues serving other apps. A disabled server uses whole-instance
// Retire instead. No count/timeout by itself produces a signed settled fact.
func (o *DNSOwner) RetireAddress(ctx context.Context, tenant, id string, target [32]byte) (*ReferenceClose, error) {
	o.effects.Lock()
	defer o.effects.Unlock()
	p, err := o.options.Current(ctx, tenant, id)
	if err != nil {
		return nil, err
	}
	if !p.Config.Enabled || p.Config.Tenant != tenant || p.Config.ID != id || target == ([32]byte{}) {
		return nil, ErrLease
	}
	local, ok := source(p.Networks, o.options.Cluster, tenant, p.Config.Network, p.Config.Pool)
	if !ok {
		return nil, ErrLease
	}
	ref, ok := p.Authority.DNSReference(tenant, id, local)
	if !ok || ref.Closed != nil {
		return nil, ErrLease
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.failed {
		return nil, errors.Join(ErrLease, o.lastErr)
	}
	key := "dns/" + dnsKey(tenant, id)
	scope, exists := o.settings.scopes[key]
	binding := o.dns.bindings[dnsKey(tenant, id)]
	if !exists || binding.Consumer != ref.ID || binding.Generation != ref.Generation || binding.Lifetime != ref.Lifetime {
		return nil, ErrLease
	}
	d, err := o.dns.SyncReferenceFence(p.Authority, ref.ID, target)
	if err == nil {
		err = o.save(o.settings, d, false)
	}
	if err != nil {
		return nil, err
	}
	if err = o.collectRetiredDNS(tenant, id); err != nil {
		return nil, err
	}
	status := o.settings.Status(key)
	if scope.Switch.Pending != nil || status.Desired != p.Config.Source || status.Applied != p.Config.Source || status.Observed != p.Config.Source || o.dns.Applied(tenant, id) != p.Config.Source {
		return nil, reconcile.ErrPending
	}
	for _, group := range o.settings.groups {
		if group.Key == key && group.State.Pending != nil {
			return nil, reconcile.ErrPending
		}
	}
	proof, err := o.dns.ReferenceFacts(p.Authority, ref.ID, target, o.clock())
	if err != nil {
		// Current/retired records, outstanding query/write pins and original
		// TTL holds all remain in the SAME journal until positive completion.
		return nil, reconcile.ErrPending
	}
	proof.Settled = true
	proof.Signature = ed25519.Sign(o.options.Key, ReferenceCloseBytes(proof))
	return &proof, nil
}
