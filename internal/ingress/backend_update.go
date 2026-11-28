// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
)

// The listener stays owned by its original committed source. This journal
// records a derived backend view before network Acquire/Return and preserves
// the old Balancer until its exact requests settle. It is not a new rollout.
type backendUpdate struct {
	Target             Spec
	Released, Acquired []string `json:",omitempty"`
}

func backendToken(b BackendSpec) string {
	raw, _ := json.Marshal(backendSource(b))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func backendSource(b BackendSpec) BackendSpec {
	b.Revision, b.Draining, b.Suspended = 0, false, false
	b.Node, b.Version = "", ""
	b.Labels = nil
	return b
}

func sameBackend(a, b BackendSpec) bool {
	return marshal(backendSource(a)) == marshal(backendSource(b))
}

// backendByID finds one exact generation of a backend ID: a same-node surge
// lists an older draining generation beside its successor under one ID.
func backendByID(s Spec, id string, generation uint64) (BackendSpec, bool) {
	for _, service := range s.Services {
		for _, b := range service.Backends {
			if b.ID == id && b.Generation == generation {
				return b, true
			}
		}
	}
	return BackendSpec{}, false
}

func backendDraining(r instanceRecord, b BackendSpec) bool {
	if r.Spec.Lifecycle.Drain || b.Draining {
		return true
	}
	if r.Update != nil {
		wanted, exists := backendByID(r.Update.Target, b.ID, b.Generation)
		return !exists || !sameBackend(b, wanted) || wanted.Draining
	}
	return false
}

func membershipValue(s Spec) string { s.BindingRevision = 0; return marshal(s) }

func validateBackendUpdate(r instanceRecord) error {
	u := r.Update
	if u == nil {
		return nil
	}
	if !r.Spec.DynamicBackends || r.Gone || !u.Target.DynamicBackends || !r.Spec.Lifecycle.Drain && u.Target.BindingRevision < r.Spec.BindingRevision || nativeSpec(u.Target) != nativeSpec(r.Spec) {
		return ErrRoute
	}
	if _, err := DecodeSpec(marshal(u.Target)); err != nil {
		return err
	}
	for _, pair := range []struct {
		tokens []string
		spec   Spec
	}{{u.Released, r.Spec}, {u.Acquired, u.Target}} {
		seen := map[string]bool{}
		for _, token := range pair.tokens {
			found := false
			for _, service := range pair.spec.Services {
				for _, b := range service.Backends {
					found = found || backendToken(b) == token
				}
			}
			if !found || seen[token] {
				return ErrRoute
			}
			seen[token] = true
		}
	}
	return nil
}

func backendConsumer(key string, generation uint64, s Spec, b BackendSpec) string {
	if !s.DynamicBackends {
		return consumer(key, generation, b.ID)
	}
	// An old Task generation's network return cannot release its replacement.
	return consumer(key, generation, b.ID+"/"+strconv.FormatUint(b.Generation, 10))
}

func (m *Manager) reconcileBackends(ctx context.Context, i *instance, revision, generation uint64, desired Spec) error {
	i.mu.Lock()
	// A completed request may have retained its exact return after a local DB
	// write failed. Settle it before checking whether a drained backend is busy;
	// otherwise a pending membership update would bypass Reconcile's retry.
	if err := i.retryReturns(); err != nil {
		i.mu.Unlock()
		return err
	}
	for _, journal := range i.record.Balances {
		for _, current := range journal.Backends {
			old, known := backendByID(i.record.Spec, current.Spec.ID, current.Spec.Generation)
			wanted, exists := backendByID(desired, current.Spec.ID, current.Spec.Generation)
			if known && exists && current.Spec.Draining && sameBackend(old, wanted) && !wanted.Draining {
				i.mu.Unlock()
				return ErrRoute // a drained generation cannot become a serving generation again
			}
		}
	}
	if desired.BindingRevision < i.record.Spec.BindingRevision || desired.BindingRevision == i.record.Spec.BindingRevision && membershipValue(desired) != membershipValue(i.record.Spec) {
		i.mu.Unlock()
		return ErrRoute
	}
	if i.record.Update == nil && membershipValue(desired) == membershipValue(i.record.Spec) {
		i.mu.Unlock()
		return nil
	}
	r := i.copyRecord()
	if r.Update == nil {
		r.Update = &backendUpdate{Target: desired}
	} else if membershipValue(r.Update.Target) != membershipValue(desired) {
		if desired.BindingRevision <= r.Update.Target.BindingRevision {
			i.mu.Unlock()
			return ErrRoute
		}
		// Return any superseded added source, including a lost Acquire reply,
		// before rebasing this derived view. The original pin ID is immutable;
		// no new request or observation of absence stands in for Return.
		i.mu.Unlock()
		for _, service := range r.Update.Target.Services {
			for _, added := range service.Backends {
				old, held := backendByID(r.Spec, added.ID, added.Generation)
				if held && sameBackend(old, added) {
					continue
				}
				wanted, retained := backendByID(desired, added.ID, added.Generation)
				if retained && sameBackend(wanted, added) {
					continue
				}
				if err := m.deps.Release(ctx, added, backendConsumer(i.key, generation, r.Update.Target, added)); err != nil {
					return err
				}
			}
		}
		i.mu.Lock()
		r = i.copyRecord()
		acquired := r.Update.Acquired[:0]
		for _, token := range r.Update.Acquired {
			for _, service := range desired.Services {
				for _, b := range service.Backends {
					if backendToken(b) == token {
						acquired = append(acquired, token)
					}
				}
			}
		}
		r.Update.Acquired, r.Update.Target = acquired, desired
	}
	for name, journal := range r.Balances {
		balancer, err := RestoreBalancer(journal)
		if err != nil {
			i.mu.Unlock()
			return err
		}
		for _, record := range journal.Backends {
			b, _ := backendByID(r.Spec, record.Spec.ID, record.Spec.Generation)
			v := record.Spec
			v.Draining = backendDraining(r, b)
			if wanted, exists := backendByID(r.Update.Target, b.ID, b.Generation); exists && wanted.Suspended {
				v.Healthy = false
			}
			if err := balancer.Update(v); err != nil {
				i.mu.Unlock()
				return err
			}
		}
		r.Balances[name] = balancer.Checkpoint()
	}
	if err := i.save(r); err != nil {
		i.mu.Unlock()
		return err
	}
	// Only a backend leaving the view waits for its requests here; one that
	// stays listed as draining (an older surge generation) settles later
	// while its successor already serves.
	for _, journal := range r.Balances {
		for _, record := range journal.Backends {
			old, _ := backendByID(r.Spec, record.Spec.ID, record.Spec.Generation)
			wanted, retained := backendByID(r.Update.Target, old.ID, old.Generation)
			if record.Spec.Draining && len(record.Pins.Active) != 0 && !(retained && sameBackend(old, wanted)) {
				i.mu.Unlock()
				return nil
			}
		}
	}
	i.mu.Unlock()
	for _, service := range r.Spec.Services {
		for _, old := range service.Backends {
			wanted, exists := backendByID(r.Update.Target, old.ID, old.Generation)
			if exists && sameBackend(old, wanted) {
				continue
			}
			token := backendToken(old)
			if slices.Contains(r.Update.Released, token) {
				continue
			}
			if err := m.deps.Release(ctx, old, backendConsumer(i.key, generation, r.Spec, old)); err != nil {
				return err
			}
			i.mu.Lock()
			r = i.copyRecord()
			r.Update.Released = append(r.Update.Released, token)
			err := i.save(r)
			i.mu.Unlock()
			if err != nil {
				return err
			}
		}
	}
	for _, service := range r.Update.Target.Services {
		for _, wanted := range service.Backends {
			old, exists := backendByID(r.Spec, wanted.ID, wanted.Generation)
			if exists && sameBackend(old, wanted) {
				continue
			}
			token := backendToken(wanted)
			if slices.Contains(r.Update.Acquired, token) {
				continue
			}
			if err := m.deps.Acquire(ctx, wanted, backendConsumer(i.key, generation, r.Update.Target, wanted)); err != nil {
				return err
			}
			i.mu.Lock()
			r = i.copyRecord()
			r.Update.Acquired = append(r.Update.Acquired, token)
			err := i.save(r)
			i.mu.Unlock()
			if err != nil {
				return err
			}
		}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	r = i.copyRecord()
	for name, journal := range r.Balances {
		balancer, err := RestoreBalancer(journal)
		if err != nil {
			return err
		}
		for _, record := range journal.Backends {
			old, _ := backendByID(r.Spec, record.Spec.ID, record.Spec.Generation)
			wanted, exists := backendByID(r.Update.Target, old.ID, old.Generation)
			if !exists || !sameBackend(old, wanted) {
				if err := balancer.Remove(old.ID, old.Generation); err != nil {
					return err
				}
			}
		}
		for _, service := range r.Update.Target.Services {
			if service.ID != name {
				continue
			}
			for _, wanted := range service.Backends {
				v := Backend{ID: wanted.ID, Generation: wanted.Generation, Weight: wanted.Weight, Capacity: wanted.Capacity, Draining: wanted.Draining}
				if prior, held := balancer.entry(wanted.ID, wanted.Generation); held {
					v = prior.spec
					v.Draining = wanted.Draining
					if wanted.Suspended {
						v.Healthy = false
					}
				}
				if err := balancer.Update(v); err != nil {
					return err
				}
			}
		}
		r.Balances[name] = balancer.Checkpoint()
	}
	r.Spec, r.Revision, r.Update = r.Update.Target, revision, nil
	return i.save(r)
}

// SpecDigest binds serving semantics. The read ordinal orders native updates
// but unrelated consensus progress does not change this permission digest.
func SpecDigest(s Spec) [32]byte {
	s.BindingRevision = 0
	s.Lifecycle.Proof = nil
	s.Lifecycle.Drain = false
	s.Lifecycle.Nonce = [16]byte{}
	raw, _ := json.Marshal(s)
	return sha256.Sum256(raw)
}

func (m *Manager) NeedsBackendUpdate(key string, target Spec) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.instances[key]
	if m.closed || i == nil {
		return true
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.record.Update != nil || membershipValue(i.record.Spec) != membershipValue(target)
}

func (m *Manager) returnPendingBackends(ctx context.Context, i *instance) error {
	i.mu.Lock()
	r := i.copyRecord()
	i.mu.Unlock()
	if r.Update == nil {
		return nil
	}
	for _, service := range r.Update.Target.Services {
		for _, backend := range service.Backends {
			if err := m.deps.Release(ctx, backend, backendConsumer(i.key, r.Generation, r.Update.Target, backend)); err != nil {
				return err
			}
		}
	}
	return nil
}
