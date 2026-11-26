// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"sort"
	"time"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

// ConsumerBudget is current committed node/tenant policy, separate from every
// original durable pin. Both Bridge and TUN use the same installed owner.
type ConsumerBudget struct {
	Scope                                reconcile.ConsumerScope
	NodeMaxConsumers, TenantMaxConsumers int
}

func (b ConsumerBudget) Valid() bool {
	return b.Scope.Valid() && b.NodeMaxConsumers > 0 && b.NodeMaxConsumers <= 65536 && b.TenantMaxConsumers > 0 && b.TenantMaxConsumers <= 65536
}

func (m *Manager) currentBudget(ctx context.Context, kind, key string, d reconcile.Desired) (ConsumerBudget, error) {
	var owner string
	if kind == "bridge" {
		s, err := DecodeBridge(d.Resource.Spec)
		if err != nil || s.Lifecycle.Drain {
			return ConsumerBudget{}, ErrPolicy
		}
		owner = s.Owner
	} else if kind == "tunnel" {
		s, err := DecodeTunnel(d.Resource.Spec)
		if err != nil || s.Lifecycle.Drain {
			return ConsumerBudget{}, ErrPolicy
		}
		owner = s.Owner
	} else {
		return ConsumerBudget{}, ErrPolicy
	}
	budget, err := m.admit(ctx, key, d)
	if err != nil {
		return ConsumerBudget{}, err
	}
	if !budget.Valid() || budget.Scope.Owner != owner || m.driver.Engine != nil && owner != m.driver.Engine.Owner {
		return ConsumerBudget{}, ErrPolicy
	}
	return budget, nil
}

type consumerCount struct {
	scope reconcile.ConsumerScope
	count int
}

// The caller holds admitMu across census and the one new pin transaction.
// All enrolled fresh borrows use that lock. Concurrent Return only decreases
// counts, so a read can be conservative but cannot admit against a lower count.
func (m *Manager) localConsumerCensus(ctx context.Context) ([]consumerCount, error) {
	kinds := make([]string, 0, len(m.journals))
	for kind := range m.journals {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	var counts []consumerCount
	for _, kind := range kinds {
		j := m.journals[kind]
		for _, key := range j.Keys() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			r, err := j.Read(key)
			if err != nil {
				return nil, err
			}
			if len(r.Consumers) == 0 {
				continue
			}
			if r.Scope == (reconcile.ConsumerScope{}) {
				// Only a CURRENT permission for this exact already-installed
				// managed source can bind old metadata. A label/key is not proof.
				budget, err := m.currentBudget(ctx, kind, key, r.State.Desired)
				if err != nil {
					return nil, err
				}
				if err := j.BindConsumerScope(key, r.State.Desired, budget.Scope); err != nil {
					return nil, err
				}
				r.Scope = budget.Scope
			}
			counts = append(counts, consumerCount{r.Scope, len(r.Consumers)})
		}
	}
	return counts, nil
}

func admitConsumerCounts(counts []consumerCount, b ConsumerBudget) error {
	if !b.Valid() {
		return ErrPolicy
	}
	node, tenant := 0, 0
	for _, c := range counts {
		if !c.scope.Valid() || c.count < 0 || c.scope.Node != b.Scope.Node || c.scope.Owner != b.Scope.Owner {
			return ErrPolicy
		}
		if c.count >= b.NodeMaxConsumers-node {
			return reconcile.ErrLease
		}
		node += c.count
		if c.scope.Tenant == b.Scope.Tenant {
			if c.count >= b.TenantMaxConsumers-tenant {
				return reconcile.ErrLease
			}
			tenant += c.count
		}
	}
	return nil
}

func (m *Manager) borrowFrom(ctx context.Context, j *reconcile.Journal, kind, key, consumer string, generation uint64) (reconcile.Lease, error) {
	if ctx == nil {
		return reconcile.Lease{}, reconcile.ErrLease
	}
	if m.admit == nil {
		return j.Borrow(key, consumer, generation)
	}
	if err := ctx.Err(); err != nil {
		return reconcile.Lease{}, err
	}
	r, err := j.Read(key)
	if err != nil {
		return reconcile.Lease{}, err
	}
	// Original recovery does not queue behind any fresh quorum call/census.
	if pin, exists := r.Consumers[consumer]; exists {
		if pin.Generation != generation {
			return reconcile.Lease{}, reconcile.ErrLease
		}
		return pin, nil
	}
	unlock := m.lockConsumerAdmission()
	defer unlock()
	// Scope recovery is finite work, not one full RPC budget per old row.
	// Successfully bound original rows survive this batch's cancellation.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return reconcile.Lease{}, err
	}
	r, err = j.Read(key)
	if err != nil {
		return reconcile.Lease{}, err
	}
	if pin, exists := r.Consumers[consumer]; exists {
		if pin.Generation != generation {
			return reconcile.Lease{}, reconcile.ErrLease
		}
		return pin, nil
	}
	if !r.State.Desired.Resource.Present || r.State.Desired.Resource.Generation != generation || r.State.Pending != nil || r.State.Stopped || r.State.Applied != r.State.Desired.Resource {
		return reconcile.Lease{}, reconcile.ErrLease
	}
	counts, err := m.consumerCensus(ctx)
	if err != nil {
		return reconcile.Lease{}, err
	}
	// Take the target permission last, after any original-scope binding calls.
	budget, err := m.currentBudget(ctx, kind, key, r.State.Desired)
	if err != nil {
		return reconcile.Lease{}, err
	}
	if err := ctx.Err(); err != nil {
		return reconcile.Lease{}, err
	}
	if err := admitConsumerCounts(counts, budget); err != nil {
		return reconcile.Lease{}, err
	}
	return j.BorrowScoped(key, consumer, generation, r.State.Desired.Revision, min(budget.NodeMaxConsumers, budget.TenantMaxConsumers), budget.Scope)
}

// Enrol once during startup, before module work. Neither journal is replaced,
// merged, copied or owned by a second store; Close remains with its manager.
func (m *Manager) enrolTunnel(j *reconcile.Journal, owner string) error {
	m.admitMu.Lock()
	defer m.admitMu.Unlock()
	if m.admit == nil || j == nil || m.journals["tunnel"] != nil || m.driver.Engine != nil && m.driver.Engine.Owner != owner {
		return ErrPolicy
	}
	m.journals["tunnel"] = j
	return nil
}
