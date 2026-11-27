// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"strings"
)

func (r *Runtime) reconcileIngress(v cluster.View, g desired.Graph) error {
	if err := r.reconcileCertificates(r.ctx, v); err != nil {
		return err
	}
	if r.ingress != nil {
		if err := r.applyIngressBlocks(r.ctx, v); err != nil {
			return err
		}
	}
	keys := map[string]bool{}
	for key, s := range g.Ingress {
		if s.Owner == r.owner && !s.Lifecycle.Released() {
			keys[key] = true
		}
	}
	if r.ingress == nil {
		if len(keys) != 0 {
			return errors.New("committed ingress requires enabled module")
		}
		return nil
	}
	for _, key := range r.ingress.Keys() {
		if !clusterAppIngressKey(key) {
			keys[key] = true
		}
	}
	var result error
	for _, key := range desired.Sorted(keys) {
		o := v.State.Object(key)
		s, known := g.Ingress[key]
		if o.Revision == 0 || known && s.Owner != r.owner {
			result = errors.Join(result, errors.New("unbound ingress journal"))
			continue
		}
		var target *ingress.Spec
		if known {
			target = &s
		}
		result = errors.Join(result, r.ingress.Reconcile(r.ctx, key, o.Revision, o.Generation, target))
	}
	return result
}

type ingressDependencies struct{ r *Runtime }

func (d ingressDependencies) dependency(ctx context.Context, b ingress.BackendSpec) (key string, generation uint64, local bool, err error) {
	return d.managedDependency(ctx, b)
}
func (d ingressDependencies) Acquire(ctx context.Context, b ingress.BackendSpec, consumer string) error {
	if !strings.HasPrefix(consumer, "ingress/") {
		return reconcile.ErrLease
	}
	key, gen, local, err := d.dependency(ctx, b)
	if err != nil {
		return fmt.Errorf("ingress backend %s network binding: %w", b.Task, err)
	}
	owner, err := d.dependencyOwner(ctx, key, gen)
	if err != nil {
		return err
	}
	if local {
		if owner.network == nil {
			return reconcile.ErrLease
		}
		_, err = owner.network.Acquire(ctx, key, consumer, gen)
		if err != nil {
			return fmt.Errorf("ingress backend %s Bridge %s generation %d consumer: %w", b.Task, key, gen, err)
		}
		return nil
	}
	if owner.tunnel == nil {
		return reconcile.ErrLease
	}
	if err = owner.tunnel.Ready(key); err != nil {
		return err
	}
	_, err = owner.tunnel.manager.BorrowDependency(ctx, key, consumer, gen)
	return err
}
func (d ingressDependencies) Release(ctx context.Context, b ingress.BackendSpec, consumer string) error {
	if !strings.HasPrefix(consumer, "ingress/") {
		return reconcile.ErrLease
	}
	// A backend's Task may already have closed or changed generation. Return
	// the exact original native journal pin, never resolve its replacement's
	// current Task/network and accidentally release that newer dependency.
	for _, owner := range d.r.physicalOwners() {
		if owner.network != nil {
			for _, key := range owner.network.Keys() {
				if err := ctx.Err(); err != nil {
					return err
				}
				record, err := owner.network.View(key)
				if err != nil {
					return err
				}
				if pin, held := record.Consumers[consumer]; held {
					if err := owner.network.Return(network.BridgeLease{Key: key, Consumer: consumer, Pin: pin}); err != nil {
						return err
					}
				}
			}
		}
		if owner.tunnel != nil {
			for _, key := range owner.tunnel.manager.Keys() {
				if err := ctx.Err(); err != nil {
					return err
				}
				record, err := owner.tunnel.manager.View(key)
				if err != nil {
					return err
				}
				if pin, held := record.Consumers[consumer]; held {
					if err := owner.tunnel.manager.Return(network.TunnelLease{Key: key, Consumer: consumer, Pin: pin}); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
