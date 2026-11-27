// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
)

// Called inside the Bridge driver's FIRST create, so it must not reenter
// Manager/View or its journal lock. Consumer permission already has this same
// nonreentrant quorum/committed-source/protection boundary.
func (r *Runtime) networkBridgeProtection(ctx context.Context, key string, target reconcile.Resource) error {
	if r.Engine() == nil || r.reports == nil || !target.Present {
		return network.ErrPolicy
	}
	// Isolation reconciliation reads original Manager entries while holding
	// this mutex. Never wait for it while the driver holds such an entry.
	if !r.isolationMu.TryLock() {
		return reconcile.ErrPending
	}
	defer r.isolationMu.Unlock()
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	object := view.State.Object(key)
	bridge, err := network.DecodeBridge(object.Value)
	bridge.Lifecycle = schema.Lifecycle{}
	raw, marshalErr := json.Marshal(bridge)
	if err != nil || marshalErr != nil || !object.Present || object.Generation != target.Generation || sha256.Sum256(raw) != sha256.Sum256([]byte(target.Spec)) || bridge.GatewayMode != network.ManagedGatewayMode {
		return errors.New("managed gateway create differs from committed original Bridge")
	}
	_, current, projection, err := r.networkConsumerPermit(ctx, key, reconcile.Desired{Revision: object.Revision, Resource: target})
	if err != nil {
		return err
	}
	source, err := r.isolationSharedHash(current, projection)
	if err != nil {
		return err
	}
	if r.isolationFailed {
		return errors.New("managed gateway protection store requires reopening")
	}
	boot, err := services.NativeBootID()
	if err != nil {
		return err
	}
	stored, err := r.reports.GetBounded(isolationRecordKey(boot), 100<<20)
	if err != nil {
		return err
	}
	record, err := decodeIsolationRecord(stored, r.owner, boot)
	if err != nil || record.Source != source || record.State.Pending != nil || !record.State.Applied.Present || record.State.Applied != record.State.Desired.Resource {
		return errors.Join(err, reconcile.ErrPending)
	}
	spec, err := network.DecodeIsolation(record.State.Applied.Spec)
	if err != nil || !network.IsolationCoversBridge(spec, key, target) {
		return errors.Join(err, network.ErrPolicy)
	}
	present, err := network.InspectIsolation(spec)
	if err != nil || !present {
		return errors.Join(err, network.ErrKernelOwnership)
	}
	return ctx.Err()
}
