// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

// heldReferenceRecord only reads an original durable pin. It cannot borrow,
// resize capacity, settle Unknown or authorize a different source instance.
func heldReferenceRecord(record reconcile.Record, consumer string, source deployment.ObjectRef, spec [32]byte) (bool, error) {
	pin, held := record.Consumers[consumer]
	if !held {
		return false, nil
	}
	if consumer == "" || source.Generation == 0 || source.Revision == 0 || pin.Token == 0 || pin.Generation != source.Generation {
		return false, reconcile.ErrLease
	}
	if record.State.Stopped || record.State.Pending != nil || record.State.Desired.Revision != source.Revision || !record.State.Applied.Present || record.State.Applied.Generation != source.Generation || record.State.Desired.Resource != record.State.Applied || committedSpecDigest(record.State.Applied.Spec) != spec {
		return false, reconcile.ErrPending
	}
	return true, nil
}

// This same predicate is consumed by real read-back below and model tests.
// Complete Bridge/TUN pins are required; a partially prepared reference must
// acquire its missing dependency through the ordinary current permission.
func heldAppNetworkReference(cluster [32]byte, ref deployment.NetworkReference, consumer string, objects map[string]state.Object, bridge reconcile.Record, tunnel *reconcile.Record) (bool, error) {
	expected, err := deployment.ReferenceBridge(cluster, ref, objects)
	if err != nil {
		return false, err
	}
	raw, _ := json.Marshal(expected)
	held, err := heldReferenceRecord(bridge, consumer, ref.Source, sha256.Sum256(raw))
	if err != nil {
		return false, err
	}
	if source, exists := ref.LocalTunnel(); exists {
		if tunnel == nil {
			return false, nil
		}
		var digest [32]byte
		for _, row := range ref.ManagedSources {
			if row.Source == source {
				digest = row.Spec
				break
			}
		}
		tunHeld, err := heldReferenceRecord(*tunnel, consumer, source, digest)
		if err != nil {
			return false, err
		}
		held = held && tunHeld
	}
	return held, nil
}

func (r *Runtime) inspectAppNetworkReference(ctx context.Context, ref deployment.NetworkReference, consumer string, objects map[string]state.Object) (string, bool, error) {
	bridge, err := r.network.View(ref.Source.Key)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return "", false, err
	}
	var tunnel *reconcile.Record
	if source, exists := ref.LocalTunnel(); exists && r.tunnel != nil {
		row, err := r.tunnel.manager.View(source.Key)
		if err != nil && !errors.Is(err, storage.ErrMissing) {
			return "", false, err
		}
		tunnel = &row
	}
	held, err := heldAppNetworkReference(r.controlPolicy.Cluster, ref, consumer, objects, bridge, tunnel)
	if err != nil || !held {
		return "", false, err
	}
	actual, err := r.network.InspectConsumer(ctx, ref.Source.Key, consumer, ref.Source.Generation)
	if err != nil {
		return "", false, err
	}
	if source, exists := ref.LocalTunnel(); exists {
		if _, err := r.tunnel.manager.Inspect(ctx, source.Key); err != nil {
			return "", false, err
		}
		if err := r.tunnel.Ready(source.Key); err != nil {
			return "", false, err
		}
	}
	return "borrow/" + actual.NetworkID + "/" + consumer, true, nil
}
