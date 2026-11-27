// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/moby/moby/client"
)

func nodeJournalActivity(keys []string, read func(string) (reconcile.Record, error), retainedData bool) (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	for _, key := range keys {
		record, err := read(key)
		if err != nil {
			return activity, err
		}
		if record.State.Pending != nil || !retainedData && (record.State.Applied.Present || record.State.Desired.Present) {
			activity.Resources++
		}
		activity.Leases += uint32(len(record.Consumers))
	}
	return activity, nil
}

// nodeLocalActivity consumes the real owners' current journals/IO. It does not
// mutate Desired, rewrite IDs or delete cached/data-only Volume materialization.
// The caller serializes the module pass and holds the existing input/approval/
// provider lifetime barriers while taking and publishing a zero observation.
func (r *Runtime) nodeLocalActivity(ctx context.Context) (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	if !r.historicalOwner {
		for _, owner := range r.nativeOwners {
			next, err := owner.retainedOwnerActivity(ctx)
			if err != nil {
				return activity, err
			}
			activity, err = activity.Add(next)
			if err != nil {
				return activity, err
			}
		}
	}
	add := func(next lifecycle.Activity, err error) error {
		if err != nil {
			return err
		}
		var mergeErr error
		activity, mergeErr = activity.Add(next)
		return mergeErr
	}
	if r.network != nil {
		if err := add(nodeJournalActivity(r.network.Keys(), r.network.View, false)); err != nil {
			return activity, err
		}
	}
	if r.workload != nil {
		if err := add(nodeJournalActivity(r.workload.Keys(), r.workload.View, false)); err != nil {
			return activity, err
		}
	}
	if r.nativeVolumes != nil {
		if err := add(nodeJournalActivity(r.nativeVolumes.Keys(), r.nativeVolumes.View, true)); err != nil {
			return activity, err
		}
	}
	if r.reports != nil {
		rows, err := r.reports.ScanBounded("volume/file/", 256, 32<<20)
		if err != nil {
			return activity, err
		}
		for _, raw := range rows {
			row, err := schema.Decode[volumeFileOwner](raw)
			if err != nil || row.Schema != 1 {
				return activity, errors.New("invalid original Volume file journal")
			}
			switch row.Phase {
			case "intent", "pinned", "applying", "completed":
				activity.Resources++
			case "returned":
			default:
				return activity, errors.New("unknown original Volume file phase")
			}
		}
	}
	if r.volumeRestores != nil {
		if err := add(nodeJournalActivity(r.volumeRestores.Keys(), r.volumeRestores.Read, true)); err != nil {
			return activity, err
		}
	}
	if r.vaultApprovals != nil {
		if err := add(nodeJournalActivity(r.vaultApprovals.Keys(), r.vaultApprovals.Read, true)); err != nil {
			return activity, err
		}
	}
	if r.backupArtifacts != nil {
		if !r.backupArtifacts.mu.TryLock() {
			activity.Leases++
		} else {
			if r.backupArtifacts.closed {
				r.backupArtifacts.mu.Unlock()
				return activity, errors.New("backup artifact owner is closed")
			}
			err := add(nodeJournalActivity(r.backupArtifacts.journal.Keys(), r.backupArtifacts.journal.Read, true))
			r.backupArtifacts.mu.Unlock()
			if err != nil {
				return activity, err
			}
		}
	}
	if r.activations != nil {
		if err := add(r.activations.Activity()); err != nil {
			return activity, err
		}
	}
	if r.projections != nil {
		if err := add(r.projections.Activity()); err != nil {
			return activity, err
		}
	}
	if r.checkerSources != nil {
		if err := add(r.checkerSources.Activity()); err != nil {
			return activity, err
		}
	}
	if r.checkerCompiler != nil {
		if err := add(r.checkerCompiler.Activity()); err != nil {
			return activity, err
		}
	}
	if owner := r.dnsOwner(); owner != nil {
		if err := add(owner.Activity()); err != nil {
			return activity, err
		}
	}
	if r.ingress != nil {
		if err := add(r.ingress.Activity()); err != nil {
			return activity, err
		}
	}
	if r.tunnel != nil {
		if err := add(nodeJournalActivity(r.tunnel.manager.Keys(), r.tunnel.manager.View, false)); err != nil {
			return activity, err
		}
		if err := add(r.tunnel.activity()); err != nil {
			return activity, err
		}
	}
	if active := r.deliverySourceActive.Load(); active < 0 {
		return activity, errors.New("invalid active Git source count")
	} else if active > 0 {
		activity.CDJobs++
	}
	if !r.registryMu.TryLock() {
		activity.Resources++
	} else {
		if r.registryFailed.Load() {
			r.registryMu.Unlock()
			return activity, errors.New("registry owner requires recovery")
		}
		activity.Resources += uint32(len(r.registrySessions))
		for _, row := range r.registryRecords {
			if row.Run != nil && (row.Phase != "closed" || !row.IOClosed || !row.PinReturned) {
				activity.Writers++
			}
		}
		r.registryMu.Unlock()
	}
	// These read-only SDK inventories also catch owner-labelled native objects
	// not represented by a terminal local journal. Error is unknown, not empty.
	if r.docker != nil {
		filters := client.Filters{}.Add("label", "org.sfc.owner="+r.docker.Owner)
		containers, err := r.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
		if err != nil {
			return activity, err
		}
		networks, err := r.docker.API.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
		if err != nil {
			return activity, err
		}
		activity.Resources += uint32(len(containers.Items) + len(networks.Items))
	}
	return activity, nil
}

func (t *tunnelRuntime) activity() (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return activity, errTunnelPending
	}
	instances := make([]*tunnelInstance, 0, len(t.instances)+len(t.routes))
	for _, instance := range t.instances {
		instances = append(instances, instance)
	}
	for _, instance := range t.routes {
		instances = append(instances, instance)
	}
	t.mu.Unlock()
	for _, instance := range instances {
		if !instance.mu.TryLock() {
			activity.Flows++
			continue
		}
		if instance.plane != nil || instance.serving.Load() != nil || instance.routeReading.Load() {
			activity.Flows++
		}
		instance.mu.Unlock()
	}
	return activity, nil
}

func (r *Runtime) retainedOwnerActivity(ctx context.Context) (lifecycle.Activity, error) {
	if !r.inputLife.TryLock() {
		return lifecycle.Activity{Leases: 1}, nil
	}
	defer r.inputLife.Unlock()
	if !r.vaultApprovalLife.TryLock() {
		return lifecycle.Activity{Leases: 1}, nil
	}
	defer r.vaultApprovalLife.Unlock()
	if !r.life.TryLock() {
		return lifecycle.Activity{Leases: 1}, nil
	}
	defer r.life.Unlock()
	if r.closed {
		return lifecycle.Activity{}, errors.New("retained owner is closed")
	}
	return r.nodeLocalActivity(ctx)
}
