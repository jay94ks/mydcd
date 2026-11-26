// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"

	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// admitAppVolumeConsumers is a read-only preflight against the same current
// volume core used by real Binding reservation. It neither invents a future
// Task generation nor reserves/releases a consumer. Actual acceptance and
// Binding still recheck current state; this is not a permit to start.
func admitAppVolumeConsumers(plan deployment.Blueprint, requester [32]byte, current map[string]volumes.State, apps Apps) error {
	scope := plan.Scope()
	original := standaloneOriginalVolumeConsumers(apps, scope)
	for _, step := range plan.Steps() {
		if step.Kind != "task" {
			continue
		}
		id, err := deployment.ResourceIDFromKey("task", scope.Tenant, scope.App, step.Key)
		if err != nil {
			return err
		}
		needs, err := plan.InputMetadata(id, requester)
		if err != nil {
			return err
		}
		for _, need := range needs.Volumes {
			volume, exists := current[need.Key]
			if !exists {
				continue
			}
			for _, consumer := range volume.ForeignConsumerConflicts(AppConsumer(step.Key), need.Writable) {
				if slices.Contains(original[need.Key], consumer) {
					// Existing same-scope replacement may retire its exact
					// original Task via the Inventory DAG. Only real closure
					// and Acquire can admit its replacement afterwards.
					continue
				}
				// Only the caller's own requested key is returned. Foreign
				// consumer identities and operational state are not disclosed.
				return &deployment.InputError{Code: "VOLUME_WRITER_CONFLICT", Path: need.Key}
			}
		}
	}
	return nil
}

// This exception is derived only from checked original claims and retained
// Bindings of the same immutable standalone scope, never from plan input.
func standaloneOriginalVolumeConsumers(apps Apps, scope deployment.AppScope) map[string][]volumes.Consumer {
	out := map[string][]volumes.Consumer{}
	entry, exists := apps.entries[appKey(scope.Tenant, scope.App)]
	originalScope := entry.Inventory.Scope()
	// Inventory owns resource coordinates; the new requester need not be the
	// original registering user (for example another current tenant manager).
	if !exists || entry.Standalone == nil || originalScope.Cluster != scope.Cluster || originalScope.Tenant != scope.Tenant || originalScope.App != scope.App || originalScope.Deployment != scope.Deployment {
		return out
	}
	for _, source := range apps.sources {
		claim, found := bindingClaim(entry, source.Task)
		binding, bound := apps.binding(source.Digest)
		if !found || !bound || claim.Step.Kind != "task" {
			continue
		}
		needs := binding.Needs()
		if needs.Use.Tenant != scope.Tenant || needs.Use.App != scope.App || needs.Use.Deployment != scope.Deployment || needs.Consumer != AppConsumer(source.Task.Key) || needs.Generation != source.Task.Generation {
			continue
		}
		for _, pin := range binding.Pins() {
			out[pin.Key] = append(out[pin.Key], pin.Consumer)
		}
	}
	return out
}
