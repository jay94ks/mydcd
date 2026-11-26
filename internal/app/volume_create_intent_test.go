// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestCreationIntentCannotResetMissingOrClosedOriginalApply(t *testing.T) {
	spec := volumes.NativeSpec{Schema: 1, Scope: volumes.Scope{Cluster: [32]byte{1}, Tenant: "tenant", App: "app", ID: "data", Generation: 1}, Node: "node-a", NodeKey: [32]byte{2}, Materialization: "create", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
	raw, _ := json.Marshal(spec)
	target := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
	base, err := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: 1, Resource: target})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		state    reconcile.State
		prepared bool
		valid    bool
	}{
		{"durable-before-dispatch", base, false, true},
		{"first-authorized-dispatch", base, true, true},
		{"missing-original-intent", reconcile.State{}, true, false},
		{"unknown-original", reconcile.State{Desired: base.Desired, GenerationFloor: 1, LastID: 1, Pending: &reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.RecoveryRequired, Target: target}}, true, true},
		{"unknown-before-authorized", reconcile.State{Desired: base.Desired, GenerationFloor: 1, LastID: 1, Pending: &reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.RecoveryRequired, Target: target}}, false, false},
		{"original-definitely-failed", reconcile.State{Desired: base.Desired, GenerationFloor: 1, LastID: 1}, true, false},
		{"original-applied", reconcile.State{Desired: base.Desired, GenerationFloor: 1, LastID: 1, Applied: target}, true, true},
		{"replacement-apply", reconcile.State{Desired: base.Desired, GenerationFloor: 1, LastID: 2, Applied: target}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := reconcile.Record{Schema: 1, State: tc.state}
			if ok := validateCreationIntent(row, spec, tc.prepared) == nil; ok != tc.valid {
				t.Fatal("unexpected original intent admission", ok, tc.valid)
			}
		})
	}
}
