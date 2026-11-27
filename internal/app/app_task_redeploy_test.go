// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
)

func TestAppTaskRecipeResolvedOnlyAfterWholeRetirement(t *testing.T) {
	source := deployment.ObjectRef{Key: "workload/task/tenant/app/db", Generation: 30, Revision: 30}
	retired := reconcile.State{Desired: reconcile.Desired{Revision: 20, Retiring: 10}, LastID: 2, GenerationFloor: 10}
	for _, name := range []string{"fresh", "retired", "original-unknown", "old-unknown", "applied", "desired", "consumer", "stopped", "floor", "stale-revision"} {
		t.Run(name, func(t *testing.T) {
			r := reconcile.Record{State: retired}
			reuse, allowed := false, false
			q := source
			switch name {
			case "fresh":
				r.State = reconcile.State{}
				allowed = true
			case "retired":
				allowed = true
			case "original-unknown":
				resource := reconcile.Resource{Present: true, Generation: 30, Spec: "original resolved recipe"}
				r.State = reconcile.State{Desired: reconcile.Desired{Revision: 30, Resource: resource}, GenerationFloor: 30, LastID: 3, Pending: &reconcile.Operation{ID: 3, Kind: reconcile.Apply, Target: resource, Phase: reconcile.RecoveryRequired}}
				reuse, allowed = true, true
			case "old-unknown":
				r.State.LastID = 1
				r.State.Pending = &reconcile.Operation{ID: 1, Kind: reconcile.Apply, Target: reconcile.Resource{Present: true, Generation: 10}, Phase: reconcile.RecoveryRequired}
			case "applied":
				r.State.Applied = reconcile.Resource{Present: true, Generation: 10}
			case "desired":
				r.State.Desired = reconcile.Desired{Revision: 10, Resource: reconcile.Resource{Present: true, Generation: 10}}
			case "consumer":
				r.Consumers = map[string]reconcile.Lease{"original": {Generation: 10, Token: 1}}
			case "stopped":
				r.State.Stopped = true
			case "floor":
				q.Generation = 10
			case "stale-revision":
				r.State.Desired.Revision = 31
			}
			before, _ := json.Marshal(r)
			got, err := appTaskRecipeState(r, q)
			if (err == nil) != allowed || err == nil && got != reuse {
				t.Fatal("original/new recipe admission", name, got, err)
			}
			after, _ := json.Marshal(r)
			if string(before) != string(after) {
				t.Fatal("recipe selection rewrote original journal")
			}
		})
	}
}
