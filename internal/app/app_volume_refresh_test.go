// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestAppVolumeObservationRefreshRequiresOriginalRegistrationAndPublishedInstance(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, ed25519.SeedSize))
	owner := [32]byte(private.Public().(ed25519.PublicKey))
	spec := volumes.NativeSpec{Schema: 1, Scope: volumes.Scope{Cluster: [32]byte{82}, Tenant: "tenant", App: "app", ID: "data", Generation: 7}, Node: "node-a", NodeKey: owner, Materialization: "initial", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
	raw, _ := json.Marshal(spec)
	client := engine.Client{Owner: engine.Owner(spec.Scope.Cluster, owner)}
	id, err := client.Identity("volume", volumes.NativeKey(spec), reconcile.Resource{Present: true, Generation: 7, Spec: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	ready := volumes.NativeReady{Schema: 1, Spec: spec, Generation: 7, Owner: volumes.Owner{Node: "node-a", Key: owner, Native: id.Name}}
	ready.Signature = ed25519.Sign(private, volumes.NativeReadyBytes(ready))
	if err := ready.Verify(); err != nil {
		t.Fatal(err)
	}
	stage := deployment.StageRecord{Result: &state.Result{Code: state.Applied, Generation: 11, Revision: 13}, Observation: &deployment.Observation{Native: id.Name, Applied: true, Generation: 11, Revision: 13}}
	if !appVolumeObservationOnly(stage, ready, ready, true) {
		t.Fatal("same original registration must refresh without re-registration")
	}
	for _, kind := range []string{"absent", "unpublished", "released", "generation", "native", "signature", "changed-fact"} {
		t.Run(kind, func(t *testing.T) {
			row := stage
			o := *stage.Observation
			row.Observation = &o
			registered := ready
			registered.Signature = bytes.Clone(ready.Signature)
			found := true
			switch kind {
			case "absent":
				found = false
			case "unpublished":
				row.Observation = nil
			case "released":
				o.Released = true
			case "generation":
				o.Generation++
			case "native":
				o.Native = "another-native"
			case "signature":
				registered.Signature[0] ^= 1
			case "changed-fact":
				registered.Spec.UID++
				registered.Signature = ed25519.Sign(private, volumes.NativeReadyBytes(registered))
			}
			if appVolumeObservationOnly(row, registered, ready, found) {
				t.Fatal("refresh accepted missing or different original fact")
			}
		})
	}
}
