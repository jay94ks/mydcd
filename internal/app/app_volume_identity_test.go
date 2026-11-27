// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// The existing signed installation fixture supplies exact dual-key lineage.
// Budget selection uses the product Quotas transitions and the SAME function
// called before original native Volume observation; no native effect is faked.
func TestAppVolumeObservationUsesCurrentQuotaAndExactOriginalNativeOwner(t *testing.T) {
	root, _ := installationIdentityFixture(t)
	_, _, catalog, _, _ := routeOwnerCoreFixture(t)
	networks, err := tenancy.New(root.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	quotas, err := tenancy.NewQuotas(root.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	original := root.OriginalKey()
	var globalOnly tenancy.Quotas
	for _, tenant := range []string{"", "first"} {
		limit := tenancy.NodeLimit{Tenant: tenant, Node: root.Self.ID, Owner: original, Networks: 1, MaxConsumers: 8}
		if tenant != "" {
			limit.MaxConsumers = 4
		}
		quotas, err = quotas.Set(catalog, "admin", 0, limit, networks)
		if err != nil {
			t.Fatal(err)
		}
		if tenant == "" {
			globalOnly = quotas
		}
	}
	app := control.AppView{Tenant: "first", App: "app"}
	step := deployment.Step{Key: deployment.ResourceKey("volume", app.Tenant, app.App, "data"), Kind: "volume", Node: root.Self.ID, Owner: original}
	material := control.AppVolumeMaterial{Spec: volumes.NativeSpec{Schema: 1, Scope: volumes.Scope{Cluster: root.Cluster, Tenant: app.Tenant, App: app.App, ID: "data", Generation: 7}, Node: root.Self.ID, NodeKey: original, Materialization: "initial", Mode: 0750, Retain: true}, Generation: 7}
	originalMaterial, _ := json.Marshal(material)
	originalNative := volumes.NativeKey(material.Spec)
	for i, row := range root.Keys {
		proof, _ := json.Marshal(row.Proof)
		quotas, err = quotas.RotateOwner(tenancy.OwnerRotation{Node: root.Self.ID, Operation: row.Proof.Operation, Old: row.Proof.Old, New: row.Proof.New, Proof: sha256.Sum256(proof), Index: row.Index})
		if err != nil {
			t.Fatal(err)
		}
		global, _ := quotas.Limit("", step.Node)
		scoped, _ := quotas.Limit(app.Tenant, step.Node)
		if global.Owner == original || scoped.Owner == original || global.Owner != row.Proof.New || scoped.Owner != row.Proof.New {
			t.Fatal("fixture did not reach current quota owner", i)
		}
		before, _ := quotas.Encode()
		capacity, err := appVolumeConsumerCapacity(quotas, app, step, material, original)
		if err != nil || capacity != 4 {
			t.Fatal("original Volume observation blocked by current quota owner", i, capacity, err)
		}
		after, _ := quotas.Encode()
		gotMaterial, _ := json.Marshal(material)
		if !bytes.Equal(before, after) || !bytes.Equal(originalMaterial, gotMaterial) || volumes.NativeKey(material.Spec) != originalNative {
			t.Fatal("consumer-budget read rewrote original native material or quota lineage")
		}
		if _, err := appVolumeConsumerCapacity(quotas, app, step, material, row.Proof.New); err == nil {
			t.Fatal("current runtime selected another owner's original native journal")
		}
	}
	for name, change := range map[string]func(*control.AppView, *deployment.Step, *control.AppVolumeMaterial){
		"other-cluster":     func(_ *control.AppView, _ *deployment.Step, m *control.AppVolumeMaterial) { m.Spec.Scope.Cluster[0]++ },
		"other-tenant":      func(a *control.AppView, _ *deployment.Step, _ *control.AppVolumeMaterial) { a.Tenant = "second" },
		"other-app":         func(a *control.AppView, _ *deployment.Step, _ *control.AppVolumeMaterial) { a.App = "other" },
		"other-node":        func(_ *control.AppView, s *deployment.Step, _ *control.AppVolumeMaterial) { s.Node = "node-b" },
		"other-native-node": func(_ *control.AppView, _ *deployment.Step, m *control.AppVolumeMaterial) { m.Spec.Node = "node-b" },
		"other-native-key": func(_ *control.AppView, _ *deployment.Step, m *control.AppVolumeMaterial) {
			m.Spec.NodeKey = [32]byte{99}
		},
		"other-step-key":   func(_ *control.AppView, s *deployment.Step, _ *control.AppVolumeMaterial) { s.Key += "-other" },
		"other-step-owner": func(_ *control.AppView, s *deployment.Step, _ *control.AppVolumeMaterial) { s.Owner = [32]byte{99} },
	} {
		t.Run(name, func(t *testing.T) {
			a, s, m := app, step, material
			change(&a, &s, &m)
			if _, err := appVolumeConsumerCapacity(quotas, a, s, m, original); err == nil {
				t.Fatal("unrelated source consumed an original Volume budget")
			}
		})
	}
	if _, err := appVolumeConsumerCapacity(globalOnly, app, step, material, original); err == nil {
		t.Fatal("global quota replaced missing tenant-specific authority")
	}
	empty, _ := tenancy.NewQuotas(root.Cluster)
	if _, err := appVolumeConsumerCapacity(empty, app, step, material, original); err == nil {
		t.Fatal("absent quota was treated as a consumer grant")
	}
}
