// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestRegistryActionPreviewSharesPermissionsAndPreservesOriginalVolumeWithoutMutation(t *testing.T) {
	f, spec := registryFixture(t)
	f.apply("manager", "put-registry", 0, RegistryPut{Spec: spec}, state.Applied)
	before, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.p.PlanRegistryAction(f.s, f.sessions["manager"], 2, "tenant", RegistryActionQuery{Action: "stop-registry", ID: spec.ID})
	if err != nil || plan.Current.Spec.Volume != spec.Volume || !plan.DataPreserved || plan.WouldEnable || plan.Expected != 1 || plan.Current.Revision != plan.Expected {
		t.Fatal("original registry stop preview", err)
	}
	after, err := state.Encode(f.s)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preview changed management state", err)
	}
	f.apply("manager", "stop-registry", plan.Expected, RegistrySelection{Tenant: "tenant", ID: spec.ID}, state.Applied)
	f.apply("manager", "start-registry", plan.Expected, RegistrySelection{Tenant: "tenant", ID: spec.ID}, state.ConditionFailed)
	current, err := f.p.PlanRegistryAction(f.s, f.sessions["manager"], 2, "tenant", RegistryActionQuery{Action: "start-registry", ID: spec.ID})
	if err != nil || !current.WouldEnable || current.Expected != 2 || current.Current.Spec.Volume != spec.Volume {
		t.Fatal("same data start preview", err)
	}
	clipped := f.sessions["manager"]
	clipped.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	clipped.Signature = ed25519.Sign(f.node, access.SessionBytes(clipped))
	if _, err := f.p.PlanRegistryAction(f.s, clipped, 2, "tenant", RegistryActionQuery{Action: "stop-registry", ID: spec.ID}); err == nil {
		t.Fatal("reader previewed a management operation")
	}
	if _, err := f.p.PlanRegistryAction(f.s, f.sessions["manager"], 2, "foreign", RegistryActionQuery{Action: "start-registry", ID: spec.ID}); err == nil {
		t.Fatal("foreign tenant preview accepted")
	}
	if _, err := f.p.PlanRegistryAction(f.s, f.sessions["manager"], 2, "tenant", RegistryActionQuery{Action: "delete-registry", ID: spec.ID}); err == nil {
		t.Fatal("preview widened into deletion")
	}
}
