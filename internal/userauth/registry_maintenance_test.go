// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagesource"
)

func TestRegistryMaintenanceQueriesStayInTheirShape(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, q := range []control.RegistryMaintenanceQuery{
		{Action: "gc-registry", ID: "private"},
		{Action: "delete-registry-image", ID: "private", Repository: "team/app", Reference: "stable", Digest: digest},
		{Action: "delete-registry-image", External: true, ID: "source", Repository: "team/app", Reference: digest, Digest: digest},
	} {
		if !(RegistryMaintenancePlanQuery{Tenant: "tenant", Query: q}).Valid() {
			t.Fatal("valid plan query rejected", q)
		}
		if (RegistryMaintenancePlanQuery{Query: q}).Valid() {
			t.Fatal("plan query without a tenant accepted", q)
		}
	}
	if (RegistryMaintenancePlanQuery{Tenant: "tenant", Query: control.RegistryMaintenanceQuery{Action: control.RegistryPruneAction, ID: "private"}}).Valid() {
		t.Fatal("prune planned through maintenance")
	}
	if !(RegistryMaintenanceStatusQuery{Tenant: "tenant", Operation: "original-42"}).Valid() || (RegistryMaintenanceStatusQuery{Tenant: "tenant"}).Valid() || (RegistryMaintenanceStatusQuery{Operation: "original-42"}).Valid() {
		t.Fatal("status query shape")
	}
	if strict([]byte(`{"Tenant":"tenant","Operation":"original-42","After":"x"}`), &RegistryMaintenanceStatusQuery{}) == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestRegistryMaintenanceClientRejectsIncompleteOrAmbiguousResult(t *testing.T) {
	c := Client{Cluster: [32]byte{1}}
	q := control.RegistryMaintenanceQuery{Operation: "original-42"}
	for _, status := range []control.RegistryMaintenanceStatus{
		{},
		{Schema: 1, Tenant: "other", Operation: q.Operation, State: "queued", Revision: 1, At: 3},
		{Schema: 1, Tenant: "tenant", Operation: q.Operation, State: "done", Revision: 1, At: 3},
	} {
		if c.validMaintenanceStatus("tenant", q.Operation, status) {
			t.Fatal("missing original target/native result accepted")
		}
	}
}

func TestExternalMaintenanceClientKeepsUnknownSeparateFromTerminalFailure(t *testing.T) {
	c := Client{Cluster: [32]byte{1}}
	q := control.RegistryMaintenanceQuery{Operation: "external-original"}
	change := control.RegistryMaintenanceChange{Tenant: "tenant", Operation: q.Operation, Repository: "team/app", Reference: "sha256:" + strings.Repeat("a", 64), Digest: "sha256:" + strings.Repeat("a", 64), External: &control.ExternalRegistryMaintenanceTarget{Selection: control.ExternalRegistryReadSelection{Tenant: "tenant", ID: "source", Generation: 2}, Spec: imagesource.Source{Tenant: "tenant", ID: "source", Authority: "registry.example", Repository: "team/**", Enabled: true, Auth: "none"}, Node: "node-a", Owner: [32]byte{2}, Revision: 2, ReadSet: [32]byte{3}}}
	status := control.RegistryMaintenanceStatus{Schema: 1, Tenant: "tenant", Operation: q.Operation, Action: "delete-registry-image", State: "unknown", Revision: 3, At: 123, Change: change}
	if !c.validMaintenanceStatus("tenant", q.Operation, status) {
		t.Fatal("original external unknown status")
	}
	status.Result = &control.RegistryMaintenanceResult{Code: "DENIED", At: 123000}
	if c.validMaintenanceStatus("tenant", q.Operation, status) {
		t.Fatal("unknown external effect carried a terminal no-effect result")
	}
	status.State, status.Result = "done", &control.RegistryMaintenanceResult{Code: "OK", At: 123000, Native: [32]byte{4}}
	if !c.validMaintenanceStatus("tenant", q.Operation, status) {
		t.Fatal("original external acknowledged result")
	}
	status.Change.External = nil
	if c.validMaintenanceStatus("tenant", q.Operation, status) {
		t.Fatal("external result silently became a managed run")
	}
}
