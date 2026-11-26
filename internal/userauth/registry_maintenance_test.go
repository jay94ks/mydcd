// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagesource"
)

func TestRegistryMaintenanceRequestCannotMixScopeOrMessage(t *testing.T) {
	for _, query := range []struct {
		method string
		q      control.RegistryMaintenanceQuery
	}{
		{"registry-maintenance-plan", control.RegistryMaintenanceQuery{Action: "gc-registry", ID: "private"}},
		{"registry-maintenance-plan", control.RegistryMaintenanceQuery{Action: "delete-registry-image", ID: "private", Repository: "team/app", Reference: "stable", Digest: "sha256:" + strings.Repeat("a", 64)}},
		{"registry-maintenance-plan", control.RegistryMaintenanceQuery{Action: "delete-registry-image", External: true, ID: "source", Repository: "team/app", Reference: "sha256:" + strings.Repeat("a", 64), Digest: "sha256:" + strings.Repeat("a", 64)}},
		{"registry-maintenance-status", control.RegistryMaintenanceQuery{Operation: "original-42"}},
	} {
		base := Request{Method: query.method, Tenant: "tenant", RegistryMaintenance: &query.q}
		if !base.validMethodFields() || !base.validQuerySelectors() {
			t.Fatal("valid typed query rejected", query.method)
		}
		for _, edit := range []func(*Request){
			func(r *Request) { r.Tenant = "" },
			func(r *Request) { r.Node = "node-a" },
			func(r *Request) { r.After = "cursor" },
			func(r *Request) { r.App = "app" },
			func(r *Request) { r.Method = "whoami" },
			func(r *Request) { r.RegistryMaintenance = nil },
			func(r *Request) { r.RegistryCatalog = &control.RegistryCatalogueQuery{Kind: "managed", ID: "private"} },
		} {
			bad := base
			edit(&bad)
			if bad.validMethodFields() && bad.validQuerySelectors() {
				t.Fatal("mixed maintenance request accepted", bad)
			}
		}
	}
}

func TestRegistryMaintenanceClientRejectsIncompleteOrAmbiguousResult(t *testing.T) {
	c := Client{Cluster: [32]byte{1}}
	q := control.RegistryMaintenanceQuery{Operation: "original-42"}
	for _, reply := range []Reply{
		{Tenant: "other"},
		{Tenant: "tenant"},
		{Tenant: "tenant", RegistryMaintenanceStatus: &control.RegistryMaintenanceStatus{Schema: 1, Tenant: "tenant", Operation: q.Operation, State: "done", Revision: 1, At: 3}},
		{Tenant: "tenant", RegistryMaintenancePlan: &control.RegistryMaintenancePlan{}, RegistryMaintenanceStatus: &control.RegistryMaintenanceStatus{}},
	} {
		if c.validateRegistryMaintenanceReply(reply, "tenant", false, q) == nil {
			t.Fatal("missing original target/native result accepted")
		}
	}
}

func TestExternalMaintenanceClientKeepsUnknownSeparateFromTerminalFailure(t *testing.T) {
	c := Client{Cluster: [32]byte{1}}
	q := control.RegistryMaintenanceQuery{Operation: "external-original"}
	change := control.RegistryMaintenanceChange{Tenant: "tenant", Operation: q.Operation, Repository: "team/app", Reference: "sha256:" + strings.Repeat("a", 64), Digest: "sha256:" + strings.Repeat("a", 64), External: &control.ExternalRegistryMaintenanceTarget{Selection: control.ExternalRegistryReadSelection{Tenant: "tenant", ID: "source", Generation: 2}, Spec: imagesource.Source{Tenant: "tenant", ID: "source", Authority: "registry.example", Repository: "team/**", Enabled: true, Auth: "none"}, Node: "node-a", Owner: [32]byte{2}, Revision: 2, ReadSet: [32]byte{3}}}
	status := control.RegistryMaintenanceStatus{Schema: 1, Tenant: "tenant", Operation: q.Operation, Action: "delete-registry-image", State: "unknown", Revision: 3, At: 123, Change: change}
	reply := Reply{Tenant: "tenant", RegistryMaintenanceStatus: &status}
	if err := c.validateRegistryMaintenanceReply(reply, "tenant", false, q); err != nil {
		t.Fatal("original external unknown status", err)
	}
	status.Result = &control.RegistryMaintenanceResult{Code: "DENIED", At: 123000}
	if c.validateRegistryMaintenanceReply(reply, "tenant", false, q) == nil {
		t.Fatal("unknown external effect carried a terminal no-effect result")
	}
	status.State, status.Result = "done", &control.RegistryMaintenanceResult{Code: "OK", At: 123000, Native: [32]byte{4}}
	if err := c.validateRegistryMaintenanceReply(reply, "tenant", false, q); err != nil {
		t.Fatal("original external acknowledged result", err)
	}
	status.Change.External = nil
	if c.validateRegistryMaintenanceReply(reply, "tenant", false, q) == nil {
		t.Fatal("external result silently became a managed run")
	}
}
