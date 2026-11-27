// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
)

func TestLogClearMethodShapesCannotCrossQueryOrTenantScopes(t *testing.T) {
	plan := Request{Method: "app-log-clear-plan", Tenant: "tenant", LogClear: &control.AppLogClearQuery{Selection: containerops.Selection{App: "app", Service: "web"}}}
	if !plan.validMethodFields() || !plan.validQuerySelectors() {
		t.Fatal("valid plan request")
	}
	for _, change := range []func(*Request){
		func(r *Request) { r.Method = "whoami" },
		func(r *Request) { r.Method = "app-log-clear-status" },
		func(r *Request) { r.Tenant = "" },
		func(r *Request) { r.After = "cursor" },
		func(r *Request) { r.Node = "node-a" },
		func(r *Request) { r.Container = &containerops.Query{} },
	} {
		copy := plan
		change(&copy)
		if copy.validMethodFields() {
			t.Fatal("mixed log-clear shape admitted")
		}
	}
	status := Request{Method: "app-log-clear-status", Tenant: "tenant", LogClear: &control.AppLogClearQuery{Selection: containerops.Selection{App: "app"}, Operation: "original"}}
	if !status.validMethodFields() || !status.validQuerySelectors() {
		t.Fatal("valid original status selector")
	}
}
