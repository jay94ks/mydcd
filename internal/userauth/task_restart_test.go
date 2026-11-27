// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"testing"
)

func TestTaskRestartRequestDoesNotSmuggleOtherMethodSelectors(t *testing.T) {
	plan := Request{Method: "task-restart-plan", Tenant: "tenant", TaskRestart: &control.TaskRestartQuery{Selection: containerops.Selection{App: "app", Service: "web"}}}
	if !plan.validQuerySelectors() {
		t.Fatal("typed plan rejected")
	}
	for _, edit := range []func(*Request){func(q *Request) { q.Tenant = "" }, func(q *Request) { q.Method = "whoami" }, func(q *Request) { q.After = "next" }, func(q *Request) { q.Node = "node" }, func(q *Request) { q.TaskRestart = nil }} {
		bad := plan
		edit(&bad)
		if bad.validQuerySelectors() {
			t.Fatal("unrelated selector accepted")
		}
	}
	status := Request{Method: "task-restart-status", Tenant: "tenant", TaskRestart: &control.TaskRestartQuery{Selection: containerops.Selection{App: "app"}, Operation: "restart-1"}}
	if !status.validQuerySelectors() {
		t.Fatal("original status selector rejected")
	}
	status.TaskRestart.Selection.Service = "web"
	if status.validQuerySelectors() {
		t.Fatal("status could reselect a target")
	}
}
