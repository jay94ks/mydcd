// SPDX-License-Identifier: Apache-2.0

package userauth

import "testing"

func TestTaskQuerySelectorsCannotContaminateOtherMethods(t *testing.T) {
	for _, q := range []Request{{Method: "tasks"}, {Method: "tasks", Node: "node-a", Tenant: "tenant", App: "app", After: "cursor"}} {
		if !q.validMethodFields() || !q.validQuerySelectors() {
			t.Fatal("valid task selectors rejected")
		}
	}
	for _, q := range []Request{{Method: "tasks", App: "../app"}, {Method: "tasks", Node: "../node"}, {Method: "tasks", TargetUser: "other"}, {Method: "whoami", App: "app"}, {Method: "submit", App: "app"}} {
		if q.validMethodFields() && q.validQuerySelectors() {
			t.Fatal("foreign task selectors accepted", q.Method)
		}
	}
}
