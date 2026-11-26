// SPDX-License-Identifier: Apache-2.0

package userauth

import "testing"

func TestNodeObservationSelectorsAndRaftStatusCannotAcquireWriteInputs(t *testing.T) {
	for _, r := range []Request{{Method: "node-summary", Tenant: "tenant", Node: "node-a"}, {Method: "node-disks", After: "cursor"}, {Method: "node-tenant-usage", Node: "node-a"}, {Method: "mesh-links", Tenant: "tenant"}, {Method: "raft-status", After: "cursor"}} {
		if !r.validMethodFields() || !r.validQuerySelectors() {
			t.Fatal("valid observation selector", r.Method)
		}
	}
	for _, r := range []Request{{Method: "raft-status", Tenant: "tenant"}, {Method: "raft-status", Node: "node-a"}, {Method: "node-tenant-usage"}, {Method: "node-tenant-usage", Tenant: "tenant", Node: "node-a"}, {Method: "node-summary", Node: "../node"}, {Method: "node-disks", App: "app"}, {Method: "mesh-links", TargetUser: "other"}} {
		if r.validMethodFields() && r.validQuerySelectors() {
			t.Fatal("cross-method/private selector accepted", r.Method)
		}
	}
}
