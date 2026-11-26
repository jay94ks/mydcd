// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func TestRQ15ShellQueryFieldsAndFilteredReplyConsistency(t *testing.T) {
	for _, state := range []string{"", "open", "closed"} {
		q := Request{Method: "node-shell-sessions", State: state, Node: "node-b", After: "before"}
		if !q.validNodeShellQuery() || !q.validMethodFields() || !q.validQuerySelectors() {
			t.Fatal("valid filtered query rejected", state)
		}
	}
	for _, q := range []Request{
		{Method: "node-shell-policy", State: "open"}, {Method: "node-shell-policy", Node: "node-b"},
		{Method: "node-shell-sessions", State: "opened"}, {Method: "node-shell-sessions", State: "OPEN"},
		{Method: "node-shell-sessions", State: "open", Node: "bad node"}, {Method: "node-shell-sessions", State: "open", Tenant: "foreign"},
	} {
		if q.validNodeShellQuery() || q.validMethodFields() || q.validQuerySelectors() {
			t.Fatal("invalid/foreign filtered query accepted", q.Method, q.State)
		}
	}
	filter := control.NodeShellSessionsQuery{State: "open", Node: "node-b"}
	page := control.NodeShellSessionsPage{Schema: 1, Total: 3, Sessions: []control.NodeShellSession{{SessionID: "a", Node: "node-b", State: "queued"}, {SessionID: "b", Node: "node-b", State: "opened"}, {SessionID: "c", Node: "node-b", State: "closing"}}}
	if !validNodeShellSessionsPage(page, filter, "") {
		t.Fatal("valid filtered page rejected")
	}
	for _, change := range []func(*control.NodeShellSessionsPage){
		func(p *control.NodeShellSessionsPage) { p.Total = 2 },
		func(p *control.NodeShellSessionsPage) { p.Next = "c" },
		func(p *control.NodeShellSessionsPage) { p.Sessions[0].State = "closed" },
		func(p *control.NodeShellSessionsPage) { p.Sessions[0].Node = "node-a" },
		func(p *control.NodeShellSessionsPage) { p.Sessions[1].SessionID = "a" },
		func(p *control.NodeShellSessionsPage) { p.Sessions[0].State = "unknown" },
	} {
		bad := page
		bad.Sessions = append([]control.NodeShellSession(nil), page.Sessions...)
		change(&bad)
		if validNodeShellSessionsPage(bad, filter, "") {
			t.Fatal("mismatched filtered reply accepted")
		}
	}
	if validNodeShellSessionsPage(page, filter, "b") {
		t.Fatal("cursor did not constrain returned rows")
	}
}
