// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestRQ15ShellQueryFieldsAndFilteredReplyConsistency(t *testing.T) {
	for _, state := range []string{"", "open", "closed"} {
		if !(NodeShellSessionsQuery{State: state, Node: "node-b", After: "before"}).Valid() {
			t.Fatal("valid filtered query rejected", state)
		}
	}
	for _, q := range []NodeShellSessionsQuery{{State: "opened"}, {State: "OPEN"}, {State: "open", Node: "bad node"}, {After: string(make([]byte, 257))}} {
		if q.Valid() {
			t.Fatal("invalid filtered query accepted", q.State, q.Node)
		}
	}
	// Each method takes exactly its own Params: the policy takes {}, and
	// neither takes a field of another method.
	for _, r := range []Request{
		{Schema: 1, Method: "node-shell-policy", Params: json.RawMessage(`{"State":"open"}`)},
		{Schema: 1, Method: "node-shell-sessions", Params: json.RawMessage(`{"State":"open","Tenant":"foreign"}`)},
		{Schema: 1, Method: "node-shell-sessions", Params: json.RawMessage(`{"State":"open"}`), Tenant: "foreign"},
		{Schema: 1, Method: "members", Params: json.RawMessage(`{"After":"bad/cursor"}`)},
		{Schema: 1, Method: "node-invitation", Params: json.RawMessage(`{"Node":"node-b","After":"x"}`)},
	} {
		if r.validMethodFields() {
			t.Fatal("foreign or invalid params accepted", r.Method, string(r.Params))
		}
	}
	for _, r := range []Request{
		{Schema: 1, Method: "node-shell-policy", Params: json.RawMessage(`{}`)},
		{Schema: 1, Method: "node-shell-sessions", Params: json.RawMessage(`{"State":"open","Node":"node-b"}`)},
		{Schema: 1, Method: "members", Params: json.RawMessage(`{}`)},
		{Schema: 1, Method: "node-invitation", Params: json.RawMessage(`{"Node":"node-b"}`)},
	} {
		if !r.validMethodFields() {
			t.Fatal("valid params rejected", r.Method, string(r.Params))
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
