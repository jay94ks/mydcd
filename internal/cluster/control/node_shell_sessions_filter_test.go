// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

// Large normalized records model only the list algorithm. The authenticated
// persisted-book consumer is exercised separately below and by actual User I/O.
func TestRQ15ShellListFiltersRetentionBeforePagingWithoutMutatingOriginal(t *testing.T) {
	b := NodeShellBook{Schema: 1}
	for i := 0; i < 1000; i++ {
		user := "alice"
		if i%2 != 0 {
			user = "bob"
		}
		b.Records = append(b.Records, NodeShellRecord{Session: NodeShellSession{SessionID: fmt.Sprintf("closed-%04d", i), Node: "node-a", User: user, State: "closed", ClosedAt: int64(i + 1), End: &NodeShellEnd{Reason: "exit"}}})
	}
	for i, status := range []string{"queued", "opened", "closing"} {
		node, user := "node-b", "alice"
		if i == 0 {
			node = "node-a"
		}
		if i == 2 {
			user = "bob"
		}
		b.Records = append(b.Records, NodeShellRecord{Session: NodeShellSession{SessionID: fmt.Sprintf("zz-live-%d", i), Node: node, User: user, State: status}})
	}
	before, _ := json.Marshal(b)
	page := func(q NodeShellSessionsQuery, admin bool, after string) NodeShellSessionsPage {
		return nodeShellSessionsPage(b, NodeShellSessionsPage{Schema: 1, Sessions: []NodeShellSession{}}, "alice", admin, after, q)
	}
	for _, tc := range []struct {
		q     NodeShellSessionsQuery
		admin bool
		total int
	}{
		{NodeShellSessionsQuery{State: "open"}, true, 3},
		{NodeShellSessionsQuery{State: "open", Node: "node-b"}, true, 2},
		{NodeShellSessionsQuery{State: "open"}, false, 2},
		{NodeShellSessionsQuery{State: "closed"}, true, 200},
		{NodeShellSessionsQuery{State: "closed"}, false, 100},
		{NodeShellSessionsQuery{}, true, 203},
		{NodeShellSessionsQuery{Node: "missing"}, true, 0},
	} {
		got := page(tc.q, tc.admin, "")
		if got.Total != tc.total || len(got.Sessions) != min(8, tc.total) || (got.Next != "") != (tc.total > 8) {
			t.Fatalf("filtered count/page: %+v %t total=%d rows=%d next=%q", tc.q, tc.admin, got.Total, len(got.Sessions), got.Next)
		}
		for _, r := range got.Sessions {
			if !tc.admin && r.User != "alice" || tc.q.Node != "" && r.Node != tc.q.Node || tc.q.State == "open" && r.State == "closed" || tc.q.State == "closed" && r.State != "closed" {
				t.Fatal("foreign row in filtered page")
			}
		}
	}
	seen := map[string]bool{}
	after := ""
	for {
		got := page(NodeShellSessionsQuery{State: "closed"}, true, after)
		if got.Total != 200 {
			t.Fatal("Total depends on page position")
		}
		for _, r := range got.Sessions {
			if r.SessionID < "closed-0800" || seen[r.SessionID] || r.SessionID <= after {
				t.Fatal("retired/duplicate/out-of-order result", r.SessionID)
			}
			seen[r.SessionID] = true
		}
		if got.Next == "" {
			break
		}
		after = got.Next
	}
	if len(seen) != 200 {
		t.Fatal("closed window did not paginate exactly", len(seen))
	}
	// Even a page containing exactly eight rows has no Next when exhausted.
	last := page(NodeShellSessionsQuery{State: "closed"}, true, "closed-0991")
	if len(last.Sessions) != 8 || last.Next != "" {
		t.Fatal("false next page at exact boundary")
	}
	copied := page(NodeShellSessionsQuery{State: "closed"}, true, "")
	copied.Sessions[0].End.Reason = "changed"
	afterBytes, _ := json.Marshal(b)
	if !bytes.Equal(before, afterBytes) {
		t.Fatal("query changed original records/end")
	}
	// Per-node retention is global, not a separate per-user quota; ties use ID.
	for i := 200; i >= 0; i-- {
		b.Records = append(b.Records, NodeShellRecord{Session: NodeShellSession{SessionID: fmt.Sprintf("tie-%03d", i), Node: "node-b", User: "alice", State: "closed", ClosedAt: 9999}})
	}
	got := page(NodeShellSessionsQuery{State: "closed", Node: "node-b"}, true, "tie-198")
	if got.Total != 200 || len(got.Sessions) != 1 || got.Sessions[0].SessionID != "tie-199" || got.Next != "" {
		t.Fatal("node window/tie boundary", got)
	}
	if active := page(NodeShellSessionsQuery{State: "open"}, true, ""); active.Total != 3 {
		t.Fatal("closed retention hid live session")
	}
}

func TestRQ15ShellListCurrentAuthorityAndSignedBookFilterConsumer(t *testing.T) {
	f := nodeShellCore(t)
	aliceKey := nodeShellAlice(t, f)
	nodeShellGrant(t, f, "alice", []string{"node-a"})
	nodeShellEnable(t, f, "node-a", false)
	alice := nodeShellSessionFor(t, f, "alice", aliceKey, access.NodeShell)
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("history-%d", i)
		nodeShellApply(t, f, f.session, f.admin, id, "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Applied)
		nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "opened", SessionID: id, At: 2, LastActivity: 2}, state.Applied)
		nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "closed", SessionID: id, At: 2, LastActivity: 2, Reason: "exit"}, state.Applied)
	}
	nodeShellApply(t, f, alice, aliceKey, "alice-live", "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Applied)
	before := f.s.Object(NodeShellKey)
	got, err := f.p.NodeShellSessions(f.s, alice, 2, "", NodeShellSessionsQuery{State: "open", Node: "node-a"})
	if err != nil || got.Total != 1 || len(got.Sessions) != 1 || got.Sessions[0].SessionID != "alice-live" {
		t.Fatal("signed persisted query", got, err)
	}
	empty, err := f.p.NodeShellSessions(f.s, alice, 2, "", NodeShellSessionsQuery{State: "closed"})
	if err != nil || empty.Total != 0 {
		t.Fatal("another user's closed rows leaked", err)
	}
	admin, err := f.p.NodeShellSessions(f.s, f.session, 2, "", NodeShellSessionsQuery{State: "closed"})
	if err != nil || admin.Total != 3 || f.s.Object(NodeShellKey) != before {
		t.Fatal("admin query changed signed state", err)
	}
	for _, q := range []NodeShellSessionsQuery{{State: "opened"}, {State: "OPEN"}, {Node: "node bad"}, {Node: "/node-a"}} {
		if q.Valid() {
			t.Fatal("invalid query", q)
		}
		if _, err := f.p.NodeShellSessions(f.s, alice, 2, "", q); err == nil {
			t.Fatal("invalid query reached result")
		}
	}
	if _, err := f.p.NodeShellSessions(f.s, alice, 2, "", NodeShellSessionsQuery{}, NodeShellSessionsQuery{}); err == nil {
		t.Fatal("ambiguous filters")
	}
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User("alice")
	expected := u.Revision
	u.Revision = 0
	u.Enabled = false
	f.apply("disable-query-user", "put-user", expected, u, state.Applied)
	if _, err := f.p.NodeShellSessions(f.s, alice, 2, "", NodeShellSessionsQuery{State: "open"}); err == nil {
		t.Fatal("revoked current user enumerated sessions")
	}
}
