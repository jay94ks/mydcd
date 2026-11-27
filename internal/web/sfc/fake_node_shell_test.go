// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// REQ-67 acceptance in the fake: cluster off + node-b on → only node-b
// opens; NodeShell on node-b only → node-c forbidden; whoami is the
// account; sudo follows the server setting; records keep only counts.
func TestNodeShell(t *testing.T) {
	f, clk := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	open := func(c Conn, node string) (NodeShell, error) {
		t.Helper()
		op, err := c.Prepare(ctx, Change{Action: ActionOpenNodeShell, Payload: mustPayload(t, OpenNodeShell{Node: node, Cols: 80, Rows: 24})}, rootFor(t, c, ActionOpenNodeShell))
		if err != nil {
			t.Fatal(err)
		}
		return openShell(t, c, op)
	}
	code := func(err error) Code {
		var e *Error
		if errors.As(err, &e) {
			return e.Code
		}
		return ""
	}
	// read everything until the prompt comes back.
	// drain reads to the end: the error after the remaining output.
	drain := func(sh NodeShell) error {
		for {
			if _, err := sh.Recv(ctx); err != nil {
				return err
			}
		}
	}
	run := func(sh NodeShell, line string) string {
		t.Helper()
		if err := sh.Send(ctx, []byte(line+"\r")); err != nil {
			t.Fatal(err)
		}
		c, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		var out string
		for !strings.HasSuffix(out, "$ ") && !strings.HasSuffix(out, "# ") {
			b, err := sh.Recv(c)
			if err != nil {
				return out
			}
			out += string(b)
		}
		return out
	}

	p, err := admin.NodeShellPolicy(ctx)
	if err != nil || p.Enabled || p.Account != NodeShellAccount || len(p.Nodes) != 4 || p.MaxSessions != 4 {
		t.Fatalf("policy %+v %v", p, err)
	}
	if _, err := bob.NodeShellPolicy(ctx); err == nil {
		t.Fatal("bob has no NodeShell")
	}
	if ap, err := alice.NodeShellPolicy(ctx); err != nil || len(ap.Nodes) != 1 || ap.Nodes[0].Node != "node-b" || !ap.Nodes[0].Enabled {
		t.Fatalf("alice policy %+v %v", ap, err)
	}
	if _, err := open(admin, "node-a"); code(err) != CodeNodeShellDisabled {
		t.Fatalf("node-a %v", err)
	}
	if _, err := open(alice, "node-c"); code(err) != CodeForbidden {
		t.Fatalf("alice node-c %v", err)
	}
	sh, err := open(alice, "node-b")
	if err != nil || sh.Session().Account != NodeShellAccount || sh.Session().Sudo {
		t.Fatalf("open %+v %v", sh, err)
	}
	if out := run(sh, "whoami"); !strings.Contains(out, "\r\nsfc-shell\r\n") {
		t.Fatalf("whoami %q", out)
	}
	if out := run(sh, "echo $SFC_USER"); !strings.Contains(out, "\r\nalice\r\n") {
		t.Fatalf("SFC_USER %q", out)
	}
	if out := run(sh, "sudo -i"); !strings.Contains(out, "not in the sudoers") {
		t.Fatalf("sudo off %q", out)
	}
	if err := sh.Resize(ctx, 120, 40); err != nil {
		t.Fatal(err)
	}

	// sudo on: a new session may become root.
	if _, res := submit(t, admin, ActionSetNodeShellNode, p.Revision, SetNodeShellNode{Node: "node-b", Shell: NodeShellOn, Sudo: true}, rootFor(t, admin, ActionSetNodeShellNode)); res.Code != ResultApplied {
		t.Fatalf("sudo on %v", res.Code)
	}
	if _, res := submit(t, alice, ActionSetNodeShellNode, p.Revision+1, SetNodeShellNode{Node: "node-b", Shell: NodeShellOff}, rootFor(t, alice, ActionSetNodeShellNode)); res.Code != ResultForbidden {
		t.Fatalf("alice changes policy %v", res.Code)
	}
	sh2, err := open(alice, "node-b")
	if err != nil || !sh2.Session().Sudo {
		t.Fatalf("open 2 %v", err)
	}
	if out := run(sh2, "sudo -i"); !strings.HasSuffix(out, "root@node-b:~# ") {
		t.Fatalf("sudo on %q", out)
	}
	if out := run(sh2, "whoami"); !strings.Contains(out, "\r\nroot\r\n") {
		t.Fatalf("root whoami %q", out)
	}

	// Sessions list and the admin's close.
	sp, err := admin.NodeShellSessions(ctx, "")
	ss := sp.Sessions
	if err != nil || len(ss) != 2 || sp.Total != 2 || sp.Next != "" || ss[0].State != NodeShellOpened || ss[0].CreatedAt == 0 || ss[0].BytesIn == 0 || ss[0].BytesOut == 0 || ss[0].Username != "alice" {
		t.Fatalf("sessions %+v %v", ss, err)
	}
	if _, err := bob.NodeShellSessions(ctx, ""); err == nil {
		t.Fatal("bob reads sessions")
	}
	if _, res := submit(t, alice, ActionCloseNodeShell, 0, CloseNodeShell{SessionID: ss[0].SessionID}, rootFor(t, alice, ActionCloseNodeShell)); res.Code != ResultForbidden {
		t.Fatalf("alice close %v", res.Code)
	}
	if _, res := submit(t, admin, ActionCloseNodeShell, 0, CloseNodeShell{SessionID: sh.Session().SessionID}, rootFor(t, admin, ActionCloseNodeShell)); res.Code != ResultApplied {
		t.Fatalf("close %v", res.Code)
	}
	if err := drain(sh); err != io.EOF {
		t.Fatalf("after close %v", err)
	}
	if c, r := sh.Exit(); r != "closed" || c == 0 {
		t.Fatalf("exit %d %s", c, r)
	}
	if e := sh.End(); e.Reason != "closed" || e.ClosedBy == nil || e.ClosedBy.User != "u-admin" || e.ClosedBy.Username != "admin" {
		t.Fatalf("end %+v", e)
	}
	if out := run(sh2, "exit"); !strings.Contains(out, "logout") {
		t.Fatalf("root exit %q", out)
	}
	run(sh2, "exit")
	if err := drain(sh2); err != io.EOF {
		t.Fatalf("after exit %v", err)
	}
	if c, r := sh2.Exit(); r != "exit" || c != 0 {
		t.Fatalf("exit %d %s", c, r)
	}
	if e := sh2.End(); e.ClosedBy != nil {
		t.Fatalf("self exit has ClosedBy %+v", e)
	}

	// Limit, not ready, unreachable, idle.
	p, _ = admin.NodeShellPolicy(ctx)
	if _, res := submit(t, admin, ActionSetNodeShellPolicy, p.Revision, SetNodeShellPolicy{Enabled: true, MaxSessions: 1, IdleSeconds: 60}, rootFor(t, admin, ActionSetNodeShellPolicy)); res.Code != ResultApplied {
		t.Fatalf("policy %v", res.Code)
	}
	a1, err := open(admin, "node-a")
	if err != nil {
		t.Fatalf("node-a after enable %v", err)
	}
	if _, err := open(admin, "node-a"); code(err) != CodeLimit {
		t.Fatalf("limit %v", err)
	}
	f.SetNodeShellNotReady("node-c", "useradd failed")
	if _, err := open(admin, "node-c"); code(err) != CodeNodeShellNotReady {
		t.Fatalf("not ready %v", err)
	}
	if _, err := open(admin, "node-d"); code(err) == "" {
		t.Fatalf("node-d %v", err)
	}
	clk.add(2 * time.Minute)
	if err := drain(a1); err != io.EOF {
		t.Fatalf("idle %v", err)
	}
	if _, r := a1.Exit(); r != "idle" {
		t.Fatalf("idle reason %s", r)
	}

	// Events: opened/closed/denied, counts only.
	ev, _ := seedEvents(admin, "", "")
	kinds := map[string]int{}
	for _, e := range ev.Items {
		if strings.HasPrefix(e.Kind, "node-shell-") {
			kinds[e.Kind]++
			if strings.Contains(e.Detail, "whoami") {
				t.Fatalf("keys recorded %+v", e)
			}
		}
	}
	if kinds["node-shell-opened"] != 3 || kinds["node-shell-closed"] != 3 || kinds["node-shell-denied"] < 4 {
		t.Fatalf("events %v", kinds)
	}
}

// The grant action replaces a user's server list.
func TestNodeShellGrant(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	p, _ := admin.NodeShellPolicy(ctx)
	if _, res := submit(t, admin, ActionSetNodeShellGrant, p.Revision, SetNodeShellGrant{User: "u-bob", Nodes: []string{"node-c", "node-b"}}, rootFor(t, admin, ActionSetNodeShellGrant)); res.Code != ResultApplied {
		t.Fatalf("grant %v", res.Code)
	}
	bp, err := bob.NodeShellPolicy(ctx)
	if err != nil || len(bp.Nodes) != 2 || len(bp.Grants) != 1 || bp.Grants[0].Nodes[0] != "node-b" {
		t.Fatalf("bob policy %+v %v", bp, err)
	}
	if _, res := submit(t, admin, ActionSetNodeShellGrant, p.Revision, SetNodeShellGrant{User: "u-bob"}, rootFor(t, admin, ActionSetNodeShellGrant)); res.Code != ResultConditionFailed {
		t.Fatalf("stale revision %v", res.Code)
	}
}

// turning a server's shell off ends its open shells with reason
// policy and ClosedBy the signer; the closed event carries the same.
func TestNodeShellClosedByPolicy(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	op, err := alice.Prepare(ctx, Change{Action: ActionOpenNodeShell, Payload: mustPayload(t, OpenNodeShell{Node: "node-b", Cols: 80, Rows: 24})}, rootFor(t, alice, ActionOpenNodeShell))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := openShell(t, alice, op)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := admin.NodeShellPolicy(ctx)
	if _, res := submit(t, admin, ActionSetNodeShellNode, p.Revision, SetNodeShellNode{Node: "node-b", Shell: "off"}, rootFor(t, admin, ActionSetNodeShellNode)); res.Code != ResultApplied {
		t.Fatalf("off %v", res.Code)
	}
	c, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for {
		if _, err := sh.Recv(c); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("recv %v", err)
			}
			break
		}
	}
	if e := sh.End(); e.Reason != "policy" || e.ClosedBy == nil || e.ClosedBy.Username != "admin" {
		t.Fatalf("end %+v", e)
	}
	ev, _ := seedEvents(admin, "", "")
	found := false
	for _, e := range ev.Items {
		if e.Kind == "node-shell-closed" && e.ShellClosedBy != nil && e.ShellClosedBy.User == "u-admin" {
			found = true
		}
	}
	if !found {
		t.Fatal("no closed event with ShellClosedBy")
	}
}

// Real shape: SessionID = the open's RequestID, closed sessions stay in the
// page with State closed and End, 8 a page by SessionID, the policy's
// RootRevision is the control/node-shell root.
func TestNodeShellSessionsPage(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	p, err := admin.NodeShellPolicy(ctx)
	if w, _ := admin.Whoami(ctx); err != nil || p.RootRevision != w.RootFor(ActionOpenNodeShell) || p.Index == 0 {
		t.Fatalf("policy %+v %v", p, err)
	}
	if _, res := submit(t, admin, ActionSetNodeShellPolicy, p.Revision, SetNodeShellPolicy{MaxSessions: 16, IdleSeconds: 1800}, rootFor(t, admin, ActionSetNodeShellPolicy)); res.Code != ResultApplied {
		t.Fatalf("policy %v", res.Code)
	}
	var shells []NodeShell
	for i := 0; i < 9; i++ {
		id := fmt.Sprintf("shell-%02d", i)
		op, err := admin.PrepareRequest(ctx, id, Change{Action: ActionOpenNodeShell, Payload: mustPayload(t, OpenNodeShell{Node: "node-b", Cols: 80, Rows: 24})}, rootFor(t, admin, ActionOpenNodeShell))
		if err != nil {
			t.Fatal(err)
		}
		sh, err := openShell(t, admin, op)
		if err != nil || sh.Session().SessionID != id {
			t.Fatalf("open %d %v", i, err)
		}
		shells = append(shells, sh)
		if i == 0 {
			if _, err := openShell(t, admin, op); err == nil {
				t.Fatal("same ID opened twice")
			}
		}
	}
	if err := shells[0].Close(); err != nil {
		t.Fatal(err)
	}
	pg, err := admin.NodeShellSessions(ctx, "")
	if err != nil || len(pg.Sessions) != 8 || pg.Total != 9 || pg.Next != "shell-07" {
		t.Fatalf("page %+v %v", pg, err)
	}
	if s := pg.Sessions[0]; s.State != NodeShellClosed || s.ClosedAt == 0 || s.End == nil || s.End.Reason != "exit" || s.End.ClosedBy != nil {
		t.Fatalf("closed %+v", s)
	}
	pg2, err := admin.NodeShellSessions(ctx, pg.Next)
	if err != nil || len(pg2.Sessions) != 1 || pg2.Next != "" || pg2.Sessions[0].SessionID != "shell-08" || pg2.Sessions[0].State != NodeShellOpened {
		t.Fatalf("page 2 %+v %v", pg2, err)
	}
}

// REQ-69 (mock): State / Node filters with matching Total and Next, and at
// most NodeShellClosedKeep closed sessions per server.
func TestNodeShellSessionsFilter(t *testing.T) {
	f, clk := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	open := func(id string) NodeShell {
		t.Helper()
		op, err := admin.PrepareRequest(ctx, id, Change{Action: ActionOpenNodeShell, Payload: mustPayload(t, OpenNodeShell{Node: "node-b", Cols: 80, Rows: 24})}, rootFor(t, admin, ActionOpenNodeShell))
		if err != nil {
			t.Fatal(err)
		}
		sh, err := openShell(t, admin, op)
		if err != nil {
			t.Fatal(err)
		}
		return sh
	}
	for i := 0; i < NodeShellClosedKeep+5; i++ {
		if err := open(fmt.Sprintf("old-%03d", i)).Close(); err != nil {
			t.Fatal(err)
		}
	}
	open("live-1")
	open("live-2")
	q := func(state, node, after string) NodeShellSessionsPage {
		t.Helper()
		p, err := admin.QueryNodeShellSessions(ctx, NodeShellSessionsQuery{State: state, Node: node, After: after})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := q(NodeShellStateOpen, "", ""); p.Total != 2 || len(p.Sessions) != 2 || p.Next != "" || p.Sessions[0].SessionID != "live-1" {
		t.Fatalf("open %+v", p)
	}
	if p := q(NodeShellStateOpen, "node-c", ""); p.Total != 0 || len(p.Sessions) != 0 {
		t.Fatalf("node-c %+v", p)
	}
	// Same ClosedAt (fake clock): the window keeps the lowest SessionIDs, so
	// old-200..old-204 drop out of the list (records stay).
	p := q(NodeShellClosed, "node-b", "")
	if p.Total != NodeShellClosedKeep || len(p.Sessions) != 8 || p.Next != "old-007" || p.Sessions[0].SessionID != "old-000" {
		t.Fatalf("closed %d %d %q %s", p.Total, len(p.Sessions), p.Next, p.Sessions[0].SessionID)
	}
	if p2 := q(NodeShellClosed, "node-b", p.Next); p2.Total != NodeShellClosedKeep || p2.Sessions[0].SessionID != "old-008" {
		t.Fatalf("closed 2 %+v", p2.Sessions[0])
	}
	if all, _ := admin.NodeShellSessions(ctx, ""); all.Total != NodeShellClosedKeep+2 {
		t.Fatalf("all %d", all.Total)
	}
	if _, err := admin.QueryNodeShellSessions(ctx, NodeShellSessionsQuery{State: "opened"}); err == nil {
		t.Fatal("bad state")
	}
	if p := q("", "node-z", ""); p.Total != 0 {
		t.Fatalf("unknown node %+v", p)
	}
	// A newer close enters the window and pushes the highest ID out.
	clk.add(time.Second)
	open("new-1").Close()
	if p := q(NodeShellClosed, "node-b", ""); p.Total != NodeShellClosedKeep || p.Sessions[0].SessionID != "new-1" || p.Sessions[1].SessionID != "old-000" {
		t.Fatalf("window %+v", p.Sessions[:2])
	}
	if p := q(NodeShellClosed, "node-b", "old-197"); len(p.Sessions) != 1 || p.Sessions[0].SessionID != "old-198" {
		t.Fatalf("window end %+v", p.Sessions)
	}
	if _, err := openShell(t, admin, mustPrepare(t, admin, "old-204")); err == nil {
		t.Fatal("reused a dropped ID")
	}
}

// REQ-67 two steps: submit open-node-shell (queued or refused with sfcd's
// Result codes), then OpenNodeShell with the same signed request.
func TestNodeShellSubmitOpen(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	req := func(node string) OpenNodeShell { return OpenNodeShell{Node: node, Cols: 80, Rows: 24} }
	refused := func(c Conn, node string, want ResultCode, n int) {
		t.Helper()
		_, res := submit(t, c, ActionOpenNodeShell, 0, req(node), rootFor(t, c, ActionOpenNodeShell))
		if res.Code != want || int(res.Code) != n || res.Reason != ResultErrorCode(want) {
			t.Fatalf("%s: %+v want %d", node, res, n)
		}
	}
	if _, res := submit(t, bob, ActionOpenNodeShell, 0, req("node-b"), rootFor(t, bob, ActionOpenNodeShell)); res.Code != ResultForbidden || int(res.Code) != 4 {
		t.Fatalf("bob %+v", res)
	}
	if _, res := submit(t, alice, ActionOpenNodeShell, 1, req("node-b"), rootFor(t, alice, ActionOpenNodeShell)); res.Code != ResultConditionFailed || int(res.Code) != 1 {
		t.Fatalf("expected 1 %+v", res)
	}
	refused(admin, "node-a", ResultNodeShellDisabled, 17)
	f.SetNodeShellNotReady("node-b", "ssh-unavailable")
	refused(alice, "node-b", ResultNodeShellNotReady, 18)
	f.SetNodeShellNotReady("node-b", "")
	f.SetNodeStatus("node-b", "unreachable")
	refused(alice, "node-b", ResultNodeShellUnreachable, 20)
	f.SetNodeStatus("node-b", "ready")
	if ResultErrorCode(ResultNodeShellDisabled) != "node-shell-disabled" || ResultErrorCode(ResultNodeShellLimit) != "limit" {
		t.Fatal("reason names")
	}

	// Accepted: queued until the stream opens it.
	op, res := submit(t, alice, ActionOpenNodeShell, 0, req("node-b"), rootFor(t, alice, ActionOpenNodeShell))
	if res.Code != ResultApplied {
		t.Fatalf("open %+v", res)
	}
	pg, _ := alice.QueryNodeShellSessions(ctx, NodeShellSessionsQuery{State: NodeShellStateOpen})
	if pg.Total != 1 || pg.Sessions[0].State != NodeShellQueued || pg.Sessions[0].OpenedAt != 0 {
		t.Fatalf("queued %+v", pg)
	}
	if _, err := bob.OpenNodeShell(ctx, op); err == nil {
		t.Fatal("another user's queued session")
	}
	direct, _ := alice.Prepare(ctx, Change{Action: ActionOpenNodeShell, Payload: mustPayload(t, req("node-b"))}, rootFor(t, alice, ActionOpenNodeShell))
	if _, err := alice.OpenNodeShell(ctx, direct); err == nil {
		t.Fatal("opened without submit")
	}
	sh, err := openShell(t, alice, op)
	if err != nil {
		t.Fatal(err)
	}
	if pg, _ = alice.QueryNodeShellSessions(ctx, NodeShellSessionsQuery{State: NodeShellStateOpen}); pg.Total != 1 || pg.Sessions[0].State != NodeShellOpened {
		t.Fatalf("opened %+v", pg)
	}
	if _, err := alice.OpenNodeShell(ctx, op); err == nil {
		t.Fatal("second PTY for the same ID")
	}
	_ = sh.Close()

	// Limit: queued sessions hold slots (MaxSessions 4).
	for i := 0; i < 4; i++ {
		if _, res := submit(t, alice, ActionOpenNodeShell, 0, req("node-b"), rootFor(t, alice, ActionOpenNodeShell)); res.Code != ResultApplied {
			t.Fatalf("queue %d %+v", i, res)
		}
	}
	refused(alice, "node-b", ResultNodeShellLimit, 19)
}

// openShell: the two steps (submit, then OpenNodeShell with the same op). A
// refused submit comes back as an *Error with the refusal's code name.
func openShell(t *testing.T, c Conn, op SignedOp) (NodeShell, error) {
	t.Helper()
	res, err := c.Submit(ctx, op)
	if err != nil {
		return nil, err
	}
	switch {
	case res.Code == ResultApplied:
		return c.OpenNodeShell(ctx, op)
	case res.Code == ResultForbidden:
		return nil, &Error{Code: CodeForbidden}
	case res.Reason != "":
		return nil, &Error{Code: Code(res.Reason)}
	}
	return nil, &Error{Code: CodeInvalid}
}

func mustPrepare(t *testing.T, c Conn, id string) SignedOp {
	t.Helper()
	op, err := c.PrepareRequest(ctx, id, Change{Action: ActionOpenNodeShell, Payload: mustPayload(t, OpenNodeShell{Node: "node-b", Cols: 80, Rows: 24})}, rootFor(t, c, ActionOpenNodeShell))
	if err != nil {
		t.Fatal(err)
	}
	return op
}
