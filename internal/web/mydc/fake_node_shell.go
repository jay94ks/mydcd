// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// REQ-67 in the fake. Fixture: cluster policy off; node-b shell on (sudo
// off); alice holds NodeShell for node-b. Every active, reachable server is
// ready unless Fake.SetNodeShellNotReady says otherwise; an unreachable one
// (summary Status "unreachable", node-d) is node-unreachable.
//
// The PTY is a tiny line shell: it echoes keys, answers whoami (the
// account), id, hostname, echo $MYDC_USER, sudo -i (root prompt only when
// sudo is allowed for this session) and exit; anything else is "command not
// found".
// A policy/grant change that no longer allows a session ends it with reason
// "policy" and ClosedBy = the change's signer.
// The idle limit is checked against the fake clock on every call.

type shellState struct {
	policy   NodeShellPolicy
	nodes    map[string]*NodeShellNode
	notReady map[string]string
	grants   map[string][]string
	sessions map[string]*fakeShell // open
	records  map[string]*fakeShell // every session, closed ones kept
}

func (w *world) shells() *shellState {
	if w.shell == nil {
		w.shell = &shellState{
			policy:   NodeShellPolicy{MaxSessions: 4, IdleSeconds: 1800, Account: NodeShellAccount, Revision: 1},
			nodes:    map[string]*NodeShellNode{"node-b": {Node: "node-b", Shell: NodeShellOn}},
			notReady: map[string]string{},
			grants:   map[string][]string{"u-alice": {"node-b"}},
			sessions: map[string]*fakeShell{},
			records:  map[string]*fakeShell{},
		}
	}
	return w.shell
}

// SetNodeShellNotReady marks a server's account/key as not prepared
// (reason "" makes it ready again).
func (f *Fake) SetNodeShellNotReady(node, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.w.shells()
	if reason == "" {
		delete(s.notReady, node)
	} else {
		s.notReady[node] = reason
	}
}

func (w *world) shellNode(node string) NodeShellNode {
	s := w.shells()
	n := NodeShellNode{Node: node, Shell: NodeShellInherit}
	if x := s.nodes[node]; x != nil {
		n.Shell, n.Sudo = x.Shell, x.Sudo
	}
	n.Enabled = n.Shell == NodeShellOn || n.Shell == NodeShellInherit && s.policy.Enabled
	n.Ready = true
	if i := w.memberIndex(node); i < 0 || w.members[i].Phase != NodePhaseActive {
		n.Ready, n.NotReady = false, "server is not active"
	} else if r := s.notReady[node]; r != "" {
		n.Ready, n.NotReady = false, r
	}
	return n
}

func (w *world) shellReachable(node string) bool {
	for _, s := range w.summaries {
		if s.Node == node {
			return s.Status != "unreachable"
		}
	}
	return true
}

func (w *world) shellAllowed(user, node string) bool {
	return w.admin(user) || slices.Contains(w.shells().grants[user], node)
}

// NodeShellPolicy: `node-shell-policy`.
func (c *fakeConn) NodeShellPolicy(ctx context.Context) (NodeShellPolicy, error) {
	const m = "node-shell-policy"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return NodeShellPolicy{}, err
	}
	defer c.unlock()
	w := c.f.w
	s := w.shells()
	w.expireShells(c.f.now())
	if !w.admin(user) && len(s.grants[user]) == 0 {
		return NodeShellPolicy{}, fail(m, CodeDenied, "")
	}
	out := s.policy
	out.Index, out.RootRevision = w.root, w.keyRoot(control.NodeShellKey)
	out.Nodes, out.Grants = []NodeShellNode{}, []NodeShellGrant{}
	for _, mb := range w.members {
		if w.shellAllowed(user, mb.ID) {
			out.Nodes = append(out.Nodes, w.shellNode(mb.ID))
		}
	}
	for _, u := range sortedKeys(s.grants) {
		if w.admin(user) || u == user {
			out.Grants = append(out.Grants, NodeShellGrant{User: u, Nodes: slices.Clone(s.grants[u])})
		}
	}
	return out, nil
}

// NodeShellSessions: `node-shell-sessions`, every state (REQ-69's
// QueryNodeShellSessions with only After).
func (c *fakeConn) NodeShellSessions(ctx context.Context, after string) (NodeShellSessionsPage, error) {
	return c.QueryNodeShellSessions(ctx, NodeShellSessionsQuery{After: after})
}

// QueryNodeShellSessions: `node-shell-sessions`, 8 a page by SessionID
// ascending (After = the previous Next). REQ-69 (mock): State open (queued,
// opened, closing) / closed / "" and Node narrow the rows, Total and Next.
// At most NodeShellClosedKeep closed sessions per server are kept.
func (c *fakeConn) QueryNodeShellSessions(ctx context.Context, q NodeShellSessionsQuery) (NodeShellSessionsPage, error) {
	const m = "node-shell-sessions"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return NodeShellSessionsPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	if len(q.After) > 256 || !(control.NodeShellSessionsQuery{State: q.State, Node: q.Node}).Valid() {
		return NodeShellSessionsPage{}, fail(m, CodeInvalid, "query")
	}
	if !w.admin(user) && len(w.shells().grants[user]) == 0 {
		return NodeShellSessionsPage{}, fail(m, CodeDenied, "")
	}
	w.expireShells(c.f.now())
	admin := w.admin(user)
	out := NodeShellSessionsPage{Schema: 1, Index: w.root, RootRevision: w.keyRoot(control.NodeShellKey), Sessions: []NodeShellSession{}}
	// As mydcd: open rows always; closed rows only inside the per-node window
	// of the newest NodeShellClosedKeep (ClosedAt descending, ties SessionID
	// ascending), chosen before the caller's visibility. Records stay.
	var rows, closed []NodeShellSession
	for _, id := range sortedKeys(w.shell.records) {
		v := w.shell.records[id].snapshot()
		if q.Node != "" && v.Node != q.Node {
			continue
		}
		if v.State == NodeShellClosed {
			closed = append(closed, v)
		} else if q.State != NodeShellClosed && (admin || v.User == user) {
			rows = append(rows, v)
		}
	}
	if q.State != NodeShellStateOpen {
		slices.SortStableFunc(closed, func(a, b NodeShellSession) int {
			if a.ClosedAt != b.ClosedAt {
				return cmp.Compare(b.ClosedAt, a.ClosedAt)
			}
			return strings.Compare(a.SessionID, b.SessionID)
		})
		per := map[string]int{}
		for _, v := range closed {
			per[v.Node]++
			if per[v.Node] <= NodeShellClosedKeep && (admin || v.User == user) {
				rows = append(rows, v)
			}
		}
	}
	slices.SortFunc(rows, func(a, b NodeShellSession) int { return strings.Compare(a.SessionID, b.SessionID) })
	out.Total = len(rows) // rows before After count too
	for _, v := range rows {
		if v.SessionID <= q.After {
			continue
		}
		if len(out.Sessions) == 8 {
			out.Next = out.Sessions[7].SessionID
			break
		}
		out.Sessions = append(out.Sessions, v)
	}
	return out, nil
}

func (w *world) shellDenied(node, user, code string, now int64) {
	w.addEvent(FixtureEvent{Time: now, Scope: "node", Node: node, Kind: "node-shell-denied", Target: node, Detail: w.username(user) + " " + code})
}

// OpenNodeShell: the signed open-node-shell request, after Submit queued it
// (same op); the reply is the PTY stream.
func (c *fakeConn) OpenNodeShell(ctx context.Context, raw SignedOp) (NodeShell, error) {
	const m = "open-node-shell"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return nil, err
	}
	defer c.unlock()
	op, _, err := c.decodeOp(m, raw)
	if err != nil {
		return nil, err
	}
	w := c.f.w
	now := c.f.now()
	var q OpenNodeShell
	if op.Session.ID != c.session.ID || op.Change.Action != ActionOpenNodeShell || op.Change.Expected != 0 || decodePayload(op.Change.Payload, &q) != nil ||
		q.Cols == 0 || q.Rows == 0 || q.Cols > 1000 || q.Rows > 1000 || op.At > now.Unix() || now.Unix()-op.At > 30 {
		return nil, fail(m, CodeInvalid, "request")
	}
	s := w.shells()
	w.expireShells(now)
	if w.memberIndex(q.Node) < 0 {
		return nil, fail(m, CodeMissing, "")
	}
	// Two steps: only a session queued by the submitted
	// open-node-shell (same signed op) opens here.
	sh := s.records[op.RequestID]
	if sh == nil {
		return nil, fail(m, CodeInvalid, "not queued: submit open-node-shell first")
	}
	if sh.view.State != NodeShellQueued || sh.view.User != user || sh.view.Node != q.Node {
		return nil, fail(m, CodeInvalid, "session ID already used")
	}
	if code := w.shellRefusal(user, q.Node, true); code != "" {
		w.shellDenied(q.Node, user, string(code), now.Unix())
		w.endShell(sh.view.SessionID, string(code), "", now)
		return nil, fail(m, code, "")
	}
	at := now.Unix()
	sh.view.State, sh.view.OpenedAt, sh.view.LastActivity = NodeShellOpened, at, at
	sh.out.WriteString("MYDC_USER=" + sh.view.Username + "\r\n" + sh.prompt())
	sh.view.BytesOut = uint64(sh.out.Len())
	w.bumpKey(control.NodeShellKey)
	w.addEvent(FixtureEvent{Time: at, Scope: "node", Node: q.Node, Kind: "node-shell-opened", Target: sh.view.SessionID, Detail: sh.view.Username})
	return sh, nil
}

// shellRefusal: why user may not open a shell on node now ("" = allowed),
// in mydcd's order. queued: the session already holds its own slot.
func (w *world) shellRefusal(user, node string, queued bool) Code {
	s := w.shells()
	n := w.shellNode(node)
	switch {
	case !w.shellAllowed(user, node):
		return CodeForbidden
	case !n.Enabled:
		return CodeNodeShellDisabled
	case !w.shellReachable(node):
		return CodeNodeUnreachable
	case !n.Ready:
		return CodeNodeShellNotReady
	}
	open := 0
	for _, sh := range s.sessions {
		if sh.view.User == user && sh.view.Node == node {
			open++
		}
	}
	if queued {
		open--
	}
	if open >= s.policy.MaxSessions {
		return CodeLimit
	}
	return ""
}

// queueShell records a queued session (it counts toward the limits).
func (c *fakeConn) queueShell(id, user string, q OpenNodeShell, now time.Time) *fakeShell {
	w := c.f.w
	s := w.shells()
	n := w.shellNode(q.Node)
	sh := &fakeShell{f: c.f, notify: make(chan struct{}, 1), sudo: n.Sudo, cols: q.Cols, rows: q.Rows}
	at := now.Unix()
	sh.view = NodeShellSession{SessionID: id, User: user, Username: w.username(user), Node: q.Node, Account: s.policy.Account,
		Sudo: n.Sudo, CreatedAt: at, LastActivity: at, State: NodeShellQueued}
	s.sessions[id] = sh
	s.records[id] = sh
	return sh
}

// applyOpenNodeShell: the submitted open-node-shell. Accepting it
// queues the session (State queued); OpenNodeShell with the same signed
// request then opens the PTY. Refusals are mydcd's Result codes:
// Forbidden (no grant), 17 node-shell-disabled, 18 node-shell-not-ready,
// 19 limit, 20 node-unreachable, with Result.Reason the code name.
func (c *fakeConn) applyOpenNodeShell(op UserOperation, actor string) error {
	w := c.f.w
	ch := op.Change
	var q OpenNodeShell
	if decodePayload(ch.Payload, &q) != nil || q.Node == "" || q.Cols == 0 || q.Rows == 0 || q.Cols > 1000 || q.Rows > 1000 {
		return errors.New("payload")
	}
	if ch.Expected != 0 {
		return errCAS
	}
	if w.memberIndex(q.Node) < 0 {
		return errors.New("unknown node")
	}
	s := w.shells()
	now := c.f.now()
	w.expireShells(now)
	if s.records[op.RequestID] != nil {
		return errors.New("session ID already used")
	}
	switch code := w.shellRefusal(actor, q.Node, false); code {
	case "":
	case CodeForbidden:
		w.shellDenied(q.Node, actor, string(code), now.Unix())
		return errForbidden
	default:
		w.shellDenied(q.Node, actor, string(code), now.Unix())
		return nodeRemoveRefused{string(code)}
	}
	c.queueShell(op.RequestID, actor, q, now)
	w.bumpKey(control.NodeShellKey)
	return nil
}

// endShell: f.mu held.
func (w *world) endShell(id, reason, closer string, now time.Time) bool {
	s := w.shells()
	sh := s.sessions[id]
	if sh == nil {
		return false
	}
	delete(s.sessions, id)
	sh.mu.Lock()
	if !sh.done {
		sh.done, sh.reason = true, reason
		if reason != "exit" {
			sh.code = 130
		}
	}
	if (sh.reason == "closed" || sh.reason == "policy") && closer != "" {
		sh.closedBy = &NodeShellUser{User: closer, Username: w.username(closer)}
	}
	end := NodeShellEnd{Code: sh.code, Reason: sh.reason, ClosedBy: sh.closedBy}
	sh.view.State, sh.view.ClosedAt, sh.view.End = NodeShellClosed, now.Unix(), &end
	in, out := sh.view.BytesIn, sh.view.BytesOut
	by := sh.closedBy
	sh.mu.Unlock()
	sh.wake()
	detail := fmt.Sprintf("%s %s in=%d out=%d", sh.view.Username, reason, in, out)
	if by != nil {
		detail += " by=" + by.Username
	}
	w.addEvent(FixtureEvent{Time: now.Unix(), Scope: "node", Node: sh.view.Node, Kind: "node-shell-closed", Target: id, Detail: detail, ShellClosedBy: by})
	w.bumpKey(control.NodeShellKey)
	return true
}

func (w *world) expireShells(now time.Time) {
	s := w.shells()
	for _, id := range sortedKeys(s.sessions) {
		sh := s.sessions[id]
		sh.mu.Lock()
		idle := now.Unix()-sh.view.LastActivity > int64(s.policy.IdleSeconds)
		sh.mu.Unlock()
		if idle {
			w.endShell(id, "idle", "", now)
		}
	}
}

func (c *fakeConn) applyNodeShell(op UserOperation, actor string) error {
	w := c.f.w
	s := w.shells()
	ch := op.Change
	if !w.admin(actor) {
		return errForbidden
	}
	if ch.Action == ActionCloseNodeShell {
		var q CloseNodeShell
		if decodePayload(ch.Payload, &q) != nil || q.SessionID == "" || ch.Expected != 0 {
			return errors.New("payload")
		}
		if !w.endShell(q.SessionID, "closed", actor, c.f.now()) {
			return errCAS // unknown or already closed
		}
		return nil
	}
	if ch.Expected != s.policy.Revision {
		return errCAS
	}
	switch ch.Action {
	case ActionSetNodeShellPolicy:
		var q SetNodeShellPolicy
		if decodePayload(ch.Payload, &q) != nil || q.MaxSessions < 1 || q.MaxSessions > 16 || q.IdleSeconds < 60 || q.IdleSeconds > 86400 {
			return errors.New("payload")
		}
		s.policy.Enabled, s.policy.MaxSessions, s.policy.IdleSeconds = q.Enabled, q.MaxSessions, q.IdleSeconds
	case ActionSetNodeShellNode:
		var q SetNodeShellNode
		if decodePayload(ch.Payload, &q) != nil || w.memberIndex(q.Node) < 0 || q.Shell != NodeShellInherit && q.Shell != NodeShellOn && q.Shell != NodeShellOff {
			return errors.New("payload")
		}
		s.nodes[q.Node] = &NodeShellNode{Node: q.Node, Shell: q.Shell, Sudo: q.Sudo}
	case ActionSetNodeShellGrant:
		var q SetNodeShellGrant
		if decodePayload(ch.Payload, &q) != nil || w.users[q.User] == nil {
			return errors.New("payload")
		}
		nodes := slices.Clone(q.Nodes)
		slices.Sort(nodes)
		for i, n := range nodes {
			if w.memberIndex(n) < 0 || i > 0 && nodes[i-1] == n {
				return errors.New("payload")
			}
		}
		if len(nodes) == 0 {
			delete(s.grants, q.User)
		} else {
			s.grants[q.User] = nodes
		}
	default:
		return errors.New("action")
	}
	s.policy.Revision++
	// Sessions the new policy no longer allows end now (REQ-68 "policy").
	for _, id := range sortedKeys(s.sessions) {
		sh := s.sessions[id]
		if !w.shellAllowed(sh.view.User, sh.view.Node) || !w.shellNode(sh.view.Node).Enabled {
			w.endShell(id, "policy", actor, c.f.now())
		}
	}
	return nil
}

// fakeShell: the PTY. f.mu guards the world; mu guards the buffers.
type fakeShell struct {
	f        *Fake
	mu       sync.Mutex
	view     NodeShellSession
	out      bytes.Buffer
	line     []byte
	notify   chan struct{}
	sudo     bool
	root     bool
	done     bool
	code     int
	reason   string
	closedBy *NodeShellUser
	cols     uint16
	rows     uint16
}

func (sh *fakeShell) prompt() string {
	if sh.root {
		return "root@" + sh.view.Node + ":~# "
	}
	return sh.view.Account + "@" + sh.view.Node + ":~$ "
}

func (sh *fakeShell) wake() {
	select {
	case sh.notify <- struct{}{}:
	default:
	}
}

func (sh *fakeShell) Session() NodeShellSession {
	return sh.snapshot()
}

func (sh *fakeShell) snapshot() NodeShellSession {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	v := sh.view
	if v.End != nil {
		e := *v.End
		if e.ClosedBy != nil {
			by := *e.ClosedBy
			e.ClosedBy = &by
		}
		v.End = &e
	}
	return v
}

func (sh *fakeShell) Exit() (int, string) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.code, sh.reason
}

func (sh *fakeShell) touch() {
	sh.f.mu.Lock()
	now := sh.f.now()
	sh.f.w.expireShells(now)
	sh.f.mu.Unlock()
	sh.mu.Lock()
	if !sh.done {
		sh.view.LastActivity = now.Unix()
	}
	sh.mu.Unlock()
}

func (sh *fakeShell) Recv(ctx context.Context) ([]byte, error) {
	sh.f.mu.Lock()
	sh.f.w.expireShells(sh.f.now())
	sh.f.mu.Unlock()
	for {
		sh.mu.Lock()
		if sh.out.Len() > 0 {
			b := bytes.Clone(sh.out.Bytes())
			sh.out.Reset()
			sh.mu.Unlock()
			return b, nil
		}
		if sh.done {
			sh.mu.Unlock()
			return nil, io.EOF
		}
		sh.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, fail("node-shell", CodeTransport, ctx.Err().Error())
		case <-sh.notify:
		}
	}
}

func (sh *fakeShell) Send(ctx context.Context, data []byte) error {
	sh.touch()
	sh.mu.Lock()
	if sh.done {
		sh.mu.Unlock()
		return fail("node-shell", CodeClosed, "")
	}
	sh.view.BytesIn += uint64(len(data))
	var exit bool
	before := sh.out.Len()
	for _, b := range data {
		switch b {
		case '\r', '\n':
			sh.out.WriteString("\r\n")
			exit = sh.run(strings.TrimSpace(string(sh.line)))
			sh.line = sh.line[:0]
		case 0x7f, 0x08:
			if len(sh.line) > 0 {
				sh.line = sh.line[:len(sh.line)-1]
				sh.out.WriteString("\b \b")
			}
		default:
			sh.line = append(sh.line, b)
			sh.out.WriteByte(b)
		}
		if exit {
			break
		}
	}
	sh.view.BytesOut += uint64(sh.out.Len() - before)
	id := sh.view.SessionID
	sh.mu.Unlock()
	sh.wake()
	if exit {
		sh.f.mu.Lock()
		sh.f.w.endShell(id, "exit", "", sh.f.now())
		sh.f.mu.Unlock()
	}
	return nil
}

// run one command line; mu held. Reports whether the shell exits.
func (sh *fakeShell) run(cmd string) bool {
	user := sh.view.Account
	if sh.root {
		user = "root"
	}
	switch cmd {
	case "":
	case "exit", "logout":
		if sh.root {
			sh.root = false
			sh.out.WriteString("logout\r\n")
		} else {
			sh.out.WriteString("logout\r\n")
			sh.done, sh.reason, sh.code = true, "exit", 0
			return true
		}
	case "whoami":
		sh.out.WriteString(user + "\r\n")
	case "id":
		if sh.root {
			sh.out.WriteString("uid=0(root) gid=0(root) groups=0(root)\r\n")
		} else {
			sh.out.WriteString("uid=990(" + user + ") gid=990(" + user + ") groups=990(" + user + ")\r\n")
		}
	case "hostname":
		sh.out.WriteString(sh.view.Node + "\r\n")
	case "echo $MYDC_USER":
		sh.out.WriteString(sh.view.Username + "\r\n")
	case "sudo -i", "sudo su", "sudo -s":
		if sh.sudo {
			sh.root = true
		} else {
			sh.out.WriteString(sh.view.Account + " is not in the sudoers file.\r\n")
		}
	default:
		sh.out.WriteString(strings.Fields(cmd)[0] + ": command not found\r\n")
	}
	sh.out.WriteString(sh.prompt())
	return false
}

func (sh *fakeShell) End() NodeShellEnd {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := NodeShellEnd{Code: sh.code, Reason: sh.reason}
	if sh.closedBy != nil {
		by := *sh.closedBy
		e.ClosedBy = &by
	}
	return e
}

func (sh *fakeShell) Resize(ctx context.Context, cols, rows uint16) error {
	if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
		return fail("node-shell", CodeInvalid, "size")
	}
	sh.touch()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.done {
		return fail("node-shell", CodeClosed, "")
	}
	sh.cols, sh.rows = cols, rows
	return nil
}

func (sh *fakeShell) Close() error {
	sh.f.mu.Lock()
	defer sh.f.mu.Unlock()
	sh.f.w.endShell(sh.view.SessionID, "exit", "", sh.f.now())
	return nil
}
