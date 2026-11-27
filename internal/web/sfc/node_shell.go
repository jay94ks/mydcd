// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// REQ-67/68 server SSH shell: a PTY session as the server's dedicated
// Seafield Cluster account (not root). Types, actions and reads are sfcd's
// (docs/reference/node-shell.md); the fake still opens the PTY with one
// signed open-node-shell request (OpenNodeShell) where the real client
// submits it (queued) and then opens purpose19 with the original ID.
//
// Reads: `node-shell-policy` (system admin: everything; a user with
// NodeShell: the rows of the granted servers and their own grant) and
// `node-shell-sessions` (system admin: all; others: their own).
// Actions (system admin, Expected = NodeShellPolicy.Revision):
// set-node-shell-policy, set-node-shell-node, set-node-shell-grant.
// close-node-shell {SessionID} (system admin, Expected 0).
// open-node-shell {Node, Cols, Rows} is a signed request that opens a
// stream (Conn.OpenNodeShell), not a submit.
const (
	ActionSetNodeShellPolicy = "set-node-shell-policy"
	ActionSetNodeShellNode   = "set-node-shell-node"
	ActionSetNodeShellGrant  = "set-node-shell-grant"
	ActionOpenNodeShell      = "open-node-shell"
	ActionCloseNodeShell     = "close-node-shell"

	NodeShellAccount = access.NodeShellAccount

	// Server shell setting.
	NodeShellInherit = "inherit"
	NodeShellOn      = "on"
	NodeShellOff     = "off"
)

// Refusal codes of open-node-shell (Error.Code).
const (
	CodeNodeShellDisabled Code = "node-shell-disabled"
	CodeForbidden         Code = "forbidden"
	CodeNodeShellNotReady Code = "node-shell-not-ready"
	CodeLimit             Code = "limit"
	CodeNodeUnreachable   Code = "node-unreachable"
)

// The read and payload types are sfcd's (control/node_shell.go,
// docs/reference/unix-sockets.md purpose19):
//
//   - NodeShellPolicy {Enabled, MaxSessions, IdleSeconds, Account, Nodes,
//     Grants, Revision, Index, RootRevision}. Revision is the shared policy
//     revision all three changes CAS on; RootRevision is the control/node-shell
//     checkpoint root (also moved by readiness and session reports).
//   - NodeShellSessions page {Schema, Index, RootRevision, Sessions, Next,
//     Total}: 8 sessions a page by SessionID ascending, closed ones kept.
//   - NodeShellSession {SessionID (= the open's RequestID), User, Username,
//     Node, Account, Sudo, CreatedAt, OpenedAt, LastActivity, ClosedAt (Unix
//     s), BytesIn, BytesOut, State queued / opened / closing / closed, End?}.
type (
	NodeShellPolicy       = control.NodeShellPolicyView
	NodeShellNode         = control.NodeShellNodeView
	NodeShellGrant        = access.NodeShellGrant
	NodeShellSessionsPage = control.NodeShellSessionsPage
	NodeShellSession      = control.NodeShellSession
	SetNodeShellPolicy    = control.NodeShellPolicyChange
	SetNodeShellNode      = control.NodeShellNodeChange
	SetNodeShellGrant     = control.NodeShellGrantChange
	OpenNodeShell         = control.NodeShellOpen
	CloseNodeShell        = control.NodeShellClose
	// NodeShellEnd: how a shell ended; ClosedBy only for closed / policy.
	NodeShellEnd  = control.NodeShellEnd
	NodeShellUser = control.NodeShellUser
)

// NodeShellSessionsQuery: `node-shell-sessions` input. REQ-69 (real,
// control.NodeShellSessionsQuery plus After):
// State NodeShellStateOpen (queued, opened, closing) / NodeShellClosed /
// "" (all) and Node narrow the page.
type NodeShellSessionsQuery struct {
	After string `json:",omitempty"`
	State string `json:",omitempty"`
	Node  string `json:",omitempty"`
}

// NodeShellStateOpen: the REQ-69 State filter for not-yet-closed sessions.
const NodeShellStateOpen = "open"

// NodeShellClosedKeep: the per-server window of closed sessions in the list
// (REQ-69, sfcd NodeShellClosedListLimit). Records are not deleted.
const NodeShellClosedKeep = control.NodeShellClosedListLimit

// Session states.
const (
	NodeShellQueued  = "queued"
	NodeShellOpened  = "opened"
	NodeShellClosing = "closing"
	NodeShellClosed  = "closed"
)

// NodeShell is one open PTY session. Keys and screen content are not
// recorded anywhere; only the byte counts are.
type NodeShell interface {
	Session() NodeShellSession
	// Recv returns the next output bytes. After the shell ends (exit, idle
	// limit, close-node-shell) it returns io.EOF.
	Recv(ctx context.Context) ([]byte, error)
	// Send writes keys to the PTY.
	Send(ctx context.Context, data []byte) error
	// Resize changes the PTY size.
	Resize(ctx context.Context, cols, rows uint16) error
	// Exit after io.EOF: the shell's exit code and why it ended ("exit",
	// "idle", "closed" by close-node-shell, "policy" by a policy/grant
	// change).
	Exit() (code int, reason string)
	// End after io.EOF: Exit plus ClosedBy, the user who
	// closed it for "closed" (close-node-shell's signer) and "policy" (the
	// change's signer); nil for "exit" and "idle".
	End() NodeShellEnd
	// Close ends the session (the same as typing exit).
	Close() error
}
