// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/eventlog"
)

// NodeShellEvents is called before ProjectEvents' Applied-only guard so an
// original denied open has the same public operation/event accounting. It
// consumes only committed metadata and never screen, input or native errors.
func (p Policy) NodeShellEvents(before, after state.State, command state.Command, result state.Result) ([]eventlog.Event, error) {
	if result.Index != after.Index() {
		return nil, nil
	}
	if command.Key == NodeShellKey && result.Code != state.Applied {
		var op UserOperation
		var q NodeShellOpen
		if canonical([]byte(command.Value), &op) != nil || op.VerifyOriginal(p.Cluster) != nil || op.Change.Action != "open-node-shell" || canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Node) || op.At <= 0 || uint64(op.At) > ^uint64(0)/1000 {
			return nil, nil
		}
		code := NodeShellErrorCode(p.CheckNodeShellOpen(before, op, op.At))
		if code == "" {
			code = "conflict"
		}
		return []eventlog.Event{{Kind: "node-shell-denied", Scope: "node", At: uint64(op.At) * 1000, Target: eventlog.Target{Node: q.Node}, Detail: eventlog.Detail{Actor: op.Session.User, Operation: op.RequestID, Code: code}}}, nil
	}
	if result.Code != state.Applied || before.Object(NodeShellKey) == after.Object(NodeShellKey) {
		return nil, nil
	}
	old, err := p.NodeShells(before)
	if err != nil {
		return nil, err
	}
	next, err := p.NodeShells(after)
	if err != nil {
		return nil, err
	}
	var events []eventlog.Event
	for _, record := range next.Records {
		row := record.Session
		prior, found := old.Record(row.SessionID)
		kind := ""
		at := row.OpenedAt
		if row.State == "opened" && (!found || prior.Session.OpenedAt == 0) {
			kind = "node-shell-opened"
		}
		if row.State == "closed" && (!found || prior.Session.State != "closed") {
			kind = "node-shell-closed"
			at = row.ClosedAt
		}
		if kind == "" || at <= 0 || uint64(at) > ^uint64(0)/1000 {
			continue
		}
		detail := eventlog.Detail{Actor: row.User, Operation: row.SessionID, BytesIn: row.BytesIn, BytesOut: row.BytesOut}
		if row.End != nil {
			detail.Reason = row.End.Reason
			code := row.End.Code
			detail.ExitCode = &code
			if row.End.ClosedBy != nil {
				detail.ClosedBy = &eventlog.ActorIdentity{User: row.End.ClosedBy.User, Username: row.End.ClosedBy.Username}
			}
		}
		events = append(events, eventlog.Event{Kind: kind, Scope: "node", At: uint64(at) * 1000, Target: eventlog.Target{Node: row.Node}, Detail: detail})
	}
	return events, nil
}
