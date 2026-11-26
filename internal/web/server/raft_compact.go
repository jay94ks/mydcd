// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// Manual raft log compaction (UI-17, raft-maintenance.md). The overview is
// mydcd's raft-status read as the caller; the web reads raft-compact-plan
// for the selection's Target and sends raft-compact (CompactChange,
// Expected 0) signed by the caller; raft-compact-status follows one job.
// mydcd decides who may (system administrators).

const (
	// mydcd does not report its configured count yet; hashicorp/raft's
	// default TrailingLogs and REQ-23's "minimal" default.
	raftRetainEntries  = 10240
	raftMinimalEntries = 1000
)

type raftCompactNode struct {
	Node           string `json:"node"`
	State          string `json:"state"`
	SnapshotIndex  uint64 `json:"snapshotIndex,omitempty"`
	SnapshotBytes  uint64 `json:"snapshotBytes,omitempty"`
	LogBytesBefore uint64 `json:"logBytesBefore,omitempty"`
	LogBytesAfter  uint64 `json:"logBytesAfter,omitempty"`
	DurationMs     int64  `json:"durationMs,omitempty"`
	Error          string `json:"error,omitempty"`
}

// compactRunning: the last manual compaction still has queued or running
// servers.
func compactRunning(st mydc.RaftStatus) bool {
	lc := st.LastManualCompact
	return lc != nil && !lc.Complete
}

// GET /raft/compact → {retain, minimal, entries:{node: n}, last?}
func (s *Server) handleRaftCompact(w http.ResponseWriter, r *http.Request, ws *webSession) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var st mydc.RaftStatus
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		st, err = c.RaftStatus(ctx)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	entries := map[string]uint64{}
	for _, n := range st.Nodes {
		if n.LogEntries != nil {
			entries[n.Node] = *n.LogEntries
		}
	}
	out := map[string]any{"retain": raftRetainEntries, "minimal": raftMinimalEntries, "entries": entries}
	if lc := st.LastManualCompact; lc != nil {
		last := map[string]any{"operation": lc.Operation, "at": rfc(int64(lc.At)), "by": lc.User, "mode": lc.Options.Mode}
		// the web op that holds this original, when it was sent from here
		if ops, err := s.opt.Store.ListOps(lc.User, "", 0); err == nil {
			for _, o := range ops {
				if compactOperation(o.ID) == lc.Operation {
					last["id"], last["by"] = o.ID, o.Username
					break
				}
			}
		}
		state := "done"
		if lc.Failed > 0 {
			state = "failed"
		}
		if !lc.Complete {
			state = "running"
		}
		nodes := []raftCompactNode{}
		for _, n := range st.Nodes {
			x := n.LastManualCompact
			if x == nil || x.Operation != lc.Operation {
				continue
			}
			row := raftCompactNode{Node: n.Node, State: x.State, SnapshotIndex: x.SnapshotIndex, SnapshotBytes: x.SnapshotBytes, DurationMs: int64(x.DurationMillis), Error: x.Code}
			if x.LogUsedKnown {
				row.LogBytesBefore, row.LogBytesAfter = x.LogUsedBytesBefore, x.LogUsedBytesAfter
			}
			nodes = append(nodes, row)
		}
		last["state"], last["nodes"] = state, nodes
		out["last"] = last
	}
	writeJSON(w, http.StatusOK, out)
}

// compactOperation: the raft-compact Operation of a web opId.
func compactOperation(opID string) string { return "op-" + opID }

// compactSelection: the screen's {nodes, mode, serial} as mydcd's
// selection (minimal keeps raftMinimalEntries).
func compactSelection(nodes []string, mode string, serial bool) (mydc.CompactSelection, error) {
	sel := mydc.CompactSelection{Nodes: nodes, Mode: mode, Parallel: !serial}
	if len(sel.Nodes) == 0 {
		sel.Nodes = nil
	}
	if mode == "minimal" {
		sel.Retain = raftMinimalEntries
	}
	if mode != "keep" && mode != "minimal" {
		return sel, invalid("mode: keep or minimal")
	}
	if !sel.Valid() {
		return sel, invalid("nodes: distinct server names, at most 256")
	}
	return sel, nil
}

// compactMaxPages: raft-compact-plan pages read for one plan (64 nodes a
// page), as the CLI's client.
const compactMaxPages = 16

// compactPlan reads every plan page; a Target or Total that changes
// between pages is 409 plan-changed.
func compactPlan(ctx context.Context, c mydc.Conn, sel mydc.CompactSelection) (mydc.CompactPlanPage, error) {
	var out mydc.CompactPlanPage
	after := ""
	for i := range compactMaxPages {
		p, err := c.RaftCompactPlan(ctx, sel, after)
		if isMydcCode(err, mydc.CodeConflict) {
			return out, &httpErr{http.StatusConflict, "plan-changed", "the servers changed while reading the plan; try again"}
		}
		if err != nil {
			return out, err
		}
		if i == 0 {
			out = p
		} else if p.Target != out.Target || p.Total != out.Total {
			return out, &httpErr{http.StatusConflict, "plan-changed", "the servers changed while reading the plan; try again"}
		} else {
			out.Nodes = append(out.Nodes, p.Nodes...)
		}
		if p.Next == "" {
			out.Next = ""
			return out, nil
		}
		after = p.Next
	}
	return out, &httpErr{http.StatusUnprocessableEntity, "too-large", "too many servers for one compaction; name fewer"}
}

func compactNodeNames(p mydc.CompactPlanPage) []string {
	names := make([]string, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		names = append(names, n.Node)
	}
	return names
}

// GET /raft/compact/plan?nodes=a,b&mode=keep|minimal&serial=true|false →
// {mode, retain?, parallel, total, nodes: [run order, leader last], plan}
// (raft-compact-plan). plan is the roster's Target (64 hex); send it back
// with the POST so what was shown is what gets signed. mydcd checks again
// when it accepts.
func (s *Server) handleRaftCompactPlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	var nodes []string
	if v := q.Get("nodes"); v != "" {
		nodes = strings.Split(v, ",")
	}
	sel, err := compactSelection(nodes, q.Get("mode"), q.Get("serial") != "false")
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		p, err := compactPlan(ctx, c, sel)
		if err != nil {
			return nil, err
		}
		out := map[string]any{"mode": sel.Mode, "parallel": sel.Parallel, "total": p.Total, "nodes": compactNodeNames(p), "plan": hex.EncodeToString(p.Target[:])}
		if sel.Retain > 0 {
			out["retain"] = sel.Retain
		}
		return out, nil
	})
}

// POST /raft/compact {opId, nodes[], mode: keep|minimal, serial, plan} →
// {op}. plan: the preview's (required, 64 hex); a roster that changed
// since is 409 plan-changed.
func (s *Server) handlePostRaftCompact(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID   string   `json:"opId"`
		Nodes  []string `json:"nodes"`
		Mode   string   `json:"mode"`
		Serial bool     `json:"serial"`
		Plan   string   `json:"plan"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		sel, err := compactSelection(req.Nodes, req.Mode, req.Serial)
		if err != nil {
			return "", nil, 0, "", err
		}
		st, err := c.RaftStatus(ctx)
		if err != nil {
			return "", nil, 0, "", err
		}
		if compactRunning(st) {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "in-progress", "a compaction is still running"}
		}
		p, err := compactPlan(ctx, c, sel)
		if err != nil {
			return "", nil, 0, "", err
		}
		if err := samePlan(req.Plan, hex.EncodeToString(p.Target[:]), "servers to compact"); err != nil {
			return "", nil, 0, "", err
		}
		return mydc.ActionRaftCompact, mydc.CompactChange{Operation: compactOperation(req.OpID), Selection: sel, Target: p.Target}, 0, "raft", nil
	})
}

type compactStatusNode struct {
	Node     string `json:"node"`
	State    string `json:"state"` // queued / running / done / failed / skipped
	Code     string `json:"code,omitempty"`
	Revision uint64 `json:"revision"`
}

// GET /raft/compactions/{operation} → {operation, by, at, mode, retain?,
// sequential, complete, total, queued, running, done, failed, skipped,
// nodes: [{node, state, code?, revision}]} (raft-compact-status, every
// page). Unknown is 404. Snapshot and log numbers are on GET /raft/compact.
func (s *Server) handleRaftCompactionStatus(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		op := r.PathValue("operation")
		var out map[string]any
		nodes := []compactStatusNode{}
		after := ""
		for range compactMaxPages * 16 {
			p, err := c.RaftCompactStatus(ctx, op, after)
			// mydcd answers an unknown operation with conflict (it may not
			// be committed yet); on the first page that is "no such job".
			if isMydcCode(err, mydc.CodeMissing) || isMydcCode(err, mydc.CodeInvalid) || after == "" && isMydcCode(err, mydc.CodeConflict) {
				return nil, &httpErr{http.StatusNotFound, "not-found", "no such compaction"}
			}
			if err != nil {
				return nil, err
			}
			if after != "" && p.Summary.Operation != out["operation"] {
				return nil, &httpErr{http.StatusConflict, "changed", "the compaction changed while reading; try again"}
			}
			sm := p.Summary
			out = map[string]any{"operation": sm.Operation, "by": sm.User, "at": rfc(int64(sm.At)), "mode": sm.Options.Mode, "sequential": sm.Sequential,
				"complete": sm.Complete, "total": sm.Total, "queued": sm.Queued, "running": sm.Running, "done": sm.Done, "failed": sm.Failed, "skipped": sm.Skipped}
			if sm.Options.Retain > 0 {
				out["retain"] = sm.Options.Retain
			}
			for _, n := range p.Nodes {
				nodes = append(nodes, compactStatusNode{Node: n.Node, State: n.State, Code: n.Code, Revision: n.Revision})
			}
			if p.Next == "" || p.Next <= after {
				break
			}
			after = p.Next
		}
		out["nodes"] = nodes
		return out, nil
	})
}
