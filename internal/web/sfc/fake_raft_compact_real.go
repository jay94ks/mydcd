// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/maintenance"
)

const (
	compactPlanPage   = 64 // raft-compact-plan nodes a page
	compactStatusPage = 4  // raft-compact-status nodes a page
)

// compactTargets: the selection's roster in run order (leader last) and
// its fingerprint. No Nodes = the installed voters; named nodes must be
// cluster servers (a non-voter may be named).
func (w *world) compactTargets(sel CompactSelection) ([]maintenance.CompactNode, [32]byte, error) {
	var names []string
	for _, s := range w.raft.Servers {
		if len(sel.Nodes) == 0 && s.Suffrage == "voter" || slices.Contains(sel.Nodes, s.Node) {
			names = append(names, s.Node)
		}
	}
	for _, n := range sel.Nodes {
		if !slices.Contains(names, n) {
			return nil, [32]byte{}, fmt.Errorf("%s is not a cluster server", n)
		}
	}
	slices.SortStableFunc(names, func(a, b string) int {
		switch {
		case a == w.raft.Leader:
			return 1
		case b == w.raft.Leader:
			return -1
		}
		return strings.Compare(a, b)
	})
	parts := []string{sel.Mode, strconv.FormatUint(sel.Retain, 10), strconv.FormatBool(sel.Parallel)}
	out := make([]maintenance.CompactNode, 0, len(names))
	for _, n := range names {
		var key [32]byte
		if i := w.memberIndex(n); i >= 0 {
			_, _ = hex.Decode(key[:], []byte(w.members[i].Key))
		}
		out = append(out, maintenance.CompactNode{Node: n, Key: key, Revision: 1, State: "queued"})
		parts = append(parts, n+"="+hex.EncodeToString(key[:]))
	}
	return out, fakeDigest(append([]string{"compact-target"}, parts...)...), nil
}

// compactBusy: some node of nodes is queued or running in another job.
func (w *world) compactBusy(nodes []maintenance.CompactNode) bool {
	for _, j := range w.compactJobs {
		for _, r := range j.Results {
			if (r.State == "queued" || r.State == "running") && slices.ContainsFunc(nodes, func(n maintenance.CompactNode) bool { return n.Node == r.Node }) {
				return true
			}
		}
	}
	return false
}

// RaftCompactPlan: `raft-compact-plan` (system admin).
func (c *fakeConn) RaftCompactPlan(ctx context.Context, sel CompactSelection, after string) (CompactPlanPage, error) {
	const m = "raft-compact-plan"
	if !(control.CompactQuery{Selection: &sel, After: after}).Valid(true) {
		return CompactPlanPage{}, fail(m, CodeInvalid, "")
	}
	if err := c.adminOnly(ctx, m); err != nil {
		return CompactPlanPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	nodes, target, err := w.compactTargets(sel)
	if err != nil {
		return CompactPlanPage{}, fail(m, CodeInvalid, err.Error())
	}
	p := CompactPlanPage{Schema: 1, Cluster: w.cluster, Selection: sel, Target: target, Total: len(nodes), Nodes: []maintenance.CompactNode{}}
	start := 0
	if after != "" {
		n, err := strconv.Atoi(after)
		if err != nil || n <= 0 || n > len(nodes) {
			return CompactPlanPage{}, fail(m, CodeConflict, "COMPACT_VIEW_CHANGED")
		}
		start = n
	}
	end := min(start+compactPlanPage, len(nodes))
	p.Nodes = append(p.Nodes, nodes[start:end]...)
	if end < len(nodes) {
		p.Next = strconv.Itoa(end)
	}
	return p, nil
}

// RaftCompactStatus: `raft-compact-status` (system admin).
func (c *fakeConn) RaftCompactStatus(ctx context.Context, operation, after string) (CompactStatusPage, error) {
	const m = "raft-compact-status"
	if !(control.CompactQuery{Operation: operation, After: after}).Valid(false) {
		return CompactStatusPage{}, fail(m, CodeInvalid, "")
	}
	if err := c.adminOnly(ctx, m); err != nil {
		return CompactStatusPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	j, ok := w.compactJobs[operation]
	if !ok {
		return CompactStatusPage{}, fail(m, CodeMissing, "")
	}
	nodes, _, _ := w.compactTargets(j.Selection)
	sum := compactSummary(j)
	p := CompactStatusPage{Schema: 1, Cluster: w.cluster, RootRevision: w.keyRoot(control.CompactKey), Summary: sum, Target: j.Target, Nodes: []maintenance.CompactNode{}}
	for _, r := range j.Results {
		if r.Node <= after {
			continue
		}
		if len(p.Nodes) == compactStatusPage {
			p.Next = p.Nodes[len(p.Nodes)-1].Node
			break
		}
		row := maintenance.CompactNode{Node: r.Node, Revision: 1, State: r.State}
		if i := slices.IndexFunc(nodes, func(n maintenance.CompactNode) bool { return n.Node == r.Node }); i >= 0 {
			row.Key = nodes[i].Key
		}
		if r.State != "queued" {
			row.Revision = 2
		}
		if r.State == "failed" || r.State == "skipped" {
			row.Code = r.Error
		}
		p.Nodes = append(p.Nodes, row)
	}
	return p, nil
}

func compactSummary(j *FixtureRaftCompaction) control.CompactSummary {
	s := control.CompactSummary{Operation: j.Operation, User: j.By, At: uint64(max(j.At, 0)), AcceptedIndex: j.AcceptedIndex,
		Options: maintenance.CompactOptions{Mode: j.Retain, Retain: j.Minimal}, Sequential: !j.Parallel, Total: len(j.Results)}
	for _, x := range j.Results {
		switch x.State {
		case "queued":
			s.Queued++
		case "running":
			s.Running++
		case "done":
			s.Done++
		case "failed":
			s.Failed++
		case "skipped":
			s.Skipped++
		}
	}
	s.Complete = s.Queued+s.Running == 0
	return s
}

// applyRaftCompact: raft-compact, Expected 0, CompactChange. The Target
// must still be the selection's roster, the Operation new, and no target
// node in another unfinished job.
func (c *fakeConn) applyRaftCompact(op UserOperation, actor string) error {
	w := c.f.w
	var v CompactChange
	if decodePayload(op.Change.Payload, &v) != nil || !v.Valid() || op.Change.Expected != 0 {
		return errors.New("payload")
	}
	if !w.admin(actor) {
		return errForbidden
	}
	nodes, target, err := w.compactTargets(v.Selection)
	if err != nil {
		return err
	}
	if target != v.Target {
		return errCAS
	}
	if _, dup := w.compactJobs[v.Operation]; dup {
		return errCAS
	}
	if w.compactBusy(nodes) {
		return errors.New("a compaction is already running on a target")
	}
	now := c.f.now().Unix()
	lc := &FixtureRaftCompaction{Operation: v.Operation, By: actor, At: now, Retain: v.Selection.Mode, Minimal: v.Selection.Retain, Parallel: v.Selection.Parallel,
		Target: v.Target, Selection: v.Selection, AcceptedIndex: w.root + 1}
	for i, n := range nodes {
		st := "queued"
		if i == 0 || v.Selection.Parallel && n.Node != w.raft.Leader {
			st = "running"
		}
		lc.Results = append(lc.Results, FixtureRaftCompactResult{Node: n.Node, State: st})
	}
	if w.compactJobs == nil {
		w.compactJobs = map[string]*FixtureRaftCompaction{}
	}
	w.compactJobs[v.Operation] = lc
	w.raft.LastCompaction = lc
	if !w.compactHold {
		w.finishCompaction(now)
	}
	return nil
}
