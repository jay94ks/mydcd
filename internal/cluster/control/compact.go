// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/maintenance"
	"slices"
)

const CompactKey = "control/raft-maintenance"

type CompactSelection struct {
	Nodes    []string `json:",omitempty"`
	Mode     string
	Retain   uint64
	Parallel bool
}

func (q CompactSelection) Valid() bool {
	if (maintenance.CompactOptions{Mode: q.Mode, Retain: q.Retain}).Validate() != nil || len(q.Nodes) > 256 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range q.Nodes {
		if !lifecycle.ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

type CompactPlan struct {
	Schema    uint8
	Cluster   [32]byte
	Selection CompactSelection
	Target    [32]byte
	Nodes     []maintenance.CompactNode
}
type CompactChange struct {
	Operation string
	Selection CompactSelection
	Target    [32]byte
}

func (q CompactChange) Valid() bool {
	return lifecycle.ValidID(q.Operation) && q.Selection.Valid() && q.Target != ([32]byte{})
}

type CompactRecord struct {
	Origin            UserOperation
	Plan              CompactPlan
	Job               maintenance.CompactJob
	AcceptedIndex, At uint64
}
type Compactions struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Records  []CompactRecord
}

func compactTarget(p CompactPlan) [32]byte {
	p.Target = [32]byte{}
	p.Selection.Nodes = slices.Clone(p.Selection.Nodes)
	slices.Sort(p.Selection.Nodes)
	raw, _ := json.Marshal(p)
	return sha256.Sum256(append([]byte("sfc-raft-compact-target-1\x00"), raw...))
}
func (p CompactPlan) Valid() bool {
	if p.Schema != 1 || p.Cluster == ([32]byte{}) || !p.Selection.Valid() || p.Target == ([32]byte{}) || p.Target != compactTarget(p) {
		return false
	}
	j, err := maintenance.NewCompactJob("validate", maintenance.CompactOptions{Mode: p.Selection.Mode, Retain: p.Selection.Retain}, !p.Selection.Parallel, p.Nodes)
	if err != nil || len(j.Nodes) != len(p.Nodes) {
		return false
	}
	for i, n := range p.Nodes {
		if n.Node != j.Nodes[i].Node || n.Key != j.Nodes[i].Key || n.Revision != 1 || n.State != "queued" || n.Result != nil || n.Code != "" {
			return false
		}
	}
	if len(p.Selection.Nodes) > 0 {
		if len(p.Selection.Nodes) != len(p.Nodes) {
			return false
		}
		seen := map[string]bool{}
		for _, n := range p.Nodes {
			seen[n.Node] = true
		}
		for _, id := range p.Selection.Nodes {
			if !seen[id] {
				return false
			}
		}
	}
	return true
}
func (p Policy) PlanCompact(s state.State, session access.Session, at int64, q CompactSelection) (CompactPlan, error) {
	plan := CompactPlan{Schema: 1, Cluster: p.Cluster, Selection: q}
	p, err := p.Current(s)
	if err != nil || !q.Valid() {
		return plan, access.ErrDenied
	}
	users, err := p.Catalog(s)
	if err != nil || users.OperationAllowed(session, "raft-compact") != nil || users.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return plan, access.ErrDenied
	}
	d, err := p.Members(s)
	if err != nil {
		return plan, err
	}
	requested := map[string]bool{}
	for _, id := range q.Nodes {
		requested[id] = true
	}
	for _, entry := range d.Entries {
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		if err != nil {
			return plan, err
		}
		if !membership.FullMember(entry) || !d.MemberKey(key) || len(requested) == 0 && !entry.Peer.Voter || len(requested) > 0 && !requested[entry.Peer.ID] {
			continue
		}
		plan.Nodes = append(plan.Nodes, maintenance.CompactNode{Node: entry.Peer.ID, Key: key, Revision: 1, State: "queued"})
	}
	if len(requested) > 0 && len(plan.Nodes) != len(requested) {
		return plan, access.ErrDenied
	}
	plan.Selection.Nodes = slices.Clone(q.Nodes)
	plan.Target = compactTarget(plan)
	if !plan.Valid() {
		return plan, ErrCatalog
	}
	return plan, nil
}
func (p Policy) Compactions(s state.State) (Compactions, error) {
	out := Compactions{Schema: 1, Cluster: p.Cluster}
	raw, revision, err := readCheckpoint(s, CompactKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return out, err
	}
	if raw == nil {
		return out, nil
	}
	if canonical(raw, &out) != nil || out.Schema != 1 || out.Cluster != p.Cluster || out.Revision != revision || len(out.Records) > 128 {
		return out, ErrCatalog
	}
	seen := map[string]bool{}
	for _, r := range out.Records {
		var q CompactChange
		if r.Origin.VerifyOriginal(p.Cluster) != nil || r.Origin.Change.Action != "raft-compact" || canonical(r.Origin.Change.Payload, &q) != nil || !q.Valid() || !r.Plan.Valid() || q.Target != r.Plan.Target || r.Plan.Cluster != p.Cluster || !slices.Equal(q.Selection.Nodes, r.Plan.Selection.Nodes) || q.Selection.Mode != r.Plan.Selection.Mode || q.Selection.Retain != r.Plan.Selection.Retain || q.Selection.Parallel != r.Plan.Selection.Parallel || r.Job.Validate() != nil || r.Job.Operation != q.Operation || r.Job.Options != (maintenance.CompactOptions{Mode: q.Selection.Mode, Retain: q.Selection.Retain}) || r.Job.Sequential == q.Selection.Parallel || r.AcceptedIndex == 0 || r.AcceptedIndex > s.Index() || r.At < uint64(r.Origin.At) || seen[q.Operation] || len(r.Job.Nodes) != len(r.Plan.Nodes) {
			return out, ErrCatalog
		}
		for i, n := range r.Job.Nodes {
			if n.Node != r.Plan.Nodes[i].Node || n.Key != r.Plan.Nodes[i].Key {
				return out, ErrCatalog
			}
		}
		seen[q.Operation] = true
	}
	return out, nil
}
func (c Compactions) Record(id string) (CompactRecord, bool) {
	for _, r := range c.Records {
		if r.Job.Operation == id {
			raw, _ := json.Marshal(r)
			var own CompactRecord
			_ = json.Unmarshal(raw, &own)
			return own, true
		}
	}
	return CompactRecord{}, false
}
func (c Compactions) Quiescent() bool {
	for _, r := range c.Records {
		if !r.Job.Terminal() {
			return false
		}
	}
	return true
}
func (p Policy) compactCheckpoint(s state.State, c Compactions) (map[string][]byte, state.Code) {
	if c.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	c.Revision++
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > 4<<20 {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, CompactKey, p.Cluster, p.TrustRoot, c.Revision, raw)
}
func (p Policy) reduceCompactions(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind == state.ModuleReport {
		return p.reduceCompactReport(s, cmd)
	}
	if cmd.Kind != state.Module || cmd.Key != CompactKey {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(users, cmd, false)
	if err != nil || op.Change.Action != "raft-compact" || p.authorizeChange(s, users, op) != nil {
		return nil, state.Forbidden
	}
	var q CompactChange
	if canonical(op.Change.Payload, &q) != nil || !q.Valid() || op.Change.Expected != 0 {
		return nil, state.Invalid
	}
	c, err := p.Compactions(s)
	if err != nil {
		return nil, state.Invalid
	}
	if len(c.Records) >= 128 {
		return nil, state.ConditionFailed
	}
	if _, exists := c.Record(q.Operation); exists {
		return nil, state.ConditionFailed
	}
	plan, err := p.PlanCompact(s, op.Session, op.At, q.Selection)
	if err != nil || plan.Target != q.Target {
		return nil, state.ConditionFailed
	}
	for _, old := range c.Records {
		for _, n := range old.Job.Nodes {
			if n.State != "queued" && n.State != "running" {
				continue
			}
			for _, next := range plan.Nodes {
				if next.Key == n.Key {
					return nil, state.ConditionFailed
				}
			}
		}
	}
	job, err := maintenance.NewCompactJob(q.Operation, maintenance.CompactOptions{Mode: q.Selection.Mode, Retain: q.Selection.Retain}, !q.Selection.Parallel, plan.Nodes)
	if err != nil {
		return nil, state.Invalid
	}
	c.Records = append(c.Records, CompactRecord{Origin: op, Plan: plan, Job: job, AcceptedIndex: s.Index() + 1, At: uint64(op.At)})
	// Reserve bounded terminal result space before any owner can start SDK IO.
	// An accepted job cannot consume the remaining checkpoint on first failure.
	encoded, budgetErr := json.Marshal(c)
	if budgetErr != nil {
		return nil, state.Invalid
	}
	reserved := len(encoded)
	for _, record := range c.Records {
		for _, n := range record.Job.Nodes {
			if n.State == "queued" || n.State == "running" {
				reserved += 9 << 10
			}
		}
	}
	if reserved > 4<<20 {
		return nil, state.ConditionFailed
	}

	return p.compactCheckpoint(s, c)
}

// compactBook is the CompactKey Raft book (see book.go).
var compactBook = Book{
	Key:       CompactKey,
	Actions:   []string{"raft-compact"},
	Reduce:    Policy.reduceCompactions,
	Authorize: authorizeCluster,
	AdmitReport: func(p Policy, s state.State, cmd state.Command) error {
		_, err := p.compactReport(s, cmd)
		return err
	},
	Events: compactEvents,
}

func compactEvents(p Policy, before, after state.State, emit eventEmitter) error {
	old, err := p.Compactions(before)
	if err != nil {
		return err
	}
	next, err := p.Compactions(after)
	if err != nil {
		return err
	}
	for _, job := range next.Records {
		previous, _ := old.Record(job.Job.Operation)
		for _, node := range job.Job.Nodes {
			was, known := previous.Job.Node(node.Node)
			if known && was.State == node.State {
				continue
			}
			kind := ""
			if node.State == "running" {
				kind = "raft-compact-started"
			} else if node.State == "done" || node.State == "failed" || node.State == "skipped" {
				kind = "raft-compact-completed"
			}
			if kind != "" {
				d := eventlog.Detail{Operation: job.Job.Operation, State: node.State, Code: node.Code}
				eventReason(&d, job.Origin)
				emit(kind, "cluster", eventlog.Target{Node: node.Node}, d)
			}
		}
	}
	return nil
}
