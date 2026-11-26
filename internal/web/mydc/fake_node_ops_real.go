// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// RQ12 in mydcd's real shape (docs/protocol/mydcp.md 노드
// 운영, control/node_*.go). Reads take the control Policy names so they sit
// next to the old mocks until the web daemon moves:
//
//   - PlanNodeRemoval `node-remove-plan` → control.NodeRemovePlan
//   - PlanNodeDemotion `node-demote-plan` → control.NodeVotingPlan
//   - PlanNodeDrain / NodeDrainStatus `node-drain-plan` / `node-drain-status`
//     control.NodeDrainQuery{Node, Operation}
//   - PlanNodeForceRemoval `node-force-remove-plan` control.NodeForceQuery →
//     control.NodeForcePlan (with a signed lifecycle.RemovalProbe)
//   - ReadNodeDiagnostics `node-diagnostics` → control.NodeDiagnosticsBundle
//
// Actions (real payloads only; any other shape is Invalid): drain-node control.NodeDrainChange, demote-node
// control.NodeSelection{ID}, rotate-node-identity control.NodeIdentityChange,
// force-remove-node control.NodeForceChange. Expected is the member's
// Revision (Plan.Expected). The fake settles every step at once: a drain is
// Succeeded / Partial, a rotation Installed, a forced removal retired.

const fakeProbeObserver = "node-a" // the installed voter that probes

func blockers(codes ...string) []control.NodeBlocker {
	out := []control.NodeBlocker{}
	for _, c := range codes {
		if c != "" {
			out = append(out, control.NodeBlocker{Code: c})
		}
	}
	return out
}

// realRemovePlan: removePlan in control.NodeRemovePlan form.
func (w *world) realRemovePlan(node string) control.NodeRemovePlan {
	old := w.removePlan(node)
	p := control.NodeRemovePlan{Schema: 1, Node: node, Epoch: old.Epoch, Expected: old.Expected, RootRevision: w.keyRoot(control.MembersKey), Index: w.root,
		ConfigurationIndex: w.raft.ConfigurationIndex, Removable: old.Removable, Blockers: []control.NodeBlocker{},
		VotersBefore: old.VotersBefore, VotersAfter: old.VotersAfter, QuorumAfter: old.QuorumAfter, FaultToleranceAfter: old.FaultToleranceAfter,
		Tasks: []control.NodePlanTask{}, Storage: []control.NodePlanStorage{}, Volumes: []control.NodePlanVolume{}, PendingOperation: old.PendingOperation}
	for _, b := range old.Blockers {
		p.Blockers = append(p.Blockers, control.NodeBlocker{Code: b.Code, Detail: b.Detail})
	}
	for _, t := range w.realPlanTasks(node) {
		p.Tasks = append(p.Tasks, t)
	}
	for _, r := range w.nodeStorage {
		if r.Node != node {
			continue
		}
		s := control.NodePlanStorage{ID: r.ID, Path: r.Path, Draining: r.Draining, Closed: r.Closed}
		for _, v := range w.volumes {
			if v.Kind == "fixed" && v.Node == node && v.Storage == r.ID {
				s.Volumes++
			}
		}
		p.Storage = append(p.Storage, s)
	}
	for _, v := range w.volumes {
		if v.Kind == "fixed" && v.Node == node {
			p.Volumes = append(p.Volumes, control.NodePlanVolume{Tenant: v.Tenant, ID: v.Name, Fixed: true})
		}
	}
	p.NativeClosed = len(p.Tasks) == 0
	return p
}

// realPlanTasks: the drain plan's tasks plus pinned standalones.
func (w *world) realPlanTasks(node string) []control.NodePlanTask {
	var out []control.NodePlanTask
	for _, dt := range w.drainPlan(node).Tasks {
		t := control.NodePlanTask{Tenant: dt.Tenant, App: dt.App, Service: dt.Service, Task: dt.Tenant + "/" + dt.App + "/" + dt.Service + "/" + dt.Instance, Node: node,
			Target: dt.To, Movable: dt.Blocked == "", Reason: dt.Blocked}
		if a := w.apps[dt.Tenant+"/"+dt.App]; a != nil {
			t.Revision = a.view.Revision
			for _, x := range a.tasks {
				if x.Service == dt.Service && x.Instance == dt.Instance {
					t.Generation = x.Generation
				}
			}
		}
		out = append(out, t)
	}
	for _, k := range sortedKeys(w.standalones) {
		if e := w.standalones[k]; e.view.Node == node {
			out = append(out, control.NodePlanTask{Tenant: e.view.Tenant, Standalone: e.view.Name, Node: node, Reason: NodePinned})
		}
	}
	return out
}

func (c *fakeConn) PlanNodeRemoval(ctx context.Context, node string) (control.NodeRemovePlan, error) {
	const m = "node-remove-plan"
	if err := c.adminRead(ctx, m, node); err != nil {
		return control.NodeRemovePlan{}, err
	}
	defer c.unlock()
	if c.f.w.members[c.f.w.memberIndex(node)].Phase == NodePhaseRemoved {
		return control.NodeRemovePlan{}, fail(m, CodeMissing, "")
	}
	return c.f.w.realRemovePlan(node), nil
}

func (w *world) realVotingPlan(node string) control.NodeVotingPlan {
	vp := w.voterPlan(node, true)
	mb := w.members[w.memberIndex(node)]
	p := control.NodeVotingPlan{Schema: 1, Node: node, Epoch: fakeNodeEpoch, Expected: mb.Revision, RootRevision: w.keyRoot(control.MembersKey), Index: w.root,
		ConfigurationIndex: w.raft.ConfigurationIndex, Demotable: vp.Code == "", Blockers: blockers(vp.Code), VotersAfter: vp.VotersAfter,
		QuorumAfter: vp.Quorum, FaultToleranceAfter: vp.Tolerates, PendingOperation: mb.PendingOperation}
	p.VotersBefore = vp.VotersAfter
	if mb.Voter {
		p.VotersBefore++
	}
	return p
}

func (c *fakeConn) PlanNodeDemotion(ctx context.Context, node string) (control.NodeVotingPlan, error) {
	if err := c.adminRead(ctx, "node-demote-plan", node); err != nil {
		return control.NodeVotingPlan{}, err
	}
	defer c.unlock()
	return c.f.w.realVotingPlan(node), nil
}

// realDrainPlan at a fixed time: one Job per app with movable tasks.
func (w *world) realDrainPlan(q control.NodeDrainQuery, at int64) control.NodeDrainPlan {
	mb := w.members[w.memberIndex(q.Node)]
	p := control.NodeDrainPlan{At: at, Schema: 1, Node: q.Node, Operation: q.Operation, Expected: mb.Revision, RootRevision: w.keyRoot(control.MembersKey),
		AppsRoot: w.keyRoot(control.AppsKey), Index: w.root, Jobs: []control.NodeDrainJob{}, Tasks: w.realPlanTasks(q.Node), Blockers: []control.NodeBlocker{}}
	if p.Tasks == nil {
		p.Tasks = []control.NodePlanTask{}
	}
	jobs := map[string]*control.NodeDrainJob{}
	var order []string
	for _, t := range p.Tasks {
		if !t.Movable || t.App == "" {
			continue
		}
		k := t.Tenant + "/" + t.App
		j := jobs[k]
		if j == nil {
			d := sha256.Sum256([]byte(q.Operation + "\x00" + t.Tenant + "\x00" + t.App))
			j = &control.NodeDrainJob{Tenant: t.Tenant, App: t.App, Operation: "drain-" + hex.EncodeToString(d[:12]), Target: t.Target, Expected: t.Revision}
			if a := w.apps[k]; a != nil {
				j.Deployment = a.view.Deployment
			}
			jobs[k] = j
			order = append(order, k)
		}
		if !slices.Contains(j.Services, t.Service) {
			j.Services = append(j.Services, t.Service)
		}
		j.Tasks = append(j.Tasks, deployment.ObjectRef{Key: "task/" + t.Task, Revision: t.Revision, Generation: t.Generation})
	}
	for _, k := range order {
		j := jobs[k]
		raw, _ := json.Marshal(j)
		j.Plan = sha256.Sum256(raw)
		p.Jobs = append(p.Jobs, *j)
	}
	raw, _ := json.Marshal(p)
	p.Digest = sha256.Sum256(append([]byte("mydc-node-drain-plan-1\x00"), raw...))
	return p
}

func (c *fakeConn) PlanNodeDrain(ctx context.Context, q control.NodeDrainQuery) (control.NodeDrainPlan, error) {
	const m = "node-drain-plan"
	if !q.Valid() {
		return control.NodeDrainPlan{}, fail(m, CodeInvalid, "query")
	}
	if err := c.adminRead(ctx, m, q.Node); err != nil {
		return control.NodeDrainPlan{}, err
	}
	defer c.unlock()
	return c.f.w.realDrainPlan(q, c.f.now().Unix()), nil
}

func (c *fakeConn) NodeDrainStatus(ctx context.Context, q control.NodeDrainQuery) (control.NodeDrainStatus, error) {
	const m = "node-drain-status"
	// REQ-70 (real): no Operation = the node's running (Draining) drain,
	// else its most recent one; the reply's Operation names it.
	if q.Operation == "" && q.Node != "" {
		if err := c.adminRead(ctx, m, q.Node); err != nil {
			return control.NodeDrainStatus{}, err
		}
		op, ok := c.f.w.currentDrain(q.Node)
		c.unlock()
		if !ok {
			return control.NodeDrainStatus{}, fail(m, CodeMissing, "")
		}
		q.Operation = op
	}
	if !q.Valid() {
		return control.NodeDrainStatus{}, fail(m, CodeInvalid, "query")
	}
	if err := c.adminRead(ctx, m, q.Node); err != nil {
		return control.NodeDrainStatus{}, err
	}
	defer c.unlock()
	s, ok := c.f.w.nodeDrains[q.Node+"/"+q.Operation]
	if !ok {
		return control.NodeDrainStatus{}, fail(m, CodeMissing, "")
	}
	s.Jobs = slices.Clone(s.Jobs)
	return s, nil
}

// removalProbe: the observer voter's signed status probe of node.
func (w *world) removalProbe(node, operation string, expected uint64, at int64) lifecycle.RemovalProbe {
	pr := lifecycle.RemovalProbe{Schema: 1, Cluster: w.cluster, Node: node, Operation: operation, Target: pub32(FixtureKey(node)), Observer: pub32(FixtureKey(fakeProbeObserver)),
		Epoch: fakeNodeEpoch, Expected: expected, ConfigurationIndex: w.raft.ConfigurationIndex, RootRevision: w.keyRoot(control.MembersKey),
		StartedAt: at, FinishedAt: at, Challenge: sha256.Sum256([]byte(node + "\x00" + operation)), Responding: w.summaryStatus(node) != "unreachable"}
	pr.Signature = ed25519.Sign(FixtureKey(fakeProbeObserver), lifecycle.RemovalProbeBytes(pr))
	return pr
}

func (w *world) realForcePlan(q control.NodeForceQuery, at int64) control.NodeForcePlan {
	base := w.realRemovePlan(q.Node)
	out := control.NodeForcePlan{NodeRemovePlan: base, Operation: q.Operation}
	out.Blockers = []control.NodeBlocker{}
	for _, b := range base.Blockers {
		switch b.Code {
		case NodeLastVoter, NodeQuorumLoss, NodeOperationPending, NodeConfigurationPending:
			out.Blockers = append(out.Blockers, b)
		}
	}
	if q.Node == w.raft.Leader {
		out.Blockers = append(out.Blockers, control.NodeBlocker{Code: NodeSelfRemoval})
	}
	pr := w.removalProbe(q.Node, q.Operation, base.Expected, at)
	out.Probe = &pr
	if pr.Responding {
		out.Blockers = append(out.Blockers, control.NodeBlocker{Code: NodeResponding})
	}
	out.Forceable = len(out.Blockers) == 0
	out.Removable = false
	return out
}

func (c *fakeConn) PlanNodeForceRemoval(ctx context.Context, q control.NodeForceQuery) (control.NodeForcePlan, error) {
	const m = "node-force-remove-plan"
	if !q.Valid() {
		return control.NodeForcePlan{}, fail(m, CodeInvalid, "query")
	}
	if err := c.adminRead(ctx, m, q.Node); err != nil {
		return control.NodeForcePlan{}, err
	}
	defer c.unlock()
	return c.f.w.realForcePlan(q, c.f.now().Unix()), nil
}

// ReadNodeDiagnostics: the public allowlist bundle (config-summary.json,
// status.json, mydcd-events.json), tar+gzip at most 64 KiB.
func (c *fakeConn) ReadNodeDiagnostics(ctx context.Context, node string) (control.NodeDiagnosticsBundle, error) {
	const m = "node-diagnostics"
	if err := c.adminRead(ctx, m, node); err != nil {
		return control.NodeDiagnosticsBundle{}, err
	}
	defer c.unlock()
	w := c.f.w
	now := c.f.now().UTC().Truncate(time.Second)
	mb := w.members[w.memberIndex(node)]
	status, _ := json.Marshal(map[string]any{"node": node, "phase": mb.Phase, "voter": mb.Voter, "status": w.summaryStatus(node), "revision": mb.Revision})
	config, _ := json.Marshal(map[string]any{"node": node, "endpoint": mb.Endpoint})
	var events []map[string]any
	for _, e := range w.events {
		if e.Node == node && len(events) < 50 {
			events = append(events, map[string]any{"time": e.Time, "kind": e.Kind, "target": e.Target})
		}
	}
	evs, _ := json.Marshal(events)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, f := range []struct {
		name string
		data []byte
	}{{"config-summary.json", config}, {"status.json", status}, {"mydcd-events.json", evs}} {
		_ = tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o600, Size: int64(len(f.data)), ModTime: now})
		_, _ = tw.Write(f.data)
	}
	tw.Close()
	zw.Close()
	b := control.NodeDiagnosticsBundle{Schema: 1, Node: node, Format: "tar+gzip", CreatedAt: now.Format(time.RFC3339), Bytes: uint64(buf.Len()),
		LimitBytes: control.NodeDiagnosticsMaxBytes, ExpandedLimitBytes: control.NodeDiagnosticsExpandedBytes, Digest: sha256.Sum256(buf.Bytes()), Data: buf.Bytes()}
	return b, nil
}

// applyNodeOpsReal: the real payloads; ok false = an old mock payload.
func (c *fakeConn) applyNodeOpsReal(op UserOperation, actor string, next uint64) (bool, error) {
	w := c.f.w
	ch := op.Change
	now := c.f.now().UTC().Truncate(time.Second)
	switch ch.Action {
	case ActionDrainNode:
		var q control.NodeDrainChange
		if decodePayload(ch.Payload, &q) != nil {
			return false, nil
		}
		if !w.admin(actor) {
			return true, errForbidden
		}
		i := w.memberIndex(q.ID)
		if i < 0 || q.Operation == "" || q.At <= 0 || q.At > op.At || op.At-q.At > 30 {
			return true, errors.New("payload")
		}
		if ch.Expected != w.members[i].Revision || q.AppsRoot != w.keyRoot(control.AppsKey) {
			return true, errCAS
		}
		p := w.realDrainPlan(control.NodeDrainQuery{Node: q.ID, Operation: q.Operation}, q.At)
		if p.Digest != q.Plan || !jsonEqual(p.Jobs, q.Jobs) {
			return true, errCAS
		}
		st := control.NodeDrainStatus{Schema: 1, Node: q.ID, Operation: q.Operation, State: "Succeeded", Jobs: []control.NodeDrainJobStatus{}}
		for _, t := range p.Tasks {
			st.Total++
			if !t.Movable {
				st.Blocked++
			}
		}
		if st.Blocked > 0 && !q.LeaveBlocked {
			return true, errors.New("blocked tasks: send LeaveBlocked")
		}
		for _, j := range p.Jobs {
			a := w.apps[j.Tenant+"/"+j.App]
			for _, t := range p.Tasks {
				if t.Tenant != j.Tenant || t.App != j.App || !t.Movable {
					continue
				}
				for k := range a.tasks {
					if taskKey(a.tasks[k]) == t.Task {
						a.tasks[k].Node, a.tasks[k].StartedAt, a.tasks[k].ObservedAt = t.Target, now.Unix(), now.Unix()
					}
				}
			}
			st.Jobs = append(st.Jobs, control.NodeDrainJobStatus{Tenant: j.Tenant, App: j.App, Operation: j.Operation, State: "Succeeded", Total: len(j.Tasks), Moved: len(j.Tasks)})
			st.Moved += len(j.Tasks)
		}
		if st.Blocked > 0 {
			st.State = "Partial"
		}
		mb := &w.members[i]
		if !mb.Cordoned {
			mb.Cordoned, mb.CordonReason, mb.CordonedBy, mb.CordonedAt = true, "", w.username(actor), &now
		}
		mb.Revision = next
		if w.nodeDrains == nil {
			w.nodeDrains = map[string]control.NodeDrainStatus{}
		}
		w.nodeDrains[q.ID+"/"+q.Operation] = st
		if w.nodeDrainOps == nil {
			w.nodeDrainOps = map[string][]string{}
		}
		w.nodeDrainOps[q.ID] = append(w.nodeDrainOps[q.ID], q.Operation)
		w.addEvent(FixtureEvent{Time: now.Unix(), Scope: "node", Node: q.ID, Kind: "node-drained", Target: q.ID, Detail: q.Operation})
		return true, nil

	case ActionDemoteNode:
		var q control.NodeSelection
		if decodePayload(ch.Payload, &q) != nil {
			return false, nil
		}
		if !w.admin(actor) {
			return true, errForbidden
		}
		i := w.memberIndex(q.ID)
		if i < 0 {
			return true, errors.New("unknown node")
		}
		if ch.Expected != w.members[i].Revision {
			return true, errCAS
		}
		if p := w.realVotingPlan(q.ID); !p.Demotable {
			return true, nodeRemoveRefused{p.Blockers[0].Code}
		}
		w.members[i].Voter, w.members[i].Revision = false, next
		for j := range w.summaries {
			if w.summaries[j].Node == q.ID {
				w.summaries[j].Role = "non-voter"
			}
		}
		return true, nil

	case ActionRotateNodeIdentity:
		var q control.NodeIdentityChange
		if decodePayload(ch.Payload, &q) != nil {
			return false, nil
		}
		if !w.admin(actor) {
			return true, errForbidden
		}
		i := w.memberIndex(q.ID)
		if i < 0 || q.Operation == "" {
			return true, errors.New("payload")
		}
		if ch.Expected != w.members[i].Revision || w.summaryStatus(q.ID) == "unreachable" {
			return true, errCAS
		}
		k := fakeDigest("node-identity", q.ID, q.Operation)
		var prev [32]byte
		_, _ = hex.Decode(prev[:], []byte(w.members[i].Key))
		w.members[i].Identity = &membership.IdentityRotationView{Operation: q.Operation, Phase: "Installed", Old: prev, New: k, AcceptedIndex: next, ActivatedIndex: next, InstalledIndex: next,
			RequestedAt: time.Unix(op.At, 0).UTC().Format(time.RFC3339)}
		w.members[i].Key, w.members[i].Revision = hex.EncodeToString(k[:]), next
		return true, nil

	case ActionForceRemoveNode:
		var q control.NodeForceChange
		if decodePayload(ch.Payload, &q) != nil {
			return false, nil
		}
		if !w.admin(actor) {
			return true, errForbidden
		}
		i := w.memberIndex(q.ID)
		if i < 0 || q.Operation == "" {
			return true, errors.New("payload")
		}
		pr := q.Probe
		if !pr.Valid() || pr.Cluster != w.cluster || pr.Node != q.ID || pr.Operation != q.Operation || pr.Epoch != q.Epoch || pr.Target != pub32(FixtureKey(q.ID)) ||
			pr.Observer != pub32(FixtureKey(fakeProbeObserver)) || op.At < pr.FinishedAt || op.At-pr.FinishedAt > 30 {
			return true, errors.New("probe")
		}
		if q.Epoch != fakeNodeEpoch || ch.Expected != w.members[i].Revision || pr.Expected != ch.Expected {
			return true, errCAS
		}
		if pr.Responding {
			return true, nodeRemoveRefused{NodeResponding}
		}
		if p := w.realForcePlan(control.NodeForceQuery{Node: q.ID, Operation: q.Operation}, op.At); len(p.Blockers) > 0 && p.Blockers[0].Code != NodeResponding {
			return true, nodeRemoveRefused{p.Blockers[0].Code}
		}
		mb := &w.members[i]
		mb.Phase, mb.Voter, mb.AdmitsWork, mb.Revision = NodePhaseRemoved, false, false, next
		for j := range w.summaries {
			if w.summaries[j].Node == q.ID {
				w.summaries[j].Status, w.summaries[j].Role = "removed", "removed"
			}
		}
		// Tasks and volumes stay as they were (retired is membership only).
		for _, a := range w.apps {
			for j := range a.tasks {
				if a.tasks[j].Node == q.ID {
					a.tasks[j].Observed, a.tasks[j].Health, a.tasks[j].ObservedAt = "missing", "none", now.Unix()
				}
			}
		}
		w.addEvent(FixtureEvent{Time: now.Unix(), Scope: "node", Node: q.ID, Kind: "node-removed", Target: q.ID, Detail: "force " + q.Operation})
		return true, nil
	}
	return false, nil
}

// currentDrain: the newest Draining drain of node, else its newest drain.
func (w *world) currentDrain(node string) (string, bool) {
	ops := w.nodeDrainOps[node]
	for i := len(ops) - 1; i >= 0; i-- {
		if w.nodeDrains[node+"/"+ops[i]].State == "Draining" {
			return ops[i], true
		}
	}
	if len(ops) == 0 {
		return "", false
	}
	return ops[len(ops)-1], true
}

// SetNodeDrainState sets a recorded drain's State (e.g. "Draining") so a test
// can see one in progress; the fake otherwise settles a drain at once.
func (f *Fake) SetNodeDrainState(node, operation, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.w.nodeDrains[node+"/"+operation]; ok {
		s.State = state
		f.w.nodeDrains[node+"/"+operation] = s
	}
}
