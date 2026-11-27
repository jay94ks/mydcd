// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/maintenance"
	"testing"
)

func compactCoreFixture(t *testing.T) *backupCoreFixture {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	// The reused fixture already has the wildcard ManageCluster scope. Do not
	// append a duplicate scope: that would invalidate the entire session.
	if !access.ValidateScopes(f.session.Scopes) {
		t.Fatal("invalid source fixture scopes")
	}
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	return f
}
func acceptedCompactCore(t *testing.T, f *backupCoreFixture, id string) (state.Command, CompactRecord) {
	t.Helper()
	selection := CompactSelection{Mode: "minimal", Retain: 1}
	plan, err := f.p.PlanCompact(f.s, f.session, 2, selection)
	if err != nil || !plan.Valid() {
		t.Fatal("compact plan", err)
	}
	cmd, _ := managedDNSChange(t, f, id, "raft-compact", 0, CompactChange{Operation: id, Selection: selection, Target: plan.Target}, state.Applied)
	jobs, err := f.p.Compactions(f.s)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := jobs.Record(id)
	if !ok {
		t.Fatal("original compact missing")
	}
	return cmd, record
}
func signedCompactReportCore(t *testing.T, f *backupCoreFixture, id, action string, result *maintenance.CompactResult, code string) state.Command {
	t.Helper()
	jobs, err := f.p.Compactions(f.s)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := jobs.Record(id)
	if !ok {
		t.Fatal("job absent")
	}
	node := record.Job.Nodes[0]
	report := CompactReport{Schema: 1, Cluster: f.p.Cluster, Reporter: node.Key, Operation: id, Node: node.Node, Action: action, Expected: node.Revision, RootRevision: f.s.Object(CompactKey).Revision, Epoch: f.s.ModuleEpoch(), At: 3, Result: result, Code: code}
	if action == "begin" || action == "skip" {
		report.Leader = node.Node
	}
	report.Signature = ed25519.Sign(f.node, CompactReportBytes(report))
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}
func TestCompactRootPinsOriginalUserTargetAndPendingOwnerBeforeSDK(t *testing.T) {
	f := compactCoreFixture(t)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	activity, err := f.p.NodeActivity(f.s, owner)
	if err != nil {
		t.Fatal(err)
	}
	original, record := acceptedCompactCore(t, f, "compact-one")
	pending, err := f.p.NodeActivity(f.s, owner)
	if err != nil || pending.Resources != activity.Resources+1 {
		t.Fatal("pending maintenance missing from owner closure", err)
	}
	if f.p.storageQuiescent(f.s) {
		t.Fatal("pending compaction ledger expired")
	}
	applyRestartCore(t, f, original, state.Applied)
	selection := CompactSelection{Mode: "minimal", Retain: 1}
	plan, err := f.p.PlanCompact(f.s, f.session, 2, selection)
	if err != nil {
		t.Fatal(err)
	}
	managedDNSChange(t, f, "same-node-concurrent", "raft-compact", 0, CompactChange{Operation: "concurrent", Selection: selection, Target: plan.Target}, state.ConditionFailed)
	begin := signedCompactReportCore(t, f, "compact-one", "begin", nil, "")
	applyRestartCore(t, f, begin, state.Applied)
	skip := signedCompactReportCore(t, f, "compact-one", "skip", nil, "unreachable")
	applyRestartCore(t, f, skip, state.ConditionFailed)
	before := maintenance.CompactMetrics{LogKnown: true, FirstIndex: 1, LastIndex: 50, LogEntries: 50, LogFileKnown: true, LogUsedKnown: true, LogFileBytes: 65536, LogFreeBytes: 1024, LogUsedBytes: 64512, SnapshotKnown: true, SnapshotIndex: 40, SnapshotBytes: 128}
	after := before
	after.FirstIndex = 50
	after.LogEntries = 1
	after.LogFreeBytes = 32768
	after.LogUsedBytes = 32768
	after.SnapshotIndex = 50
	after.SnapshotBytes = 256
	result := maintenance.CompactResult{Schema: 1, Dispatch: maintenance.CompactDispatch{Schema: 1, Operation: "compact-one", At: 1, MinimumIndex: 50, Options: record.Job.Options, ConfiguredTrailing: 512, EffectiveTrailing: 1, Before: before}, After: after, ConfigRestored: true, TargetMet: true}
	finish := signedCompactReportCore(t, f, "compact-one", "finish", &result, "")
	applyRestartCore(t, f, finish, state.Applied)
	jobs, err := f.p.Compactions(f.s)
	if err != nil {
		t.Fatal(err)
	}
	done, _ := jobs.Record("compact-one")
	if !done.Job.Terminal() || done.Summary().Done != 1 || done.Origin.RequestID != record.Origin.RequestID {
		t.Fatal("owner result detached from original")
	}
	current, err := f.p.NodeActivity(f.s, owner)
	if err != nil || current.Resources != activity.Resources {
		t.Fatal("terminal original still pins owner", err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Compactions(restored); err != nil {
		t.Fatal("snapshot lost original user/result", err)
	}
}
func TestCompactQueriesRequireCurrentSystemAdminAndCursorSameTarget(t *testing.T) {
	f := compactCoreFixture(t)
	_, record := acceptedCompactCore(t, f, "compact-query")
	q := CompactQuery{Selection: &record.Plan.Selection}
	page, err := f.p.CompactPlanPage(f.s, f.session, 2, q)
	if err != nil || len(page.Nodes) != 1 || page.Target != record.Plan.Target {
		t.Fatal("plan page", err)
	}
	status, err := f.p.CompactStatusPage(f.s, f.session, 2, CompactQuery{Operation: "compact-query"})
	if err != nil || status.Summary.User != f.session.User || status.Summary.Queued != 1 {
		t.Fatal("public original status", err)
	}
	raw, _ := json.Marshal(status)
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	if payload["Origin"] != nil {
		t.Fatal("public status exposed original session/grant")
	}
	clipped := f.session
	clipped.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	clipped.Signature = ed25519.Sign(f.node, access.SessionBytes(clipped))
	if _, err = f.p.CompactStatusPage(f.s, clipped, 2, CompactQuery{Operation: "compact-query"}); err == nil {
		t.Fatal("tenant reader gained cluster maintenance")
	}
	if _, err = f.p.PlanCompact(f.s, clipped, 2, record.Plan.Selection); err == nil {
		t.Fatal("reader planned maintenance")
	}
	q.After = compactCursor([32]byte{9}, 1)
	if _, err = f.p.CompactPlanPage(f.s, f.session, 2, q); err == nil {
		t.Fatal("foreign cursor reused")
	}
}
