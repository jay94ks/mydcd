// SPDX-License-Identifier: Apache-2.0

package maintenance

import "testing"

func TestCompactSequentialLeaderLastFollowsCurrentLeaderAndOriginalNodeCAS(t *testing.T) {
	j, err := NewCompactJob("maintenance-1", CompactOptions{Mode: "minimal", Retain: 1000}, true, []CompactNode{{Node: "a", Key: [32]byte{1}}, {Node: "b", Key: [32]byte{2}}, {Node: "c", Key: [32]byte{3}}})
	if err != nil {
		t.Fatal(err)
	}
	if j.CanBegin("a", "a") || !j.CanBegin("b", "a") || j.CanBegin("c", "a") {
		t.Fatal("leader-last/serial order")
	}
	before := j
	j, err = j.Begin("b", "a", 1)
	if err != nil || before.Nodes[1].State != "queued" {
		t.Fatal("begin changed original", err)
	}
	if j.CanBegin("c", "a") {
		t.Fatal("parallel start in serial job")
	}
	if _, err = j.Skip("b", 2); err == nil {
		t.Fatal("unknown running effect became skipped")
	}
	j, err = j.Finish("b", 2, nil, "snapshot-failed")
	if err != nil {
		t.Fatal(err)
	}
	// b has failed; a now runs before c when c became leader. No new job/ID.
	if !j.CanBegin("a", "c") || j.CanBegin("c", "c") {
		t.Fatal("handoff failed to keep current leader last")
	}
	j, err = j.Skip("a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !j.CanBegin("c", "c") {
		t.Fatal("failure/unreachable blocked remaining target")
	}
	j, err = j.Begin("c", "c", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.Finish("c", 1, nil, "stale"); err == nil {
		t.Fatal("stale result accepted")
	}
	j, err = j.Finish("c", 2, nil, "disk-full")
	if err != nil || !j.Terminal() {
		t.Fatal("original job did not settle", err)
	}
}
func TestCompactNeverCallsLogicalFreePagesPhysicalShrinkingOrDeletesUnsnapshottedTail(t *testing.T) {
	options := CompactOptions{Mode: "minimal", Retain: 1000}
	if options.Effective(512) != 512 || (CompactOptions{Mode: "minimal", Retain: 1}).Effective(512) != 1 || (CompactOptions{Mode: "keep"}).Effective(512) != 512 {
		t.Fatal("retention unexpectedly increased or ignored")
	}
	m := CompactMetrics{LogKnown: true, FirstIndex: 3, LastIndex: 10, LogEntries: 8, LogFileKnown: true, LogUsedKnown: true, LogFileBytes: 4096, LogFreeBytes: 1024, LogUsedBytes: 3072, SnapshotKnown: true, SnapshotIndex: 5}
	if !m.Valid() || RetentionMet(m, 1) {
		t.Fatal("unsnapshotted tail became target success")
	}
	r := CompactResult{Schema: 1, Dispatch: CompactDispatch{Schema: 1, Operation: "maintenance-1", At: 1, MinimumIndex: 5, Options: CompactOptions{Mode: "minimal", Retain: 1}, ConfiguredTrailing: 512, EffectiveTrailing: 1, Before: m}, After: m, ConfigRestored: true}
	if r.Validate() != nil || r.TargetMet {
		t.Fatal("valid SDK snapshot with retained tail misreported")
	}
	j, err := NewCompactJob("maintenance-1", r.Dispatch.Options, true, []CompactNode{{Node: "a", Key: [32]byte{1}}})
	if err != nil {
		t.Fatal(err)
	}
	j, err = j.Begin("a", "a", 1)
	if err != nil {
		t.Fatal(err)
	}
	j, err = j.Finish("a", 2, &r, "retention-not-met")
	if err != nil || j.Nodes[0].State != "failed" {
		t.Fatal("unmet target hidden as done", err)
	}
}

func TestCompactFailureCannotBecomeSuccessFromEmptyLogsWithoutAcceptedSnapshot(t *testing.T) {
	// Empty logs alone satisfy a numeric retention check. An early snapshot
	// failure still has no positive accepted-prefix evidence and must serialize.
	r := CompactResult{Schema: 1, Dispatch: CompactDispatch{Schema: 1, Operation: "failed-snapshot", At: 1, MinimumIndex: 10, Options: CompactOptions{Mode: "minimal", Retain: 1}, ConfiguredTrailing: 512, EffectiveTrailing: 1}, After: CompactMetrics{LogKnown: true}, ConfigRestored: true, ErrorCode: "disk-full", Error: "no space left on device"}
	if r.Validate() != nil || r.Compacted() || r.TargetMet {
		t.Fatal("early failure cannot be recorded", r)
	}
	r.TargetMet = true
	if r.Validate() == nil {
		t.Fatal("empty log counts replaced accepted snapshot evidence")
	}
}
