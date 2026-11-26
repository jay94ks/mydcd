// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	controlapi "github.com/moby/buildkit/api/services/control"
	bolt "go.etcd.io/bbolt"
)

// Actual pinned SDK gRPC/bbolt, fixture Engine and shared work. Observations
// are verified separately from prune success and actual container shutdown.
func TestManualCacheObservationRefreshesScopeItemsAndSummaryWithoutPretendingItWasASolve(t *testing.T) {
	f, g, authorize := cachePruneDaemonFixture(t)
	if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.StartCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	server := &cachePruneControlFixture{rows: map[string]*controlapi.UsageRecord{"one": {ID: "one", Size: 7, Description: "RUN PASSWORD=never-copy"}, "busy": {ID: "busy", Size: 5, InUse: true}}}
	cachePruneDaemonSDK(t, f, g, server)
	if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	page, err := f.jobs.ReadCacheScope(g.Spec.Source, 0, [32]byte{})
	if err != nil || !page.Available || page.ObservedKind != "cache-prune" || page.ObservedBy != g.Spec.Intent || page.Count != 1 || page.Entries[0].ID != "busy" || page.ReportedBytes != 5 {
		t.Fatal(page, err)
	}
	summary, err := f.jobs.ReadCacheSummary(g.Spec.Source)
	if err != nil || summary.Snapshot != page.Snapshot || summary.ObservedKind != page.ObservedKind || summary.ObservedBy != page.ObservedBy || summary.ReportedBytes != 5 {
		t.Fatal(summary, err)
	}
	newer := g.Spec.Source.Own()
	newer.ID = "new-representative"
	if _, err := f.jobs.Record(newer); !errors.Is(err, ErrNativeMissing) {
		t.Fatal(err)
	}
	if next, err := f.jobs.ReadCacheScope(newer, 0, page.Snapshot); err != nil || next.Snapshot != page.Snapshot || next.ObservedBy != g.Spec.Intent {
		t.Fatal("new representative relabelled observation", next, err)
	}
	row, err := f.jobs.CachePruneRecord(g.Spec)
	if err != nil || row.Observation == nil || row.Observation.Snapshot == nil || *row.Observation.Snapshot != page.Snapshot || row.RPC == nil || row.RPC.Snapshot == page.Snapshot {
		t.Fatal("readback did not retain distinct pre-prune selection", row, err)
	}
	raw, _ := json.Marshal(row)
	if strings.Contains(string(raw), "never-copy") {
		t.Fatal("opaque SDK description retained")
	}
	f.reopen()
	if again, err := f.jobs.ReadCacheScope(g.Spec.Source, 0, page.Snapshot); err != nil || again.Snapshot != page.Snapshot {
		t.Fatal("observation lost original journal", again, err)
	}
}

func TestManualObservationFailurePreservesPriorSnapshotAndDoesNotRewritePruneACK(t *testing.T) {
	f, g, authorize := cachePruneDaemonFixture(t)
	if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.StartCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	server := &cachePruneControlFixture{failUsageAt: 2, rows: map[string]*controlapi.UsageRecord{"one": {ID: "one", Size: 7}, "busy": {ID: "busy", Size: 5, InUse: true}}}
	cachePruneDaemonSDK(t, f, g, server)
	if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal("failed readback changed actual prune", err)
	}
	page, err := f.jobs.ReadCacheScope(g.Spec.Source, 0, [32]byte{})
	if err != nil || !page.Available || page.LastAttemptCode != "UNAVAILABLE" || page.Count != 2 || page.ReportedBytes != 12 || page.ObservedKind != "cache-prune" {
		t.Fatal("last success erased or replaced by empty", page, err)
	}
	row, err := f.jobs.CachePruneRecord(g.Spec)
	if err != nil || row.RPC == nil || row.RPC.Code != "OK" || row.RPC.RemovedCount != 1 || row.RPC.ReportedBytes != 7 || row.Observation == nil || row.Observation.Code != "UNAVAILABLE" {
		t.Fatal(row, err)
	}
	if err := f.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(nativeBucket).Get(cacheUsageKey(f.plan.Cache))
		if strings.Contains(string(raw), "PASSWORD") {
			t.Fatal("raw observation error retained")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestManualObservationRejectsMissingOrChangedNativeWitnessInsteadOfFallingBackToSource(t *testing.T) {
	f, g, authorize := cachePruneDaemonFixture(t)
	if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.StartCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	server := &cachePruneControlFixture{rows: map[string]*controlapi.UsageRecord{"one": {ID: "one", Size: 7}}}
	cachePruneDaemonSDK(t, f, g, server)
	if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	row, err := f.jobs.CachePruneRecord(g.Spec)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := *row.Observation.Snapshot
	row.Observation.Snapshot = &[32]byte{99}
	if err := f.jobs.saveCachePrune(row); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.ReadCacheScope(g.Spec.Source, 0, [32]byte{}); !errors.Is(err, ErrStorage) {
		t.Fatal("foreign snapshot became observed data", err)
	}
	row.Observation.Snapshot = &snapshot
	if err := f.jobs.saveCachePrune(row); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(nativeBucket).Delete(nativeCachePruneKey(g.Spec.Intent)) }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.ReadCacheSummary(g.Spec.Source); !errors.Is(err, ErrStorage) {
		t.Fatal("missing maintenance became a build observation", err)
	}
}
