// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	controlapi "github.com/moby/buildkit/api/services/control"
	bkclient "github.com/moby/buildkit/client"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func cachePolicyDaemonFixture(t *testing.T) (*nativeFixture, NativeCachePruneGrant, NativeCachePruneAuthority) {
	t.Helper()
	return cachePruneDaemonFixtureWithSpec(t, func(s *NativeCachePruneSpec) {
		policy := s.Source.Policy.Own()
		policy.Cleanup.UnusedDays, policy.Cleanup.HighWaterPercent = 1, 50
		policy.CacheBytes, policy.MemoryBytes, policy.WorkspaceBytes = 100, 64<<20, 128<<20
		policy.CPUMillis, policy.Seconds = 125, 45
		s.Automatic, s.Filter = &policy, CachePruneFilter{Mode: "policy"}
	})
}

func cachePolicyRows() map[string]*controlapi.UsageRecord {
	return map[string]*controlapi.UsageRecord{
		"old":    {ID: "old", Size: 10, CreatedAt: timestamppb.New(time.Now().Add(-72 * time.Hour))},
		"young":  {ID: "young", Size: 100, CreatedAt: timestamppb.Now()},
		"busy":   {ID: "busy", Size: 1000, InUse: true},
		"shared": {ID: "shared", Size: 1000, Shared: true},
	}
}

func startPolicyDaemon(t *testing.T, f *nativeFixture, g NativeCachePruneGrant, authorize NativeCachePruneAuthority, server *cachePruneControlFixture) {
	t.Helper()
	if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.StartCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	cachePruneDaemonSDK(t, f, g, server)
}

// Real pinned SDK gRPC, native DB/files and the common finite daemon path.
// Docker/shared user/quorum authority remain fixtures and prove no rollout.
func TestPolicyCachePassUsesCurrentLimitsAndTwoIndependentSDKReceipts(t *testing.T) {
	f, g, authorize := cachePolicyDaemonFixture(t)
	server := &cachePruneControlFixture{rows: cachePolicyRows()}
	startPolicyDaemon(t, f, g, authorize, server)
	_, opts, err := planCachePrune(g.Spec, f.docker.Owner)
	if err != nil || opts.Config.Image != f.spec.Policy.BuilderImage || opts.HostConfig.NanoCPUs != 125_000_000 || opts.HostConfig.Memory != 64<<20 || opts.Config.Entrypoint[4] != strconv.FormatUint(g.Spec.At+45, 10) || g.Spec.Source.Digest() != f.spec.Digest() {
		t.Fatal("original source or current execution limits changed", err)
	}
	if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	row, err := f.jobs.CachePruneRecord(g.Spec)
	if err != nil || !row.SDKSucceeded() || row.RPC.Kind != "age" || row.RPC.Code != "OK" || row.PolicySize.Kind != "size" || row.PolicySize.Code != "OK" || row.PolicySize.MaxUsedSpace != 50 || row.RPC.Snapshot == row.PolicySize.Snapshot {
		t.Fatal("two-step selection/receipt lost", row, err)
	}
	server.mu.Lock()
	requests, reads := append([]*controlapi.PruneRequest(nil), server.requests...), server.usageCalls
	server.mu.Unlock()
	if len(requests) != 2 || reads != 3 || len(requests[0].Filter) != 1 || requests[0].Filter[0] != `id=="old"` || len(requests[1].Filter) != 1 || requests[1].Filter[0] != `id=="young"` || requests[0].MaxUsedSpace != 0 || requests[1].MaxUsedSpace != 50 {
		t.Fatal("SDK did not use fresh age then size selection", requests, reads)
	}
	if err := f.jobs.RecordCachePruneOutcome(g.Spec, "OK"); err != nil {
		t.Fatal(err)
	}
	row, err = f.jobs.CachePruneRecord(g.Spec)
	if err != nil || row.Outcome.RemovedCount != 2 || row.Outcome.ReportedBytes != 110 {
		t.Fatal(row, err)
	}
	if err := f.jobs.StopCachePrune(f.ctx(), g.Spec, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.RemoveCachePrune(f.ctx(), g.Spec); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec); err != nil {
		t.Fatal(err)
	}
	_, private := testScope(1, [32]byte{1})
	completion, err := f.jobs.SealCachePruneCompletion(g.Spec, uint64(time.Now().Unix()), private)
	if err != nil || !completion.Valid(g.Spec) || completion.Result.RemovedCount != 2 {
		t.Fatal("full policy outcome did not close", completion, err)
	}
	f.reopen()
	if page, err := f.jobs.ReadCacheScope(g.Spec.Source, 0, [32]byte{}); err != nil || page.Count != 2 || page.ReportedBytes != 2000 {
		t.Fatal("live protected entries lost", page, err)
	}
	// A replaced shared slot may retire this pass, but the last successful
	// observation must retain its original signed native producer.
	if removed, err := f.jobs.CollectClosedAutomaticCachePrunes(100, nil); err != nil || len(removed) != 0 {
		t.Fatal("last successful observation lost its producer", removed, err)
	}
	if _, err := f.jobs.ReadCacheSummary(g.Spec.Source); err != nil {
		t.Fatal("retention broke the original observation", err)
	}
	if err := f.jobs.BeginRootReturn(f.spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.FinishRootReturn(f.spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.SealCompletion(f.grant, JobResult{Code: "BUILD_FAILED"}, uint64(time.Now().Unix()), private); err != nil {
		t.Fatal(err)
	}
	retirement := NativeCacheRetirementGrant{Source: f.spec.Own(), Operation: "retire-tenant", InventoryHash: [32]byte{2}, OwnersHash: [32]byte{3}, StartedRevision: 2, Index: 100, Epoch: 1}
	root := nativeTestRoot(t, f.spec)
	if err := f.jobs.RetireTenantCache(f.ctx(), retirement, originalCacheLease(f), int(root.Fd())); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.FinishCacheRetirement(retirement); err != nil {
		t.Fatal(err)
	}
	if summary, err := f.jobs.ReadCacheSummary(f.spec); err != nil || summary.Available || summary.Allocated {
		t.Fatal("deallocated cache still exposes old successful observation", summary, err)
	}
	if removed, err := f.jobs.CollectClosedAutomaticCachePrunes(100, nil); err != nil || len(removed) != 1 || removed[0] != g.Spec.Intent {
		t.Fatal("disposed cache kept an otherwise retired observation producer", removed, err)
	}
}

func TestPolicyCacheFailureStopsSuffixAndNeverReplaysEitherSentPrune(t *testing.T) {
	for _, mode := range []string{"age-partial", "between-reads", "size-partial", "final-observation", "size-commit"} {
		t.Run(mode, func(t *testing.T) {
			f, g, authorize := cachePolicyDaemonFixture(t)
			server := &cachePruneControlFixture{rows: cachePolicyRows()}
			switch mode {
			case "age-partial":
				server.mode = "partial"
			case "between-reads":
				server.failUsageAt = 2
			case "final-observation":
				server.failUsageAt = 3
			case "size-partial":
				server.before = func(*controlapi.PruneRequest) {
					if len(server.requests) == 2 {
						server.mode = "partial"
					}
				}
			}
			startPolicyDaemon(t, f, g, authorize, server)
			if mode == "size-commit" {
				f.jobs.db = &policySizeCommitFailure{Transactions: f.db}
			}
			if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); err == nil {
				t.Fatal("failed policy pass returned success", mode)
			}
			row, err := f.jobs.CachePruneRecord(g.Spec)
			if err != nil || row.RPC == nil {
				t.Fatal(row, err)
			}
			positive := mode == "final-observation"
			if row.SDKSucceeded() != positive {
				t.Fatal("observation or one positive step replaced complete RPC outcome", row)
			}
			server.mu.Lock()
			count := len(server.requests)
			server.mu.Unlock()
			if (mode == "age-partial" || mode == "between-reads") && (count != 1 || row.PolicySize != nil) {
				t.Fatal("size sent after incomplete age/readback", count, row)
			}
			if (mode == "size-partial" || mode == "size-commit") && (row.PolicySize == nil || row.PolicySize.Code != "UNKNOWN") {
				t.Fatal("lost size response was promoted", row)
			}
			if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); !errors.Is(err, ErrConflict) {
				t.Fatal("retained primary receipt allowed replay", err)
			}
			server.mu.Lock()
			after := len(server.requests)
			server.mu.Unlock()
			if after != count {
				t.Fatal("original Prune resent")
			}
			code := "FAILED"
			if positive {
				code = "OK"
			}
			if err := f.jobs.RecordCachePruneOutcome(g.Spec, code); err != nil {
				t.Fatal("failure could not be settled", err)
			}
		})
	}
}

type policySizeCommitFailure struct{ Transactions }

func (s *policySizeCommitFailure) Update(edit func(*bolt.Tx) error) error {
	return s.Transactions.Update(func(tx *bolt.Tx) error {
		if err := edit(tx); err != nil {
			return err
		}
		b := tx.Bucket(nativeBucket)
		return b.ForEach(func(key, raw []byte) error {
			if !bytes.HasPrefix(key, []byte("cache-prune/")) {
				return nil
			}
			var row NativeCachePruneRecord
			if json.Unmarshal(raw, &row) == nil && row.PolicySize != nil && row.PolicySize.ReturnedAt > 0 {
				return errors.New("injected policy size result commit loss")
			}
			return nil
		})
	})
}

func TestPolicyCacheNoOpStillObservesAndKeepsBothExplicitSkippedReceipts(t *testing.T) {
	f, g, authorize := cachePolicyDaemonFixture(t)
	server := &cachePruneControlFixture{rows: map[string]*controlapi.UsageRecord{"young": {ID: "young", Size: 1, CreatedAt: timestamppb.Now()}}}
	startPolicyDaemon(t, f, g, authorize, server)
	if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	row, err := f.jobs.CachePruneRecord(g.Spec)
	if err != nil || !row.SDKSucceeded() || row.RPC.Code != "SKIPPED" || row.PolicySize.Code != "SKIPPED" || row.RPC.SentAt != 0 || row.PolicySize.SentAt != 0 {
		t.Fatal(row, err)
	}
	server.mu.Lock()
	count, reads := len(server.requests), server.usageCalls
	server.mu.Unlock()
	if count != 0 || reads != 3 {
		t.Fatal("empty selection sent unbounded Prune or skipped observations", count, reads)
	}
}

func TestPolicyAckBudgetPreservesClosablePrefixInsteadOfOverflow(t *testing.T) {
	selection := CacheCleanupSelection{Kind: "size", Snapshot: [32]byte{1}, IDs: []string{"one", "two"}, MaxUsedSpace: 1}
	acks := newCacheCleanupAcks(selection)
	acks.byteLimit = 5
	if !acks.add(bkclient.UsageInfo{ID: "one", Size: 4}) || acks.add(bkclient.UsageInfo{ID: "two", Size: 2}) || !acks.invalid || acks.bytes != 4 || acks.count != 1 {
		t.Fatal("overflow ACK entered retained prefix", acks)
	}
	result, err := cachePruneNativeResult(NativeCachePruneRecord{RPC: &CacheCleanupStep{ReportedBytes: math.MaxInt64 - 5}, PolicySize: &CacheCleanupStep{ReportedBytes: acks.bytes, RemovedCount: acks.count}}, "FAILED")
	if err != nil || result.ReportedBytes != math.MaxInt64-1 {
		t.Fatal("valid partial prefix could not close", result, err)
	}
}
