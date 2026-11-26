// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/moby/moby/client"
)

// S5/S6/S7 share the original registered ext4 root, managed registry, installed
// rootless BuildKit and Runtime. No Git/draft/private-FROM/Tail/100MB scope is
// repeated. Age/partial/UNKNOWN details reuse the existing SDK/core cases.
func (f *managedRegistryNative) verifyImageBuildCacheRuntimeNative(t *testing.T, ctx context.Context, r *Runtime, root string, base imagebuild.ContextSpec, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	f.public["ImageBuildScope"] = "cache-runtime"
	f.save()
	if r.imageBuildNative == nil || r.nodeRoots == nil {
		t.Fatal("existing native build/root owners required")
	}
	// Give each sequential subtest the existing CLI runner with its own failure
	// owner. The wallet/journal is opened only by that one synchronous runner.
	withCLI := func(t *testing.T) *managedRegistryNative {
		copy := *f
		copy.cli = func(inputs []*os.File, args ...string) []byte {
			t.Helper()
			body, diagnostic, err := copy.runCLI(inputs, args...)
			if err != nil {
				t.Fatal("actual cache CLI", args, err, string(body), string(diagnostic))
			}
			return body
		}
		return &copy
	}
	book := func(t *testing.T) control.ImageBuildCatalog {
		t.Helper()
		b, err := p.ImageBuilds(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var seed control.ImageBuildJobRecord
	var version, cache [32]byte
	var entries []imagebuild.CacheEntry
	var before imagebuild.CacheSummary
	var cacheHold imagebuild.NativeRootHold
	var cachePin nodestorage.RootPin
	var cacheDir os.FileInfo
	const jobID = "rq6-cache-seed"
	const manualID = "rq6-cache-selected"
	var manual control.ImageBuildCachePruneRecord
	var automatic control.ImageBuildCachePruneRecord
	items := func(t *testing.T, f *managedRegistryNative) (imagebuild.CachePage, []imagebuild.CacheEntry) {
		t.Helper()
		var first imagebuild.CachePage
		var all []imagebuild.CacheEntry
		after := ""
		for {
			args := []string{"registry", "build-cache-items", hex.EncodeToString(cache[:]), "--node", "node-a", "--tenant", "tenant"}
			if after != "" {
				args = append(args, "--after", after)
			}
			var page control.ImageBuildCachePage
			if err := json.Unmarshal(f.cli(nil, args...), &page); err != nil || !page.ValidQuery("tenant", imagebuild.CacheQuery{Cache: &cache, Node: "node-a"}, after) || !page.Page.Available || page.Page.Borrowed || page.JobSnapshot != seed.Run.Spec.Digest() || page.Context != base.ID || page.Page.Offset != uint32(len(all)) {
				t.Fatal("exact original cache item page", err)
			}
			if after == "" {
				first = page.Page
			} else if page.Page.Snapshot != first.Snapshot || page.Page.Count != first.Count || page.Page.ReportedBytes != first.ReportedBytes {
				t.Fatal("cache items mixed observation snapshots")
			}
			all = append(all, page.Page.Entries...)
			if page.Next == "" {
				if uint32(len(all)) != first.Count {
					t.Fatal("cache pagination omitted original SDK entries")
				}
				return first, all
			}
			if page.Next == after || len(page.Page.Entries) == 0 {
				t.Fatal("cache item cursor did not advance")
			}
			after = page.Next
		}
	}
	inventory := func(t *testing.T, f *managedRegistryNative, context string) control.ImageBuildCacheInventoryRow {
		t.Helper()
		var selected control.ImageBuildCacheInventoryRow
		found, after := false, ""
		for {
			args := []string{"registry", "build-caches"}
			if context != "" {
				args = append(args, context)
			}
			args = append(args, "--node", "node-a", "--tenant", "tenant")
			if after != "" {
				args = append(args, "--after", after)
			}
			var page control.ImageBuildPage
			if err := json.Unmarshal(f.cli(nil, args...), &page); err != nil || !control.ValidImageBuildCacheInventoryPage(page, control.ImageBuildQuery{Part: "caches", ID: context, Node: "node-a"}, after, true) {
				t.Fatal("actual server/context cache inventory", err)
			}
			for _, row := range page.Caches {
				if row.Cache != cache {
					continue
				}
				if found || row.Code != "OK" || row.Owner != r.Identity.Public || row.Root != base.Root.ID || row.RootGeneration != base.Root.Generation || row.Builder != seed.Run.Spec.Policy.BuilderImage || row.RepresentativeJob != jobID || row.RepresentativeSnapshot != seed.Run.Spec.Digest() || row.Context != base.ID || row.Usage == nil || !row.Usage.Recorded || !row.Usage.Allocated || !row.Usage.Available || row.Usage.Borrowed {
					t.Fatal("inventory lost original native cache/owner/root/builder")
				}
				selected, found = row, true
			}
			if page.Next == "" {
				break
			}
			if page.Next == after {
				t.Fatal("cache inventory cursor did not advance")
			}
			after = page.Next
		}
		if !found {
			t.Fatal("original cache absent from actual inventory")
		}
		return selected
	}
	retained := func(t *testing.T) {
		t.Helper()
		hold, exists, err := r.imageBuildNative.RootHold(seed.Run.Spec, imagebuild.CacheRoot)
		if err != nil || !exists || hold != cacheHold || hold.Returning || hold.Returned {
			t.Fatal("cleanup released/replaced original cache root lease", err)
		}
		pin, held, err := r.nodeRoots.RecordedPin(base.Root, cachePin.Consumer)
		if err != nil || !held || pin.Lease != cachePin.Lease || pin.Root != cachePin.Root {
			t.Fatal("cleanup changed original RootManager dependency", err)
		}
		current, err := os.Lstat(filepath.Join(base.Root.Path, ".mydc-imagebuild", "build-cache", hex.EncodeToString(cache[:])))
		if err != nil || !os.SameFile(cacheDir, current) || !current.IsDir() {
			t.Fatal("cleanup removed/recreated original cache inode", err)
		}
	}
	closed := func(t *testing.T, row control.ImageBuildCachePruneRecord) imagebuild.NativeCachePruneRecord {
		t.Helper()
		spec, err := row.NativeSpec(seed.Run.Spec)
		if err != nil {
			t.Fatal(err)
		}
		native, err := r.imageBuildNative.CachePruneRecord(spec)
		if err != nil || row.Pending() || row.State != "succeeded" || len(row.Reports) < 2 || row.Reports[0].Action != "begin" || !native.Claimed || !native.Closed || !native.SDKSucceeded() || native.Completion == nil || !native.Completion.Valid(spec) || native.Completion.Result.Code != "OK" || native.Daemon == nil || !native.Daemon.Effects.StartSent || !native.Daemon.Effects.Waited || !native.Daemon.Effects.Removed || native.Observation == nil || native.Observation.Code != "OK" {
			t.Fatal("original cleanup did not close actual SDK/daemon/FD/cache ownership", row.State, err)
		}
		last := row.Reports[len(row.Reports)-1]
		if last.Action != "complete" || last.Native == nil || *last.Native != native.Completion.Native || last.ClosedAt != native.Completion.At || last.RemovedCount != native.Completion.Result.RemovedCount || last.ReportedBytes != native.Completion.Result.ReportedBytes || last.Code != native.Completion.Result.Code || native.Spec.Source.Digest() != seed.Run.Spec.Digest() || native.Spec.Source.Scope.Root != base.Root {
			t.Fatal("shared cleanup report differs from original native closure")
		}
		for _, report := range row.Reports {
			if report.Owner != r.Identity.Public || report.Intent != row.Digest() || report.Epoch < row.SubmissionEpoch() || report.RootRevision <= row.SubmissionRootRevision() || !ed25519.Verify(r.Identity.Public[:], control.ImageBuildCachePruneReportBytes(report), report.Signature) {
				t.Fatal("cleanup report changed original owner/intent/epoch/root")
			}
		}
		if _, err = r.docker.API.ContainerInspect(ctx, native.Daemon.Effects.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatal("finite cache maintenance daemon survived original completion", err)
		}
		projection, err := p.ProjectResources(read().State)
		q, changeErr := row.Change()
		if err != nil || changeErr != nil {
			t.Fatal(err, changeErr)
		}
		if _, held := projection.Resources.Quotas.Reservation("workload/imagebuild-cache-prune/tenant/" + q.ID + "/builder"); held {
			t.Fatal("terminal owner cleanup retained execution budget")
		}
		retained(t)
		return native
	}
	waitPrune := func(t *testing.T, id string, auto bool) control.ImageBuildCachePruneRecord {
		t.Helper()
		var result control.ImageBuildCachePruneRecord
		var reserved, borrowed bool
		var nextPoll time.Time
		registryNativeWait(t, ctx, "original cache cleanup "+id, func() bool {
			if auto && time.Now().Before(nextPoll) {
				return false
			}
			nextPoll = time.Now().Add(time.Second)
			view := read()
			b, err := p.ImageBuilds(view.State)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range b.CachePrunes {
				q, err := row.Change()
				if err != nil || q.Cache != cache || (row.Automatic != nil) != auto || !auto && q.ID != id {
					continue
				}
				if row.Source != jobID || row.SourceDigest != seed.Run.Spec.Digest() || q.Node != base.Root.Node || q.Tenant != base.Tenant {
					t.Fatal("scheduler/worker changed original cache source")
				}
				if row.State == "running" || row.State == "unknown" {
					projection, err := p.ProjectResources(view.State)
					if err != nil {
						t.Fatal(err)
					}
					hold, found := projection.Resources.Quotas.Reservation("workload/imagebuild-cache-prune/tenant/" + q.ID + "/builder")
					limits, err := row.Limits(seed.Run.Spec)
					if err != nil || !found || hold.Owner != r.Identity.Public || hold.Need.CPU != uint64(limits.CPUMillis)*1_000_000 || hold.Need.Memory != uint64(limits.MemoryBytes) {
						t.Fatal("running actual cache worker lacks original budget reservation", err)
					}
					reserved = true
					spec, err := row.NativeSpec(seed.Run.Spec)
					if err != nil {
						t.Fatal(err)
					}
					if native, err := r.imageBuildNative.CachePruneRecord(spec); err == nil && native.Claimed && !native.Closed {
						summary, err := r.imageBuildNative.ReadCacheSummary(seed.Run.Spec)
						if err != nil || !summary.Allocated {
							t.Fatal("actual maintenance worker lost original cache allocation", err)
						}
						// The worker may close between these read-only snapshots.
						// Only a positively observed borrow is ownership evidence.
						if summary.Borrowed {
							retained(t)
							borrowed = true
						}
					}
				}
				if !row.Pending() {
					// A finite worker can begin and close between polls. Sampling
					// is supplementary; signed begin/complete, persisted native
					// closure and terminal budget/RootHold checks remain mandatory.
					t.Log("original cache worker samples", q.ID, "reservation", reserved, "borrow", borrowed)
					f.public["ImageBuildCacheSamples/"+q.ID] = map[string]bool{"ReservationObserved": reserved, "BorrowObserved": borrowed}
					result = row
					return true
				}
			}
			return false
		})
		return result
	}
	if !t.Run("RQ6-S5-cache-inventory", func(t *testing.T) {
		f := withCLI(t)
		b := book(t)
		context, ok := b.Context("tenant", base.ID)
		if !ok {
			t.Fatal("original context missing")
		}
		base.Secrets, base.Tags = nil, []string{"native-cache-runtime"}
		change("rq6-cache-context", "put-build-context", context.Revision, control.ImageBuildContextPut{Spec: base})
		// Small real COPY layers provide SDK cache records without a base pull,
		// shell fixture, private-FROM flow or the large log/build-secret scope.
		dockerfile := "FROM scratch\nCOPY context-proof /seed-one\nCOPY context-proof /seed-two\nCOPY context-proof /seed-three\n"
		version = f.uploadBuildNative(t, root, base.ID, "rq6-cache-upload", dockerfile, strings.Repeat("owned-cache-seed\n", 32768))
		f.cli(nil, "registry", "build", base.ID, hex.EncodeToString(version[:]), "--tenant", "tenant", "--job", jobID, "--request-id", "rq6-cache-submit", "--no-input")
		seed = f.waitImageBuildNative(t, ctx, r, p, read, jobID, "OK")
		cache = imagebuild.CacheIdentity(seed.Run.Spec)
		native, err := r.imageBuildNative.Record(seed.Run.Spec)
		if err != nil || native.Solve == nil || native.Solve.Code != "OK" || !native.Solve.Returned || !native.Waited || !native.Removed || native.Workspace == nil || !native.Workspace.Closed || native.Root == nil || !native.Root.Returned || native.Completion == nil || native.Completion.Result != seed.Run.Closure.Result {
			t.Fatal("seed solve/daemon/workspace/job-root did not close", err)
		}
		if _, err = r.docker.API.ContainerInspect(ctx, native.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatal("seed builder survived completion", err)
		}
		var exists bool
		cacheHold, exists, err = r.imageBuildNative.RootHold(seed.Run.Spec, imagebuild.CacheRoot)
		if err != nil || !exists || cacheHold.Lease.Token == 0 || cacheHold.Returned || cacheHold.Returning {
			t.Fatal("seed completion discarded reusable cache lease", err)
		}
		consumer, err := r.imageBuildNative.RootConsumer(seed.Run.Spec, imagebuild.CacheRoot)
		if err != nil {
			t.Fatal(err)
		}
		cachePin, exists, err = r.nodeRoots.RecordedPin(base.Root, consumer)
		if err != nil || !exists || cachePin.Lease != cacheHold.Lease {
			t.Fatal("original cache RootManager pin missing", err)
		}
		cacheDir, err = os.Lstat(filepath.Join(base.Root.Path, ".mydc-imagebuild", "build-cache", hex.EncodeToString(cache[:])))
		if err != nil || !cacheDir.IsDir() {
			t.Fatal("original retained native cache missing", err)
		}
		server, contextPage := inventory(t, f, ""), inventory(t, f, base.ID)
		if !reflect.DeepEqual(server, contextPage) {
			t.Fatal("server/context filters changed the selected native cache")
		}
		before = *server.Usage
		page, all := items(t, f)
		entries = all
		if page.Snapshot != before.Snapshot || page.ReportedBytes != before.ReportedBytes || page.Count != before.Count || page.ObservedBy != seed.Run.Spec.Digest() || page.Count == 0 || page.ReportedBytes <= 0 {
			t.Fatal("actual cache summary/items differ from SDK solve observation")
		}
		var jobPage control.ImageBuildCachePage
		if err = json.Unmarshal(f.cli(nil, "registry", "build-cache", jobID, "--tenant", "tenant"), &jobPage); err != nil || jobPage.Page.Snapshot != page.Snapshot || !reflect.DeepEqual(jobPage.Page.Entries, page.Entries) {
			t.Fatal("job and explicit cache ID selected different native observation", err)
		}
		retained(t)
	}) {
		return
	}
	if !t.Run("RQ6-S6-selected-manual-prune", func(t *testing.T) {
		f := withCLI(t)
		var eligible []imagebuild.CacheEntry
		var protected []string
		for _, entry := range entries {
			if entry.InUse || entry.Shared || entry.Kind == "internal" || entry.Kind == "frontend" {
				// Internal/frontend identities remain protected across the finite
				// daemon reopen; cached InUse by itself is not a live SDK verdict.
				if entry.Kind == "internal" || entry.Kind == "frontend" {
					protected = append(protected, entry.ID)
				}
			} else if entry.Bytes > 0 {
				eligible = append(eligible, entry)
			}
		}
		if len(eligible) < 2 {
			t.Fatal("seed must expose at least two actual private SDK records for manual and automatic cleanup")
		}
		slices.SortFunc(eligible, func(a, b imagebuild.CacheEntry) int {
			if a.Bytes < b.Bytes {
				return -1
			}
			if a.Bytes > b.Bytes {
				return 1
			}
			return strings.Compare(a.ID, b.ID)
		})
		selected := eligible[0].ID
		requested := append([]string{selected}, protected...)
		slices.Sort(requested)
		if len(requested) > 64 {
			requested = []string{selected} // Preserve the public selection bound.
			protected = nil
		}
		args := []string{"registry", "prune-build-cache", hex.EncodeToString(cache[:]), "--node", "node-a", "--tenant", "tenant", "--prune-id", manualID, "--request-id", "rq6-cache-prune", "--mode", "entries"}
		for _, id := range requested {
			args = append(args, "--entry", id)
		}
		f.cli(nil, args...)
		manual = waitPrune(t, manualID, false)
		q, err := manual.Change()
		if err != nil || manual.Origin.VerifyOriginal(p.Cluster) != nil || manual.Origin.RequestID != "rq6-cache-prune" || q.Filter.Mode != "entries" || !slices.Equal(q.Filter.IDs, requested) {
			t.Fatal("manual cleanup changed original signed selection", err)
		}
		native := closed(t, manual)
		selection := imagebuild.CacheCleanupSelection{Kind: "manual-entries", Snapshot: native.RPC.Snapshot, IDs: []string{selected}}
		if native.RPC.Code != "OK" || native.RPC.Selected != 1 || native.RPC.Selection != selection.Digest() || native.RPC.RemovedCount > 1 || native.RPC.SentAt == 0 || native.RPC.ReturnedAt == 0 {
			t.Fatal("actual SDK did not consume exactly the eligible explicit ID", native.RPC)
		}
		page, after := items(t, f)
		if page.ObservedKind != "cache-prune" || page.ObservedBy != manual.Digest() || page.Snapshot == before.Snapshot {
			t.Fatal("actual manual SDK readback lost its original observation")
		}
		// A selected unused record can still be a parent of retained cache.
		// SDK success therefore permits zero ACKs; only a positive removal ACK
		// is evidence of reclamation, and the readback must agree for this ID.
		present := slices.ContainsFunc(after, func(e imagebuild.CacheEntry) bool { return e.ID == selected })
		if present != (native.RPC.RemovedCount == 0) || native.RPC.RemovedCount == 0 && native.RPC.ReportedBytes != 0 {
			t.Fatal("manual SDK removal ACK differs from selected ID readback", native.RPC.RemovedCount, present)
		}
		f.public["ImageBuildCacheManualSDK"] = map[string]any{"Selected": native.RPC.Selected, "RemovedCount": native.RPC.RemovedCount, "ReportedBytes": native.RPC.ReportedBytes, "ReclamationObserved": native.RPC.RemovedCount == 1}
		f.save()
		for _, id := range protected {
			if !slices.ContainsFunc(after, func(e imagebuild.CacheEntry) bool { return e.ID == id }) {
				t.Fatal("explicit manual selection removed a protected SDK entry", id)
			}
		}
		// The current InUse exclusion is the same SelectCachePrune/SDK core
		// covered by TestManualCacheSelectionScopesEntriesAndAgeWithoutDeletingLiveSharedOrInternal;
		// a stale seed InUse bit is never asserted as current native protection.
		entries = after
		retained(t)
	}) {
		return
	}
	if !t.Run("RQ6-S7-runtime-policy-cleanup", func(t *testing.T) {
		f := withCLI(t)
		b := book(t)
		policy, ok := b.Policy("tenant")
		if !ok || policy.Deleted {
			t.Fatal("current accepted cleanup policy missing")
		}
		current := policy.Spec.Own()
		// A current policy, not a modified frozen JobSpec, lowers high-water.
		// Keep capacity >= the original small ZIP and use a genuinely occupied
		// native cache. Age witnesses are reused; no dates/DB clocks are edited.
		current.CacheBytes, current.Cleanup.HighWaterPercent = 1<<20, 1
		target := current.CacheBytes / 100
		var private int64
		for _, entry := range entries {
			if !entry.Shared {
				private += entry.Bytes
			}
		}
		if private <= target {
			t.Fatal("remaining real cache does not exceed the selected high-water")
		}
		change("rq6-cache-high-water", "set-image-build-policy", policy.Revision, control.ImageBuildPolicyPut{Spec: current})
		definition, _ := book(t).Policy("tenant")
		// This intentionally waits for the REAL 300-second interval after the
		// latest SDK observation (and the ordinary scheduler's next due tick).
		// Only the same original handle/cache status is observed while pending.
		// No direct submit/consume/prune, synthetic timestamp or retry is used.
		automatic = waitPrune(t, "automatic-current-policy", true)
		if automatic.Automatic == nil || automatic.Automatic.PolicyRevision != definition.Revision || !reflect.DeepEqual(automatic.Origin, definition.Definition) || automatic.Automatic.SourceDigest != seed.Run.Spec.Digest() || automatic.Automatic.Owner != r.Identity.Public || automatic.Automatic.Sequence != 1 {
			t.Fatal("runtime scheduler did not bind the original current policy/source")
		}
		native := closed(t, automatic)
		if native.Spec.Automatic == nil || !reflect.DeepEqual(*native.Spec.Automatic, current) || native.Spec.Source.Policy.CacheBytes != seed.Run.Spec.Policy.CacheBytes || native.PolicySize == nil || native.PolicySize.Kind != "size" || native.PolicySize.MaxUsedSpace != target || native.PolicySize.Code != "OK" || native.PolicySize.Selected == 0 || native.PolicySize.SentAt == 0 || native.PolicySize.ReturnedAt == 0 || native.PolicySize.RemovedCount == 0 || native.RPC.Kind != "age" || native.RPC.Code != "SKIPPED" || native.RPC.Snapshot == ([32]byte{}) || native.PolicySize.Snapshot == ([32]byte{}) {
			t.Fatal("actual automatic worker did not use current high-water and separate age/size receipts")
		}
		page, _ := items(t, f)
		row := inventory(t, f, base.ID)
		if page.ObservedKind != "cache-prune" || page.ObservedBy != automatic.Digest() || row.Usage.ObservedBy != automatic.Digest() || row.Usage.Snapshot != page.Snapshot || page.ReportedBytes >= before.ReportedBytes {
			t.Fatal("automatic SDK result not reflected in actual public cache observation")
		}
		var status control.ImageBuildPage
		if err := json.Unmarshal(f.cli(nil, "registry", "build-cache-prunes", automatic.Automatic.ID(), "--node", "node-a", "--tenant", "tenant"), &status); err != nil || len(status.CachePrunes) != 1 || status.CachePrunes[0].State != "succeeded" || !status.CachePrunes[0].Automatic || status.CachePrunes[0].Code != native.Completion.Result.Code || status.CachePrunes[0].ReportedBytes != native.Completion.Result.ReportedBytes || status.CachePrunes[0].RemovedCount != native.Completion.Result.RemovedCount {
			t.Fatal("actual CLI automatic result differs from original closed owner fact", err)
		}
		retained(t)
	}) {
		return
	}
	// Stop future passes through an exact current policy delete after releasing
	// the original metadata references. The owned fixture then joins Runtime and
	// removes its root; cache cleanup itself never returns the retained lease.
	f.cli(nil, "registry", "delete-build-job", jobID, "--tenant", "tenant", "--request-id", "rq6-cache-delete-job")
	b := book(t)
	stored, ok := b.Version("tenant", version)
	if !ok {
		t.Fatal("original cache seed version missing")
	}
	change("rq6-cache-delete-version", "delete-build-version", stored.Number, control.ImageBuildVersionSelection{Tenant: "tenant", ID: version})
	context, _ := book(t).Context("tenant", base.ID)
	change("rq6-cache-delete-context", "delete-build-context", context.Revision, control.ImageBuildSelection{Tenant: "tenant", ID: base.ID})
	policy, _ := book(t).Policy("tenant")
	change("rq6-cache-delete-policy", "delete-image-build-policy", policy.Revision, control.ImageBuildSelection{Tenant: "tenant"})
	parts := strings.SplitN(seed.Run.Closure.Result.Image, "@", 2)
	if len(parts) != 2 {
		t.Fatal("original seed publication is not digest pinned")
	}
	f.cli(nil, "registry", "delete-image", "private", "--tenant", "tenant", "--repository", base.Repository, "--reference", parts[1], "--expected-digest", parts[1], "--request-id", "rq6-cache-delete-output")
	f.maintenanceNativeWait(t, ctx, p, read, "rq6-cache-delete-output", "done", "OK")
	f.public["ImageBuildCacheSeed"], f.public["ImageBuildCacheManual"], f.public["ImageBuildCacheAutomatic"] = jobID, manual.Digest(), automatic.Digest()
	f.save()
}
