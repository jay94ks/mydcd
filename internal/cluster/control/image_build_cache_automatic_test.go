// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/reconcile"
)

func idleCacheAutomaticFixture(t *testing.T) (*nodeStorageFixture, ImageBuildJobPlan) {
	t.Helper()
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	f.apply("manager", "cancel-image-build", 1, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
	book, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := book.Policy("tenant")
	policy.Spec.MemoryBytes, policy.Spec.CPUMillis = 64<<20, 125
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
	return f, plan
}

func cacheAutomaticPlanFixture(t *testing.T, f *nodeStorageFixture, plan ImageBuildJobPlan, at int64) ImageBuildCacheAutomaticReport {
	t.Helper()
	row, err := f.p.ImageBuildCacheAutomaticPlan(f.s, plan.Spec.Scope.Root.Key, "tenant", "node-a", imagebuild.CacheIdentity(plan.Spec), at)
	if err != nil {
		t.Fatal(err)
	}
	report := *row.Automatic
	report.Signature = ed25519.Sign(f.node, ImageBuildCacheAutomaticBytes(report))
	return report
}
func applyCacheAutomaticFixture(t *testing.T, f *nodeStorageFixture, r ImageBuildCacheAutomaticReport, want state.Code) state.Command {
	t.Helper()
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(result.Code, want, err)
	}
	f.s = next
	return cmd
}

// Actual accepted policy/UserOperation, signed owner reports and FSM state.
// Owner SDK/real closure facts are injected and prove no Docker execution.
func TestCacheAutomaticSlotConsumesAcceptedPolicyReservesCurrentLimitsAndAdvancesOnlyAfterClosure(t *testing.T) {
	f, plan := idleCacheAutomaticFixture(t)
	cache := imagebuild.CacheIdentity(plan.Spec)
	var previousID string
	for sequence := uint64(1); sequence <= 3; sequence++ {
		at := int64(2000 + (sequence-1)*400)
		r := cacheAutomaticPlanFixture(t, f, plan, at)
		if r.Sequence != sequence || r.ID() == previousID {
			t.Fatal("pass ID/sequence reused")
		}
		cmd := applyCacheAutomaticFixture(t, f, r, state.Applied)
		raw, _ := json.Marshal(r)
		if replay, err := f.p.ResolveImageBuildCacheAutomaticReport(f.s, r.Owner, raw); err != nil || replay != cmd {
			t.Fatal("original accepted report could not be resolved", err)
		}
		book, err := f.p.ImageBuilds(f.s)
		if err != nil || len(book.CachePrunes) != 1 {
			t.Fatal("recurring rows accumulated", len(book.CachePrunes), err)
		}
		row := book.CachePrunes[0]
		work, err := f.p.ImageBuildCachePruneWork(f.s, r.Owner, ImageBuildCachePruneWorkQuery{Tenant: "tenant", ID: r.ID(), At: at + 1})
		grant, cause := work.NativeGrant()
		if err != nil || cause != nil || !work.Allowed || grant.Spec.At != uint64(at) || grant.Spec.Automatic == nil || grant.Spec.Automatic.MemoryBytes != 64<<20 || grant.Spec.Source.Digest() != plan.Spec.Digest() {
			t.Fatal("policy limits replaced source or used old submission time", work.Blocked, err, cause)
		}
		if row.AcceptedAt() == uint64(row.Origin.At) || row.SubmissionRootRevision() == row.Origin.RootRevision {
			t.Fatal("definition and pass coordinates collapsed")
		}
		cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "begin", At: uint64(at + 1)}, state.Applied)
		reservations, err := f.p.imageBuildReservations(f.s)
		if err != nil || len(reservations) != 1 || reservations[0].Need.Memory != 64<<20 || reservations[0].Need.CPU != 125_000_000 {
			t.Fatal("wrong current common budget", reservations, err)
		}
		if _, err := f.p.ImageBuildCacheAutomaticPlan(f.s, r.Owner, "tenant", "node-a", cache, at+350); !errors.Is(err, reconcile.ErrPending) {
			t.Fatal("live pass allowed replacement", err)
		}
		cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "uncertain", At: uint64(at + 2)}, state.Applied)
		if _, err := f.p.ImageBuildCacheAutomaticPlan(f.s, r.Owner, "tenant", "node-a", cache, at+350); !errors.Is(err, reconcile.ErrPending) {
			t.Fatal("unknown pass allowed replacement", err)
		}
		native := [32]byte{byte(sequence)}
		cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "complete", At: uint64(at + 3), ClosedAt: uint64(at + 3), Native: &native, Code: "FAILED"}, state.Applied)
		if _, err := f.p.ImageBuildCacheAutomaticPlan(f.s, r.Owner, "tenant", "node-a", cache, at+302); !errors.Is(err, reconcile.ErrPending) {
			t.Fatal("cadence ignored original closure time", err)
		}
		encoded, err := state.Encode(f.s)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := state.Decode(encoded)
		if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
			t.Fatal("retained automatic checkpoint invalid", err)
		}
		count := 0
		for _, object := range f.s.Objects(ImageBuildKey + "/records/cache-automatic/") {
			if object.Present {
				count++
			}
		}
		if count != 1 {
			t.Fatal("automatic slot not bounded", count)
		}
		previousID = r.ID()
	}
}

func TestCacheAutomaticRejectsChangedOwnerPolicyRootSourceSequenceAndCannotEnterManualLane(t *testing.T) {
	f, plan := idleCacheAutomaticFixture(t)
	original := cacheAutomaticPlanFixture(t, f, plan, 2000)
	for _, mutate := range []func(*ImageBuildCacheAutomaticReport){
		func(r *ImageBuildCacheAutomaticReport) { r.Owner[0] ^= 1 },
		func(r *ImageBuildCacheAutomaticReport) { r.Tenant = "other" },
		func(r *ImageBuildCacheAutomaticReport) { r.Node = "other" },
		func(r *ImageBuildCacheAutomaticReport) { r.Definition[0] ^= 1 },
		func(r *ImageBuildCacheAutomaticReport) { r.SourceDigest[0] ^= 1 },
		func(r *ImageBuildCacheAutomaticReport) { r.Cache[0] ^= 1 },
		func(r *ImageBuildCacheAutomaticReport) { r.Source = "other" },
		func(r *ImageBuildCacheAutomaticReport) { r.Sequence++ },
		func(r *ImageBuildCacheAutomaticReport) { r.PolicyRevision++ },
		func(r *ImageBuildCacheAutomaticReport) { r.RootRevision++ },
		func(r *ImageBuildCacheAutomaticReport) { r.Epoch++ },
	} {
		r := original
		mutate(&r)
		r.Signature = ed25519.Sign(f.node, ImageBuildCacheAutomaticBytes(r))
		want := state.Forbidden
		if r.Epoch != original.Epoch {
			want = state.Expired // The shared ledger rejects a different module epoch before typed admission.
		}
		applyCacheAutomaticFixture(t, f, r, want)
	}
	forged := original
	forged.Signature = ed25519.Sign(f.manager, ImageBuildCacheAutomaticBytes(forged))
	applyCacheAutomaticFixture(t, f, forged, state.Forbidden)
	f.apply("manager", ImageBuildCachePruneAction, 0, original.Change(), state.Forbidden)
	applyCacheAutomaticFixture(t, f, original, state.Applied)
	book, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row := book.CachePrunes[0]
	policy, _ := book.Policy("tenant")
	policy.Spec.Cleanup.UnusedDays++
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
	work, err := f.p.ImageBuildCachePruneWork(f.s, original.Owner, ImageBuildCachePruneWorkQuery{Tenant: "tenant", ID: original.ID(), At: 2001})
	if err != nil || work.Allowed {
		t.Fatal("changed policy still authorized original pass", err)
	}
	native := [32]byte{77}
	cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "complete", At: 2002, ClosedAt: 2002, Native: &native, Code: "PERMISSION_REVOKED"}, state.Applied)
	if _, err := row.NativeSpec(plan.Spec); err != nil {
		t.Fatal("current policy edit changed retained original spec", err)
	}
}

func TestCacheAutomaticRevokedPolicyAuthorCannotAdmitOrExecuteButCanCloseOriginal(t *testing.T) {
	f, plan := idleCacheAutomaticFixture(t)
	r := cacheAutomaticPlanFixture(t, f, plan, 2000)
	applyCacheAutomaticFixture(t, f, r, state.Applied)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	user, ok := c.User("manager")
	if !ok {
		t.Fatal("missing original policy author")
	}
	f.changeAccount(user.ID, func(u *access.User) { u.Enabled = false })
	work, err := f.p.ImageBuildCachePruneWork(f.s, r.Owner, ImageBuildCachePruneWorkQuery{Tenant: "tenant", ID: r.ID(), At: 2001})
	if err != nil || work.Allowed || work.Blocked != "PERMISSION_REVOKED" {
		t.Fatal("revoked author still executes", work.Blocked, err)
	}
	if _, err := f.p.ImageBuildCacheAutomaticPlan(f.s, r.Owner, "tenant", "node-a", r.Cache, 2400); err == nil {
		t.Fatal("revoked author admitted another pass")
	}
	native := [32]byte{78}
	cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "complete", At: 2002, ClosedAt: 2002, Native: &native, Code: "PERMISSION_REVOKED"}, state.Applied)
}

func TestManualCacheRecordBytesAndDigestRemainUnchangedWithoutAutomaticProof(t *testing.T) {
	f, _ := retainedCachePruneFixture(t)
	book, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row := book.CachePrunes[0]
	raw, _ := json.Marshal(row)
	legacy, _ := json.Marshal(struct {
		Origin       UserOperation
		Source       string
		SourceDigest [32]byte
		State        string
		Revision, At uint64
		Reports      []ImageBuildCachePruneReport `json:",omitempty"`
	}{row.Origin, row.Source, row.SourceDigest, row.State, row.Revision, row.At, row.Reports})
	if !bytes.Equal(raw, legacy) {
		t.Fatal("old manual schema1 bytes changed")
	}
	if _, err := row.recordKey(); err != nil {
		t.Fatal(err)
	}
}
