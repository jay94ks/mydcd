// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/reconcile"
)

func automaticGitReportFixture(t *testing.T, f *nodeStorageFixture, spec imagebuild.ContextSpec, at int64) (ImageBuildAutomaticGitReport, ImageBuildJobPlan) {
	t.Helper()
	applyGitObservationTestReport(t, f, gitObservationTestReport(t, f, spec, 3), state.Applied)
	plan, err := f.p.ImageBuildAutomaticGitSavePlan(f.s, spec.Root.Key, spec.Tenant, spec.ID, at, nil)
	if err != nil {
		t.Fatal(err)
	}
	saved := gitSavedFactFixture(f, plan)
	saved.Fact.ExpandedBytes = 17
	saved.Fact.Signature = ed25519.Sign(f.node, imagebuild.SealReceiptBytes(saved.Fact))
	saved.Signature = ed25519.Sign(f.node, imagebuild.SavedGitBytes(saved))
	jobPlan, err := f.p.ImageBuildAutomaticGitPlan(f.s, spec.Root.Key, saved, at, at)
	if err != nil {
		t.Fatal(err)
	}
	book, _ := f.p.ImageBuilds(f.s)
	context, _ := book.Context(spec.Tenant, spec.ID)
	report := ImageBuildAutomaticGitReport{Schema: 1, Kind: "automatic-git", Cluster: f.p.Cluster, Owner: spec.Root.Key, Definition: imageBuildContextDefinition(context), Tenant: spec.Tenant, Context: spec.ID, RootRevision: jobPlan.RootRevision, Epoch: jobPlan.Epoch, At: uint64(at), StartedAt: uint64(at), Saved: saved, Snapshot: ImageBuildAutomaticGitSnapshot(jobPlan.Spec)}
	report.Signature = ed25519.Sign(f.node, ImageBuildAutomaticGitReportBytes(report))
	return report, jobPlan
}

func applyAutomaticGitReport(t *testing.T, f *nodeStorageFixture, report ImageBuildAutomaticGitReport, want state.Code) state.Command {
	t.Helper()
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal("automatic Git submission", result, want, err)
	}
	f.s = next
	return cmd
}

func TestAutomaticGitQueuesOriginalArchiveVersionAndJobAtomicallyAfterLoginExpiry(t *testing.T) {
	f, spec := imageBuildGitWatchFixture(t)
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: "private", Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	report, plan := automaticGitReportFixture(t, f, spec, 2000)
	raw, _ := json.Marshal(report)
	if _, err := f.p.ResolveImageBuildAutomaticGitReport(f.s, spec.Root.Key, raw); err != nil {
		t.Fatal("accepted Automatic authority replaced by an expired-login check", err)
	}
	applyAutomaticGitReport(t, f, report, state.Applied)
	book, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	context, _ := book.Context(spec.Tenant, spec.ID)
	job, ok := book.Job(spec.Tenant, report.Saved.Plan.ID)
	upload, stored := book.Upload(spec.Tenant, report.Saved.Plan.ID)
	version, published := book.Version(spec.Tenant, plan.Spec.Version)
	if !ok || !stored || !published || context.NextVersion != 1 || context.Revision != 1 || job.Run.Phase != "queued" || job.Automatic == nil || upload.Automatic == nil || !buildJSONEqual(job.Origin, context.Definition) || !buildJSONEqual(upload.Begin, context.Definition) || version.Number != job.Run.Spec.Number || job.Run.Spec.Digest() != plan.Spec.Digest() || version.Commit != report.Saved.Plan.Commit || len(f.s.Objects(buildPartPrefix(spec.Tenant, upload.Scope.Upload))) != 0 {
		t.Fatal("automatic submission synthesized user input/part slots or split its transaction")
	}
	if validateImageBuildJob(job, f.p.Cluster) != nil || !validBuildVersionOrigin(version, upload, f.p.Cluster) || !validGeneratedBuildUpload(upload, context, f.p.Cluster) || job.SubmissionRootRevision() != report.RootRevision || job.SubmissionRootRevision() <= job.Origin.RootRevision || job.acquisitionAt() != 2000 {
		t.Fatal("original authority and actual submission provenance conflated")
	}
	page, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 2, spec.Tenant, ImageBuildQuery{Part: "jobs"}, "")
	if err != nil || len(page.Jobs) != 1 || !page.Jobs[0].Automatic || page.Jobs[0].CreatedAt != 2000 {
		t.Fatal("automatic public job view", page, err)
	}
	versions, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 2, spec.Tenant, ImageBuildQuery{Part: "versions", ID: spec.ID}, "")
	if err != nil || len(versions.Versions) != 1 || versions.Versions[0].At != 2000 {
		t.Fatal("version uses old context-registration time", versions, err)
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("automatic provenance did not restore", err)
	}
	withoutJob := book
	withoutJob.Jobs = nil
	root, err := withoutJob.root(f.p.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	orphan := map[string][]byte{ImageBuildKey: root, buildRecordKey("job", spec.Tenant, job.Run.Spec.ID): nil}
	cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "orphan-auto-job", Key: ImageBuildKey, Expected: f.s.Object(ImageBuildKey).Revision, Value: "fixed-fixture"}
	if _, result, err := state.ApplyReduced(f.s, f.s.Index()+1, cmd, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return orphan, state.Applied }); err != nil || result.Code != state.Invalid {
		t.Fatal("automatic archive/version accepted without its atomically reserved job", result.Code, err)
	}
	if _, err := f.p.ImageBuildAutomaticGitPlan(f.s, spec.Root.Key, report.Saved, 2000, 2001); !errors.Is(err, imagebuild.ErrUsed) {
		t.Fatal("same accepted commit queued twice", err)
	}
	bad := job
	copy := *job.Automatic
	bad.Automatic = &copy
	copy.Snapshot[0] ^= 1
	if validateImageBuildJob(bad, f.p.Cluster) == nil {
		t.Fatal("changed original automatic intent accepted")
	}
}

func TestAutomaticGitRejectsUnsignedReboundAndChangedIntentWithoutPartialPublication(t *testing.T) {
	f, spec := imageBuildGitWatchFixture(t)
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: "private", Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	original, _ := automaticGitReportFixture(t, f, spec, 4)
	for _, mutate := range []func(*ImageBuildAutomaticGitReport){
		func(r *ImageBuildAutomaticGitReport) { r.Cluster[0] ^= 1 },
		func(r *ImageBuildAutomaticGitReport) { r.Owner[0] ^= 1 },
		func(r *ImageBuildAutomaticGitReport) { r.Definition[0] ^= 1 },
		func(r *ImageBuildAutomaticGitReport) { r.Tenant = "other" },
		func(r *ImageBuildAutomaticGitReport) { r.Context = "source" },
		func(r *ImageBuildAutomaticGitReport) { r.Snapshot[0] ^= 1 },
		func(r *ImageBuildAutomaticGitReport) { r.StartedAt++ },
		func(r *ImageBuildAutomaticGitReport) { r.RootRevision++ },
		func(r *ImageBuildAutomaticGitReport) { r.Epoch++ },
		func(r *ImageBuildAutomaticGitReport) { r.Saved.Plan.Commit = strings.Repeat("b", 40) },
	} {
		bad := original
		mutate(&bad)
		bad.Signature = ed25519.Sign(f.node, ImageBuildAutomaticGitReportBytes(bad))
		before := f.s.Object(ImageBuildKey)
		want := state.Forbidden
		if bad.Epoch != original.Epoch {
			want = state.Expired // The shared ledger rejects a different module epoch before typed admission.
		}
		applyAutomaticGitReport(t, f, bad, want)
		book, _ := f.p.ImageBuilds(f.s)
		if f.s.Object(ImageBuildKey) != before || len(book.Uploads) != 0 || len(book.Versions) != 0 || len(book.Jobs) != 0 {
			t.Fatal("rejected report published part of an automatic build")
		}
	}
	forged := original
	forged.Signature = ed25519.Sign(f.manager, ImageBuildAutomaticGitReportBytes(forged))
	applyAutomaticGitReport(t, f, forged, state.Forbidden)
	f.changeAccount("manager", func(u *access.User) { u.Enabled = false })
	original.RootRevision = f.s.Object(ImageBuildKey).Revision
	original.Signature = ed25519.Sign(f.node, ImageBuildAutomaticGitReportBytes(original))
	applyAutomaticGitReport(t, f, original, state.Forbidden)
}

func TestAutomaticGitMissingSecretDoesNotPublishVersionOrJob(t *testing.T) {
	f, spec := imageBuildGitWatchFixture(t)
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: "private", Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	session := f.sessions["manager"]
	session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.Deploy)
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	spec.Secrets = []imagebuild.SecretMount{{ID: "missing", Realm: "tenant", Secret: "missing", Key: "value"}}
	f.apply("manager", "put-build-context", 1, ImageBuildContextPut{Spec: spec}, state.Applied)
	report, plan := automaticGitReportFixture(t, f, spec, 4)
	current, _ := f.p.ImageBuilds(f.s)
	context, _ := current.Context(spec.Tenant, spec.ID)
	currentPolicy, err := f.p.Current(f.s)
	if err != nil {
		t.Fatal(err)
	}
	uses, err := currentPolicy.approvalUsesFor(f.s, session, 4, &context.Definition, nil)
	if err != nil || !buildJSONEqual(uses, plan.Uses) {
		t.Fatal("automatic approval is not bound to the exact observed job use", err)
	}
	unaccepted := context.Definition
	unaccepted.RequestID = "unaccepted-lookalike"
	unaccepted.Signature = ed25519.Sign(f.manager, OperationBytes(unaccepted))
	if _, err := currentPolicy.approvalUsesFor(f.s, session, 4, &unaccepted, nil); err == nil {
		t.Fatal("unaccepted context operation created an automatic approval target")
	}
	before, vaultBefore := f.s.Object(ImageBuildKey), f.s.Object(VaultKey)
	if err := f.p.CheckImageBuildAutomaticGit(f.s, spec.Root.Key, report); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("unready Secret was allowed to start a submitted build's clock", err)
	}
	if f.s.Object(ImageBuildKey) != before || f.s.Object(VaultKey) != vaultBefore {
		t.Fatal("admission preview mutated source or Vault")
	}
	applyAutomaticGitReport(t, f, report, state.ConditionFailed)
	book, _ := f.p.ImageBuilds(f.s)
	if f.s.Object(ImageBuildKey) != before || f.s.Object(VaultKey) != vaultBefore || len(book.Uploads) != 0 || len(book.Versions) != 0 || len(book.Jobs) != 0 {
		t.Fatal("Secret failure left an archive/version/job/usage fragment")
	}
}

func TestAutomaticGitVersionAllocatorDoesNotRetargetOriginalIntent(t *testing.T) {
	f, spec := imageBuildGitWatchFixture(t)
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: "private", Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	report, plan := automaticGitReportFixture(t, f, spec, 4)
	// Same sealed Git bytes may also be manually published under a separate
	// explicit archive ID. That publication owns the first version number.
	manual := report.Saved.Plan
	manual.ID = "explicit-manual"
	manual.CreatedAt, manual.ExpiresAt = 1, 1000
	f.apply("manager", "publish-build-git", manual.ContextRevision, ImageBuildGitPublish{Tenant: spec.Tenant, Context: spec.ID, Saved: gitSavedFactFixture(f, manual)}, state.Applied)
	newPlan, err := f.p.ImageBuildAutomaticGitPlan(f.s, spec.Root.Key, report.Saved, 4, 4)
	if err != nil || newPlan.Spec.Number != 2 || newPlan.Spec.Digest() == plan.Spec.Digest() || ImageBuildAutomaticGitSnapshot(newPlan.Spec) != report.Snapshot {
		t.Fatal("version allocation changed the original auto intent", err)
	}
	report.RootRevision = newPlan.RootRevision
	report.Signature = ed25519.Sign(f.node, ImageBuildAutomaticGitReportBytes(report))
	applyAutomaticGitReport(t, f, report, state.Applied)
	book, _ := f.p.ImageBuilds(f.s)
	job, _ := book.Job(spec.Tenant, report.Saved.Plan.ID)
	if job.Run.Spec.Number != 2 || ImageBuildAutomaticGitSnapshot(job.Run.Spec) != report.Snapshot {
		t.Fatal("FSM did not assign the next number to the exact original intent")
	}
	// Another commit waits for actual prior job closure, not just publication.
	observed := gitObservationTestReport(t, f, spec, 5)
	observed.Result.Commit = strings.Repeat("b", 40)
	observed.Signature = ed25519.Sign(f.node, ImageBuildGitObservationReportBytes(observed))
	applyGitObservationTestReport(t, f, observed, state.Applied)
	next, err := f.p.ImageBuildAutomaticGitSavePlan(f.s, spec.Root.Key, spec.Tenant, spec.ID, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	saved := gitSavedFactFixture(f, next)
	saved.Fact.ExpandedBytes = 17
	saved.Fact.Signature = ed25519.Sign(f.node, imagebuild.SealReceiptBytes(saved.Fact))
	saved.Signature = ed25519.Sign(f.node, imagebuild.SavedGitBytes(saved))
	if _, err := f.p.ImageBuildAutomaticGitPlan(f.s, spec.Root.Key, saved, 5, 5); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("new automatic commit races an unfinished previous publication", err)
	}
}
