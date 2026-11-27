// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

func buildJobFixture(t *testing.T) (*nodeStorageFixture, ImageBuildJobPlan) {
	t.Helper()
	f, _ := imageBuildFixture(t)
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: "private", Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	data := []byte("injected native artifact")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "retained", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	f.apply("manager", "put-build-zip-part", 1, buildTestPart(t, f, "retained", 0, data), state.Applied)
	seal := buildTestSeal(t, f, "retained")
	f.apply("manager", "upload-build-zip", 2, ImageBuildZIPConsume{Tenant: "tenant", ID: "source", Upload: "retained", Fact: seal}, state.Applied)
	plan, err := f.p.ImageBuildJobPlan(f.s, f.sessions["manager"], 2, "tenant", ImageBuildJobQuery{ID: "build-one", Context: "source", Version: imagebuild.VersionID(seal)})
	if err != nil {
		t.Fatal(err)
	}
	return f, plan
}
func buildJobReportFixture(t *testing.T, f *nodeStorageFixture, report ImageBuildJobReport, want state.Code) {
	t.Helper()
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := b.Job("tenant", report.Job)
	if !ok {
		t.Fatal("missing job")
	}
	report.Schema, report.Kind, report.Cluster, report.Owner = 1, "job", f.p.Cluster, r.Run.Spec.Scope.Root.Key
	report.Tenant, report.Expected, report.RootRevision, report.Epoch = "tenant", r.Run.Revision, f.s.Object(ImageBuildKey).Revision, f.s.ModuleEpoch()
	if report.At == 0 {
		report.At = 3
		if report.Closure != nil {
			report.At = report.Closure.At
		}
	}
	report.Signature = ed25519.Sign(f.node, ImageBuildJobReportBytes(report))
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(report.Action, result.Code, want, err)
	}
	f.s = next
}

func TestBuildJobCompletionKeepsOriginalClosureTimeInFreshReport(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	f.apply("manager", "cancel-image-build", 1, ImageBuildJobSelection{Tenant: "tenant", ID: "build-one"}, state.Applied)
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "complete", Closure: &closure, At: closure.At - 1}, state.Forbidden)
	// A later envelope revalidates current owner/CAS without inventing a new
	// native result or changing the signed time at which cleanup completed.
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "complete", Closure: &closure, At: closure.At + 3600}, state.Applied)
	book, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row, exists := book.Job("tenant", "build-one")
	if !exists || !row.Run.Terminal() || row.Run.Closure == nil || row.Run.Closure.At != closure.At || row.Run.Closure.Native != closure.Native {
		t.Fatal("late report changed native closure", row, err)
	}
}
func buildJobClosure(f *nodeStorageFixture, spec imagebuild.JobSpec, code string) imagebuild.JobClosure {
	result := imagebuild.JobResult{Code: code}
	if code == "OK" {
		result.Image = spec.OutputRepository() + "@sha256:" + strings.Repeat("c", 64)
		result.Bytes = 123
	}
	c := imagebuild.JobClosure{Schema: 1, Job: spec.Digest(), Native: sha256.Sum256([]byte("injected actual closure")), At: 4, Result: result}
	c.Signature = ed25519.Sign(f.node, imagebuild.JobClosureBytes(c))
	return c
}

// Actual product reducer/signatures/checkpoint. Native closure is explicitly
// injected; Docker/BuildKit/registry push need the final RQ6 adapter run.
func TestBuildJobsProtectVersionAndImagesThroughCancelUnknownAndHistory(t *testing.T) {
	f, plan := buildJobFixture(t)
	bad := plan.Change
	bad.Snapshot[0] ^= 1
	f.apply("manager", "begin-image-build", 0, bad, state.ConditionFailed)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	f.apply("manager", "delete-build-version", 1, ImageBuildVersionSelection{Tenant: "tenant", ID: plan.Spec.Version}, state.ConditionFailed)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "begin"}, state.Applied)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "uncertain"}, state.Applied)
	f.apply("manager", "cancel-image-build", 3, ImageBuildJobSelection{Tenant: "tenant", ID: "build-one"}, state.Applied)
	f.apply("manager", "delete-image-build-job", 4, ImageBuildJobSelection{Tenant: "tenant", ID: "build-one"}, state.ConditionFailed)
	refs, err := f.p.ImageReferences(f.s, "tenant", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	protected := false
	for _, r := range refs {
		protected = protected || r.Kind == "image-build-builder" && r.Operation == "build-one"
	}
	if !protected || f.p.storageQuiescent(f.s) {
		t.Fatal("unknown/cancelled job lost active references")
	}
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "complete", Closure: &closure}, state.Applied)
	f.apply("manager", "delete-build-version", 1, ImageBuildVersionSelection{Tenant: "tenant", ID: plan.Spec.Version}, state.ConditionFailed)
	f.apply("manager", "delete-image-build-job", 5, ImageBuildJobSelection{Tenant: "tenant", ID: "build-one"}, state.Applied)
	f.apply("manager", "delete-build-version", 1, ImageBuildVersionSelection{Tenant: "tenant", ID: plan.Spec.Version}, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil || len(b.Jobs) != 1 || !b.Jobs[0].Deleted {
		t.Fatal(err)
	}
	u, _ := b.Upload("tenant", "retained")
	if b.ArtifactReferenced(u) {
		t.Fatal("deleted history still pins artifact")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("job grant/closure/history restore", err)
	}
	if _, err := f.p.ImageBuildJobPlan(f.s, f.sessions["manager"], 2, "tenant", ImageBuildJobQuery{ID: "build-one", Context: "source", Version: plan.Spec.Version}); err == nil {
		t.Fatal("deleted job ID reused")
	}
}

func TestBuildJobConcurrencyAndQueuedCancellationRequireOwnerSettlement(t *testing.T) {
	f, one := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, one.Change, state.Applied)
	two, err := f.p.ImageBuildJobPlan(f.s, f.sessions["manager"], 2, "tenant", ImageBuildJobQuery{ID: "build-two", Context: "source", Version: one.Spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "begin-image-build", 0, two.Change, state.Applied)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "begin"}, state.Applied)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-two", Action: "begin"}, state.Forbidden)
	work, err := f.p.ImageBuildJobWork(f.s, two.Spec.Scope.Root.Key, ImageBuildJobWorkQuery{Tenant: "tenant", ID: "build-two", At: 3})
	if err != nil || work.Allowed || work.Blocked != "WAITING_FOR_SLOT" {
		t.Fatal("slot wait became revocation", work, err)
	}
	f.apply("manager", "cancel-image-build", 1, ImageBuildJobSelection{Tenant: "tenant", ID: "build-two"}, state.Applied)
	closure := buildJobClosure(f, two.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-two", Action: "complete", Closure: &closure}, state.Applied)
	page, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 4, "tenant", ImageBuildQuery{Part: "jobs", Job: "build-two"}, "")
	if err != nil || len(page.Jobs) != 1 || page.Jobs[0].Phase != "cancelled" || page.Jobs[0].Revision != 3 {
		t.Fatal(page, err)
	}
	if _, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 4, "other", ImageBuildQuery{Part: "jobs"}, ""); err == nil {
		t.Fatal("cross-tenant jobs exposed")
	}
}
