// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

func imageBuildGitWatchFixture(t *testing.T) (*nodeStorageFixture, imagebuild.ContextSpec) {
	t.Helper()
	f, spec := imageBuildFixture(t)
	spec.ID, spec.Kind = "watched", "git"
	spec.Git = &imagebuild.GitContext{Repository: "https://example.test/team/source.git", Ref: "main", Path: ".", Automatic: true}
	f.apply("manager", "put-build-context", 0, ImageBuildContextPut{Spec: spec}, state.Applied)
	return f, spec
}

func gitObservationTestReport(t *testing.T, f *nodeStorageFixture, spec imagebuild.ContextSpec, at int64) ImageBuildGitObservationReport {
	t.Helper()
	work, err := f.p.ImageBuildGitWatchWork(f.s, spec.Root.Key, spec.Tenant, spec.ID, at)
	if err != nil {
		t.Fatal(err)
	}
	report := ImageBuildGitObservationReport{Schema: 1, Kind: "git-observation", Cluster: f.p.Cluster, Owner: spec.Root.Key, Definition: work.Definition, Tenant: spec.Tenant, Expected: work.Expected, RootRevision: work.RootRevision, Epoch: work.Read.Epoch, At: uint64(at), Result: ImageBuildSourceResult{Schema: 1, Context: spec.ID, Code: "OK", Commit: strings.Repeat("a", 40), Tree: [32]byte{1}, Entries: 1, ExpandedBytes: 17, ContextRevision: work.Read.ContextRevision, PolicyRevision: work.Read.PolicyRevision, Epoch: work.Read.Epoch}}
	report.Signature = ed25519.Sign(f.node, ImageBuildGitObservationReportBytes(report))
	return report
}

func applyGitObservationTestReport(t *testing.T, f *nodeStorageFixture, report ImageBuildGitObservationReport, want state.Code) state.Command {
	t.Helper()
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		t.Fatal("observation reducer", result, want, err)
	}
	f.s = next
	return cmd
}

func TestGitAutomaticObservationRetainsAcceptedDefinitionWithoutPublishingBuild(t *testing.T) {
	f, spec := imageBuildGitWatchFixture(t)
	book, _ := f.p.ImageBuilds(f.s)
	before, _ := book.Context(spec.Tenant, spec.ID)
	// Login expiry does not invent a new session or end an accepted policy.
	report := gitObservationTestReport(t, f, spec, 2000)
	raw, _ := json.Marshal(report)
	if _, err := f.p.ResolveImageBuildGitObservationReport(f.s, spec.Root.Key, raw); err != nil {
		t.Fatal("installed owner report rejected", err)
	}
	applyGitObservationTestReport(t, f, report, state.Applied)
	book, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := book.Context(spec.Tenant, spec.ID)
	if after.Revision != before.Revision || after.NextVersion != before.NextVersion || !buildJSONEqual(after.Definition, before.Definition) || !buildJSONEqual(after.Origin, before.Origin) || after.GitObservation == nil || after.GitObservation.Revision != 1 || after.GitObservation.Report.Result.Commit != report.Result.Commit || len(book.Uploads) != 0 || len(book.Versions) != 0 || len(book.Jobs) != 0 {
		t.Fatal("read-only observation changed original configuration or created a build")
	}
	page, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 2, spec.Tenant, ImageBuildQuery{Part: "contexts", ID: spec.ID}, "")
	if err != nil || len(page.Contexts) != 1 || page.Contexts[0].GitObservation == nil || page.Contexts[0].GitObservation.At != 2000 || page.Contexts[0].GitObservation.Commit != report.Result.Commit {
		t.Fatal("public observation projection", page, err)
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("retained observation restore", err)
	}
	work, err := f.p.ImageBuildGitWatchWork(f.s, spec.Root.Key, spec.Tenant, spec.ID, 2001)
	if err != nil || !after.GitObservation.Same(work, report.Result) {
		t.Fatal("identical observation would produce a replicated heartbeat", err)
	}
	changed := report.Result
	changed.Commit = strings.Repeat("b", 40)
	if after.GitObservation.Same(work, changed) {
		t.Fatal("new commit was suppressed")
	}
}

func TestGitObservationRejectsForeignOrChangedScopeBeforeAndInsideReducer(t *testing.T) {
	f, spec := imageBuildGitWatchFixture(t)
	original := gitObservationTestReport(t, f, spec, 3)
	for _, mutate := range []func(*ImageBuildGitObservationReport){
		func(r *ImageBuildGitObservationReport) { r.Cluster[0] ^= 1 },
		func(r *ImageBuildGitObservationReport) { r.Owner[0] ^= 1 },
		func(r *ImageBuildGitObservationReport) { r.Definition[0] ^= 1 },
		func(r *ImageBuildGitObservationReport) { r.Tenant = "foreign" },
		func(r *ImageBuildGitObservationReport) { r.Expected++ },
		func(r *ImageBuildGitObservationReport) { r.RootRevision++ },
		func(r *ImageBuildGitObservationReport) { r.Epoch++ },
		func(r *ImageBuildGitObservationReport) { r.Result.ContextRevision++ },
		func(r *ImageBuildGitObservationReport) { r.Result.PolicyRevision++ },
		func(r *ImageBuildGitObservationReport) { r.Result.Epoch++ },
		func(r *ImageBuildGitObservationReport) { r.Result.Context = "source" },
		func(r *ImageBuildGitObservationReport) { r.Result.Commit = strings.Repeat("0", 40) },
		func(r *ImageBuildGitObservationReport) { r.Result.ExpandedBytes = imagebuild.MaxExpandedBytes },
		func(r *ImageBuildGitObservationReport) { r.Result.Code = "SOURCE_FETCH" },
	} {
		bad := original
		mutate(&bad)
		bad.Signature = ed25519.Sign(f.node, ImageBuildGitObservationReportBytes(bad))
		raw, _ := json.Marshal(bad)
		if _, err := f.p.ResolveImageBuildGitObservationReport(f.s, spec.Root.Key, raw); err == nil {
			t.Fatal("foreign/rebound observation accepted", bad)
		}
		want := state.Forbidden
		if bad.Epoch != original.Epoch {
			want = state.Expired // The shared ledger rejects a different module epoch before typed admission.
		}
		applyGitObservationTestReport(t, f, bad, want)
	}
	forged := original
	forged.Signature = ed25519.Sign(f.manager, ImageBuildGitObservationReportBytes(forged))
	applyGitObservationTestReport(t, f, forged, state.Forbidden)
	applyGitObservationTestReport(t, f, original, state.Applied)
	// Merely refreshing the global CAS cannot replay an older observation CAS.
	book, _ := f.p.ImageBuilds(f.s)
	row, _ := book.Context(spec.Tenant, spec.ID)
	if row.GitObservation.Revision != 1 {
		t.Fatal("unexpected observation revision")
	}
	old := original
	old.RootRevision = f.s.Object(ImageBuildKey).Revision
	old.Signature = ed25519.Sign(f.node, ImageBuildGitObservationReportBytes(old))
	applyGitObservationTestReport(t, f, old, state.Forbidden)
}

func TestGitObservationStopsOnAccountRevocationOrAutomaticDefinitionChange(t *testing.T) {
	for _, change := range []string{"account", "automatic", "definition", "policy"} {
		t.Run(change, func(t *testing.T) {
			f, spec := imageBuildGitWatchFixture(t)
			original := gitObservationTestReport(t, f, spec, 3)
			switch change {
			case "account":
				f.changeAccount("manager", func(u *access.User) { u.Enabled = false })
			case "automatic", "definition":
				spec = spec.Own()
				if change == "automatic" {
					spec.Git.Automatic = false
				} else {
					spec.Git.Ref = "release"
				}
				f.apply("manager", "put-build-context", 1, ImageBuildContextPut{Spec: spec}, state.Applied)
			case "policy":
				book, _ := f.p.ImageBuilds(f.s)
				policy, _ := book.Policy(spec.Tenant)
				policy.Spec.CPUMillis *= 2
				f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
			}
			original.RootRevision = f.s.Object(ImageBuildKey).Revision
			original.Signature = ed25519.Sign(f.node, ImageBuildGitObservationReportBytes(original))
			applyGitObservationTestReport(t, f, original, state.Forbidden)
			if change == "account" || change == "automatic" {
				if _, err := f.p.ImageBuildGitWatchWork(f.s, spec.Root.Key, spec.Tenant, spec.ID, 4); err == nil {
					t.Fatal("withdrawn policy still fetches Git")
				}
			}
		})
	}
}

func TestGitObservationErrorsAreCodeOnlyAndNewDefinitionsResetOnlyObservation(t *testing.T) {
	f, spec := imageBuildGitWatchFixture(t)
	applyGitObservationTestReport(t, f, gitObservationTestReport(t, f, spec, 3), state.Applied)
	report := gitObservationTestReport(t, f, spec, 4)
	report.Result.Code, report.Result.Commit, report.Result.Tree = "SOURCE_FETCH", "", [32]byte{}
	report.Result.Entries, report.Result.BaseSources, report.Result.ExpandedBytes = 0, 0, 0
	report.Signature = ed25519.Sign(f.node, ImageBuildGitObservationReportBytes(report))
	applyGitObservationTestReport(t, f, report, state.Applied)
	book, _ := f.p.ImageBuilds(f.s)
	row, _ := book.Context(spec.Tenant, spec.ID)
	if row.GitObservation == nil || row.GitObservation.Revision != 2 || row.GitObservation.Report.Result.Code != "SOURCE_FETCH" {
		t.Fatal("failed source read not recorded independently")
	}
	spec = spec.Own()
	spec.Git.Ref = "release"
	f.apply("manager", "put-build-context", row.Revision, ImageBuildContextPut{Spec: spec}, state.Applied)
	book, _ = f.p.ImageBuilds(f.s)
	updated, _ := book.Context(spec.Tenant, spec.ID)
	if updated.GitObservation != nil || updated.DraftGeneration() != row.DraftGeneration() || updated.NextVersion != row.NextVersion {
		t.Fatal("configuration change inherited stale observation or reset source lifetime")
	}
	raw, _ := json.Marshal(ImageBuildContextView{Spec: spec})
	if bytes.Contains(raw, []byte("GitObservation")) {
		t.Fatal("nil addition changes original schema1 JSON")
	}
}

func TestGitObservationHistoricalFactSurvivesLowerPolicyAndRevocation(t *testing.T) {
	f, spec := imageBuildGitWatchFixture(t)
	applyGitObservationTestReport(t, f, gitObservationTestReport(t, f, spec, 3), state.Applied)
	book, _ := f.p.ImageBuilds(f.s)
	policy, _ := book.Policy(spec.Tenant)
	policy.Spec.WorkspaceBytes = 1
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
	f.changeAccount("manager", func(u *access.User) { u.Enabled = false })
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("historical fact wrongly uses today's smaller policy or authority", err)
	}
	book, _ = f.p.ImageBuilds(restored)
	row, _ := book.Context(spec.Tenant, spec.ID)
	if row.GitObservation == nil || row.GitObservation.Report.Result.ExpandedBytes != 17 {
		t.Fatal("retained source observation was erased")
	}
	if _, err := f.p.ImageBuildGitWatchWork(restored, spec.Root.Key, spec.Tenant, spec.ID, 4); err == nil {
		t.Fatal("historical observation authorized another fetch after revocation")
	}
	tampered := row
	copy := *row.GitObservation
	tampered.GitObservation = &copy
	copy.Report.Result.Commit = strings.Repeat("b", 40)
	if validImageBuildGitObservation(tampered, f.p.Cluster) {
		t.Fatal("changed retained commit accepted without original owner signature")
	}
}
