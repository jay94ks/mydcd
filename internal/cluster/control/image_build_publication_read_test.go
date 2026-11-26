// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// Actual accepted signatures/FSM/checkpoint; native publication is exercised
// by the separate native/SDK fixtures, not by these metadata-only permits.
func TestOriginalBuildPublicationReadSurvivesExpiryPolicyRevocationAndCancel(t *testing.T) {
	for _, mode := range []string{"expiry", "policy", "user", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, plan := buildJobFixture(t)
			f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
			targets, _ := plan.Spec.OutputTags()
			q := ImageBuildPublicationQuery{Tenant: "tenant", Job: plan.Spec.ID, Snapshot: plan.Spec.Digest(), Target: targets[0]}
			if _, err := f.p.ImageBuildPublicationRead(f.s, plan.Spec.Scope.Root.Key, q); err == nil {
				t.Fatal("queued job acquired publication observation")
			}
			buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin"}, state.Applied)
			at := int64(3)
			switch mode {
			case "expiry":
				at = int64(plan.Spec.CreatedAt + plan.Spec.Policy.Seconds + 1)
			case "policy":
				book, _ := f.p.ImageBuilds(f.s)
				policy, _ := book.Policy("tenant")
				policy.Spec.Seconds++
				f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
			case "user":
				catalog, _ := f.p.Catalog(f.s)
				user, _ := catalog.User("manager")
				expected := user.Revision
				user.Revision = 0
				user.Enabled = false
				f.apply("admin", "put-user", expected, user, state.Applied)
			case "cancel":
				f.apply("manager", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
			}
			if _, err := f.p.ImageBuildRegistryPermit(f.s, plan.Spec.Scope.Root.Key, ImageBuildRegistryRequest{Tenant: "tenant", Job: plan.Spec.ID, Snapshot: plan.Spec.Digest(), Action: "push", At: at}); err == nil {
				t.Fatal("revoked job could obtain a new push grant")
			}
			before, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			read, err := f.p.ImageBuildPublicationRead(f.s, plan.Spec.Scope.Root.Key, q)
			if err != nil || read.Query != q || read.Run.Spec.Digest() != plan.Spec.RegistrySpec || read.Index != f.s.Index() {
				t.Fatal("original read lost accepted target", read, err)
			}
			after, err := state.Encode(f.s)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("observation changed shared state", err)
			}
		})
	}
}

func TestOriginalBuildPublicationReadRejectsOtherNodeTargetAndNamespace(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin"}, state.Applied)
	targets, _ := plan.Spec.OutputTags()
	q := ImageBuildPublicationQuery{Tenant: "tenant", Job: plan.Spec.ID, Snapshot: plan.Spec.Digest(), Target: targets[0]}
	for _, edit := range []func(*ImageBuildPublicationQuery){func(q *ImageBuildPublicationQuery) { q.Tenant = "other" }, func(q *ImageBuildPublicationQuery) { q.Job = "other" }, func(q *ImageBuildPublicationQuery) { q.Snapshot[0] ^= 1 }, func(q *ImageBuildPublicationQuery) { q.Target = plan.Spec.OutputRepository() + ":not-approved" }, func(q *ImageBuildPublicationQuery) { q.Target = "other.example/team/app:context-1" }} {
		bad := q
		edit(&bad)
		if _, err := f.p.ImageBuildPublicationRead(f.s, plan.Spec.Scope.Root.Key, bad); err == nil {
			t.Fatal("altered original read accepted", bad)
		}
	}
	if _, err := f.p.ImageBuildPublicationRead(f.s, [32]byte{9}, q); err == nil {
		t.Fatal("another node borrowed original job")
	}
	read, err := f.p.ImageBuildPublicationRead(f.s, plan.Spec.Scope.Root.Key, q)
	if err != nil {
		t.Fatal(err)
	}
	changed := read.Run
	changed.Spec.Volume.Generation++
	if controlSame := SameRegistryReadRun(read.Run, changed); controlSame {
		t.Fatal("replacement data namespace treated as original")
	}
	changed = read.Run
	changed.Ready = &RegistryObservation{Boot: [32]byte{8}, Certificate: [32]byte{9}, At: 9}
	changed.Draining = true
	changed.Budget.Draining = true
	changed.Budget.Revision++
	if !SameRegistryReadRun(read.Run, changed) {
		t.Fatal("read identity included heartbeat/drain observation")
	}
	changed.Budget.Key += "-other"
	if SameRegistryReadRun(read.Run, changed) {
		t.Fatal("different writer reservation accepted")
	}
}

func TestRegistryOriginalBuildHoldEndsOnlyAfterActualJobClosure(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	registries, _ := f.p.Registries(f.s)
	entry, _ := registries.Entry("tenant", plan.Spec.Policy.Registry)
	run := entry.Active.Reference()
	if held, err := f.p.RegistryImageBuildsPending(f.s, run); err != nil || held {
		t.Fatal("queued job requires retained output Store", held, err)
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin"}, state.Applied)
	if held, err := f.p.RegistryImageBuildsPending(f.s, run); err != nil || !held {
		t.Fatal("running original output lost Store", held, err)
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "uncertain"}, state.Applied)
	if held, err := f.p.RegistryImageBuildsPending(f.s, run); err != nil || !held {
		t.Fatal("unknown output lost Store", held, err)
	}
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: plan.Spec.Policy.Registry, Action: "drain", SpecRevision: run.SpecRevision, Generation: run.Generation}, state.Applied)
	q := ImageBuildPublicationQuery{Tenant: "tenant", Job: plan.Spec.ID, Snapshot: plan.Spec.Digest(), Target: mustPublicationTarget(t, plan.Spec)}
	draining, err := f.p.ImageBuildPublicationRead(f.s, plan.Spec.Scope.Root.Key, q)
	if err != nil || !draining.Run.Draining || !SameRegistryReadRun(run, draining.Run) {
		t.Fatal("drain erased original observation", draining, err)
	}
	// Native closure facts are injected, as in the existing registry core
	// fixture. Even otherwise valid facts cannot bypass a live original job.
	gone, budget := registryClosureFixture(f, draining.Run)
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: plan.Spec.Policy.Registry, Action: "closed", SpecRevision: run.SpecRevision, Generation: run.Generation, Gone: gone, Budget: budget}, state.ConditionFailed)
	closure := buildJobClosure(f, plan.Spec, "BUILD_FAILED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
	if held, err := f.p.RegistryImageBuildsPending(f.s, run); err != nil || held {
		t.Fatal("closed build retained registry forever", held, err)
	}
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: plan.Spec.Policy.Registry, Action: "closed", SpecRevision: run.SpecRevision, Generation: run.Generation, Gone: gone, Budget: budget}, state.Applied)
}

func mustPublicationTarget(t *testing.T, spec imagebuild.JobSpec) string {
	t.Helper()
	targets, err := spec.OutputTags()
	if err != nil || len(targets) == 0 {
		t.Fatal(err)
	}
	return targets[0]
}
