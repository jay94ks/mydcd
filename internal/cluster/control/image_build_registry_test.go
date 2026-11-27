// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

func TestBuildRegistryPermitUsesOriginalJobCurrentScopeAndNoQueuedPush(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	owner := plan.Spec.Scope.Root.Key
	q := ImageBuildRegistryRequest{Tenant: "tenant", Job: "build-one", Snapshot: plan.Spec.Digest(), Action: "push", At: 3}
	if _, err := f.p.ImageBuildRegistryPermit(f.s, owner, q); err == nil {
		t.Fatal("queued job could push")
	}
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: "private", Action: "serving", SpecRevision: 1, Generation: 1, Observation: &RegistryObservation{Boot: [32]byte{1}, Certificate: [32]byte{2}}}, state.Applied)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "begin"}, state.Applied)
	permit, err := f.p.ImageBuildRegistryPermit(f.s, owner, q)
	if err != nil || permit.Subject.Job != q.Job || permit.Subject.Snapshot != q.Snapshot || permit.Subject.Image != "" || permit.Repository != plan.Spec.Context.Repository || permit.Run.Generation != plan.Spec.RegistryGeneration {
		t.Fatal("job output permit", permit, err)
	}
	for _, edit := range []func(*ImageBuildRegistryRequest){
		func(q *ImageBuildRegistryRequest) { q.Tenant = "other" }, func(q *ImageBuildRegistryRequest) { q.Job = "other" },
		func(q *ImageBuildRegistryRequest) { q.Snapshot[0] ^= 1 }, func(q *ImageBuildRegistryRequest) { q.Image = "registry.example/other:latest" },
	} {
		bad := q
		edit(&bad)
		if _, err := f.p.ImageBuildRegistryPermit(f.s, owner, bad); err == nil {
			t.Fatal("foreign/altered job image permit accepted")
		}
	}
	if _, err := f.p.ImageBuildRegistryPermit(f.s, [32]byte{9}, q); err == nil {
		t.Fatal("another node borrowed accepted job")
	}
	f.apply("manager", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: "tenant", ID: "build-one"}, state.Applied)
	if _, err := f.p.ImageBuildRegistryPermit(f.s, owner, q); err == nil {
		t.Fatal("cancelled job retained fresh image I/O authority")
	}
}
