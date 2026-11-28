// SPDX-License-Identifier: Apache-2.0

package control

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

func TestBuildBeginKeepsTheBuilderPinOnlyOnThatJob(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	other := testBuilder(plan.Spec)
	other.Image = "docker.io/moby/buildkit@sha256:" + strings.Repeat("c", 64)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "begin", Builder: other}, state.Forbidden)
	elsewhere := testBuilder(plan.Spec)
	elsewhere.Image = "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "begin", Builder: elsewhere}, state.Forbidden)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "begin", Builder: testBuilder(plan.Spec), BuilderLocal: imagebuild.BuilderRegistryUnreachable}, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row, _ := b.Job("tenant", "build-one")
	if row.Run.Builder == nil || row.Run.Builder.Image != plan.Spec.Policy.BuilderImage || row.Run.BuilderLocal != imagebuild.BuilderRegistryUnreachable || row.Begin == nil || row.Begin.Builder != nil {
		t.Fatal("builder pin not kept once on the run", row.Run.Builder, row.Run.BuilderLocal)
	}
	policy, _ := b.Policy("tenant")
	if policy.Spec.BuilderImage != plan.Spec.Policy.BuilderImage {
		t.Fatal("policy changed by a job's builder pin")
	}
	refs, err := f.p.ImageReferences(f.s, "tenant", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	protected := false
	for _, r := range refs {
		protected = protected || r.Kind == "image-build-builder" && r.Image == row.Run.Builder.Image
	}
	if !protected {
		t.Fatal("running job's builder pin unprotected")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("builder pin restore", err)
	}
}
