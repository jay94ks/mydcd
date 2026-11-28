// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/moby/moby/api/types/container"
)

func TestBuilderImageTagIsKeptAndContainerPinsTheImageID(t *testing.T) {
	s, _ := testJobSpec(t)
	s.Policy.BuilderImage = "docker.io/moby/buildkit:v0.35.1-rootless"
	if err := s.Policy.Validate(s.Cluster); err != nil {
		t.Fatal("tag builder refused", err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal("job with tag builder refused", err)
	}
	for _, bad := range []string{"moby/buildkit:v0.35.1-rootless", "docker.io/moby/buildkit:v1@sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("a", 64)} {
		p := s.Policy
		p.BuilderImage = bad
		if p.Validate(s.Cluster) == nil {
			t.Fatal("non-normalized builder accepted", bad)
		}
	}
	p, err := PlanNative(s, engine.Owner(s.Cluster, s.Scope.Root.Key))
	if err != nil {
		t.Fatal(err)
	}
	opts, err := p.createOptions(s, false)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Config.Image != s.Policy.BuilderImage {
		t.Fatal("options lost the tag", opts.Config.Image)
	}
	// The created container carries the image ID checked just before create.
	id := "sha256:" + strings.Repeat("c", 64)
	config := *opts.Config
	config.Image = id
	got := container.InspectResponse{ID: strings.Repeat("e", 64), Name: "/" + p.Container.Name, Image: id, Config: &config, HostConfig: opts.HostConfig, State: &container.State{}}
	if !matchNativeContainerOptions(got, p.Container, id, got.ID, opts) {
		t.Fatal("container created from the checked image ID not matched")
	}
	got.Config.Image = "sha256:" + strings.Repeat("d", 64)
	if matchNativeContainerOptions(got, p.Container, id, got.ID, opts) {
		t.Fatal("another image accepted")
	}
}

func TestBuilderPinIsPerJobAndSameRepository(t *testing.T) {
	s, _ := testJobSpec(t)
	s.Policy.BuilderImage = "docker.io/moby/buildkit:v0.35.1-rootless"
	source := BuilderSource(s, "linux/amd64")
	if !source.Valid() {
		t.Fatal("builder source invalid")
	}
	digest := "sha256:" + strings.Repeat("b", 64)
	good := FrozenSource{Source: source, Image: "docker.io/moby/buildkit@" + digest}
	if !ValidBuilder(s, good) || ValidateJobBuilder(s, &good, "") != nil || ValidateJobBuilder(s, &good, BuilderRegistryUnreachable) != nil || ValidateJobBuilder(s, &good, BuilderRegistryMissing) != nil {
		t.Fatal("tag builder pin refused")
	}
	if ValidateJobBuilder(s, nil, "") == nil || ValidateJobBuilder(s, &good, "other") == nil {
		t.Fatal("missing builder or unknown local state accepted")
	}
	other := good
	other.Image = "docker.io/moby/other@" + digest
	tagged := good
	tagged.Image = "docker.io/moby/buildkit:v0.35.1-rootless"
	moved := good
	moved.Source.Reference = "docker.io/moby/buildkit:other"
	kind := good
	kind.Source.Kind = "from"
	for _, bad := range []FrozenSource{other, tagged, moved, kind} {
		if ValidBuilder(s, bad) {
			t.Fatal("bad builder pin accepted", bad)
		}
	}
	// The builder is never a BuildKit input.
	if ValidateJobInputs(s, []FrozenSource{good}) == nil {
		t.Fatal("builder accepted as a BuildKit input")
	}
	// A digest policy resolves only to itself.
	s.Policy.BuilderImage = "docker.io/moby/buildkit@" + digest
	self := FrozenSource{Source: BuilderSource(s, "linux/arm64"), Image: s.Policy.BuilderImage}
	if !ValidBuilder(s, self) {
		t.Fatal("digest builder refused")
	}
	self.Image = "docker.io/moby/buildkit@sha256:" + strings.Repeat("c", 64)
	if ValidBuilder(s, self) {
		t.Fatal("digest builder resolved to another digest")
	}
	run := JobRun{Spec: s, Inputs: []FrozenSource{}, Builder: &good, BuilderLocal: BuilderRegistryUnreachable}
	if len(run.Frozen()) != 1 || len(run.Read()) != 0 || run.BuilderImage() != good.Image {
		t.Fatal("local builder copy read from a registry", run.Read())
	}
}
