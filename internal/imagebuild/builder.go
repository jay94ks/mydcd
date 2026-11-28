// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"github.com/jay94ks/seafield/internal/access"
)

// BuilderKind marks the one frozen source that is the build container's own
// image. A Dockerfile never produces it, and it is never a BuildKit input.
const BuilderKind = "builder"

// Builder image states when the registry could not answer and the node used
// the copy it last pulled for the policy's tag (Jay 2026-11-28 13:59 KST).
const (
	BuilderRegistryUnreachable = "registry-unreachable"
	BuilderRegistryMissing     = "registry-missing"
)

// BuilderSource is the policy's builder reference, as written (a tag or a
// digest), for the node platform the build container runs on.
func BuilderSource(spec JobSpec, platform string) Source {
	return Source{Reference: spec.Policy.BuilderImage, Platform: platform, Kind: BuilderKind}
}

// ValidBuilder reports a builder pin for spec: the policy's own reference,
// resolved for this one job to a digest of the same repository. A digest
// policy resolves only to itself. The policy never keeps the digest.
func ValidBuilder(spec JobSpec, b FrozenSource) bool {
	s := b.Source
	if s.Kind != BuilderKind || s.Stage != 0 || s.Line != 0 || s.Reference != spec.Policy.BuilderImage || !ValidPlatform(s.Platform) {
		return false
	}
	policy, err := access.ParseImage(spec.Policy.BuilderImage)
	if err != nil {
		return false
	}
	pinned, err := access.PinImage(b.Image)
	if err != nil || pinned.Reference != b.Image || pinned.Registry != policy.Registry || pinned.Repository != policy.Repository {
		return false
	}
	return !policy.Pinned() || pinned.Reference == policy.Reference
}

// Frozen is every pinned image the job uses: its BuildKit inputs and, once
// begin fixed it, the builder.
func (r JobRun) Frozen() []FrozenSource {
	out := append([]FrozenSource(nil), r.Inputs...)
	if r.Builder != nil {
		out = append(out, *r.Builder)
	}
	return out
}

// Read is the pinned images the job reads from a registry: Frozen without a
// builder taken from the node's local copy.
func (r JobRun) Read() []FrozenSource {
	if r.BuilderLocal != "" {
		return append([]FrozenSource(nil), r.Inputs...)
	}
	return r.Frozen()
}

// BuilderImage is the reference the build container is created from: the
// begin pin, or the policy's own digest for a run that has none.
func (r JobRun) BuilderImage() string {
	if r.Builder != nil {
		return r.Builder.Image
	}
	return r.Spec.Policy.BuilderImage
}

// ValidateJobBuilder is the begin report's builder: required, and a local
// copy is only one of the two registry states.
func ValidateJobBuilder(spec JobSpec, builder *FrozenSource, local string) error {
	return validJobBuilder(spec, builder, local, true)
}

func validJobBuilder(spec JobSpec, builder *FrozenSource, local string, required bool) error {
	if builder == nil {
		if required || local != "" {
			return ErrInvalid
		}
		return nil
	}
	if !ValidBuilder(spec, *builder) || local != "" && local != BuilderRegistryUnreachable && local != BuilderRegistryMissing {
		return ErrInvalid
	}
	return nil
}
