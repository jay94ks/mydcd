// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"

	"github.com/distribution/reference"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// builderLocalState maps a resolution failure to the local-copy state Jay
// allowed (2026-11-28 13:59 KST): the registry could not be reached, or it
// answered that the image is gone. Policy refusals never fall back.
func builderLocalState(code string) string {
	switch code {
	case "UNAVAILABLE", "TIMEOUT", "SOURCE_NOT_READY", unreachableOwner:
		return imagebuild.BuilderRegistryUnreachable
	case "NOT_FOUND":
		return imagebuild.BuilderRegistryMissing
	}
	return ""
}

// resolveImageBuildBuilder resolves the policy's builder reference once for
// this job. The digest lives only in this job's begin report and run; the
// policy keeps the reference as written.
func (r *Runtime) resolveImageBuildBuilder(ctx context.Context, spec imagebuild.JobSpec) (imagebuild.FrozenSource, string, error) {
	source := imagebuild.BuilderSource(spec, runtime.GOOS+"/"+runtime.GOARCH)
	pinned, code, err := r.resolveImageBuildSource(ctx, spec, source)
	if err == nil {
		return imagebuild.FrozenSource{Source: source, Image: pinned}, "", nil
	}
	local := builderLocalState(code)
	if local == "" {
		return imagebuild.FrozenSource{}, "", err
	}
	copy, cause := r.localBuilderCopy(ctx, spec.Policy.BuilderImage)
	if cause != nil {
		// No local copy: the build fails visibly with the registry's error.
		return imagebuild.FrozenSource{}, "", err
	}
	return imagebuild.FrozenSource{Source: source, Image: copy}, local, nil
}

// localBuilderCopy is the digest this node last pulled for ref's tag, kept
// only as the engine's own local tag (TagLocal). A digest ref is its own copy
// when present.
func (r *Runtime) localBuilderCopy(ctx context.Context, ref string) (string, error) {
	if r.docker == nil {
		return "", sfcp.ErrAdmission
	}
	want, err := access.ParseImage(ref)
	if err != nil {
		return "", err
	}
	got, err := r.docker.LocalImage(ctx, want.Reference)
	if err != nil {
		return "", err
	}
	for _, d := range got.RepoDigests {
		pin, err := access.PinImage(d)
		if err == nil && pin.Registry == want.Registry && pin.Repository == want.Repository && (!want.Pinned() || pin.Reference == want.Reference) {
			return pin.Reference, nil
		}
	}
	return "", imagebuild.ErrSourceFetch
}

// pullImageBuildBuilder makes the run's builder pin present on this node
// before the build container is created from it. It reads through the same
// frozen source path, owner and credentials as the job's base images. A
// local copy, or an older run with no pin, is only checked to be present.
func (r *Runtime) pullImageBuildBuilder(ctx context.Context, spec imagebuild.JobSpec, run imagebuild.JobRun) error {
	if r.docker == nil {
		return sfcp.ErrAdmission
	}
	if run.Builder == nil || run.BuilderLocal != "" {
		_, err := r.docker.LocalImage(ctx, run.BuilderImage())
		return err
	}
	b := *run.Builder
	if !imagebuild.ValidBuilder(spec, b) {
		return imagebuild.ErrInvalid
	}
	pin, err := access.PinImage(b.Image)
	if err != nil {
		return err
	}
	open := func(ctx context.Context, q registryclient.GraphContentQuery, offset int64) (registryclient.ContentInfo, io.ReadCloser, error) {
		return r.openImageBuildBuilderContent(ctx, spec, b.Source, q, offset)
	}
	auth, err := engine.NewOpenerAuth(pin.Registry, open)
	if err != nil {
		return err
	}
	if _, err := r.docker.ImageWithAuth(ctx, b.Image, true, auth); err != nil {
		return errors.Join(imagebuild.ErrSourceFetch, err)
	}
	if policy, err := access.ParseImage(spec.Policy.BuilderImage); err == nil && !policy.Pinned() {
		// Best effort: this node's record of its last received copy.
		_ = r.docker.TagLocal(ctx, b.Image, policy.Reference)
	}
	return nil
}

// openImageBuildBuilderContent reads one item of the builder graph through
// readImageBuildBaseContent, which streams the whole item from its source's
// owner, into a private temporary file the engine then reads from offset.
func (r *Runtime) openImageBuildBuilderContent(ctx context.Context, spec imagebuild.JobSpec, source imagebuild.Source, q registryclient.GraphContentQuery, offset int64) (registryclient.ContentInfo, io.ReadCloser, error) {
	if offset < 0 {
		return registryclient.ContentInfo{}, nil, imagebuild.ErrInvalid
	}
	if _, err := reference.ParseNormalizedNamed(q.Root); err != nil {
		return registryclient.ContentInfo{}, nil, imagebuild.ErrInvalid
	}
	f, err := os.CreateTemp("", "sfc-builder-*")
	if err != nil {
		return registryclient.ContentInfo{}, nil, err
	}
	_ = os.Remove(f.Name()) // unlinked: the open descriptor alone holds it
	info, err := r.readImageBuildBaseContent(ctx, spec, source, q, f)
	if err == nil && offset > info.Bytes {
		err = imagebuild.ErrInvalid
	}
	if err == nil {
		_, err = f.Seek(offset, io.SeekStart)
	}
	if err != nil {
		return registryclient.ContentInfo{}, nil, errors.Join(err, f.Close())
	}
	return info, f, nil
}
