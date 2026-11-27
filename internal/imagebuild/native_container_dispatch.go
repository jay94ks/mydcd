// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// A projection of actual effects, shared by builds and finite maintenance.
// Each caller persists it in its own original record; it is not a new job.
type nativeContainerReceipt struct {
	ImageID, NativeID                                   string
	CreateSent, CreateNotSent, StartSent                bool
	Waited, Exited, RemoveSent, Removed, AbsentObserved bool  `json:",omitempty"`
	ExitCode                                            int64 `json:",omitempty"`
}

func (r NativeRecord) containerReceipt() nativeContainerReceipt {
	return nativeContainerReceipt{ImageID: r.ImageID, NativeID: r.NativeID, CreateSent: r.CreateSent, CreateNotSent: r.CreateNotSent, StartSent: r.StartSent, Waited: r.Waited, Exited: r.Exited, RemoveSent: r.RemoveSent, Removed: r.Removed, AbsentObserved: r.AbsentObserved, ExitCode: r.ExitCode}
}
func (r *NativeRecord) setContainerReceipt(e nativeContainerReceipt) {
	r.ImageID, r.NativeID, r.CreateSent, r.CreateNotSent, r.StartSent = e.ImageID, e.NativeID, e.CreateSent, e.CreateNotSent, e.StartSent
	r.Waited, r.Exited, r.RemoveSent, r.Removed, r.AbsentObserved, r.ExitCode = e.Waited, e.Exited, e.RemoveSent, e.Removed, e.AbsentObserved, e.ExitCode
}

func (r nativeContainerReceipt) valid() bool {
	return (r.ImageID == "" || nativeImageID(r.ImageID)) && (r.NativeID == "" || nativeID(r.NativeID) && r.CreateSent) && (!r.CreateSent || r.ImageID != "") && (!r.CreateNotSent || r.CreateSent && r.NativeID == "" && !r.StartSent) && (!r.StartSent || r.NativeID != "") && (!r.Waited || r.NativeID != "") && (!r.Exited || r.StartSent && r.Waited && r.ExitCode >= 0 && r.ExitCode <= 255) && (r.Exited || r.ExitCode == 0) && (!r.RemoveSent || r.NativeID != "" && r.Waited) && (!r.AbsentObserved || r.NativeID != "") && (!r.Removed || r.RemoveSent || r.AbsentObserved)
}

// Caller holds the original module lock and validated root/cache FDs. A lost
// Create is adopted only by matching this exact identity/image/options. Name
// absence after Sent never authorizes a replacement request.
func (n *NativeJobs) createNativeContainer(ctx context.Context, identity engine.Identity, options client.ContainerCreateOptions, files *nativeWorkspaceFiles, r *nativeContainerReceipt, check, dispatch func() error, save func(nativeContainerReceipt) error) error {
	api, err := n.docker.BindClient(files.Sources())
	if err != nil {
		return err
	}
	defer api.Close()
	lookup := r.NativeID
	if lookup == "" {
		lookup = identity.Name
	}
	got, err := n.docker.API.ContainerInspect(ctx, lookup, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		if r.CreateSent {
			return reconcile.ErrPending
		}
		image, imageErr := n.docker.Image(ctx, options.Config.Image, false)
		if imageErr != nil {
			return nativeFailure(ctx)
		}
		if image.Config == nil || image.Os != "linux" || image.Architecture != runtime.GOARCH || !nativeImageID(image.ID) {
			return engine.ErrOwnership
		}
		for _, env := range image.Config.Env {
			key, _, _ := strings.Cut(env, "=")
			if !slices.Contains([]string{"PATH", "HOME", "USER", "XDG_RUNTIME_DIR", "TMPDIR", "BUILDKIT_HOST", "BUILDKITD_FLAGS"}, key) {
				return engine.ErrOwnership
			}
		}
		for name := range image.Config.Volumes {
			if name != "/home/user/.local/share/buildkit" {
				return engine.ErrOwnership
			}
		}
		if err := check(); err != nil {
			return err
		}
		if err := dispatch(); err != nil {
			return err
		}
		r.ImageID, r.CreateSent = image.ID, true
		if err := save(*r); err != nil {
			return err
		}
		created, createErr := api.ContainerCreate(ctx, options)
		if createErr != nil {
			if errors.Is(createErr, engine.ErrBindBeforeRequest) {
				r.CreateNotSent = true
				if err := save(*r); err != nil {
					return err
				}
			}
			return nativeFailure(ctx)
		}
		if !nativeID(created.ID) {
			return engine.ErrOwnership
		}
		r.NativeID = created.ID
		if err := save(*r); err != nil {
			return err
		}
		got, err = n.docker.API.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
	}
	if err != nil {
		return nativeFailure(ctx)
	}
	if !r.CreateSent || !matchNativeContainerOptions(got.Container, identity, r.ImageID, r.NativeID, options) {
		return engine.ErrOwnership
	}
	if r.NativeID == "" {
		r.NativeID = got.Container.ID
		return save(*r)
	}
	return nil
}

func (n *NativeJobs) startNativeContainer(ctx context.Context, identity engine.Identity, options client.ContainerCreateOptions, files *nativeWorkspaceFiles, r *nativeContainerReceipt, save func(nativeContainerReceipt) error) error {
	api, err := n.docker.BindClient(files.Sources())
	if err != nil {
		return err
	}
	defer api.Close()
	got, err := n.docker.API.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
	if err != nil {
		return nativeFailure(ctx)
	}
	if !matchNativeContainerOptions(got.Container, identity, r.ImageID, r.NativeID, options) {
		return engine.ErrOwnership
	}
	if r.StartSent {
		if nativeStarted(got.Container.State) {
			return nil
		}
		return reconcile.ErrPending
	}
	if nativeStarted(got.Container.State) || !engine.ContainerStartable(got.Container.State) {
		return engine.ErrOwnership
	}
	r.StartSent = true
	if err := save(*r); err != nil {
		return err
	}
	if _, err := api.ContainerStart(ctx, r.NativeID, client.ContainerStartOptions{}); err != nil {
		return nativeFailure(ctx)
	}
	return nil
}

// Original stopping/waiting/removal never requires a replacement grant or
// container. Unknown Create/Start/Remove responses retain their exact ID.
func (n *NativeJobs) observeNativeContainerExit(ctx context.Context, id engine.Identity, opts client.ContainerCreateOptions, r *nativeContainerReceipt, stopping bool, save func(nativeContainerReceipt) error) error {
	if r.NativeID == "" {
		if !r.CreateSent || r.CreateNotSent {
			return nil
		}
		got, err := n.docker.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
		if cerrdefs.IsNotFound(err) {
			return reconcile.ErrPending
		}
		if err != nil {
			return nativeFailure(ctx)
		}
		if !matchNativeContainerOptions(got.Container, id, r.ImageID, r.NativeID, opts) {
			return engine.ErrOwnership
		}
		r.NativeID = got.Container.ID
		if err := save(*r); err != nil {
			return err
		}
	}
	if r.Removed || r.Waited {
		return nil
	}
	got, err := n.docker.API.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		r.AbsentObserved, r.Removed = true, true
		return save(*r)
	}
	if err != nil {
		return nativeFailure(ctx)
	}
	if !matchNativeContainerOptions(got.Container, id, r.ImageID, r.NativeID, opts) {
		return engine.ErrOwnership
	}
	if !stopping && r.StartSent && !nativeStarted(got.Container.State) {
		return reconcile.ErrPending
	}
	if got.Container.State.Running || got.Container.State.Paused || got.Container.State.Restarting {
		if !stopping {
			return reconcile.ErrPending
		}
		if err := n.docker.StopContainer(ctx, r.NativeID, engine.StopPolicy{GraceSeconds: 10, Signal: "SIGTERM"}); err != nil {
			return nativeFailure(ctx)
		}
	}
	wait := n.docker.API.ContainerWait(ctx, r.NativeID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case result, ok := <-wait.Result:
		if !ok || result.Error != nil {
			return ErrStorage
		}
		got, err := n.docker.API.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
		if err != nil {
			return nativeFailure(ctx)
		}
		if !matchNativeContainerOptions(got.Container, id, r.ImageID, r.NativeID, opts) || got.Container.State.Running || got.Container.State.Paused || got.Container.State.Restarting {
			return engine.ErrOwnership
		}
		r.Waited = true
		if r.StartSent && nativeExited(got.Container.State, result.StatusCode) {
			r.Exited, r.ExitCode = true, result.StatusCode
		} else if !stopping {
			return reconcile.ErrPending
		}
	case <-wait.Error:
		return nativeFailure(ctx)
	}
	return save(*r)
}

func (n *NativeJobs) removeNativeContainer(ctx context.Context, id engine.Identity, opts client.ContainerCreateOptions, r *nativeContainerReceipt, save func(nativeContainerReceipt) error) error {
	if r.Removed {
		return nil
	}
	if r.NativeID == "" || !r.Waited {
		return reconcile.ErrPending
	}
	got, err := n.docker.API.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		r.AbsentObserved, r.Removed = true, true
		return save(*r)
	}
	if err != nil {
		return nativeFailure(ctx)
	}
	if !matchNativeContainerOptions(got.Container, id, r.ImageID, r.NativeID, opts) || got.Container.State.Running || got.Container.State.Paused || got.Container.State.Restarting {
		return engine.ErrOwnership
	}
	if r.RemoveSent {
		return reconcile.ErrPending
	}
	r.RemoveSent = true
	if err := save(*r); err != nil {
		return err
	}
	if _, err := n.docker.API.ContainerRemove(ctx, r.NativeID, client.ContainerRemoveOptions{}); err != nil {
		return nativeFailure(ctx)
	}
	if _, err := n.docker.API.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		return reconcile.ErrPending
	}
	r.Removed = true
	return save(*r)
}
