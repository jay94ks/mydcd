// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"io"
	"reflect"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func nativeFailure(ctx context.Context) error { return errors.Join(ErrStorage, ctx.Err()) }
func nativeStarted(s *container.State) bool {
	if s == nil {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, s.StartedAt)
	return err == nil && !at.IsZero()
}
func matchNativeContainer(got container.InspectResponse, r NativeRecord, p NativePlan) bool {
	want, err := p.createOptionsWithTLS(r.Spec, r.Solve != nil, r.Solve != nil && r.Solve.TLS)
	return err == nil && matchNativeContainerOptions(got, p.Container, r.ImageID, r.NativeID, want)
}
func matchNativeContainerOptions(got container.InspectResponse, identity engine.Identity, imageID, native string, want client.ContainerCreateOptions) bool {
	if got.Config == nil || got.HostConfig == nil || got.State == nil || !nativeID(got.ID) || native != "" && got.ID != native || imageID == "" || got.Image != imageID || !identity.Matches(got.Name, got.Config.Labels) {
		return false
	}
	c, h := got.Config, got.HostConfig
	wc, wh := want.Config, want.HostConfig
	if c.Image != wc.Image || c.User != wc.User || c.WorkingDir != wc.WorkingDir || !slices.Equal(c.Entrypoint, wc.Entrypoint) || !slices.Equal(c.Cmd, wc.Cmd) || c.OpenStdin || c.Tty || c.StdinOnce || len(c.ExposedPorts) != 0 || !slices.Equal(c.Env, wc.Env) || c.StopSignal != wc.StopSignal || c.StopTimeout == nil || *c.StopTimeout != *wc.StopTimeout || c.Healthcheck == nil || !slices.Equal(c.Healthcheck.Test, []string{"NONE"}) {
		return false
	}
	if h.Privileged || h.AutoRemove || h.NetworkMode != wh.NetworkMode || h.IpcMode != wh.IpcMode || h.PidMode != "" || h.UsernsMode == "host" || h.UTSMode != "" || !h.ReadonlyRootfs || h.RestartPolicy.Name != "no" || h.LogConfig.Type != "none" || h.Memory != wh.Memory || h.MemorySwap != wh.MemorySwap || h.NanoCPUs != wh.NanoCPUs || h.PidsLimit == nil || *h.PidsLimit != *wh.PidsLimit || len(h.Binds) != 0 || len(h.VolumesFrom) != 0 || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.CapAdd) != 0 || len(h.CapDrop) != 0 || len(h.PortBindings) != 0 || !reflect.DeepEqual(h.Tmpfs, wh.Tmpfs) || len(h.Mounts) != len(wh.Mounts) {
		return false
	}
	security := slices.Clone(h.SecurityOpt)
	expected := slices.Clone(wh.SecurityOpt)
	slices.Sort(security)
	slices.Sort(expected)
	if !slices.Equal(security, expected) || !slices.Equal(h.MaskedPaths, wh.MaskedPaths) || !slices.Equal(h.ReadonlyPaths, wh.ReadonlyPaths) {
		return false
	}
	for _, wm := range wh.Mounts {
		found := false
		for _, m := range h.Mounts {
			if m.Type == wm.Type && m.Source == wm.Source && m.Target == wm.Target && m.ReadOnly == wm.ReadOnly && reflect.DeepEqual(m.BindOptions, wm.BindOptions) && m.VolumeOptions == nil {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Create is one native dispatch. Its original workspace/cache identities and
// root pin already exist; the guarded SDK checks the actual daemon's paths.
func (n *NativeJobs) Create(ctx context.Context, spec JobSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	check := func() error { _, err := n.current(ctx, &r, false); return err }
	if err := check(); err != nil {
		return err
	}
	if r.Cancel || r.Removed || r.CreateNotSent {
		return ErrConflict
	}
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return err
	}
	options, err := p.createOptionsWithTLS(spec, r.Solve != nil, r.Solve != nil && r.Solve.TLS)
	if err != nil {
		return err
	}
	files, err := n.openWorkspace(r)
	if err != nil {
		return err
	}
	defer files.Close()
	receipt := r.containerReceipt()
	persist := func(v nativeContainerReceipt) error {
		r.setContainerReceipt(v)
		if v.CreateNotSent {
			r.Cancel = true
		}
		return n.save(r)
	}
	dispatch := func() error {
		if r.State.Pending == nil || r.State.Pending.Phase != reconcile.Prepared {
			return ErrStorage
		}
		r.State, err = reconcile.Dispatch(r.State, r.State.Pending.ID)
		return err
	}
	return n.createNativeContainer(ctx, p.Container, options, files, &receipt, check, dispatch, persist)
}

func (n *NativeJobs) stage(ctx context.Context, spec JobSpec, controls bool, encode func(io.Writer) error) error {
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	if _, err := n.current(ctx, &r, false); err != nil {
		return err
	}
	if r.Cancel || r.NativeID == "" || r.StartSent || r.Removed {
		return ErrConflict
	}
	if controls && r.ControlsDone || !controls && r.ContextDone {
		return nil
	}
	if controls && (r.ControlsSent || !r.ContextDone) || !controls && r.ContextSent {
		return reconcile.ErrPending
	}
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return err
	}
	got, err := n.docker.API.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
	if err != nil {
		return nativeFailure(ctx)
	}
	if !matchNativeContainer(got.Container, r, p) || nativeStarted(got.Container.State) || !engine.ContainerStartable(got.Container.State) {
		return engine.ErrOwnership
	}
	files, err := n.openWorkspace(r)
	if err != nil {
		return err
	}
	defer files.Close()
	api, err := n.docker.BindStreamingClient(files.Sources())
	if err != nil {
		return err
	}
	defer api.Close()
	if controls {
		r.ControlsSent = true
	} else {
		r.ContextSent = true
	}
	if err := n.save(r); err != nil {
		return err
	}
	if err := copyInputArchive(ctx, api, r.NativeID, encode); err != nil {
		return err
	}
	if controls {
		r.ControlsDone = true
	} else {
		r.ContextDone = true
	}
	return n.save(r)
}
func (n *NativeJobs) StageContext(ctx context.Context, spec JobSpec, body io.ReaderAt) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.stage(ctx, spec, false, func(w io.Writer) error { _, err := WriteContextTAR(ctx, body, spec.Scope, spec.Seal, w); return err })
}
func (n *NativeJobs) StageControls(ctx context.Context, spec JobSpec, values []SecretValue) error {
	return n.stageControls(ctx, spec, values, nil, false)
}

func (n *NativeJobs) StageControlsTLS(ctx context.Context, spec JobSpec, values []SecretValue, roots []registryclient.RegistryTrust) error {
	return n.stageControls(ctx, spec, values, roots, true)
}

func (n *NativeJobs) stageControls(ctx context.Context, spec JobSpec, values []SecretValue, roots []registryclient.RegistryTrust, tls bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	grant, err := n.current(ctx, &r, false)
	if err != nil {
		return err
	}
	if (r.Solve != nil && r.Solve.TLS) != tls {
		return ErrConflict
	}
	var files []buildTrustFile
	if tls {
		var trust [32]byte
		inputs := grant.Run.Inputs
		if r.Solve.SourceContent {
			if len(roots) != 0 {
				return ErrConflict
			}
			inputs = nil
		}
		files, trust, err = buildTrustControls(inputs, roots)
		if err != nil {
			return err
		}
		if r.Solve.Trust != nil && *r.Solve.Trust != trust {
			return ErrConflict
		}
		if r.Solve.Trust == nil {
			r.Solve.Trust = &trust
			if err := n.save(r); err != nil {
				return err
			}
		}
	}
	return n.stage(ctx, spec, true, func(w io.Writer) error { return writeControlFilesTAR(ctx, w, spec, grant.Run.Inputs, values, files) })
}
func (n *NativeJobs) Start(ctx context.Context, spec JobSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	if _, err := n.current(ctx, &r, false); err != nil {
		return err
	}
	if r.Cancel || r.NativeID == "" || !r.ContextDone || !r.ControlsDone || r.Removed || r.Solve != nil && r.Solve.Stopping {
		return ErrConflict
	}
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return err
	}
	options, err := p.createOptionsWithTLS(spec, r.Solve != nil, r.Solve != nil && r.Solve.TLS)
	if err != nil {
		return err
	}
	files, err := n.openWorkspace(r)
	if err != nil {
		return err
	}
	defer files.Close()
	receipt := r.containerReceipt()
	return n.startNativeContainer(ctx, p.Container, options, files, &receipt, func(v nativeContainerReceipt) error { r.setContainerReceipt(v); return n.save(r) })
}

// ObserveExit does not hold the module loop waiting for a running build. Once
// the same native is stopped, it consumes the SDK Wait result before removal.
func (n *NativeJobs) ObserveExit(ctx context.Context, spec JobSpec, cancel bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	stopping := r.Solve != nil && r.Solve.Stopping
	if !cancel && !r.Cancel && !stopping {
		g, err := n.current(ctx, &r, true)
		if err != nil {
			return err
		}
		cancel = g.Run.Cancel
	}
	if cancel && !r.Cancel {
		r.Cancel = true
		if err := n.save(r); err != nil {
			return err
		}
	}
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return err
	}
	opts, err := p.createOptionsWithTLS(spec, r.Solve != nil, r.Solve != nil && r.Solve.TLS)
	if err != nil {
		return err
	}
	receipt := r.containerReceipt()
	return n.observeNativeContainerExit(ctx, p.Container, opts, &receipt, r.Cancel || stopping, func(v nativeContainerReceipt) error { r.setContainerReceipt(v); return n.save(r) })
}
func (n *NativeJobs) Remove(ctx context.Context, spec JobSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	if !r.Cancel && !r.Exited {
		if _, err := n.current(ctx, &r, true); err != nil {
			return err
		}
	}
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return err
	}
	opts, err := p.createOptionsWithTLS(spec, r.Solve != nil, r.Solve != nil && r.Solve.TLS)
	if err != nil {
		return err
	}
	receipt := r.containerReceipt()
	return n.removeNativeContainer(ctx, p.Container, opts, &receipt, func(v nativeContainerReceipt) error { r.setContainerReceipt(v); return n.save(r) })
}

// Build failure (including OOM) is a completed process too. This receipt is
// local build execution evidence, not a Volume writer fence.
func nativeExited(s *container.State, code int64) bool {
	if s == nil || s.Status != container.StateExited || s.Running || s.Paused || s.Restarting || s.Pid != 0 || !nativeStarted(s) || code < 0 || code > 255 || int64(s.ExitCode) != code {
		return false
	}
	started, _ := time.Parse(time.RFC3339Nano, s.StartedAt)
	finished, err := time.Parse(time.RFC3339Nano, s.FinishedAt)
	return err == nil && !finished.IsZero() && !finished.Before(started)
}
