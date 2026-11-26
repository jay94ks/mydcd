// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

const compilerPIDLimit int64 = 128

func (m *CompilerOwner) grant(ctx context.Context, r *compilerDisk, recover bool) (CompilerGrant, error) {
	g, err := m.authorize(ctx, r.Intent.Clone(), recover)
	raw, _ := json.Marshal(r.Policy)
	if err != nil {
		return g, err
	}
	if g.Schema != 1 || g.Job != r.Intent.Digest() || g.Manifest != r.Intent.Manifest || g.Policy != sha256.Sum256(raw) || g.Owner != r.Intent.Owner || g.Index == 0 || g.Index < r.Index || g.Revision == 0 || g.Revision < r.SharedRevision || g.DeadlineUnixMilli != r.Intent.DeadlineUnixMilli || g.Recovery != recover || g.Phase != "reserved" && g.Phase != "dispatched" && g.Phase != "closed" || !recover && g.Phase != "dispatched" {
		return g, ErrCompilerOwner
	}
	if g.Phase == "reserved" && g.Revision != 1 || g.Phase == "dispatched" && g.Revision != 2 || g.Phase == "closed" && g.Revision != 2 && g.Revision != 3 {
		return g, ErrCompilerOwner
	}
	if g.Index != r.Index || g.Revision != r.SharedRevision {
		r.Index, r.SharedRevision = g.Index, g.Revision
		if err := m.save(*r); err != nil {
			return g, err
		}
	}
	return g, nil
}

func compilerOptions(r compilerDisk, id engine.Identity, f *compilerFiles) client.ContainerCreateOptions {
	pids := compilerPIDLimit
	stop := 2
	config := &container.Config{Image: r.Policy.Build.Image, User: "10001:10001", WorkingDir: "/work", Entrypoint: []string{"/usr/local/bin/lifecycle-compiler"}, Cmd: []string{}, Env: []string{"GOMAXPROCS=2"}, Labels: id.Labels, StopSignal: "SIGTERM", StopTimeout: &stop, Healthcheck: &container.HealthConfig{Test: []string{"NONE"}}}
	host := &container.HostConfig{NetworkMode: "none", IpcMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, RestartPolicy: container.RestartPolicy{Name: "no"}, LogConfig: container.LogConfig{Type: "none"}, Resources: container.Resources{Memory: r.Policy.Build.MemoryBytes, MemorySwap: r.Policy.Build.MemoryBytes, NanoCPUs: r.Policy.Build.NanoCPU, PidsLimit: &pids}, Mounts: []mount.Mount{
		{Type: mount.TypeBind, Source: f.inputPath, Target: "/input", ReadOnly: true, BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}},
		{Type: mount.TypeBind, Source: f.outputPath, Target: "/output", BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}},
		{Type: mount.TypeBind, Source: f.cachePath, Target: "/cache", BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}},
	}, Tmpfs: map[string]string{"/work": "rw,nosuid,nodev,exec,uid=10001,gid=10001,mode=0700,size=" + strconv.FormatUint(r.Policy.Build.WorkspaceBytes, 10)}}
	return client.ContainerCreateOptions{Name: id.Name, Config: config, HostConfig: host}
}

func matchCompiler(got container.InspectResponse, r compilerDisk, id engine.Identity, f *compilerFiles) bool {
	if got.State == nil || got.HostConfig == nil || got.Config == nil || !digest(got.ID) || r.NativeID != "" && got.ID != r.NativeID || r.ImageID != "" && got.Image != r.ImageID || !id.Matches(got.Name, got.Config.Labels) {
		return false
	}
	want := compilerOptions(r, id, f)
	h, c := got.HostConfig, got.Config
	wc, wh := want.Config, want.HostConfig
	if c.Image != wc.Image || c.User != wc.User || c.WorkingDir != wc.WorkingDir || !slices.Equal(c.Entrypoint, wc.Entrypoint) || len(c.Cmd) != 0 || !slices.Equal(c.Env, wc.Env) || c.StopSignal != wc.StopSignal || c.StopTimeout == nil || *c.StopTimeout != *wc.StopTimeout || c.Healthcheck == nil || !slices.Equal(c.Healthcheck.Test, []string{"NONE"}) || len(c.Volumes) != 0 || len(c.ExposedPorts) != 0 || c.OpenStdin || c.StdinOnce || c.Tty {
		return false
	}
	if h.NetworkMode != "none" || h.IpcMode != "none" || h.PidMode != "" || h.UTSMode != "" || h.UsernsMode == "host" || !h.ReadonlyRootfs || h.Privileged || h.AutoRemove || h.RestartPolicy.Name != "no" || h.LogConfig.Type != "none" || !slices.Equal(h.CapDrop, wh.CapDrop) || len(h.CapAdd) != 0 || !slices.Contains(h.SecurityOpt, "no-new-privileges") && !slices.Contains(h.SecurityOpt, "no-new-privileges=true") || h.Memory != wh.Memory || h.MemorySwap != wh.MemorySwap || h.NanoCPUs != wh.NanoCPUs || h.PidsLimit == nil || *h.PidsLimit != compilerPIDLimit || !reflect.DeepEqual(h.Tmpfs, wh.Tmpfs) || len(h.Binds) != 0 || len(h.VolumesFrom) != 0 || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.PortBindings) != 0 || len(h.Mounts) != 3 {
		return false
	}
	for _, want := range wh.Mounts {
		found := false
		for _, got := range h.Mounts {
			if got.Target == want.Target && got.Type == want.Type && got.Source == want.Source && got.ReadOnly == want.ReadOnly && got.BindOptions != nil && got.BindOptions.Propagation == mount.PropagationRPrivate {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func compilerStarted(state *container.State) bool {
	if state == nil {
		return false
	}
	when, err := time.Parse(time.RFC3339Nano, state.StartedAt)
	return err == nil && !when.IsZero()
}

// Step advances only the original compound A2 job. Each native dispatch has a
// separate synced witness; an uncertain Create/Start is never sent again.
// The sole Applied meaning here is CLOSED finite job, never container Ready.
func (m *CompilerOwner) Step(ctx context.Context, tenant, id string) error {
	m.life.RLock()
	defer m.life.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil || ctx.Err() != nil {
		return ErrCompilerOwner
	}
	r, err := m.load(tenant, id)
	if err != nil {
		return err
	}
	if r.Closure != nil {
		return nil
	}
	ctx, stop := context.WithCancel(ctx)
	m.interruptMu.Lock()
	m.active[compilerJobKey(r.Intent)] = stop
	interrupted := m.requested[compilerJobKey(r.Intent)] || m.shuttingDown && !r.Cancel
	m.interruptMu.Unlock()
	defer func() {
		stop()
		m.interruptMu.Lock()
		delete(m.active, compilerJobKey(r.Intent))
		m.interruptMu.Unlock()
	}()
	if interrupted {
		stop()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.State.Pending == nil {
		r.State, _, err = reconcile.Plan(r.State)
		if err != nil || r.State.Pending == nil {
			return errors.Join(ErrCompilerOwner, err)
		}
		if err := m.save(r); err != nil {
			return err
		}
	}
	if r.State.Pending.Phase == reconcile.Prepared {
		r.State, err = reconcile.Dispatch(r.State, r.State.Pending.ID)
		if err != nil {
			return err
		}
		if err := m.save(r); err != nil {
			return err
		}
	}
	err = m.advanceNative(ctx, &r)
	if err != nil && r.State.Pending != nil {
		r.State, _ = reconcile.Settle(r.State, r.State.Pending.ID, reconcile.EffectUnknown)
		err = errors.Join(err, m.save(r))
	}
	return err
}

func (m *CompilerOwner) advanceNative(ctx context.Context, r *compilerDisk) error {
	if !r.Cancel && time.Now().UnixMilli() >= r.Intent.DeadlineUnixMilli {
		r.Cancel = true
		if err := m.save(*r); err != nil {
			return err
		}
	}
	var grant CompilerGrant
	if r.Cancel && r.WorkspaceClosed && r.SharedRevision == 2 {
		grant.Phase = "dispatched"
	} else if !r.Cancel || r.WorkspaceClosed {
		var err error
		grant, err = m.grant(ctx, r, true)
		if err != nil {
			return err
		}
	} // cancellation performs native cleanup BEFORE any new quorum wait
	if grant.Phase == "closed" {
		return ErrCompilerOwner
	}
	if r.WorkspaceClosed {
		return m.finishNative(r, grant.Phase)
	}
	if r.Cancel && (!r.CreateDispatched || r.CreateNotSent) {
		r.CreateNotSent, r.OutputSettled = true, true
		if err := m.save(*r); err != nil {
			return err
		}
		return m.closeWorkspace(ctx, r, grant.Phase)
	}
	if r.Cancel {
		// Removal never mounts a source or starts a process. Original native
		// ownership, not current source/SDK/path availability, governs cleanup.
		if !r.Removed {
			if err := m.stopRemoveOriginal(ctx, r); err != nil {
				return err
			}
		}
		if !r.CollectionDispatched {
			r.OutputSettled = true
			if err := m.save(*r); err != nil {
				return err
			}
			return m.closeWorkspace(ctx, r, grant.Phase)
		}
	}
	if !r.InputReady {
		return reconcile.ErrPending
	}
	var batch CompileBatch
	var err error
	if r.Cancel {
		batch, err = m.readOriginalBatch(*r)
	} else {
		batch, err = m.readBatch(*r)
	}
	if err != nil {
		return err
	}
	files, err := m.openFiles(*r)
	if err != nil {
		return err
	}
	defer files.Close()
	api, err := m.engine.BindClient(files.Sources())
	if err != nil {
		return err
	}
	defer api.Close()
	native, err := m.engine.Identity("container", compilerKey(r.Intent), r.State.Desired.Resource)
	if err != nil {
		return err
	}
	if !r.Removed {
		if err := m.progressContainer(ctx, r, api, native, files); err != nil {
			return err
		}
	}
	// Never leave a finished compiler running while cache/transport is pending.
	// Output keeps its original durable reference until a collector confirms it.
	if !r.OutputSettled {
		if r.Cancel && !r.CollectionDispatched {
			r.OutputSettled = true
			if err := m.save(*r); err != nil {
				return err
			}
		} else {
			if m.collect == nil {
				return reconcile.ErrPending
			}
			recover := r.CollectionDispatched
			r.CollectionDispatched = true
			if err := m.save(*r); err != nil {
				return err
			}
			root, err := m.collect(ctx, CompilerOutput{Intent: r.Intent.Clone(), Policy: r.Policy.Clone(), Batch: batch, ExitCode: r.ExitCode, ExitKnown: r.Exited, Recover: recover, Root: files.outputRoot})
			if err != nil {
				return err
			}
			if root == ([32]byte{}) {
				return ErrCompilerOwner
			}
			artifacts, err := m.collectedArtifacts(*r, root)
			if err != nil {
				return err
			}
			r.Artifacts = artifacts
			r.Output, r.OutputSettled = root, true
			if err := m.save(*r); err != nil {
				return err
			}
		}
	}
	// Close the guarded client and held leaves before their original workspace
	// disappears. Both are idempotently safe to close again in deferred cleanup.
	if err := api.Close(); err != nil {
		return err
	}
	if err := files.Close(); err != nil {
		return err
	}
	return m.closeWorkspace(ctx, r, grant.Phase)
}

// stopRemoveOriginal is deliberately independent of input mounts, compiler
// validation and current Start authority. It can NEVER Create or Start.
func (m *CompilerOwner) stopRemoveOriginal(ctx context.Context, r *compilerDisk) error {
	id, err := m.engine.Identity("container", compilerKey(r.Intent), r.State.Desired.Resource)
	if err != nil {
		return err
	}
	lookup := r.NativeID
	if lookup == "" {
		lookup = id.Name
	}
	got, err := m.engine.API.ContainerInspect(ctx, lookup, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		if r.NativeID == "" {
			return reconcile.ErrPending
		} // possible late Create
		r.Removed = true
		return m.save(*r)
	}
	if err != nil {
		return err
	}
	if got.Container.Config == nil || got.Container.State == nil || !digest(got.Container.ID) || r.NativeID != "" && r.NativeID != got.Container.ID || !id.Matches(got.Container.Name, got.Container.Config.Labels) {
		return engine.ErrOwnership
	}
	if r.NativeID == "" {
		if !r.CreateDispatched {
			return engine.ErrOwnership
		}
		r.NativeID = got.Container.ID
		if err := m.save(*r); err != nil {
			return err
		}
	}
	if got.Container.State.Running || got.Container.State.Paused || got.Container.State.Restarting {
		timeout := 2
		if _, err := m.engine.API.ContainerStop(ctx, r.NativeID, client.ContainerStopOptions{Timeout: &timeout, Signal: "SIGTERM"}); err != nil {
			return err
		}
	}
	wait := m.engine.API.ContainerWait(ctx, r.NativeID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case result := <-wait.Result:
		if result.Error != nil {
			return ErrCompilerOwner
		}
		if r.StartDispatched {
			r.Exited, r.ExitCode = true, result.StatusCode
			if err := m.save(*r); err != nil {
				return err
			}
		}
	case err := <-wait.Error:
		return err
	}
	if _, err := m.engine.API.ContainerRemove(ctx, r.NativeID, client.ContainerRemoveOptions{}); err != nil {
		return err
	}
	if _, err := m.engine.API.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		return errors.Join(reconcile.ErrPending, err)
	}
	r.Removed = true
	return m.save(*r)
}

func (m *CompilerOwner) progressContainer(ctx context.Context, r *compilerDisk, api *client.Client, id engine.Identity, files *compilerFiles) error {
	lookup := r.NativeID
	if lookup == "" {
		lookup = id.Name
	}
	got, err := api.ContainerInspect(ctx, lookup, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		if r.NativeID != "" {
			r.Removed = true
			return m.save(*r)
		}
		if r.CreateDispatched {
			return reconcile.ErrPending
		} // late Create remains possible
		if r.Cancel {
			return ErrCompilerOwner
		}
		if _, err := m.grant(ctx, r, false); err != nil {
			return err
		}
		image, err := m.engine.Image(ctx, r.Policy.Build.Image, false)
		if err != nil {
			return err
		}
		if image.Config == nil || image.Os != "linux" || image.Architecture != runtime.GOARCH || len(image.Config.Volumes) != 0 || len(image.Config.Env) != 0 {
			return engine.ErrOwnership
		}
		if !strings.HasPrefix(image.ID, "sha256:") || !digest(strings.TrimPrefix(image.ID, "sha256:")) {
			return engine.ErrOwnership
		}
		if _, err := m.grant(ctx, r, false); err != nil {
			return err
		}
		if time.Now().UnixMilli() >= r.Intent.DeadlineUnixMilli {
			return context.DeadlineExceeded
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r.ImageID, r.CreateDispatched = image.ID, true
		if err := m.save(*r); err != nil {
			return err
		}
		created, err := api.ContainerCreate(ctx, compilerOptions(*r, id, files))
		if err != nil {
			// Only this SDK transport's positive no-request fact can say absent.
			if errors.Is(err, engine.ErrBindBeforeRequest) {
				r.CreateNotSent, r.Cancel = true, true
				if e := m.save(*r); e != nil {
					return errors.Join(err, e)
				}
			}
			return err
		}
		if !digest(created.ID) {
			return engine.ErrOwnership
		}
		r.NativeID = created.ID
		if err := m.save(*r); err != nil {
			return err
		}
		got, err = api.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
	}
	if err != nil {
		return err
	}
	if !matchCompiler(got.Container, *r, id, files) {
		return engine.ErrOwnership
	}
	if r.NativeID == "" {
		if !r.CreateDispatched {
			return engine.ErrOwnership
		}
		r.NativeID = got.Container.ID
		if err := m.save(*r); err != nil {
			return err
		}
	}
	started := compilerStarted(got.Container.State)
	if !r.StartDispatched && started {
		return engine.ErrOwnership
	}
	if !r.StartDispatched && !r.Cancel {
		if _, err := m.grant(ctx, r, false); err != nil {
			return err
		}
		if time.Now().UnixMilli() >= r.Intent.DeadlineUnixMilli {
			return context.DeadlineExceeded
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r.StartDispatched = true
		if err := m.save(*r); err != nil {
			return err
		}
		if _, err := api.ContainerStart(ctx, r.NativeID, client.ContainerStartOptions{}); err != nil {
			return err
		}
		got, err = api.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
		if err != nil || !matchCompiler(got.Container, *r, id, files) {
			return errors.Join(engine.ErrOwnership, err)
		}
		started = compilerStarted(got.Container.State)
	}
	if !started && !r.Cancel {
		return reconcile.ErrPending
	} // uncertain Start: never restart
	if r.Cancel || got.Container.State.Running || started {
		if r.Cancel && (got.Container.State.Running || got.Container.State.Paused || got.Container.State.Restarting) {
			timeout := 2
			if _, err := api.ContainerStop(ctx, r.NativeID, client.ContainerStopOptions{Timeout: &timeout, Signal: "SIGTERM"}); err != nil {
				return err
			}
		}
		waitContext, cancel := context.WithDeadline(ctx, time.UnixMilli(r.Intent.DeadlineUnixMilli))
		if r.Cancel {
			cancel()
			waitContext, cancel = context.WithCancel(ctx)
		}
		wait := api.ContainerWait(waitContext, r.NativeID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
		// Always consume the SDK's one terminal channel. Leaving Result unread
		// on cancellation can strand the SDK goroutine after a fast exit.
		select {
		case result := <-wait.Result:
			cancel()
			if result.Error != nil {
				return ErrCompilerOwner
			}
		case err := <-wait.Error:
			cancel()
			return err
		}
		got, err = api.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
		if err != nil || !matchCompiler(got.Container, *r, id, files) {
			return errors.Join(engine.ErrOwnership, err)
		}
	}
	if got.Container.State.Running || got.Container.State.Paused || got.Container.State.Restarting {
		return reconcile.ErrPending
	}
	started = compilerStarted(got.Container.State)
	if started {
		r.Exited, r.ExitCode = true, int64(got.Container.State.ExitCode)
		if err := m.save(*r); err != nil {
			return err
		}
	} else if !r.Cancel {
		return reconcile.ErrPending
	}
	// No force/volume/image cleanup: remove this exact immutable native only.
	if _, err := api.ContainerRemove(ctx, r.NativeID, client.ContainerRemoveOptions{}); err != nil {
		return err
	}
	if _, err := api.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		return errors.Join(reconcile.ErrPending, err)
	}
	r.Removed = true
	return m.save(*r)
}

func (m *CompilerOwner) closeWorkspace(ctx context.Context, r *compilerDisk, sharedPhase string) error {
	if !r.OutputSettled || !r.Removed && !r.CreateNotSent {
		return ErrCompilerOwner
	}
	if r.Directory == (compilerDirectory{}) {
		// A crash may occur after our private job directory was made but before
		// its inode receipt synced. It cannot have reached native dispatch.
		if r.CreateDispatched && !r.CreateNotSent {
			return ErrCompilerOwner
		}
		for _, name := range []string{"jobs", "jobs/" + r.Intent.Tenant, compilerJobPath(r.Intent)} {
			info, err := m.root.Lstat(name)
			if os.IsNotExist(err) {
				break
			}
			if err != nil {
				return err
			}
			uid, gid, ok := compilerOwnership(info)
			if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || uid != os.Geteuid() || gid != os.Getegid() {
				return ErrCompilerOwner
			}
			if name == compilerJobPath(r.Intent) {
				r.Directory, err = directoryIdentity(info)
				if err != nil {
					return err
				}
				if err := m.save(*r); err != nil {
					return err
				}
			}
		}
	}
	if err := m.removeWorkspace(*r); err != nil {
		return err
	}
	r.WorkspaceClosed = true
	if err := m.save(*r); err != nil {
		return err
	}
	if sharedPhase == "" {
		// The originally observed dispatched revision cannot become reserved
		// again. Signing native closure needs no current execution permission;
		// its delivery and shared pin release still need a committed FSM result.
		if r.SharedRevision == 2 {
			sharedPhase = "dispatched"
		}
	}
	if sharedPhase == "" {
		grant, err := m.grant(ctx, r, true)
		if err != nil {
			return errors.Join(reconcile.ErrPending, err)
		}
		sharedPhase = grant.Phase
	}
	return m.finishNative(r, sharedPhase)
}
func (m *CompilerOwner) finishNative(r *compilerDisk, sharedPhase string) error {
	if !r.WorkspaceClosed || !r.OutputSettled || r.State.Pending == nil {
		return ErrCompilerOwner
	}
	// Native cleanup may complete while quorum is unavailable. Keep its exact
	// references and wait to reconcile the original shared phase before signing.
	if sharedPhase != "reserved" && sharedPhase != "dispatched" {
		return reconcile.ErrPending
	}
	disposition := "removed"
	if r.CreateNotSent {
		disposition = "not-created"
		if sharedPhase == "reserved" {
			disposition = "never-dispatched"
		}
	}
	c := BuildClosure{Schema: 1, Cluster: r.Intent.Cluster, Job: r.Intent.Digest(), Owner: r.Intent.Owner, Journal: compilerJournalDigest(*r), Output: r.Output, Native: r.NativeID, Disposition: disposition, Artifacts: slices.Clone(r.Artifacts)}
	c.Signature = ed25519.Sign(m.private, BuildClosureBytes(c))
	if c.Verify(r.Intent, sharedPhase) != nil {
		return ErrCompilerOwner
	}
	state, err := reconcile.Settle(r.State, r.State.Pending.ID, reconcile.EffectApplied)
	if err != nil {
		return err
	}
	r.State, r.Closure = state, &c
	return m.save(*r)
}
