// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/hex"
	"maps"
	"path/filepath"
	"strconv"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/moby/moby/client"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

type NativeCachePruneDaemon struct {
	Job, Output     NativeDirectory
	Ready, Stopping bool
	Effects         nativeContainerReceipt
}

func (d NativeCachePruneDaemon) valid(r NativeCachePruneRecord) bool {
	if !r.Claimed || r.CleanupOnly || d.Job != (NativeDirectory{}) && !d.Job.valid() || d.Output != (NativeDirectory{}) && (!d.Output.valid() || !d.Job.valid()) || d.Ready && (!d.Job.valid() || !d.Output.valid()) {
		return false
	}
	e := d.Effects
	return e.valid() && (!e.CreateSent || d.Ready) && (!e.CreateNotSent || d.Stopping)
}

type NativeCachePruneAuthority func(context.Context, NativeCachePruneSpec, bool) (NativeCachePruneGrant, error)

func cachePruneWorkspaceNames(s NativeCachePruneSpec) [2]string {
	job := ".sfc-imagebuild/cache-maintenance/" + hex.EncodeToString(s.Intent[:])
	return [2]string{job, job + "/output"}
}
func planCachePrune(s NativeCachePruneSpec, owner string) (engine.Identity, client.ContainerCreateOptions, error) {
	if !s.Valid() || owner != engine.Owner(s.Source.Cluster, s.Source.Scope.Root.Key) {
		return engine.Identity{}, client.ContainerCreateOptions{}, ErrInvalid
	}
	source, err := PlanNative(s.Source, owner)
	if err != nil {
		return engine.Identity{}, client.ContainerCreateOptions{}, err
	}
	// Reuse the adopted rootless image's budgets/isolation without constructing
	// a replacement JobSpec. SDK mode carries no build arguments or secrets.
	opts, err := source.createOptions(s.Source, true)
	if err != nil {
		return engine.Identity{}, opts, err
	}
	api := engine.Client{Owner: owner}
	id, err := api.IdentityDigest("container", "image-build-cache-prune/"+s.Source.Tenant+"/"+s.ID, 1, s.Digest())
	if err != nil {
		return id, opts, err
	}
	names := cachePruneWorkspaceNames(s)
	opts.Name, opts.Config.Labels = id.Name, maps.Clone(id.Labels)
	opts.Config.WorkingDir = "/"
	opts.Config.Entrypoint[3] = "sfc-cache-prune"
	limits := s.Limits()
	opts.Config.Entrypoint[4] = strconv.FormatUint(s.At+limits.Seconds, 10)
	if s.Automatic != nil {
		opts.HostConfig.NanoCPUs = int64(limits.CPUMillis) * 1_000_000
		opts.HostConfig.Memory, opts.HostConfig.MemorySwap = limits.MemoryBytes, limits.MemoryBytes
		opts.HostConfig.Tmpfs["/tmp"] = "rw,nosuid,nodev,exec,uid=1000,gid=1000,mode=0700,size=" + strconv.FormatInt(limits.WorkspaceBytes, 10)
	}
	opts.HostConfig.NetworkMode = "none"
	opts.HostConfig.Mounts = opts.HostConfig.Mounts[1:]
	opts.HostConfig.Mounts[0].Source = filepath.Join(s.Source.Scope.Root.Path, names[1])
	return id, opts, nil
}
func (n *NativeJobs) loadCachePrune(s NativeCachePruneSpec) (NativeCachePruneRecord, error) {
	var r NativeCachePruneRecord
	err := n.db.View(func(tx *bolt.Tx) error {
		var err error
		r, err = readNativeCachePrune(tx, s, n.docker.Owner)
		return err
	})
	return r, err
}
func (n *NativeJobs) saveCachePrune(r NativeCachePruneRecord) error {
	return n.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		if b == nil || string(b.Get([]byte("owner"))) != n.docker.Owner {
			return ErrStorage
		}
		return writeNativeCachePrune(tx, r)
	})
}
func (n *NativeJobs) currentCachePrune(ctx context.Context, r *NativeCachePruneRecord, authorize NativeCachePruneAuthority, recover bool) (NativeCachePruneGrant, error) {
	if authorize == nil {
		return NativeCachePruneGrant{}, ErrInvalid
	}
	g, err := authorize(ctx, r.Spec.Own(), recover)
	if err != nil {
		return g, err
	}
	if !g.Valid() || g.Spec.Digest() != r.Spec.Digest() || g.Index < r.Index || g.Revision < r.Revision || g.Epoch < r.Epoch || !recover && (!g.Allowed || g.Phase != "running" || r.CleanupOnly || r.Outcome != nil || r.Removing || r.Closed || r.Daemon != nil && r.Daemon.Stopping) {
		return g, ErrConflict
	}
	if g.Index != r.Index || g.Revision != r.Revision || g.Epoch != r.Epoch {
		r.Index, r.Revision, r.Epoch = g.Index, g.Revision, g.Epoch
		if err := n.saveCachePrune(*r); err != nil {
			return g, err
		}
	}
	return g, nil
}

func (n *NativeJobs) openCachePruneWorkspace(r NativeCachePruneRecord) (*nativeWorkspaceFiles, error) {
	if r.Daemon == nil || !r.Daemon.Ready || !r.Claimed {
		return nil, ErrStorage
	}
	source, err := PlanNative(r.Spec.Source, n.docker.Owner)
	if err != nil {
		return nil, err
	}
	var c nativeCacheBorrow
	err = n.db.View(func(tx *bolt.Tx) error {
		var err error
		c, err = readNativeCache(tx, r.Spec.Source, source)
		return err
	})
	if err != nil || c.Owner != r.Spec.Intent || c.Directory != r.Cache || c.RootHold == nil || c.RootHold.Lease.Token == 0 || c.RootHold.Returning || c.RootHold.Returned {
		return nil, ErrStorage
	}
	f := &nativeWorkspaceFiles{}
	var st unix.Stat_t
	f.root, st, err = openNativeRoot(r.Spec.Source.Scope.Root.Path)
	if err != nil || nativeDirectory(st) != r.Root {
		_ = f.Close()
		return nil, ErrStorage
	}
	names := cachePruneWorkspaceNames(r.Spec)
	job, st, err := openNativeDirectory(int(f.root.Fd()), names[0])
	if err != nil {
		_ = f.Close()
		return nil, ErrStorage
	}
	_ = job.Close()
	if nativeDirectory(st) != r.Daemon.Job {
		_ = f.Close()
		return nil, ErrStorage
	}
	for _, leaf := range []struct {
		index    int
		name     string
		identity NativeDirectory
	}{{1, names[1], r.Daemon.Output}, {2, nativeWorkspaceNames(source)[2], r.Cache}} {
		f.leaves[leaf.index], st, err = openNativeDirectory(int(f.root.Fd()), leaf.name)
		if err != nil || nativeDirectory(st) != leaf.identity {
			_ = f.Close()
			return nil, ErrStorage
		}
		f.paths[leaf.index] = filepath.Join(r.Spec.Source.Scope.Root.Path, leaf.name)
	}
	return f, nil
}

func (n *NativeJobs) PrepareCachePruneWorkspace(ctx context.Context, s NativeCachePruneSpec, authorize NativeCachePruneAuthority) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.loadCachePrune(s)
	if err != nil {
		return err
	}
	if _, err := n.currentCachePrune(ctx, &r, authorize, false); err != nil {
		return err
	}
	if !r.Claimed || r.Daemon != nil && r.Daemon.Effects.CreateSent {
		return ErrConflict
	}
	root, st, err := openNativeRoot(s.Source.Scope.Root.Path)
	if err != nil {
		return ErrStorage
	}
	defer root.Close()
	if nativeDirectory(st) != r.Root {
		return ErrStorage
	}
	if r.Daemon == nil {
		r.Daemon = &NativeCachePruneDaemon{}
		if err := n.saveCachePrune(r); err != nil {
			return err
		}
	}
	if err := ensureNativeParent(int(root.Fd()), ".sfc-imagebuild/cache-maintenance"); err != nil {
		return err
	}
	names := cachePruneWorkspaceNames(s)
	r.Daemon.Job, err = prepareNativeDirectory(int(root.Fd()), names[0], r.Daemon.Job, nativeBuilderUID, nativeBuilderUID, 0700)
	if err != nil {
		return err
	}
	if err := n.saveCachePrune(r); err != nil {
		return err
	}
	r.Daemon.Output, err = prepareNativeDirectory(int(root.Fd()), names[1], r.Daemon.Output, nativeBuilderUID, nativeBuilderUID, 0700)
	if err != nil {
		return err
	}
	r.Daemon.Ready = true
	return n.saveCachePrune(r)
}

func (n *NativeJobs) CreateCachePrune(ctx context.Context, s NativeCachePruneSpec, authorize NativeCachePruneAuthority) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.loadCachePrune(s)
	if err != nil {
		return err
	}
	check := func() error { _, err := n.currentCachePrune(ctx, &r, authorize, false); return err }
	if err := check(); err != nil {
		return err
	}
	id, opts, err := planCachePrune(s, n.docker.Owner)
	if err != nil {
		return err
	}
	files, err := n.openCachePruneWorkspace(r)
	if err != nil {
		return err
	}
	defer files.Close()
	effects := r.Daemon.Effects
	if effects.CreateNotSent || effects.Removed {
		return ErrConflict
	}
	return n.createNativeContainer(ctx, id, opts, files, &effects, check, func() error { return nil }, func(v nativeContainerReceipt) error {
		r.Daemon.Effects = v
		if v.CreateNotSent {
			r.Daemon.Stopping = true
		}
		return n.saveCachePrune(r)
	})
}
func (n *NativeJobs) StartCachePrune(ctx context.Context, s NativeCachePruneSpec, authorize NativeCachePruneAuthority) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.loadCachePrune(s)
	if err != nil {
		return err
	}
	if _, err := n.currentCachePrune(ctx, &r, authorize, false); err != nil {
		return err
	}
	if r.Daemon == nil || r.Daemon.Effects.NativeID == "" || r.Daemon.Effects.CreateNotSent || r.Daemon.Effects.Removed {
		return ErrConflict
	}
	id, opts, err := planCachePrune(s, n.docker.Owner)
	if err != nil {
		return err
	}
	files, err := n.openCachePruneWorkspace(r)
	if err != nil {
		return err
	}
	defer files.Close()
	effects := r.Daemon.Effects
	return n.startNativeContainer(ctx, id, opts, files, &effects, func(v nativeContainerReceipt) error { r.Daemon.Effects = v; return n.saveCachePrune(r) })
}

// Actual shutdown needs no new shared authorization once the original is
// known. This may stop a daemon with a live SDK reader, but removal and cache
// return wait for that reader to drain/join.
func (n *NativeJobs) StopCachePrune(ctx context.Context, s NativeCachePruneSpec, authorize NativeCachePruneAuthority, stop bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.loadCachePrune(s)
	if err != nil {
		return err
	}
	if r.Closed {
		return nil
	}
	if r.Daemon == nil {
		return nil
	}
	if !stop && !r.Daemon.Stopping {
		g, err := n.currentCachePrune(ctx, &r, authorize, true)
		if err != nil {
			return err
		}
		stop = !g.Allowed
	}
	if stop && !r.Daemon.Stopping {
		r.Daemon.Stopping = true
		if err := n.saveCachePrune(r); err != nil {
			return err
		}
	}
	id, opts, err := planCachePrune(s, n.docker.Owner)
	if err != nil {
		return err
	}
	effects := r.Daemon.Effects
	return n.observeNativeContainerExit(ctx, id, opts, &effects, r.Daemon.Stopping, func(v nativeContainerReceipt) error { r.Daemon.Effects = v; return n.saveCachePrune(r) })
}
func (n *NativeJobs) RemoveCachePrune(ctx context.Context, s NativeCachePruneSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.loadCachePrune(s)
	if err != nil {
		return err
	}
	if r.Daemon == nil || n.readers[s.Intent] > 0 {
		return ErrConflict
	}
	if !r.Daemon.Stopping && !r.Daemon.Effects.Exited {
		return ErrConflict
	}
	id, opts, err := planCachePrune(s, n.docker.Owner)
	if err != nil {
		return err
	}
	effects := r.Daemon.Effects
	return n.removeNativeContainer(ctx, id, opts, &effects, func(v nativeContainerReceipt) error { r.Daemon.Effects = v; return n.saveCachePrune(r) })
}
