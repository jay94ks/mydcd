// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

// These identities remain in the original native job record. No user path,
// auxiliary DB or independently managed Docker volume is introduced.
type NativeDirectory struct {
	Device, Inode  uint64
	UID, GID, Mode uint32
}

func nativeDirectory(st unix.Stat_t) NativeDirectory {
	return NativeDirectory{uint64(st.Dev), st.Ino, st.Uid, st.Gid, st.Mode & 07777}
}
func (d NativeDirectory) valid() bool { return d.Device != 0 && d.Inode != 0 && d.Mode <= 0777 }

type NativeWorkspace struct {
	Root, Job, Input, Output, Cache NativeDirectory
	Ready, Removing, Closed         bool
}

func (w NativeWorkspace) validate() error {
	if !w.Root.valid() {
		return ErrStorage
	}
	for _, d := range []NativeDirectory{w.Job, w.Input, w.Output, w.Cache} {
		if d != (NativeDirectory{}) && !d.valid() {
			return ErrStorage
		}
	}
	if w.Ready && (!w.Job.valid() || !w.Input.valid() || !w.Output.valid() || !w.Cache.valid()) {
		return ErrStorage
	}
	if (w.Input.valid() || w.Output.valid() || w.Cache.valid()) && !w.Job.valid() {
		return ErrStorage
	}
	if w.Closed && !w.Removing {
		return ErrStorage
	}
	return nil
}

type nativeCacheBorrow struct {
	Schema       uint8
	Root         nodestorage.Reference
	Cache, Owner [32]byte
	Directory    NativeDirectory
	RootHold     *NativeRootHold        `json:",omitempty"`
	Retirement   *NativeCacheRetirement `json:",omitempty"`
}

func nativeCacheKey(cache [32]byte) []byte { return []byte("cache/" + hex.EncodeToString(cache[:])) }
func readNativeCache(tx *bolt.Tx, spec JobSpec, p NativePlan) (nativeCacheBorrow, error) {
	b := tx.Bucket(nativeBucket)
	if b == nil {
		return nativeCacheBorrow{}, ErrStorage
	}
	c := nativeCacheBorrow{Schema: 1, Root: spec.Scope.Root, Cache: p.Cache}
	raw := b.Get(nativeCacheKey(p.Cache))
	if raw != nil && (len(raw) > 16<<10 || json.Unmarshal(raw, &c) != nil || c.Schema != 1 || c.Root != spec.Scope.Root || c.Cache != p.Cache || c.Directory != (NativeDirectory{}) && !c.Directory.valid()) {
		return nativeCacheBorrow{}, ErrStorage
	}
	if c.RootHold != nil && c.RootHold.validate(spec.Scope.Root.Generation) != nil {
		return nativeCacheBorrow{}, ErrStorage
	}
	if c.RootHold != nil && c.RootHold.Returning && (c.Owner != ([32]byte{}) || c.Directory.valid()) {
		return nativeCacheBorrow{}, ErrStorage
	}
	if c.Retirement != nil && (!c.Retirement.valid(c) || c.Retirement.Tenant != spec.Tenant) {
		return nativeCacheBorrow{}, ErrStorage
	}
	return c, nil
}
func (n *NativeJobs) cacheBorrow(spec JobSpec, p NativePlan, claim bool) (nativeCacheBorrow, error) {
	var c nativeCacheBorrow
	read := func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		var err error
		c, err = readNativeCache(tx, spec, p)
		if err != nil {
			return err
		}
		if c.Owner != ([32]byte{}) && c.Owner != p.Job {
			return ErrUsed
		}
		if c.Retirement != nil {
			return ErrUsed
		}
		if claim && (c.RootHold == nil || c.RootHold.Lease.Token == 0) {
			return ErrStorage
		}
		if claim && c.RootHold != nil && (c.RootHold.Returning || c.RootHold.Returned) {
			return ErrUsed
		}
		if claim {
			c.Owner = p.Job
			raw, _ := json.Marshal(c)
			return b.Put(nativeCacheKey(p.Cache), raw)
		}
		if c.Owner != p.Job {
			return ErrStorage
		}
		return nil
	}
	var err error
	if claim {
		err = n.db.Update(read)
	} else {
		err = n.db.View(read)
	}
	return c, err
}
func openNativeDirectory(root int, name string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Openat2(root, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, st, err
	}
	f := os.NewFile(uintptr(fd), "imagebuild-owned-directory")
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = f.Close()
		return nil, st, ErrStorage
	}
	return f, st, nil
}
func openNativeRoot(name string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Openat2(unix.AT_FDCWD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, st, err
	}
	f := os.NewFile(uintptr(fd), "imagebuild-original-root")
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = f.Close()
		return nil, st, ErrStorage
	}
	return f, st, nil
}
func syncNativeParent(root int, name string) error {
	f, _, err := openNativeDirectory(root, path.Dir(name))
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
func ensureNativeParent(root int, name string) error {
	if err := unix.Mkdirat(root, name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return ErrStorage
	}
	f, st, err := openNativeDirectory(root, name)
	if err != nil {
		return err
	}
	defer f.Close()
	if st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) || st.Mode&0777 != 0700 {
		return ErrStorage
	}
	if f.Sync() != nil {
		return ErrStorage
	}
	return syncNativeParent(root, name)
}
func prepareNativeDirectory(root int, name string, original NativeDirectory, uid, gid int, mode uint32) (NativeDirectory, error) {
	if original == (NativeDirectory{}) {
		if err := unix.Mkdirat(root, name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return NativeDirectory{}, ErrStorage
		}
	}
	f, st, err := openNativeDirectory(root, name)
	if err != nil {
		return NativeDirectory{}, err
	}
	defer f.Close()
	if original != (NativeDirectory{}) {
		if nativeDirectory(st) != original || st.Uid != uint32(uid) || st.Gid != uint32(gid) || st.Mode&0777 != mode {
			return NativeDirectory{}, ErrStorage
		}
		return original, nil
	}
	// The original preparation intent exists, but no leaf identity has been
	// committed yet. Only an EMPTY daemon/builder-owned allocation can finish
	// that phase; existing data or a previously recorded inode is never reset.
	if st.Uid != uint32(os.Geteuid()) && st.Uid != uint32(uid) || st.Mode&0777 != 0700 && st.Mode&0777 != mode {
		return NativeDirectory{}, ErrStorage
	}
	if entries, err := f.ReadDir(1); len(entries) != 0 || !errors.Is(err, io.EOF) {
		return NativeDirectory{}, ErrStorage
	}
	if st.Uid != uint32(uid) || st.Gid != uint32(gid) {
		if unix.Fchown(int(f.Fd()), uid, gid) != nil {
			return NativeDirectory{}, ErrStorage
		}
	}
	if st.Mode&0777 != mode {
		if unix.Fchmod(int(f.Fd()), mode) != nil {
			return NativeDirectory{}, ErrStorage
		}
	}
	if f.Sync() != nil || syncNativeParent(root, name) != nil || unix.Fstat(int(f.Fd()), &st) != nil {
		return NativeDirectory{}, ErrStorage
	}
	if st.Uid != uint32(uid) || st.Gid != uint32(gid) || st.Mode&0777 != mode {
		return NativeDirectory{}, ErrStorage
	}
	return nativeDirectory(st), nil
}

// PrepareWorkspace consumes the actual RootManager-pinned FD, after Accept
// and before shared/native dispatch. Existing leaf/cache data uses only its
// original inode; unknown nonempty paths are neither adopted nor repaired.
func (n *NativeJobs) PrepareWorkspace(ctx context.Context, spec JobSpec, rootFD int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	g, err := n.current(ctx, &r, true)
	if err != nil {
		return err
	}
	if !g.Allowed || g.Run.Cancel || g.Run.Terminal() || r.Cancel || r.CreateSent || r.Workspace != nil && (r.Workspace.Removing || r.Workspace.Closed) {
		return ErrConflict
	}
	if r.Root == nil || r.Root.Lease.Token == 0 || r.Root.Returning || r.Root.Returned {
		return ErrStorage
	}
	root, st, err := openNativeRoot(spec.Scope.Root.Path)
	if err != nil {
		return ErrStorage
	}
	defer root.Close()
	var pinned unix.Stat_t
	if rootFD < 0 || unix.Fstat(rootFD, &pinned) != nil || nativeDirectory(pinned) != nativeDirectory(st) {
		return ErrStorage
	}
	spool, err := OpenExistingSpool(rootFD, spec.Scope.Root, n.db)
	if err != nil {
		return err
	}
	if err = spool.Close(); err != nil {
		return err
	}
	if r.Workspace == nil {
		r.Workspace = &NativeWorkspace{Root: nativeDirectory(st)}
		if err = n.save(r); err != nil {
			return err
		}
	} else if r.Workspace.Root != nativeDirectory(st) {
		return ErrStorage
	}
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return err
	}
	cache, err := n.cacheBorrow(spec, p, true)
	if err != nil {
		return err
	}
	for _, name := range []string{".mydc-imagebuild/jobs", ".mydc-imagebuild/build-cache"} {
		if err := ensureNativeParent(rootFD, name); err != nil {
			return err
		}
	}
	names := nativeWorkspaceNames(p)
	uid, gid := os.Geteuid(), os.Getegid()
	r.Workspace.Job, err = prepareNativeDirectory(rootFD, path.Dir(names[0]), r.Workspace.Job, uid, gid, 0700)
	if err != nil {
		return err
	}
	if err = n.save(r); err != nil {
		return err
	}
	r.Workspace.Input, err = prepareNativeDirectory(rootFD, names[0], r.Workspace.Input, uid, gid, 0755)
	if err != nil {
		return err
	}
	if err = n.save(r); err != nil {
		return err
	}
	r.Workspace.Output, err = prepareNativeDirectory(rootFD, names[1], r.Workspace.Output, nativeBuilderUID, nativeBuilderUID, 0700)
	if err != nil {
		return err
	}
	if err = n.save(r); err != nil {
		return err
	}
	if r.Workspace.Cache != (NativeDirectory{}) && cache.Directory != r.Workspace.Cache {
		return ErrStorage
	}
	cache.Directory, err = prepareNativeDirectory(rootFD, names[2], cache.Directory, nativeBuilderUID, nativeBuilderUID, 0700)
	if err != nil {
		return err
	}
	r.Workspace.Cache = cache.Directory
	r.Workspace.Ready = true
	if r.Validate() != nil {
		return ErrStorage
	}
	jobRaw, _ := json.Marshal(r)
	cacheRaw, _ := json.Marshal(cache)
	return n.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		if b == nil {
			return ErrStorage
		}
		var held nativeCacheBorrow
		if json.Unmarshal(b.Get(nativeCacheKey(p.Cache)), &held) != nil || held.Owner != p.Job || held.Root != cache.Root || held.Cache != cache.Cache {
			return ErrStorage
		}
		if err := b.Put(nativeCacheKey(p.Cache), cacheRaw); err != nil {
			return err
		}
		return b.Put(nativeKey(spec), jobRaw)
	})
}

type nativeWorkspaceFiles struct {
	root   *os.File
	leaves [3]*os.File
	paths  [3]string
}

func (f *nativeWorkspaceFiles) Close() error {
	var err error
	for _, leaf := range f.leaves {
		if leaf != nil {
			err = errors.Join(err, leaf.Close())
		}
	}
	if f.root != nil {
		err = errors.Join(err, f.root.Close())
	}
	return err
}
func (f *nativeWorkspaceFiles) Sources() []engine.BindSource {
	var out []engine.BindSource
	for i, leaf := range f.leaves {
		if leaf == nil {
			continue
		}
		out = append(out, engine.BindSource{Path: f.paths[i], DirectoryFD: int(leaf.Fd())})
	}
	return out
}
func (n *NativeJobs) openWorkspace(r NativeRecord) (*nativeWorkspaceFiles, error) {
	if r.Workspace == nil || !r.Workspace.Ready || r.Workspace.Removing || r.Workspace.Closed {
		return nil, ErrStorage
	}
	if r.Root != nil && (r.Root.Returning || r.Root.Returned) {
		return nil, ErrStorage
	}
	p, err := PlanNative(r.Spec, n.docker.Owner)
	if err != nil {
		return nil, err
	}
	cache, err := n.cacheBorrow(r.Spec, p, false)
	if err != nil || cache.Directory != r.Workspace.Cache {
		return nil, ErrStorage
	}
	f := &nativeWorkspaceFiles{paths: nativeWorkspacePaths(r.Spec, p)}
	var st unix.Stat_t
	f.root, st, err = openNativeRoot(r.Spec.Scope.Root.Path)
	if err != nil || nativeDirectory(st) != r.Workspace.Root {
		_ = f.Close()
		return nil, ErrStorage
	}
	names := nativeWorkspaceNames(p)
	job, st, err := openNativeDirectory(int(f.root.Fd()), filepath.ToSlash(filepath.Dir(names[0])))
	if err != nil || nativeDirectory(st) != r.Workspace.Job {
		if job != nil {
			_ = job.Close()
		}
		_ = f.Close()
		return nil, ErrStorage
	}
	_ = job.Close()
	for i, identity := range []NativeDirectory{r.Workspace.Input, r.Workspace.Output, r.Workspace.Cache} {
		f.leaves[i], st, err = openNativeDirectory(int(f.root.Fd()), names[i])
		if err != nil || nativeDirectory(st) != identity {
			_ = f.Close()
			return nil, ErrStorage
		}
	}
	return f, nil
}
