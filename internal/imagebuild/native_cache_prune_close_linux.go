// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

func inspectCachePruneWorkspace(root int, r NativeCachePruneRecord) (bool, error) {
	names := cachePruneWorkspaceNames(r.Spec)
	job, st, err := openNativeDirectory(root, names[0])
	if errors.Is(err, unix.ENOENT) {
		if !r.Removing && r.Daemon != nil && r.Daemon.Job.valid() {
			return false, ErrStorage
		}
		return false, nil
	}
	if err != nil {
		return false, ErrStorage
	}
	defer job.Close()
	if r.Daemon == nil {
		return false, ErrStorage
	}
	if r.Daemon.Job.valid() {
		if nativeDirectory(st) != r.Daemon.Job {
			return false, ErrStorage
		}
	} else if st.Uid != uint32(os.Geteuid()) && st.Uid != nativeBuilderUID || st.Mode&07777 != 0700 {
		return false, ErrStorage
	}
	entries, err := job.ReadDir(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, ErrStorage
	}
	if !r.Daemon.Job.valid() && len(entries) != 0 {
		return false, ErrStorage
	}
	seen := false
	for _, entry := range entries {
		if entry.Name() != "output" {
			return false, ErrStorage
		}
		output, st, err := openNativeDirectory(int(job.Fd()), "output")
		if err != nil {
			return false, ErrStorage
		}
		seen = true
		if r.Daemon.Output.valid() {
			if nativeDirectory(st) != r.Daemon.Output {
				_ = output.Close()
				return false, ErrStorage
			}
		} else {
			children, readErr := output.ReadDir(1)
			if len(children) != 0 || !errors.Is(readErr, io.EOF) || st.Uid != uint32(os.Geteuid()) && st.Uid != nativeBuilderUID || st.Mode&07777 != 0700 {
				_ = output.Close()
				return false, ErrStorage
			}
		}
		if err := output.Close(); err != nil {
			return false, err
		}
	}
	if !r.Removing && r.Daemon.Output.valid() && !seen {
		return false, ErrStorage
	}
	return true, nil
}

// Closes only this original maintenance directory. The shared cache contents
// and root lease are retained. Cache owner return and Closed commit atomically
// after actual native removal, reader join, unlink and parent fsync.
func (n *NativeJobs) FinishCachePrune(ctx context.Context, s NativeCachePruneSpec) ([32]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.loadCachePrune(s)
	if err != nil {
		return [32]byte{}, err
	}
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	if n.readers[s.Intent] != 0 || n.solving[s.Intent] || r.Outcome == nil || !cachePruneNativeStopped(r) {
		return [32]byte{}, ErrUsed
	}
	if r.Closed {
		return cachePruneNativeWitness(r), nil
	}
	if !r.Claimed {
		// No cache claim means no native workspace/container could be prepared.
		if r.Daemon != nil || r.RPC != nil {
			return [32]byte{}, ErrStorage
		}
		r.Removing, r.Closed = true, true
		if err := n.saveCachePrune(r); err != nil {
			return [32]byte{}, err
		}
		return cachePruneNativeWitness(r), nil
	}
	source, err := PlanNative(s.Source, n.docker.Owner)
	if err != nil {
		return [32]byte{}, err
	}
	var cache nativeCacheBorrow
	err = n.db.View(func(tx *bolt.Tx) error { var err error; cache, err = readNativeCache(tx, s.Source, source); return err })
	if err != nil || cache.Owner != s.Intent || cache.Directory != r.Cache || cache.RootHold == nil || cache.RootHold.Lease.Token == 0 || cache.RootHold.Returning || cache.RootHold.Returned {
		return [32]byte{}, ErrStorage
	}
	root, st, err := openNativeRoot(s.Source.Scope.Root.Path)
	if err != nil {
		return [32]byte{}, ErrStorage
	}
	defer root.Close()
	if nativeDirectory(st) != r.Root {
		return [32]byte{}, ErrStorage
	}
	retained, cacheStat, err := openNativeDirectory(int(root.Fd()), nativeWorkspaceNames(source)[2])
	if err != nil {
		return [32]byte{}, ErrStorage
	}
	closeErr := retained.Close()
	if closeErr != nil || nativeDirectory(cacheStat) != r.Cache {
		return [32]byte{}, ErrStorage
	}
	exists, err := inspectCachePruneWorkspace(int(root.Fd()), r)
	if err != nil {
		return [32]byte{}, err
	}
	if !r.Removing {
		r.Removing = true
		if err := n.saveCachePrune(r); err != nil {
			return [32]byte{}, err
		}
	}
	name := cachePruneWorkspaceNames(s)[0]
	if exists {
		confined, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", root.Fd()))
		if err != nil {
			return [32]byte{}, err
		}
		err = confined.RemoveAll(name)
		closeErr := confined.Close()
		if err != nil || closeErr != nil {
			return [32]byte{}, errors.Join(err, closeErr)
		}
	}
	if err := syncNativeParent(int(root.Fd()), name); err != nil {
		if r.Daemon != nil && r.Daemon.Job.valid() || exists || !errors.Is(err, unix.ENOENT) {
			return [32]byte{}, err
		}
		if err := root.Sync(); err != nil {
			return [32]byte{}, err
		}
	}
	r.Closed = true
	err = n.db.Update(func(tx *bolt.Tx) error {
		before, err := readNativeCache(tx, s.Source, source)
		if err != nil {
			return err
		}
		if !sameNativeCache(before, cache) {
			return ErrConflict
		}
		before.Owner = [32]byte{}
		raw, err := json.Marshal(before)
		if err != nil {
			return err
		}
		if err := tx.Bucket(nativeBucket).Put(nativeCacheKey(source.Cache), raw); err != nil {
			return err
		}
		return writeNativeCachePrune(tx, r)
	})
	if err != nil {
		return [32]byte{}, err
	}
	return cachePruneNativeWitness(r), nil
}
