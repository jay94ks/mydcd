// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

// NativeOutput borrows the original directories/cache until Close joins the
// consumer. Registry output I/O must release it before workspace cleanup.
type NativeOutput struct {
	Directory *os.File
	owner     *NativeJobs
	job       [32]byte
	files     *nativeWorkspaceFiles
	once      sync.Once
	err       error
}

func (o *NativeOutput) Close() error {
	if o == nil {
		return nil
	}
	o.once.Do(func() {
		o.err = o.files.Close()
		if o.err == nil {
			o.owner.mu.Lock()
			defer o.owner.mu.Unlock()
			o.owner.readers[o.job]--
			if o.owner.readers[o.job] == 0 {
				delete(o.owner.readers, o.job)
			}
		}
	})
	return o.err
}

func (n *NativeJobs) OpenOutput(spec JobSpec) (*NativeOutput, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return nil, err
	}
	if !nativeOutputSucceeded(r) {
		return nil, ErrConflict
	}
	files, err := n.openWorkspace(r)
	if err != nil {
		return nil, err
	}
	h := spec.Digest()
	n.readers[h]++
	return &NativeOutput{Directory: files.leaves[1], owner: n, job: h, files: files}, nil
}

// inspectNativeJob checks identities BEFORE recording a removal intent. Only
// reentry after that durable intent can accept a missing recorded directory.
// Unknown allocation leaves are allowed only while empty and never dispatched.
func inspectNativeJob(root int, p NativePlan, w NativeWorkspace) (bool, error) {
	job, st, err := openNativeDirectory(root, path.Dir(nativeWorkspaceNames(p)[0]))
	if errors.Is(err, unix.ENOENT) {
		if !w.Removing && w.Job.valid() {
			return false, ErrStorage
		}
		return false, nil
	}
	if err != nil {
		return false, ErrStorage
	}
	defer job.Close()
	if w.Job.valid() {
		if nativeDirectory(st) != w.Job {
			return false, ErrStorage
		}
	} else if w.Ready || st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) || st.Mode&07777 != 0700 {
		return false, ErrStorage
	}
	entries, err := job.ReadDir(3)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if !w.Job.valid() && len(entries) != 0 {
		return false, ErrStorage
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		var identity NativeDirectory
		switch entry.Name() {
		case "input":
			identity = w.Input
		case "output":
			identity = w.Output
		default:
			return false, ErrStorage
		}
		seen[entry.Name()] = true
		leaf, actual, err := openNativeDirectory(int(job.Fd()), entry.Name())
		if err != nil {
			return false, ErrStorage
		}
		if identity.valid() {
			if nativeDirectory(actual) != identity {
				_ = leaf.Close()
				return false, ErrStorage
			}
		} else {
			items, readErr := leaf.ReadDir(1)
			if len(items) != 0 || !errors.Is(readErr, io.EOF) || actual.Uid != uint32(os.Geteuid()) && actual.Uid != nativeBuilderUID || actual.Mode&07777 != 0700 && actual.Mode&07777 != 0755 {
				_ = leaf.Close()
				return false, ErrStorage
			}
		}
		if err := leaf.Close(); err != nil {
			return false, err
		}
	}
	if !w.Removing && (w.Input.valid() && !seen["input"] || w.Output.valid() && !seen["output"]) {
		return false, ErrStorage
	}
	return true, nil
}

// FinishWorkspace follows positive original container removal (or an
// undispatched original) and reader join. It never deletes shared build cache.
// Removal intent precedes unlink; original IDs survive partial cleanup/reopen.
func (n *NativeJobs) FinishWorkspace(ctx context.Context, spec JobSpec) ([32]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return [32]byte{}, err
	}
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	if n.readers[spec.Digest()] != 0 || n.publishing[spec.Digest()] {
		return [32]byte{}, ErrUsed
	}
	if r.Publication != nil {
		if _, closed := r.Publication.result(spec); !closed {
			return [32]byte{}, ErrUsed
		}
	}
	if r.CreateSent && !r.CreateNotSent && !r.Removed || !r.CreateSent && !r.Cancel {
		return [32]byte{}, ErrUsed
	}
	if r.Workspace == nil {
		return [32]byte{}, ErrStorage
	}
	if r.Workspace.Closed {
		return workspaceClosure(r), nil
	}
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return [32]byte{}, err
	}
	var cache nativeCacheBorrow
	err = n.db.View(func(tx *bolt.Tx) error { var err error; cache, err = readNativeCache(tx, spec, p); return err })
	if err != nil {
		return [32]byte{}, err
	}
	// A failed preparation may have stopped before borrowing the cache. It can
	// close its own empty workspace without touching another job's cache lease.
	if (r.Workspace.Ready || r.Workspace.Cache.valid()) && (cache.Owner != p.Job || cache.Directory != r.Workspace.Cache) {
		return [32]byte{}, ErrStorage
	}
	root, st, err := openNativeRoot(spec.Scope.Root.Path)
	if err != nil {
		return [32]byte{}, ErrStorage
	}
	defer root.Close()
	if nativeDirectory(st) != r.Workspace.Root {
		return [32]byte{}, ErrStorage
	}
	if cache.Owner == p.Job && cache.Directory.valid() {
		leaf, actual, err := openNativeDirectory(int(root.Fd()), nativeWorkspaceNames(p)[2])
		if err != nil {
			return [32]byte{}, ErrStorage
		}
		closeErr := leaf.Close()
		if nativeDirectory(actual) != cache.Directory || closeErr != nil {
			return [32]byte{}, ErrStorage
		}
	}
	exists, err := inspectNativeJob(int(root.Fd()), p, *r.Workspace)
	if err != nil {
		return [32]byte{}, err
	}
	if !r.Workspace.Removing {
		r.Workspace.Removing = true
		if err := n.save(r); err != nil {
			return [32]byte{}, err
		}
	}
	name := path.Dir(nativeWorkspaceNames(p)[0])
	if exists {
		// OpenRoot follows only this product-owned held FD. RemoveAll uses
		// Go's confined root, not a tenant-supplied absolute cleanup path.
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
		// No allocation and no recorded job identity means there was no entry
		// to unlink. In all other cases the original parent must be fsynced.
		if r.Workspace.Job.valid() || exists || !errors.Is(err, unix.ENOENT) {
			return [32]byte{}, err
		}
		if err := root.Sync(); err != nil {
			return [32]byte{}, err
		}
	}
	r.Workspace.Closed = true
	if r.Validate() != nil {
		return [32]byte{}, ErrStorage
	}
	jobRaw, _ := json.Marshal(r)
	err = n.db.Update(func(tx *bolt.Tx) error {
		before, err := readNativeCache(tx, spec, p)
		if err != nil {
			return err
		}
		if !sameNativeCache(before, cache) {
			return ErrConflict
		}
		b := tx.Bucket(nativeBucket)
		if before.Owner == p.Job {
			before.Owner = [32]byte{}
			cacheRaw, _ := json.Marshal(before)
			if err := b.Put(nativeCacheKey(p.Cache), cacheRaw); err != nil {
				return err
			}
		}
		return b.Put(nativeKey(spec), jobRaw)
	})
	if err != nil {
		return [32]byte{}, err
	}
	return workspaceClosure(r), nil
}

func workspaceClosure(r NativeRecord) [32]byte {
	return digestJSON("sfc-imagebuild-native-workspace-1", struct {
		Job                                [32]byte
		Workspace                          *NativeWorkspace
		NativeID                           string
		CreateSent, CreateNotSent, Removed bool
		Publication                        *NativePublication `json:",omitempty"`
		Solve                              *NativeSolve       `json:",omitempty"`
	}{r.Spec.Digest(), r.Workspace, r.NativeID, r.CreateSent, r.CreateNotSent, r.Removed, r.Publication, r.Solve})
}
