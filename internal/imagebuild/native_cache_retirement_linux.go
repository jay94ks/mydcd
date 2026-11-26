// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jay94ks/mydcd/internal/reconcile"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

func (n *NativeJobs) saveCacheRetirement(spec JobSpec, plan NativePlan, before, next nativeCacheBorrow, clearObservation bool) error {
	if next.Retirement == nil || !next.Retirement.valid(next) {
		return ErrStorage
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > 16<<10 {
		return ErrStorage
	}
	return n.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(nativeBucket)
		if bucket == nil || string(bucket.Get([]byte("owner"))) != n.docker.Owner {
			return ErrStorage
		}
		current, err := readNativeCache(tx, spec, plan)
		if err != nil {
			return err
		}
		if !sameNativeCache(current, before) {
			return ErrConflict
		}
		if err := bucket.Put(nativeCacheKey(plan.Cache), raw); err != nil {
			return err
		}
		if clearObservation {
			return bucket.Delete(cacheUsageKey(plan.Cache))
		}
		return nil
	})
}

// RetireTenantCache deletes only an original disposable cache under a committed
// irreversible tenant retirement. The caller supplies the existing RootManager
// pin, never a new borrow. Returning the pin is a separate durable final step.
func (n *NativeJobs) RetireTenantCache(ctx context.Context, g NativeCacheRetirementGrant, lease reconcile.Lease, rootFD int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.validCacheRetirementGrant(g) {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	activity, err := n.tenantActivity(g.Source.Tenant, n.docker.Owner, false, g.Index)
	if err != nil {
		return err
	}
	if activity.Resources != 0 || activity.Flows != 0 || activity.Writers != 0 || activity.CDJobs != 0 {
		return ErrUsed
	}
	source, err := n.load(g.Source)
	if err != nil {
		return err
	}
	if source.Completion == nil {
		return ErrUsed
	}
	plan, err := PlanNative(g.Source, n.docker.Owner)
	if err != nil {
		return err
	}
	var cache nativeCacheBorrow
	if err := n.db.View(func(tx *bolt.Tx) error {
		var err error
		cache, err = readNativeCache(tx, g.Source, plan)
		return err
	}); err != nil {
		return err
	}
	if cache.Owner != ([32]byte{}) || cache.RootHold == nil {
		return ErrUsed
	}
	if cache.Retirement != nil {
		if !cache.Retirement.matches(g) {
			return ErrConflict
		}
		if cache.RootHold.Lease != lease {
			return ErrStorage
		}
		if cache.Retirement.Unlinked {
			return nil // original unlink/return intent, never recreate or reopen
		}
	}
	if cache.RootHold.Returning || cache.RootHold.Returned || cache.RootHold.Lease.Token != 0 && cache.RootHold.Lease != lease || lease.Token != 0 && lease.Generation != g.Source.Scope.Root.Generation || lease.Token == 0 && lease.Generation != 0 {
		return ErrStorage
	}
	if lease.Token == 0 {
		// A durable borrow intent that never obtained a lease cannot have
		// materialized a cache. Preserve it as a no-effect return intent.
		if cache.Directory.valid() || cache.Retirement != nil || source.Workspace != nil {
			return ErrStorage
		}
		next := cache
		next.RootHold = &NativeRootHold{Returning: true}
		next.Retirement = &NativeCacheRetirement{Schema: 1, Tenant: g.Source.Tenant, Operation: g.Operation, Source: g.Source.Digest(), InventoryHash: g.InventoryHash, OwnersHash: g.OwnersHash, StartedRevision: g.StartedRevision, Index: g.Index, Epoch: g.Epoch, Unlinked: true}
		return n.saveCacheRetirement(g.Source, plan, cache, next, true)
	}
	var pinned unix.Stat_t
	if rootFD < 0 || unix.Fstat(rootFD, &pinned) != nil || pinned.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrStorage
	}
	root, st, err := openNativeRoot(g.Source.Scope.Root.Path)
	if err != nil {
		return ErrStorage
	}
	defer root.Close()
	identity := nativeDirectory(st)
	if identity != nativeDirectory(pinned) || source.Workspace != nil && source.Workspace.Root != identity || cache.Retirement != nil && cache.Retirement.Root != identity {
		return ErrStorage
	}
	name := nativeWorkspaceNames(plan)[2]
	leaf, leafStat, openErr := openNativeDirectory(rootFD, name)
	exists := openErr == nil
	if openErr != nil && !errors.Is(openErr, unix.ENOENT) {
		return ErrStorage
	}
	directory := cache.Directory
	if exists {
		actual := nativeDirectory(leafStat)
		if cache.Retirement != nil {
			directory = cache.Retirement.Directory
		}
		if directory.valid() {
			if actual != directory {
				_ = leaf.Close()
				return ErrStorage
			}
		} else {
			// Recover only the empty leaf allocated before its original Ready
			// commit. Unknown data is never adopted as disposable cache.
			children, err := leaf.ReadDir(1)
			if len(children) != 0 || !errors.Is(err, io.EOF) || leafStat.Uid != nativeBuilderUID || leafStat.Gid != nativeBuilderUID || leafStat.Mode&07777 != 0700 {
				_ = leaf.Close()
				return ErrStorage
			}
			directory = actual
		}
		if err := leaf.Close(); err != nil {
			return err
		}
	} else if cache.Retirement == nil && directory.valid() {
		return ErrStorage // absence before our durable delete intent is unknown
	}
	if cache.Retirement == nil {
		next := cache
		hold := *cache.RootHold
		hold.Lease = lease // recover only the original RecordedPin acknowledgement
		next.RootHold = &hold
		next.Retirement = &NativeCacheRetirement{Schema: 1, Tenant: g.Source.Tenant, Operation: g.Operation, Source: g.Source.Digest(), InventoryHash: g.InventoryHash, OwnersHash: g.OwnersHash, StartedRevision: g.StartedRevision, Index: g.Index, Epoch: g.Epoch, Root: identity, Directory: directory}
		if err := n.saveCacheRetirement(g.Source, plan, cache, next, false); err != nil {
			return err
		}
		cache = next
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if exists {
		confined, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", rootFD))
		if err != nil {
			return err
		}
		err = confined.RemoveAll(name)
		closeErr := confined.Close()
		if err != nil || closeErr != nil {
			return errors.Join(err, closeErr)
		}
	}
	if err := syncNativeParent(rootFD, name); err != nil {
		if directory.valid() || !errors.Is(err, unix.ENOENT) {
			return err
		}
		if err := root.Sync(); err != nil {
			return err
		}
	}
	next := cache
	hold, retirement := *cache.RootHold, *cache.Retirement
	hold.Returning, retirement.Unlinked = true, true
	next.Directory, next.RootHold, next.Retirement = NativeDirectory{}, &hold, &retirement
	return n.saveCacheRetirement(g.Source, plan, cache, next, true)
}

// FinishCacheRetirement records the original RootManager Return acknowledgement.
// A missing/failed Return does not release the cache's native reference.
func (n *NativeJobs) FinishCacheRetirement(g NativeCacheRetirementGrant) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.validCacheRetirementGrant(g) {
		return ErrInvalid
	}
	plan, err := PlanNative(g.Source, n.docker.Owner)
	if err != nil {
		return err
	}
	var cache nativeCacheBorrow
	if err := n.db.View(func(tx *bolt.Tx) error {
		var err error
		cache, err = readNativeCache(tx, g.Source, plan)
		return err
	}); err != nil {
		return err
	}
	if cache.Retirement == nil || !cache.Retirement.matches(g) || !cache.Retirement.Unlinked || cache.RootHold == nil || !cache.RootHold.Returning {
		return ErrConflict
	}
	if cache.RootHold.Returned {
		return nil
	}
	next := cache
	hold := *cache.RootHold
	hold.Returned = true
	next.RootHold = &hold
	return n.saveCacheRetirement(g.Source, plan, cache, next, false)
}
