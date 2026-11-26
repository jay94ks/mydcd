// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	bolt "go.etcd.io/bbolt"
)

// TenantActivity observes the same native journals and live I/O as execution.
// Retained data alone is not an active effect, but its outstanding root lease
// is. A terminal shared job cannot substitute for local cleanup/lease return.
func (n *NativeJobs) TenantActivity(tenant string) (lifecycle.Activity, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.tenantActivity(tenant, n.docker.Owner, false, 0)
}

// StoredTenantActivity is the read-only fallback when the build module is
// disabled. Disabling an adapter does not erase its stored native obligations.
// It creates no bucket, client, executor or replacement source records.
func StoredTenantActivity(db Transactions, owner, tenant string) (lifecycle.Activity, error) {
	n := NativeJobs{db: db}
	return n.tenantActivity(tenant, owner, true, 0)
}

func (n *NativeJobs) tenantActivity(tenant, owner string, allowMissing bool, applied uint64) (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	if !lifecycle.ValidID(tenant) || owner == "" || n.db == nil {
		return activity, ErrInvalid
	}
	err := n.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(nativeBucket)
		if bucket == nil && allowMissing {
			return nil
		}
		if bucket == nil || string(bucket.Get([]byte("owner"))) != owner {
			return ErrStorage
		}
		known := map[[32]byte]bool{}
		caches := map[[32]byte]JobSpec{}
		cacheDirectories := map[[32]byte]NativeDirectory{}
		cacheRoots := map[[32]byte]NativeDirectory{}
		add := func(next lifecycle.Activity) error {
			var err error
			activity, err = activity.Add(next)
			return err
		}
		io := func(key [32]byte) lifecycle.Activity {
			var next lifecycle.Activity
			if n.readers[key] != 0 {
				next.Flows++
			}
			if n.solving[key] || n.publishing[key] || n.logging[key] || n.logWriters[key] {
				next.Writers++
			}
			return next
		}
		if err := bucket.ForEach(func(key, raw []byte) error {
			if strings.HasPrefix(string(key), "cache-prune/") {
				var row NativeCachePruneRecord
				if len(raw) > 128<<10 || json.Unmarshal(raw, &row) != nil || string(key) != string(nativeCachePruneKey(row.Spec.Intent)) {
					return ErrStorage
				}
				row, err := readNativeCachePrune(tx, row.Spec, owner)
				if err != nil {
					return err
				}
				known[row.Spec.Intent] = true
				caches[CacheIdentity(row.Spec.Source)] = row.Spec.Source
				if row.Spec.Source.Tenant != tenant {
					return nil
				}
				if applied != 0 && row.Index > applied {
					return ErrConflict
				}
				next := io(row.Spec.Intent)
				if !row.Closed || row.Completion == nil {
					next.Resources++
				}
				return add(next)
			}
			if len(key) != 64 {
				return nil
			}
			if _, err := hex.DecodeString(string(key)); err != nil {
				return nil
			}
			var row NativeRecord
			if len(raw) > 128<<10 || json.Unmarshal(raw, &row) != nil || string(key) != string(nativeKey(row.Spec)) {
				return ErrStorage
			}
			row, err := readNativeRecord(tx, row.Spec, owner)
			if err != nil {
				return err
			}
			job := row.Spec.Digest()
			known[job] = true
			cache := CacheIdentity(row.Spec)
			caches[cache] = row.Spec
			if row.Workspace != nil {
				if original, found := cacheRoots[cache]; found && original != row.Workspace.Root {
					return ErrStorage
				}
				cacheRoots[cache] = row.Workspace.Root
				if row.Workspace.Cache.valid() {
					if original, found := cacheDirectories[cache]; found && original != row.Workspace.Cache {
						return ErrStorage
					}
					cacheDirectories[cache] = row.Workspace.Cache
				}
			}
			if row.Spec.Tenant != tenant {
				return nil
			}
			if applied != 0 && row.Index > applied {
				return ErrConflict
			}
			next := io(job)
			if !nativeEffectsClosed(row) || row.Completion == nil {
				next.Resources++
			}
			if row.Root != nil && !row.Root.Returned {
				next.Leases++
			}
			return add(next)
		}); err != nil {
			return err
		}
		// A cache root consumer is shared across jobs, so count it once and
		// require an original source instead of guessing a tenant from a hash.
		if err := bucket.ForEach(func(key, raw []byte) error {
			if !strings.HasPrefix(string(key), "cache/") {
				return nil
			}
			var cache nativeCacheBorrow
			if len(raw) > 16<<10 || json.Unmarshal(raw, &cache) != nil || string(key) != string(nativeCacheKey(cache.Cache)) {
				return ErrStorage
			}
			spec, found := caches[cache.Cache]
			if !found {
				return ErrStorage
			}
			plan, err := PlanNative(spec, owner)
			if err != nil {
				return err
			}
			cache, err = readNativeCache(tx, spec, plan)
			if err != nil {
				return err
			}
			if (cache.Directory.valid() || cache.Owner != ([32]byte{})) && (cache.RootHold == nil || cache.RootHold.Lease.Token == 0 || cache.RootHold.Returned) {
				return ErrStorage
			}
			if cache.Owner != ([32]byte{}) && !known[cache.Owner] {
				return ErrStorage
			}
			if cache.Retirement != nil && !known[cache.Retirement.Source] {
				return ErrStorage
			}
			observedDirectory := cache.Directory
			if cache.Retirement != nil {
				observedDirectory = cache.Retirement.Directory
				if root, found := cacheRoots[cache.Cache]; found && cache.Retirement.Root != root {
					return ErrStorage
				}
			}
			if original, found := cacheDirectories[cache.Cache]; found && observedDirectory != original {
				return ErrStorage
			}
			if spec.Tenant != tenant {
				return nil
			}
			var next lifecycle.Activity
			if cache.Owner != ([32]byte{}) {
				next.Resources++
			}
			if cache.RootHold != nil && !cache.RootHold.Returned {
				next.Leases++
			}
			return add(next)
		}); err != nil {
			return err
		}
		for key, count := range n.readers {
			if count < 0 || count != 0 && !known[key] {
				return ErrStorage
			}
		}
		for _, active := range []map[[32]byte]bool{n.solving, n.publishing, n.logging, n.logWriters} {
			for key, running := range active {
				if running && !known[key] {
					return ErrStorage
				}
			}
		}
		return nil
	})
	return activity, err
}
