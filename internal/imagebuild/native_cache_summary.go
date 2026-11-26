// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/hex"
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

// A newly queued representative may have no native job of its own. Cache
// inventory reads the existing shared cache scope and validates the actual
// observation's original job, rather than fabricating an empty namespace.
func (n *NativeJobs) ReadCacheSummary(spec JobSpec) (CacheSummary, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return CacheSummary{}, err
	}
	out := CacheSummary{Schema: 1, Cache: p.Cache}
	err = n.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		if b == nil || string(b.Get([]byte("owner"))) != n.docker.Owner {
			return ErrStorage
		}
		c, err := readNativeCache(tx, spec, p)
		if err != nil {
			return err
		}
		o, err := readCacheObservation(tx, p.Cache)
		if err != nil {
			return err
		}
		if err := n.validateCacheObservation(tx, c, o); err != nil {
			return err
		}
		out.Recorded = b.Get(nativeCacheKey(p.Cache)) != nil
		out.Allocated = c.Directory.valid()
		out.Borrowed = c.Owner != ([32]byte{})
		if o.Usage != nil {
			out, err = o.Usage.Summary(out.Recorded, out.Allocated, out.Borrowed)
			if err != nil {
				return err
			}
		}
		out.LastAttemptAt, out.LastAttemptCode = o.AttemptAt, o.Code
		if o.LastCleanup != nil {
			status, found, err := readNativeCacheCleanup(tx, p.Cache, *o.LastCleanup)
			if err != nil || !found {
				return ErrStorage
			}
			out.Cleanup = &status
		}
		if !out.Valid(p.Cache) {
			return ErrStorage
		}
		return nil
	})
	return out, err
}

// Both item and summary reads use the same original observation witness.
// Missing/corrupt evidence is an error, never a new unobserved namespace.
func (n *NativeJobs) validateCacheObservation(tx *bolt.Tx, c nativeCacheBorrow, o nativeCacheObservation) error {
	b := tx.Bucket(nativeBucket)
	if b == nil || string(b.Get([]byte("owner"))) != n.docker.Owner || o.AttemptAt != 0 && b.Get(nativeCacheKey(c.Cache)) == nil {
		return ErrStorage
	}
	if o.Usage == nil {
		return nil
	}
	if !c.Directory.valid() {
		return ErrStorage
	}
	if o.Usage.Maintenance != nil {
		raw := b.Get(nativeCachePruneKey(*o.Usage.Maintenance))
		var record NativeCachePruneRecord
		if raw == nil || len(raw) > 128<<10 || json.Unmarshal(raw, &record) != nil {
			return ErrStorage
		}
		r, err := readNativeCachePrune(tx, record.Spec, n.docker.Owner)
		if err != nil || r.Spec.Intent != *o.Usage.Maintenance || r.Spec.Source.Digest() != o.Usage.Job || CacheIdentity(r.Spec.Source) != c.Cache || r.Cache != c.Directory || r.Observation == nil || r.Observation.Snapshot == nil || *r.Observation.Snapshot != o.Usage.Digest() || r.Observation.ObservedAt != o.Usage.At {
			return ErrStorage
		}
		return nil
	}
	raw := b.Get([]byte(hex.EncodeToString(o.Usage.Job[:])))
	var record NativeRecord
	if raw == nil || len(raw) > 128<<10 || json.Unmarshal(raw, &record) != nil || record.Spec.Digest() != o.Usage.Job || CacheIdentity(record.Spec) != c.Cache || record.Solve == nil || !record.Solve.Sent {
		return ErrStorage
	}
	if _, err := readNativeRecord(tx, record.Spec, n.docker.Owner); err != nil {
		return ErrStorage
	}
	return nil
}
