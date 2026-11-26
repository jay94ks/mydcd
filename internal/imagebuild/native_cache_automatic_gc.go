// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/json"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// CollectClosedAutomaticCachePrunes bounds recurring native metadata. Keep
// the shared current intents, any future/local-ahead evidence, all unfinished
// work, and the original producer of the last successful cache observation.
// This never removes manual receipts, cache bytes, root leases or workspaces.
func (n *NativeJobs) CollectClosedAutomaticCachePrunes(applied uint64, keep map[[32]byte]bool) ([][32]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if applied == 0 {
		return nil, ErrInvalid
	}
	var removed [][32]byte
	err := n.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(nativeBucket)
		if bucket == nil || string(bucket.Get([]byte("owner"))) != n.docker.Owner {
			return ErrStorage
		}
		var keys [][]byte
		if err := bucket.ForEach(func(key, raw []byte) error {
			if !strings.HasPrefix(string(key), "cache-prune/") {
				return nil
			}
			var row NativeCachePruneRecord
			if len(raw) > 128<<10 || json.Unmarshal(raw, &row) != nil || string(key) != string(nativeCachePruneKey(row.Spec.Intent)) {
				return ErrStorage
			}
			if row.Spec.Automatic == nil || keep[row.Spec.Intent] || row.Index > applied || !row.Closed || row.Completion == nil || n.solving[row.Spec.Intent] || n.readers[row.Spec.Intent] != 0 {
				return nil
			}
			if _, err := readNativeCachePrune(tx, row.Spec, n.docker.Owner); err != nil {
				return err
			}
			plan, err := PlanNative(row.Spec.Source, n.docker.Owner)
			if err != nil {
				return err
			}
			cache, err := readNativeCache(tx, row.Spec.Source, plan)
			if err != nil {
				return err
			}
			observed, err := readCacheObservation(tx, plan.Cache)
			if err != nil {
				return err
			}
			if err := n.validateCacheObservation(tx, cache, observed); err != nil {
				return err
			}
			if cache.Owner == row.Spec.Intent || observed.Usage != nil && observed.Usage.Maintenance != nil && *observed.Usage.Maintenance == row.Spec.Intent {
				return nil
			}
			keys = append(keys, append([]byte(nil), key...))
			removed = append(removed, row.Spec.Intent)
			return nil
		}); err != nil {
			return err
		}
		for _, key := range keys {
			if err := bucket.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}
