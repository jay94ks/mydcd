// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	bkclient "github.com/moby/buildkit/client"
	bolt "go.etcd.io/bbolt"
)

type nativeCacheObservation struct {
	Schema      uint8
	Cache       [32]byte
	AttemptAt   uint64
	Code        string
	Usage       *CacheUsage `json:",omitempty"`
	LastCleanup *[32]byte   `json:",omitempty"`
}

func cacheUsageKey(cache [32]byte) []byte {
	return []byte("cache-usage/" + hex.EncodeToString(cache[:]))
}

func readCacheObservation(tx *bolt.Tx, cache [32]byte) (nativeCacheObservation, error) {
	o := nativeCacheObservation{Schema: 1, Cache: cache}
	b := tx.Bucket(nativeBucket)
	if b == nil {
		return o, ErrStorage
	}
	raw := b.Get(cacheUsageKey(cache))
	if raw == nil {
		return o, nil
	}
	if len(raw) > maxCacheUsageBytes || json.Unmarshal(raw, &o) != nil || o.Schema != 1 || o.Cache != cache || o.AttemptAt == 0 || o.Code != "OK" && o.Code != "UNAVAILABLE" || o.Code == "OK" && (o.Usage == nil || o.Usage.At != o.AttemptAt) || o.Usage != nil && !o.Usage.valid(cache) || o.LastCleanup != nil && *o.LastCleanup == ([32]byte{}) {
		return nativeCacheObservation{}, ErrStorage
	}
	if o.LastCleanup != nil {
		if _, found, err := readNativeCacheCleanup(tx, cache, *o.LastCleanup); err != nil || !found {
			return nativeCacheObservation{}, ErrStorage
		}
	}
	return o, nil
}

// The original finite daemon owns this RPC. Its caller still holds the SDK
// session and cache reader until this read and the synchronous DB write join.
// Cache observation failure does not replace the independent Solve result.
func (n *NativeJobs) sampleCacheUsage(ctx context.Context, spec JobSpec, sdk *bkclient.Client) (*CacheUsage, error) {
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := sdk.DiskUsage(probe)
	var usage *CacheUsage
	at := uint64(time.Now().Unix())
	if err == nil {
		value, e := NewCacheUsage(spec, at, rows)
		if e == nil {
			usage = &value
		}
	}
	return usage, n.saveCacheObservation(spec, at, usage)
}

func (n *NativeJobs) saveCacheObservation(spec JobSpec, at uint64, usage *CacheUsage) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil || at == 0 || r.Solve == nil || !r.Solve.Sent || !n.solving[p.Job] || r.Workspace == nil || r.Workspace.Closed || usage != nil && (!usage.valid(p.Cache) || usage.Job != p.Job || usage.At != at || usage.Maintenance != nil) {
		return ErrConflict
	}
	return n.db.Update(func(tx *bolt.Tx) error {
		cache, err := readNativeCache(tx, spec, p)
		if err != nil || cache.Owner != p.Job || cache.Directory != r.Workspace.Cache {
			return ErrStorage
		}
		o, err := readCacheObservation(tx, p.Cache)
		if err != nil {
			return err
		}
		o.AttemptAt = at
		o.Code = "UNAVAILABLE"
		if usage != nil {
			o.Code, o.Usage = "OK", usage
		}
		raw, err := json.Marshal(o)
		if err != nil || len(raw) > maxCacheUsageBytes {
			return ErrStorage
		}
		return tx.Bucket(nativeBucket).Put(cacheUsageKey(p.Cache), raw)
	})
}

// ReadCacheUsage never starts a daemon or a new job, recreates a missing native
// journal, or walks a tenant-controlled filesystem. Authorization and the
// current shared job/root identity are checked by the Runtime on both sides.
func (n *NativeJobs) ReadCacheUsage(spec JobSpec, offset uint32, snapshot [32]byte) (CachePage, error) {
	return n.readCacheUsage(spec, offset, snapshot, true)
}

// ReadCacheScope uses an authorized shared namespace representative, which
// may not yet have its own native record. The actual observation's original
// native job is still required and checked below.
func (n *NativeJobs) ReadCacheScope(spec JobSpec, offset uint32, snapshot [32]byte) (CachePage, error) {
	return n.readCacheUsage(spec, offset, snapshot, false)
}

func (n *NativeJobs) readCacheUsage(spec JobSpec, offset uint32, snapshot [32]byte, requireJob bool) (CachePage, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return CachePage{}, err
	}
	if requireJob {
		if _, err := n.load(spec); err != nil {
			if errors.Is(err, ErrNativeMissing) {
				err = n.db.View(func(tx *bolt.Tx) error {
					c, err := readNativeCache(tx, spec, p)
					if err != nil {
						return err
					}
					o, err := readCacheObservation(tx, p.Cache)
					if err != nil {
						return err
					}
					if o.Usage != nil || c.Owner == p.Job {
						return ErrStorage
					}
					return ErrNativeMissing
				})
			}
			return CachePage{}, err
		}
	}
	var out CachePage
	err = n.db.View(func(tx *bolt.Tx) error {
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
		out = CachePage{Schema: 1, Cache: p.Cache, Borrowed: c.Owner != ([32]byte{})}
		if o.Usage != nil {
			out, err = o.Usage.Page(offset, snapshot, out.Borrowed)
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
		if !out.Valid(p.Cache, offset, snapshot) {
			return ErrConflict
		}
		return nil
	})
	return out, err
}
