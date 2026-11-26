// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	bkclient "github.com/moby/buildkit/client"
	bolt "go.etcd.io/bbolt"
)

func nativeCacheCleanupKey(job [32]byte) []byte {
	return []byte("cache-cleanup/" + hex.EncodeToString(job[:]))
}
func readNativeCacheCleanup(tx *bolt.Tx, cache, job [32]byte) (CacheCleanupStatus, bool, error) {
	out := CacheCleanupStatus{Schema: 1, Cache: cache, Job: job}
	b := tx.Bucket(nativeBucket)
	if b == nil {
		return out, false, ErrStorage
	}
	raw := b.Get(nativeCacheCleanupKey(job))
	if raw == nil {
		return out, false, nil
	}
	if len(raw) > 16<<10 || json.Unmarshal(raw, &out) != nil || !out.Valid(cache) || out.Job != job {
		return CacheCleanupStatus{}, false, ErrStorage
	}
	return out, true, nil
}

// Caller holds n.mu and the original finite solve/cache reader. These are
// native receipts in the existing node DB, not new tasks or a second executor.
func (n *NativeJobs) editCacheCleanup(spec JobSpec, snapshot [32]byte, edit func(*CacheCleanupStatus) error) error {
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil || r.Solve == nil || !r.Solve.Sent || !n.solving[p.Job] || r.Workspace == nil || r.Workspace.Closed {
		return ErrConflict
	}
	return n.db.Update(func(tx *bolt.Tx) error {
		cache, err := readNativeCache(tx, spec, p)
		if err != nil || cache.Owner != p.Job || cache.Directory != r.Workspace.Cache {
			return ErrStorage
		}
		status, _, err := readNativeCacheCleanup(tx, p.Cache, p.Job)
		if err != nil {
			return err
		}
		if err := edit(&status); err != nil {
			return err
		}
		if !status.Valid(p.Cache) || status.Job != p.Job {
			return ErrStorage
		}
		for _, step := range status.Steps {
			if step.Kind == "size" && step.MaxUsedSpace != cacheCleanupTarget(spec.Policy) {
				return ErrStorage
			}
		}
		o, err := readCacheObservation(tx, p.Cache)
		if err != nil || o.AttemptAt == 0 {
			return ErrStorage
		}
		if snapshot != ([32]byte{}) && (o.Usage == nil || o.Usage.Job != p.Job || o.Usage.Digest() != snapshot) {
			return ErrConflict
		}
		job := p.Job
		o.LastCleanup = &job
		raw, err := json.Marshal(status)
		if err != nil || len(raw) > 16<<10 {
			return ErrStorage
		}
		observed, err := json.Marshal(o)
		if err != nil || len(observed) > maxCacheUsageBytes {
			return ErrStorage
		}
		b := tx.Bucket(nativeBucket)
		if err := b.Put(nativeCacheCleanupKey(job), raw); err != nil {
			return err
		}
		return b.Put(cacheUsageKey(p.Cache), observed)
	})
}

func (n *NativeJobs) beginCacheCleanup(ctx context.Context, spec JobSpec, s CacheCleanupSelection) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !s.valid() {
		return false, ErrInvalid
	}
	r, err := n.load(spec)
	if err != nil {
		return false, err
	}
	step := CacheCleanupStep{Kind: s.Kind, Snapshot: s.Snapshot, Selection: s.Digest(), Selected: uint32(len(s.IDs)), MaxUsedSpace: s.MaxUsedSpace, Code: "SKIPPED"}
	send := false
	if len(s.IDs) > 0 {
		step.Code = "NOT_AUTHORIZED"
		if _, err := n.current(ctx, &r, false); err == nil && ctx.Err() == nil {
			step.Code = "UNKNOWN"
			step.SentAt = uint64(time.Now().Unix())
			send = true
		}
	}
	err = n.editCacheCleanup(spec, s.Snapshot, func(status *CacheCleanupStatus) error {
		// Missing ACK, a new observation, or a restart never permits a second
		// dispatch of the same phase. A failed/unknown age also blocks size.
		if s.Kind == "age" && len(status.Steps) != 0 || s.Kind == "size" && (len(status.Steps) != 1 || status.Steps[0].Code != "OK" && status.Steps[0].Code != "SKIPPED") {
			return ErrConflict
		}
		status.Steps = append(status.Steps, step)
		return nil
	})
	return send, err
}

func (n *NativeJobs) finishCacheCleanup(spec JobSpec, s CacheCleanupSelection, acks *cacheCleanupAcks, complete bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.editCacheCleanup(spec, [32]byte{}, func(status *CacheCleanupStatus) error {
		if len(status.Steps) == 0 {
			return ErrConflict
		}
		step := &status.Steps[len(status.Steps)-1]
		if step.Kind != s.Kind || step.Selection != s.Digest() || step.Code != "UNKNOWN" || step.ReturnedAt != 0 {
			return ErrConflict
		}
		step.ReturnedAt = uint64(time.Now().Unix())
		step.RemovedCount, step.ReportedBytes = acks.count, acks.bytes
		if complete && !acks.invalid {
			step.Code = "OK"
		}
		return nil
	})
}

func (n *NativeJobs) runCacheCleanup(ctx context.Context, spec JobSpec, sdk *bkclient.Client, s CacheCleanupSelection) (bool, error) {
	_, err := s.PruneOptions()
	if err != nil && len(s.IDs) > 0 {
		return false, err
	}
	send, err := n.beginCacheCleanup(ctx, spec, s)
	if err != nil {
		return false, err
	}
	if !send {
		return len(s.IDs) == 0, nil
	}
	acks, complete := invokeSDKCachePrune(ctx, sdk, s)
	return complete, n.finishCacheCleanup(spec, s, acks, complete)
}

// One automatic age/size pass per original solve, using its frozen policy.
// No background daemon, native restart or cleanup RPC replay is introduced.
func (n *NativeJobs) maintainCache(ctx context.Context, spec JobSpec, sdk *bkclient.Client) error {
	u, err := n.sampleCacheUsage(ctx, spec, sdk)
	if err != nil || u == nil {
		return err
	}
	for _, kind := range []string{"age", "size"} {
		selection, err := SelectCacheCleanup(spec, *u, kind)
		if err != nil {
			return err
		}
		complete, err := n.runCacheCleanup(ctx, spec, sdk, selection)
		if err != nil {
			return err
		}
		if len(selection.IDs) > 0 {
			// A readback is not a retry or a replacement for the original
			// streamed result. An unknown result stays unknown after readback.
			u, err = n.sampleCacheUsage(ctx, spec, sdk)
			if err != nil || u == nil {
				return err
			}
		}
		if !complete {
			return nil
		}
	}
	return nil
}
