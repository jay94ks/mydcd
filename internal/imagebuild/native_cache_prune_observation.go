// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/json"
	"time"

	bkclient "github.com/moby/buildkit/client"
	bolt "go.etcd.io/bbolt"
)

// The successful snapshot is retained through a later failed read. It is an
// observation witness, not proof that the independent prune RPC completed.
type NativeCachePruneObservation struct {
	AttemptAt, ObservedAt uint64
	Code                  string
	Snapshot              *[32]byte `json:",omitempty"`
}

func (o NativeCachePruneObservation) valid() bool {
	if o.AttemptAt == 0 || o.Code != "OK" && o.Code != "UNAVAILABLE" || (o.Snapshot == nil) != (o.ObservedAt == 0) || o.Snapshot != nil && *o.Snapshot == ([32]byte{}) {
		return false
	}
	return o.Code != "OK" || o.Snapshot != nil && o.ObservedAt == o.AttemptAt
}
func (n *NativeJobs) sampleManualCacheObservation(ctx context.Context, s NativeCachePruneSpec, sdk *bkclient.Client) (*CacheUsage, error) {
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := sdk.DiskUsage(probe)
	at := uint64(time.Now().Unix())
	var usage *CacheUsage
	if err == nil {
		u, e := NewCacheUsage(s.Source, at, rows)
		if e == nil {
			intent := s.Intent
			u.Maintenance = &intent
			usage = &u
		}
	}
	return usage, n.saveManualCacheObservation(s, at, usage)
}
func (n *NativeJobs) saveManualCacheObservation(s NativeCachePruneSpec, at uint64, usage *CacheUsage) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if at == 0 || !n.solving[s.Intent] || n.readers[s.Intent] == 0 || usage != nil && (!usage.valid(CacheIdentity(s.Source)) || usage.Job != s.Source.Digest() || usage.Maintenance == nil || *usage.Maintenance != s.Intent || usage.At != at) {
		return ErrConflict
	}
	p, err := PlanNative(s.Source, n.docker.Owner)
	if err != nil {
		return err
	}
	return n.db.Update(func(tx *bolt.Tx) error {
		r, err := readNativeCachePrune(tx, s, n.docker.Owner)
		if err != nil {
			return err
		}
		if !r.Claimed || r.Closed || r.Removing || r.Completion != nil || r.Daemon == nil || !r.Daemon.Effects.StartSent || r.Daemon.Effects.Removed {
			return ErrConflict
		}
		c, err := readNativeCache(tx, s.Source, p)
		if err != nil || c.Owner != s.Intent || c.Directory != r.Cache {
			return ErrStorage
		}
		o, err := readCacheObservation(tx, p.Cache)
		if err != nil {
			return err
		}
		if err := n.validateCacheObservation(tx, c, o); err != nil {
			return err
		}
		observation := NativeCachePruneObservation{AttemptAt: at, Code: "UNAVAILABLE"}
		if r.Observation != nil {
			observation = *r.Observation
			observation.AttemptAt = at
			observation.Code = "UNAVAILABLE"
		}
		o.AttemptAt, o.Code = at, "UNAVAILABLE"
		if usage != nil {
			snapshot := usage.Digest()
			observation.Code, observation.ObservedAt, observation.Snapshot = "OK", at, &snapshot
			o.Code, o.Usage = "OK", usage
		}
		r.Observation = &observation
		if err := writeNativeCachePrune(tx, r); err != nil {
			return err
		}
		raw, err := json.Marshal(o)
		if err != nil || len(raw) > maxCacheUsageBytes {
			return ErrStorage
		}
		return tx.Bucket(nativeBucket).Put(cacheUsageKey(p.Cache), raw)
	})
}
