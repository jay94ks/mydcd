// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/engine"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

// Source remains the original immutable shared job. Intent names a separately
// authorized maintenance request; no new JobSpec or simulated build is made.
type NativeCachePruneSpec struct {
	Schema    uint8
	Intent    [32]byte
	ID        string
	At        uint64
	Source    JobSpec
	Filter    CachePruneFilter
	Automatic *Policy `json:",omitempty"`
}

func (s NativeCachePruneSpec) Valid() bool {
	if s.Schema != 1 || s.Intent == ([32]byte{}) || !lifecycle.ValidID(s.ID) || s.At == 0 || s.At > math.MaxInt64 || s.Source.Validate() != nil || s.Limits().Seconds > math.MaxInt64-s.At {
		return false
	}
	if s.Automatic == nil {
		return s.Filter.Valid()
	}
	return s.Filter.Mode == "policy" && len(s.Filter.IDs) == 0 && s.Filter.UnusedDays == 0 && cachePolicyMatchesSource(s.Source, *s.Automatic)
}

func (s NativeCachePruneSpec) Limits() Policy {
	if s.Automatic != nil {
		return *s.Automatic
	}
	return s.Source.Policy
}

func (s NativeCachePruneSpec) selectionKind(kind string) bool {
	if s.Automatic != nil {
		return kind == "age" || kind == "size"
	}
	return kind == "manual-"+s.Filter.Mode
}
func (s NativeCachePruneSpec) Digest() [32]byte {
	return digestJSON("sfc-native-cache-prune-spec-1", s)
}
func (s NativeCachePruneSpec) Own() NativeCachePruneSpec {
	s.Source = s.Source.Own()
	s.Filter = s.Filter.Own()
	if s.Automatic != nil {
		value := s.Automatic.Own()
		s.Automatic = &value
	}
	return s
}

type NativeCachePruneGrant struct {
	Spec                   NativeCachePruneSpec
	Index, Revision, Epoch uint64
	Phase                  string
	Allowed                bool
}

func (g NativeCachePruneGrant) Valid() bool {
	if !g.Spec.Valid() || g.Index == 0 || g.Revision == 0 || g.Epoch == 0 {
		return false
	}
	switch g.Phase {
	case "queued":
		return g.Revision == 1
	case "running":
		return g.Revision == 2
	case "unknown":
		return g.Revision == 3
	case "succeeded":
		return g.Revision == 3 || g.Revision == 4
	case "failed":
		return g.Revision >= 2 && g.Revision <= 4
	}
	return false
}

// Original maintenance effects live in the same node DB as the retained
// cache. Claimed/daemon workspace Ready do not imply SDK readiness, dispatch
// or native closure. The original RPC receipt survives unknown responses.
type NativeCachePruneRecord struct {
	Schema                 uint8
	Spec                   NativeCachePruneSpec
	Index, Revision, Epoch uint64
	Claimed                bool
	CleanupOnly            bool `json:",omitempty"`
	Root, Cache            NativeDirectory
	Daemon                 *NativeCachePruneDaemon      `json:",omitempty"`
	RPC                    *CacheCleanupStep            `json:",omitempty"`
	Outcome                *NativeCachePruneResult      `json:",omitempty"`
	Removing, Closed       bool                         `json:",omitempty"`
	Completion             *NativeCachePruneCompletion  `json:",omitempty"`
	Observation            *NativeCachePruneObservation `json:",omitempty"`
	PolicySize             *CacheCleanupStep            `json:",omitempty"`
}

func (r NativeCachePruneRecord) valid() bool {
	if !(r.Schema == 1 && r.Spec.Valid() && r.Index > 0 && r.Revision > 0 && r.Epoch > 0 && !(r.CleanupOnly && r.Claimed) && (r.Claimed && r.Root.valid() && r.Cache.valid() || !r.Claimed && r.Root == (NativeDirectory{}) && r.Cache == (NativeDirectory{})) && (r.Daemon == nil || r.Daemon.valid(r)) && (r.RPC == nil || r.RPC.valid() && r.Spec.selectionKind(r.RPC.Kind) && r.RPC.Kind != "size" && r.Daemon != nil && r.Daemon.Effects.StartSent && r.RPC.Code != "NOT_AUTHORIZED")) {
		return false
	}
	if r.PolicySize != nil && (r.Spec.Automatic == nil || !cachePruneStepSucceeded(r.RPC) || !r.PolicySize.valid() || r.PolicySize.Kind != "size" || r.PolicySize.MaxUsedSpace != cacheCleanupTarget(*r.Spec.Automatic) || r.PolicySize.Code == "NOT_AUTHORIZED") {
		return false
	}
	if r.Outcome != nil {
		result, err := cachePruneNativeResult(r, r.Outcome.Code)
		if err != nil || result != *r.Outcome {
			return false
		}
	}
	if r.Removing && (r.Outcome == nil || !cachePruneNativeStopped(r)) || r.Closed && !r.Removing {
		return false
	}
	if r.Completion != nil && (!r.Closed || r.Outcome == nil || !r.Completion.Valid(r.Spec) || r.Completion.Result != *r.Outcome || r.Completion.Native != cachePruneNativeWitness(r)) {
		return false
	}
	if r.Observation != nil && (!r.Observation.valid() || r.Daemon == nil || !r.Daemon.Effects.StartSent) {
		return false
	}
	return true
}
func nativeCachePruneKey(intent [32]byte) []byte {
	return []byte("cache-prune/" + hex.EncodeToString(intent[:]))
}
func readNativeCachePrune(tx *bolt.Tx, s NativeCachePruneSpec, owner string) (NativeCachePruneRecord, error) {
	var r NativeCachePruneRecord
	if !s.Valid() || owner != engine.Owner(s.Source.Cluster, s.Source.Scope.Root.Key) {
		return r, ErrStorage
	}
	b := tx.Bucket(nativeBucket)
	if b == nil || string(b.Get([]byte("owner"))) != owner {
		return r, ErrStorage
	}
	raw := b.Get(nativeCachePruneKey(s.Intent))
	if raw == nil {
		return r, ErrNativeMissing
	}
	if len(raw) > 128<<10 || json.Unmarshal(raw, &r) != nil || !r.valid() || r.Spec.Digest() != s.Digest() {
		return r, ErrStorage
	}
	canonical, err := json.Marshal(r)
	if err != nil || string(canonical) != string(raw) {
		return r, ErrStorage
	}
	return r, nil
}
func writeNativeCachePrune(tx *bolt.Tx, r NativeCachePruneRecord) error {
	if !r.valid() {
		return ErrStorage
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 128<<10 {
		return ErrStorage
	}
	b := tx.Bucket(nativeBucket)
	if b == nil {
		return ErrStorage
	}
	return b.Put(nativeCachePruneKey(r.Spec.Intent), raw)
}
func (n *NativeJobs) CachePruneRecord(s NativeCachePruneSpec) (NativeCachePruneRecord, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !s.Valid() || n.docker.Owner != engine.Owner(s.Source.Cluster, s.Source.Scope.Root.Key) {
		return NativeCachePruneRecord{}, ErrInvalid
	}
	var r NativeCachePruneRecord
	err := n.db.View(func(tx *bolt.Tx) error {
		var err error
		r, err = readNativeCachePrune(tx, s, n.docker.Owner)
		return err
	})
	return r, err
}

// Uses the retained cache's original lease directly. A newer representative
// may have no native build record and must not create another cache/root pin.
func (n *NativeJobs) CachePruneRootHold(s NativeCachePruneSpec) (NativeRootHold, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, err := n.loadCachePrune(s); err != nil {
		return NativeRootHold{}, err
	}
	p, err := PlanNative(s.Source, n.docker.Owner)
	if err != nil {
		return NativeRootHold{}, err
	}
	var hold NativeRootHold
	err = n.db.View(func(tx *bolt.Tx) error {
		c, err := readNativeCache(tx, s.Source, p)
		if err != nil {
			return err
		}
		if c.Owner != ([32]byte{}) && c.Owner != s.Intent {
			return ErrUsed
		}
		if !c.Directory.valid() || c.RootHold == nil || c.RootHold.Lease.Token == 0 || c.RootHold.Returning || c.RootHold.Returned {
			return ErrStorage
		}
		hold = *c.RootHold
		return nil
	})
	return hold, err
}

// Discovery preserves originals across shared metadata loss. It does not
// reconstruct missing records or authorize a new effect from their presence.
func (n *NativeJobs) CachePruneRecords() ([]NativeCachePruneRecord, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var records []NativeCachePruneRecord
	err := n.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		if b == nil || string(b.Get([]byte("owner"))) != n.docker.Owner {
			return ErrStorage
		}
		return b.ForEach(func(key, raw []byte) error {
			if !strings.HasPrefix(string(key), "cache-prune/") {
				return nil
			}
			var row NativeCachePruneRecord
			if raw == nil || len(raw) > 128<<10 || json.Unmarshal(raw, &row) != nil {
				return ErrStorage
			}
			row, err := readNativeCachePrune(tx, row.Spec, n.docker.Owner)
			if err != nil || string(key) != string(nativeCachePruneKey(row.Spec.Intent)) {
				return ErrStorage
			}
			records = append(records, row)
			return nil
		})
	})
	return records, err
}

// Must precede the shared begin. A missing running/unknown original journal
// cannot be recreated from its shared metadata or a new authorization.
func (n *NativeJobs) AcceptCachePrune(g NativeCachePruneGrant) error {
	return n.acceptCachePrune(g, false)
}
func (n *NativeJobs) AcceptCachePruneForCleanup(g NativeCachePruneGrant) error {
	return n.acceptCachePrune(g, true)
}
func (n *NativeJobs) acceptCachePrune(g NativeCachePruneGrant, cleanup bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !g.Valid() || n.docker.Owner != engine.Owner(g.Spec.Source.Cluster, g.Spec.Source.Scope.Root.Key) {
		return ErrInvalid
	}
	return n.db.Update(func(tx *bolt.Tx) error {
		r, err := readNativeCachePrune(tx, g.Spec, n.docker.Owner)
		if err == nil {
			if r.Index > g.Index || r.Revision > g.Revision || r.Epoch > g.Epoch {
				return ErrConflict
			}
			return nil
		}
		if err != ErrNativeMissing {
			return err
		}
		if g.Phase != "queued" || !cleanup && !g.Allowed {
			return ErrNativeMissing
		}
		return writeNativeCachePrune(tx, NativeCachePruneRecord{Schema: 1, Spec: g.Spec.Own(), Index: g.Index, Revision: g.Revision, Epoch: g.Epoch, CleanupOnly: cleanup})
	})
}

// rootFD is the existing RootManager-held descriptor. This never creates a
// directory/cache/root lease or releases one; native closure must precede the
// eventual return. The shared owner grant is obtained before entering here.
func (n *NativeJobs) ClaimCachePrune(g NativeCachePruneGrant, rootFD int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !g.Valid() || g.Phase != "running" || !g.Allowed || n.docker.Owner != engine.Owner(g.Spec.Source.Cluster, g.Spec.Source.Scope.Root.Key) {
		return ErrInvalid
	}
	spec := g.Spec.Source
	plan, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return err
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
	rootIdentity := nativeDirectory(st)
	file, cacheStat, err := openNativeDirectory(rootFD, nativeWorkspaceNames(plan)[2])
	if err != nil {
		return ErrStorage
	}
	defer file.Close()
	cacheIdentity := nativeDirectory(cacheStat)
	return n.db.Update(func(tx *bolt.Tx) error {
		r, err := readNativeCachePrune(tx, g.Spec, n.docker.Owner)
		if err != nil {
			return err
		}
		if r.CleanupOnly {
			return ErrConflict
		}
		if r.Outcome != nil || r.Removing || r.Closed {
			return ErrConflict
		}
		if r.Index > g.Index || r.Revision > g.Revision || r.Epoch > g.Epoch {
			return ErrConflict
		}
		cache, err := readNativeCache(tx, spec, plan)
		if err != nil || cache.Retirement != nil || !cache.Directory.valid() || cache.Directory != cacheIdentity || cache.RootHold == nil || cache.RootHold.Lease.Token == 0 || cache.RootHold.Returning || cache.RootHold.Returned {
			return ErrStorage
		}
		if r.Claimed {
			if r.Root != rootIdentity || r.Cache != cacheIdentity || cache.Owner != g.Spec.Intent {
				return ErrStorage
			}
		} else {
			if cache.Owner != ([32]byte{}) {
				return ErrUsed
			}
			cache.Owner = g.Spec.Intent
			r.Claimed, r.Root, r.Cache = true, rootIdentity, cacheIdentity
			raw, err := json.Marshal(cache)
			if err != nil {
				return ErrStorage
			}
			if err := tx.Bucket(nativeBucket).Put(nativeCacheKey(plan.Cache), raw); err != nil {
				return err
			}
		}
		r.Index, r.Revision, r.Epoch = g.Index, g.Revision, g.Epoch
		return writeNativeCachePrune(tx, r)
	})
}
