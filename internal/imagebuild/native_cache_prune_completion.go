// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"encoding/json"
	"math"
	"slices"
)

type NativeCachePruneResult struct {
	Code          string
	RemovedCount  uint64
	ReportedBytes int64
}

func (r NativeCachePruneResult) Valid() bool {
	if r.RemovedCount > 2*MaxCacheEntries || r.ReportedBytes < 0 {
		return false
	}
	switch r.Code {
	case "OK", "FAILED", "PERMISSION_REVOKED", "TIMEOUT":
		return true
	}
	return false
}
func cachePruneNativeResult(r NativeCachePruneRecord, code string) (NativeCachePruneResult, error) {
	result := NativeCachePruneResult{Code: code}
	if r.RPC != nil {
		result.RemovedCount = uint64(r.RPC.RemovedCount)
		result.ReportedBytes = r.RPC.ReportedBytes
	}
	if r.PolicySize != nil {
		if r.PolicySize.ReportedBytes > math.MaxInt64-result.ReportedBytes {
			return NativeCachePruneResult{}, ErrInvalid
		}
		result.RemovedCount += uint64(r.PolicySize.RemovedCount)
		result.ReportedBytes += r.PolicySize.ReportedBytes
	}
	if !result.Valid() || code == "OK" && !r.SDKSucceeded() {
		return NativeCachePruneResult{}, ErrInvalid
	}
	return result, nil
}
func cachePruneNativeStopped(r NativeCachePruneRecord) bool {
	if r.Daemon == nil {
		return true
	}
	e := r.Daemon.Effects
	return !e.CreateSent || e.CreateNotSent || e.Removed
}
func cachePruneNativeWitness(r NativeCachePruneRecord) [32]byte {
	return digestJSON("sfc-native-cache-prune-completion-witness-1", struct {
		Spec                                   [32]byte
		Root, Cache                            NativeDirectory
		Claimed, CleanupOnly, Removing, Closed bool
		Daemon                                 *NativeCachePruneDaemon
		RPC                                    *CacheCleanupStep
		Outcome                                *NativeCachePruneResult
		Observation                            *NativeCachePruneObservation `json:",omitempty"`
		PolicySize                             *CacheCleanupStep            `json:",omitempty"`
	}{r.Spec.Digest(), r.Root, r.Cache, r.Claimed, r.CleanupOnly, r.Removing, r.Closed, r.Daemon, r.RPC, r.Outcome, r.Observation, r.PolicySize})
}

type NativeCachePruneCompletion struct {
	Schema         uint8
	Intent, Native [32]byte
	Result         NativeCachePruneResult
	At             uint64
	Signature      []byte
}

func cachePruneCompletionBytes(c NativeCachePruneCompletion) []byte {
	c.Signature = nil
	raw, _ := json.Marshal(c)
	return append([]byte("sfc-native-cache-prune-completion-1\x00"), raw...)
}
func (c NativeCachePruneCompletion) Valid(s NativeCachePruneSpec) bool {
	return s.Valid() && c.Schema == 1 && c.Intent == s.Intent && c.Native != ([32]byte{}) && c.At >= s.At && c.At <= math.MaxInt64 && c.Result.Valid() && (s.Automatic != nil || c.Result.RemovedCount <= MaxCacheEntries) && ed25519.Verify(s.Source.Scope.Root.Key[:], cachePruneCompletionBytes(c), c.Signature)
}
func (n *NativeJobs) RecordCachePruneOutcome(s NativeCachePruneSpec, code string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.loadCachePrune(s)
	if err != nil {
		return err
	}
	if n.readers[s.Intent] != 0 || n.solving[s.Intent] {
		return ErrUsed
	}
	result, err := cachePruneNativeResult(r, code)
	if err != nil {
		return err
	}
	if r.Outcome != nil {
		if *r.Outcome != result {
			return ErrConflict
		}
		return nil
	}
	r.Outcome = &result
	return n.saveCachePrune(r)
}
func (n *NativeJobs) SealCachePruneCompletion(s NativeCachePruneSpec, at uint64, key ed25519.PrivateKey) (NativeCachePruneCompletion, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(key) != ed25519.PrivateKeySize || [32]byte(key.Public().(ed25519.PublicKey)) != s.Source.Scope.Root.Key {
		return NativeCachePruneCompletion{}, ErrInvalid
	}
	r, err := n.loadCachePrune(s)
	if err != nil {
		return NativeCachePruneCompletion{}, err
	}
	if r.Completion != nil {
		copy := *r.Completion
		copy.Signature = slices.Clone(copy.Signature)
		return copy, nil
	}
	if !r.Closed || r.Outcome == nil || n.readers[s.Intent] != 0 || n.solving[s.Intent] {
		return NativeCachePruneCompletion{}, ErrUsed
	}
	c := NativeCachePruneCompletion{Schema: 1, Intent: s.Intent, Native: cachePruneNativeWitness(r), Result: *r.Outcome, At: at}
	c.Signature = ed25519.Sign(key, cachePruneCompletionBytes(c))
	if !c.Valid(s) {
		return NativeCachePruneCompletion{}, ErrInvalid
	}
	r.Completion = &c
	if err := n.saveCachePrune(r); err != nil {
		return NativeCachePruneCompletion{}, err
	}
	c.Signature = slices.Clone(c.Signature)
	return c, nil
}
