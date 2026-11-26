// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
)

// JSON bytes are the actual signed fact payload charged by the store. This
// fixture computes the receiving owner's exact metadata size, not admission.
func measuredCompiledCacheCost(t *testing.T, key ed25519.PrivateKey, build CompiledBuild) uint64 {
	t.Helper()
	fact := CompiledFact{Schema: 1, Owner: [32]byte(key.Public().(ed25519.PublicKey)), Build: build.Clone()}
	fact.Signature = ed25519.Sign(key, CompiledFactBytes(fact))
	raw, err := json.Marshal(fact)
	if err != nil || fact.Verify() != nil {
		t.Fatal("invalid expected cache fact", err)
	}
	return build.Length + uint64(len(raw))
}

func TestCheckerCompiledCacheBudgetSumsOwnerCopiesAndPreservesOriginalReceipts(t *testing.T) {
	ctx := context.Background()
	build, d, policy, data, _ := compiledTestBuild(t)
	group := &SourceCacheBudget{}
	old, _, _ := groupedSourceStore(t, group, build.Cluster, 51)
	current, _, currentKey := groupedSourceStore(t, group, build.Cluster, 52)
	original, err := old.StageCompiled(ctx, d, policy, build, data)
	if err != nil {
		t.Fatal(err)
	}
	oldCost := old.compiledBytes[d.Tenant]
	currentCost := measuredCompiledCacheCost(t, currentKey, build)
	policy.Build.ArtifactBytes = build.Length
	policy.CompiledCacheBytes = oldCost + currentCost - 1
	if _, err = current.StageCompiled(ctx, d, policy, build, data); !errors.Is(err, ErrCompiledCapacity) {
		t.Fatal("new key treated historical compiled bytes as free", err)
	}
	if len(current.compiled) != 0 || current.compiledBytes[d.Tenant] != 0 {
		t.Fatal("rejected copy partly published")
	}
	policy.CompiledCacheBytes++
	copied, err := current.StageCompiled(ctx, d, policy, build, data)
	if err != nil {
		t.Fatal("exact aggregate capacity rejected", err)
	}
	if copied.Owner == original.Owner || copied.Build.Job != original.Build.Job || !bytes.Equal(copied.Build.Signature, original.Build.Signature) || current.compiledBytes[d.Tenant] != currentCost || old.compiledBytes[d.Tenant] != oldCost {
		t.Fatal("global sum replaced a local counter or original provenance")
	}
	for _, entry := range []struct {
		store *SourceStore
		fact  CompiledFact
	}{{old, original}, {current, copied}} {
		recovered, err := entry.store.RecoverCompiled(ctx, d.Tenant, build.Recipe.Key())
		if err != nil || recovered.Digest() != entry.fact.Digest() {
			t.Fatal("original compiled recovery allocated/replaced receipt", err)
		}
		replay, err := entry.store.StageCompiled(ctx, d, policy, build, data)
		if err != nil || replay.Digest() != entry.fact.Digest() {
			t.Fatal("full shared quota prevented exact cache hit", err)
		}
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	next := build.Clone()
	next.Recipe.Tree[0]++
	// A fresh independently signed builder must sign its own Builder field.
	builder := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, 32))
	next.Builder = [32]byte(builder.Public().(ed25519.PublicKey))
	next.Signature = ed25519.Sign(builder, CompiledBuildBytes(next))
	if _, err = current.StageCompiled(ctx, d, policy, next, data); !errors.Is(err, ErrCompiledCapacity) {
		t.Fatal("closed historical cache stopped being charged", err)
	}
}

func TestCheckerCompiledCacheBudgetReservesCollectorDiagnosticsOnceAndFencesUnknown(t *testing.T) {
	ctx := context.Background()
	build, d, policy, data, _ := compiledTestBuild(t)
	group := &SourceCacheBudget{}
	old, _, _ := groupedSourceStore(t, group, build.Cluster, 53)
	current, _, currentKey := groupedSourceStore(t, group, build.Cluster, 54)
	original, err := old.StageCompiled(ctx, d, policy, build, data)
	if err != nil {
		t.Fatal(err)
	}
	oldCost := old.compiledBytes[d.Tenant]
	currentCost := measuredCompiledCacheCost(t, currentKey, build)
	const reserved = uint64(64)
	policy.Build.ArtifactBytes = build.Length
	policy.CompiledCacheBytes = oldCost + currentCost + reserved
	// stageCompiled is the actual CollectCompiled adoption core. Its reserved
	// argument is this collector's not-yet-written diagnostic bytes, excluded
	// from every store counter until the collection transaction commits them.
	current.mu.Lock()
	fact, err := current.stageCompiled(ctx, d, policy, build, data, reserved)
	current.mu.Unlock()
	if err != nil || current.compiledBytes[d.Tenant] != currentCost || old.compiledBytes[d.Tenant] != oldCost {
		t.Fatal("collector reservation was charged twice or global used became local", err)
	}
	builder := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{55}, 32))
	next := build.Clone()
	next.Recipe.Tree[0]++
	next.Builder = [32]byte(builder.Public().(ed25519.PublicKey))
	next.Signature = ed25519.Sign(builder, CompiledBuildBytes(next))
	old.mu.Lock()
	old.uncertain = true
	old.mu.Unlock()
	if _, err = current.StageCompiled(ctx, d, policy, next, data); !errors.Is(err, ErrSourceUncertain) {
		t.Fatal("fresh compiled write spent unknown historical bytes", err)
	}
	if hit, err := current.StageCompiled(ctx, d, policy, build, data); err != nil || hit.Digest() != fact.Digest() {
		t.Fatal("known current receipt was rewritten under another store's uncertainty", err)
	}
	if _, err = old.StageCompiled(ctx, d, policy, build, data); !errors.Is(err, ErrSourceUncertain) {
		t.Fatal("own uncertainty bypassed explicit recovery", err)
	}
	recovered, err := old.RecoverCompiled(ctx, d.Tenant, build.Recipe.Key())
	if err != nil || recovered.Digest() != original.Digest() {
		t.Fatal("original recovery changed compiled provenance", err)
	}
	current.mu.Lock()
	_, err = current.stageCompiled(ctx, d, policy, next, data, reserved)
	current.mu.Unlock()
	if !errors.Is(err, ErrCompiledCapacity) {
		t.Fatal("recovery discarded retained compiled cost/reservation", err)
	}
}
