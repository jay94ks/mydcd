// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/reconcile"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/storage"
)

func TestCheckerCompiledGCDeletesBinaryPreservesOriginalEvidenceAndCanRehydrateExactBytes(t *testing.T) {
	store, db, path, key := cacheRetentionFixture(t)
	ctx := context.Background()
	build, d, policy, data, _ := compiledTestBuild(t)
	source, err := store.Stage(ctx, d, []byte(compileTestSource), policy)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := store.StageCompiled(ctx, d, policy, build, data)
	if err != nil {
		t.Fatal(err)
	}
	collection := CompiledCollection{Schema: 1, Cluster: build.Cluster, Owner: store.identity.Node, Job: build.Job, Manifest: [32]byte{7}, Report: [32]byte{8}, Tenant: d.Tenant, ID: build.ID, ExitKnown: true, Outcome: "complete", Items: []CompiledCollectionItem{{Key: build.Recipe.Key(), Cached: fact.Digest(), Status: "cached", Reason: "verified"}}}
	collection.Signature = ed25519.Sign(key, CompiledCollectionBytes(collection))
	if collection.Verify() != nil {
		t.Fatal("invalid synthetic signed history")
	}
	raw, _ := json.Marshal(collection)
	if err := db.Write(map[string][]byte{collectionMetaPrefix + compiledCollectionKey(d.Tenant, build.Job): raw}); err != nil {
		t.Fatal(err)
	}
	if err := store.recover(); err != nil {
		t.Fatal(err)
	}
	before := store.compiledBytes[d.Tenant]
	dead := cacheRetentionCatalog(t, policy, source, true)
	got := collectRetention(t, store, dead)
	if got.Compiled != 1 || store.compiledBytes[d.Tenant] != before-uint64(len(data)) {
		t.Fatal("compiled cache quota was not reclaimed", got)
	}
	if _, _, err := store.CompiledArtifact(ctx, d.Tenant, build.Recipe.Key()); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("evicted cache advertised ready", err)
	}
	id := compiledObjectKey(d.Tenant, build.Recipe.Key())
	if _, err := db.Get(compiledDataPrefix + id); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("binary still present", err)
	}
	if _, err := db.Get(compiledMetaPrefix + id); err != nil {
		t.Fatal("original signed fact erased", err)
	}
	after, err := store.CompiledCollection(ctx, d.Tenant, build.Job)
	if err != nil || after.Digest() != collection.Digest() {
		t.Fatal("historical cached receipt was rewritten", err)
	}
	store.Close()
	db.Close()
	reopened, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := OpenSources(reopened, build.Cluster, key)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, _, err := next.CompiledArtifact(ctx, d.Tenant, build.Recipe.Key()); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("eviction floor lost on reopen", err)
	}
	rehydrated, err := next.StageCompiled(ctx, d, policy, build, data)
	if err != nil || rehydrated.Digest() != fact.Digest() || next.compiledBytes[d.Tenant] != before {
		t.Fatal("rehydration changed original builder/job or quota", err)
	}
	if _, _, err := next.CompiledArtifact(ctx, d.Tenant, build.Recipe.Key()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckerCacheGCRetainsOriginalLocalCompilerEvenAfterSharedUseDisappears(t *testing.T) {
	ctx := context.Background()
	_, _, intent, _, key := buildJobFixture(t)
	_, policy := compilationFixture(t)
	db, err := storage.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSources(db, intent.Cluster, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	data := []byte(compileTestSource)
	d := sourceDescriptor(policy.Tenant, data)
	fact, err := store.Stage(ctx, d, data, policy)
	if err != nil {
		t.Fatal(err)
	}
	state, err := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: compilerSpec(intent, policy)}})
	if err != nil {
		t.Fatal(err)
	}
	record := compilerDisk{Schema: 1, Intent: intent, Policy: policy, State: state}
	raw, _ := json.Marshal(record)
	keyName := compilerRecordPrefix + compilerJobKey(intent)
	if err := db.Write(map[string][]byte{keyName: raw}); err != nil {
		t.Fatal(err)
	}
	dead := cacheRetentionCatalog(t, policy, fact, true)
	if collectRetention(t, store, dead).Sources != 0 {
		t.Fatal("local original preparation lost source")
	}
	record.Cancel = true
	raw, _ = json.Marshal(record)
	if err := db.Write(map[string][]byte{keyName: raw}); err != nil {
		t.Fatal(err)
	}
	if collectRetention(t, store, dead).Sources != 0 {
		t.Fatal("cancellation substituted for native/workspace closure")
	}
	if err := db.Write(map[string][]byte{keyName: []byte(`{"Schema":1}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CollectCache(ctx, func(context.Context) (CacheRetention, error) { return CacheRetention{Catalog: dead}, nil }); !errors.Is(err, ErrCompilerOwner) {
		t.Fatal("invalid local original metadata authorized collection", err)
	}
	if _, err := db.Get(sourcePrefix + "data/" + sourceObjectKey(d)); err != nil {
		t.Fatal("failure erased original source", err)
	}
}

func TestCheckerCompiledEvictionMarkerLossIsCorruptionRatherThanReadyOrOrdinaryMiss(t *testing.T) {
	store, db, _, _ := cacheRetentionFixture(t)
	ctx := context.Background()
	build, d, policy, data, _ := compiledTestBuild(t)
	source, err := store.Stage(ctx, d, []byte(compileTestSource), policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageCompiled(ctx, d, policy, build, data); err != nil {
		t.Fatal(err)
	}
	if collectRetention(t, store, cacheRetentionCatalog(t, policy, source, true)).Compiled != 1 {
		t.Fatal("fixture not evicted")
	}
	id := compiledObjectKey(d.Tenant, build.Recipe.Key())
	if err := db.Write(map[string][]byte{evictedCompiledPrefix + id: nil}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompiledArtifact(ctx, d.Tenant, build.Recipe.Key()); !errors.Is(err, ErrSourceStore) {
		t.Fatal("lost marker became ordinary miss", err)
	}
	if _, err := store.StageCompiled(ctx, d, policy, build, data); !errors.Is(err, ErrSourceStore) {
		t.Fatal("lost marker repaired implicitly", err)
	}
	if _, err := db.Get(compiledDataPrefix + id); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("failed rehydration wrote bytes", err)
	}
}
