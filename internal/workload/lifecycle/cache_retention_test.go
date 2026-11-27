// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/storage"
)

// Actual bbolt/source owner; the supplied catalog is the deterministic shared
// input. These tests do not establish a real quorum or native compiler result.
func cacheRetentionFixture(t *testing.T) (*SourceStore, *storage.DB, string, ed25519.PrivateKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	store, err := OpenSources(db, [32]byte{1}, key)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close(); db.Close() })
	return store, db, path, key
}
func cacheRetentionCatalog(t *testing.T, policy TenantPolicy, fact SourceFact, deleted bool) Catalog {
	t.Helper()
	book, err := NewCatalog(fact.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	book.d.Revision = 1
	if err := book.rememberPublication(fact); err != nil {
		t.Fatal(err)
	}
	book.d.Policies[policy.Tenant] = []TenantPolicy{policy}
	book.d.Scripts[catalogKey(policy.Tenant, "check")] = ScriptRecord{Tenant: policy.Tenant, Name: "check", Revision: 1, Versions: []ScriptVersion{{Revision: 1, Source: fact.Clone(), Active: !deleted, Deleted: deleted}}}
	if book.Validate() != nil {
		t.Fatal("invalid shared input")
	}
	return book
}
func collectRetention(t *testing.T, store *SourceStore, book Catalog, local ...CacheReference) CacheCollection {
	t.Helper()
	result, err := store.CollectCache(context.Background(), func(context.Context) (CacheRetention, error) { return CacheRetention{Catalog: book, Local: local}, nil })
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func stageRetentionSource(t *testing.T, store *SourceStore, data []byte, policy TenantPolicy, id [32]byte) SourceFact {
	t.Helper()
	ctx := context.Background()
	d := sourceDescriptor(policy.Tenant, data)
	if err := store.BeginUpload(ctx, d, id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stage(ctx, d, data, policy); err != nil {
		t.Fatal(err)
	}
	fact, err := store.UploadedFact(ctx, d, id, false)
	if err != nil {
		t.Fatal(err)
	}
	return fact
}
func TestCheckerCacheGCJoinsUploadCatalogAndActualDBRecovery(t *testing.T) {
	store, db, path, key := cacheRetentionFixture(t)
	ctx := context.Background()
	data := []byte("package checker\n")
	policy := sourcePolicy()
	id := [32]byte{71}
	fact := stageRetentionSource(t, store, data, policy, id)
	d := fact.Descriptor()
	done, err := store.HoldUpload(ctx, d, id, false)
	if err != nil {
		t.Fatal(err)
	}
	live := cacheRetentionCatalog(t, policy, fact, false)
	if got := collectRetention(t, store, live); got.Sources != 0 {
		t.Fatal("live source collected", got)
	}
	gone := cacheRetentionCatalog(t, policy, fact, true)
	if got := collectRetention(t, store, gone); got.Sources != 0 {
		t.Fatal("stream still in flight", got)
	}
	done()
	done() // idempotent release, no negative reference count
	if got := collectRetention(t, store, gone, CacheReference{d.Tenant, d.ContentDigest()}); got.Sources != 0 {
		t.Fatal("unsettled local run lost bytes", got)
	}
	got := collectRetention(t, store, gone)
	if got.Sources != 1 || got.Bytes != uint64(len(data)) || store.bytes[d.Tenant] != 0 {
		t.Fatal("eligible bytes/quota not reclaimed", got)
	}
	if _, err := db.Get(sourcePrefix + "data/" + sourceObjectKey(d)); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("only a tombstone was written", err)
	}
	if _, err := store.UploadedFact(ctx, d, id, true); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("old upload became available", err)
	}
	if err := store.BeginUpload(ctx, d, id); !errors.Is(err, ErrReference) {
		t.Fatal("consumed original reopened", err)
	}
	original, _ := json.Marshal(gone)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := OpenSources(reopened, [32]byte{1}, key)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if collectRetention(t, next, gone).Sources != 0 {
		t.Fatal("double collection")
	}
	if err := next.BeginUpload(ctx, d, id); !errors.Is(err, ErrReference) {
		t.Fatal("reopen forgot consumed floor", err)
	}
	after, _ := json.Marshal(gone)
	if !bytes.Equal(original, after) || fact.Verify() != nil {
		t.Fatal("historical signature/catalog changed")
	}
}
func TestCheckerCacheGCUnpublishedConcurrentUploadSurvivesReopen(t *testing.T) {
	store, db, path, key := cacheRetentionFixture(t)
	ctx := context.Background()
	policy := sourcePolicy()
	data := []byte("package checker\n")
	first := stageRetentionSource(t, store, data, policy, [32]byte{72})
	dead := cacheRetentionCatalog(t, policy, first, true)
	// Another original intent stages the SAME content before publishing it.
	second := stageRetentionSource(t, store, data, policy, [32]byte{73})
	if collectRetention(t, store, dead).Sources != 0 {
		t.Fatal("unpublished second upload erased")
	}
	store.Close()
	db.Close()
	reopened, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := OpenSources(reopened, [32]byte{1}, key)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if collectRetention(t, next, dead).Sources != 0 {
		t.Fatal("restart/expired session released uncertain publication")
	}
	recovered, err := next.UploadedFact(ctx, second.Descriptor(), *second.Upload, true)
	if err != nil || !sameSourceFact(recovered, second) {
		t.Fatal("original upload identity changed", err)
	}
	secondGone := cacheRetentionCatalog(t, policy, second, true)
	if collectRetention(t, next, secondGone).Sources != 1 {
		t.Fatal("second publication closure did not permit collection")
	}
}
func TestCheckerCacheGCSharedUseAndInactiveVersionStillProtectBytes(t *testing.T) {
	store, _, _, _ := cacheRetentionFixture(t)
	ctx := context.Background()
	data := []byte("package checker\n")
	p := sourcePolicy()
	d := sourceDescriptor(p.Tenant, data)
	fact, err := store.Stage(ctx, d, data, p)
	if err != nil {
		t.Fatal(err)
	}
	book := cacheRetentionCatalog(t, p, fact, false)
	record := book.d.Scripts[catalogKey(p.Tenant, "check")]
	record.Versions[0].Active = false
	book.d.Scripts[catalogKey(p.Tenant, "check")] = record
	if collectRetention(t, store, book).Sources != 0 {
		t.Fatal("retire was treated as delete")
	}
	record.Versions[0].Deleted = true
	book.d.Scripts[catalogKey(p.Tenant, "check")] = record
	use := Use{Tenant: p.Tenant, ID: "accepted", Kind: "app-binding", Principal: "alice", Node: "node", Owner: [32]byte{2}, Parent: [32]byte{3}, PolicyRevision: 1, Sources: []SourceFact{fact}}
	book.d.Uses[catalogKey(use.Tenant, use.ID)] = use
	if collectRetention(t, store, book).Sources != 0 {
		t.Fatal("same content's other app lost bytes")
	}
	delete(book.d.Uses, catalogKey(use.Tenant, use.ID))
	if collectRetention(t, store, book).Sources != 1 {
		t.Fatal("last use released without collection")
	}
}
func TestCheckerCacheGCFailureAndKnownMissingHoldNeverAuthorizeDeletion(t *testing.T) {
	store, db, _, _ := cacheRetentionFixture(t)
	ctx := context.Background()
	p := sourcePolicy()
	id := [32]byte{75}
	fact := stageRetentionSource(t, store, []byte("package checker\n"), p, id)
	dead := cacheRetentionCatalog(t, p, fact, true)
	quorumLost := errors.New("no quorum")
	if _, err := store.CollectCache(ctx, func(context.Context) (CacheRetention, error) { return CacheRetention{}, quorumLost }); !errors.Is(err, quorumLost) {
		t.Fatal(err)
	}
	if _, err := store.Read(ctx, fact.Descriptor()); err != nil {
		t.Fatal("fence failure changed cache", err)
	}
	if err := db.Write(map[string][]byte{uploadPrefix + uploadKey(p.Tenant, id): nil}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CollectCache(ctx, func(context.Context) (CacheRetention, error) { return CacheRetention{Catalog: dead}, nil }); !errors.Is(err, ErrSourceUncertain) {
		t.Fatal("missing known hold accepted", err)
	}
	if _, err := db.Get(sourcePrefix + "data/" + sourceObjectKey(fact.Descriptor())); err != nil {
		t.Fatal("corruption was masked by collection", err)
	}
}
func TestCheckerCacheGCSharedModuleAndPartialUploadRemainProtected(t *testing.T) {
	store, _, _, _ := cacheRetentionFixture(t)
	ctx := context.Background()
	archive := moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte("package safe\n")})
	data := []byte("package checker\n")
	policy, d, _ := resolverInput(data, []ModuleArchive{archive}, "example.invalid/safe")
	if _, err := store.StageModule(ctx, d, archive, policy); err != nil {
		t.Fatal(err)
	}
	fact, err := store.Stage(ctx, d, data, policy)
	if err != nil {
		t.Fatal(err)
	}
	dead := cacheRetentionCatalog(t, policy, fact, true)
	partial := d.Clone()
	partial.Digest[0]++
	id := [32]byte{76}
	if err := store.BeginUpload(ctx, partial, id); err != nil {
		t.Fatal(err)
	}
	got := collectRetention(t, store, dead)
	if got.Sources != 1 || got.Modules != 0 {
		t.Fatal("shared module lost before partial upload publishes", got)
	}
	if _, _, err := store.ModuleArtifact(ctx, d.Tenant, archive.Pin); err != nil {
		t.Fatal(err)
	}
	// No invented timeout or abort: the unresolved upload keeps its modules.
	if collectRetention(t, store, dead).Modules != 0 {
		t.Fatal("unresolved module protection expired")
	}
}
func TestCheckerCacheGCFastPublishedAndReleasedInlineUseSurvivesSnapshot(t *testing.T) {
	store, _, _, _ := cacheRetentionFixture(t)
	ctx := context.Background()
	p := sourcePolicy()
	fact := stageRetentionSource(t, store, []byte("package checker\n"), p, [32]byte{78})
	book, err := NewCatalog(fact.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	book.d.Revision = 1
	book.d.Policies[p.Tenant] = []TenantPolicy{p}
	use := Use{Tenant: p.Tenant, ID: "fast-app", Kind: "app-binding", Principal: "alice", Node: "node", Owner: [32]byte{2}, Parent: [32]byte{3}, PolicyRevision: 1, Sources: []SourceFact{fact}}
	book, err = book.Reserve(use)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.Release(use)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := book.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeCatalog(encoded)
	if err != nil {
		t.Fatal(err)
	}
	// The collector never saw this Use live. The compact original FSM receipt
	// must still distinguish accepted-and-released from unpublished/unknown.
	if got := collectRetention(t, store, restored); got.Sources != 1 {
		t.Fatal("fast release lost publication proof", got)
	}
	if _, err := store.UploadedFact(ctx, fact.Descriptor(), *fact.Upload, true); !errors.Is(err, storage.ErrMissing) {
		t.Fatal(err)
	}
}
