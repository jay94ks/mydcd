// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jay94ks/seafield/internal/storage"
)

func groupedSourceStore(t *testing.T, group *SourceCacheBudget, cluster [32]byte, seed byte) (*SourceStore, *storage.DB, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenSourcesInCacheBudget(db, cluster, key, group)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(); _ = db.Close(); clear(key) })
	return store, db, key
}

func TestCheckerSourceCacheBudgetSumsOriginalOwnerNamespacesAndKeepsTenantIsolation(t *testing.T) {
	for _, kind := range []string{"source-source", "module-source", "source-module"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			group := &SourceCacheBudget{}
			old, _, _ := groupedSourceStore(t, group, [32]byte{1}, 31)
			current, db, _ := groupedSourceStore(t, group, [32]byte{1}, 32)
			policy := sourcePolicy()
			policy.Resolver.SourceCacheBytes = MaxScriptBytes
			root := bytes.Repeat([]byte("a"), 200<<10)
			d := sourceDescriptor("tenant", root)
			archive := moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte("package safe\n"), "LICENSE": bytes.Repeat([]byte("x"), 120<<10)})
			modulePolicy, moduleRoot, _ := resolverInput([]byte("package checker\n"), []ModuleArchive{archive}, "example.invalid/safe")
			modulePolicy.Resolver.SourceCacheBytes = MaxScriptBytes
			if kind == "module-source" {
				original, err := old.StageModule(ctx, moduleRoot, archive, modulePolicy)
				if err != nil {
					t.Fatal(err)
				}
				remaining := policy.Resolver.SourceCacheBytes - old.bytes["tenant"]
				other := bytes.Repeat([]byte("b"), int(remaining+1))
				if _, err = current.Stage(ctx, sourceDescriptor("tenant", other), other, policy); err == nil {
					t.Fatal("new key reset original ZIP/expanded/metadata budget")
				}
				recovered, err := old.RecoverModule(ctx, "tenant", archive.Pin)
				if err != nil || !bytes.Equal(recovered.Signature, original.Signature) {
					t.Fatal("original module fact changed", err)
				}
			} else {
				original, err := old.Stage(ctx, d, root, policy)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "source-module" {
					if _, err = current.StageModule(ctx, moduleRoot, archive, modulePolicy); err == nil {
						t.Fatal("new key ignored historical source bytes")
					}
				} else {
					// Exact same digest in another physical namespace still requires its
					// own bytes/fact; a matching old digest cannot make that allocation free.
					if _, err = current.Stage(ctx, d, root, policy); err == nil {
						t.Fatal("physical copy in new owner namespace was uncharged")
					}
				}
				again, err := old.Stage(ctx, d, root, policy)
				if err != nil || !bytes.Equal(again.Signature, original.Signature) {
					t.Fatal("idempotent original was reallocated", err)
				}
			}
			if len(current.entries) != 0 || len(current.modules) != 0 {
				t.Fatal("rejected quota partly published current cache")
			}
			if _, err := db.Get(sourceMetaPrefix + sourceObjectKey(d)); !errors.Is(err, storage.ErrMissing) {
				t.Fatal("rejected source wrote metadata", err)
			}
			other := bytes.Repeat([]byte("z"), 32<<10)
			otherDescriptor := sourceDescriptor("other", other)
			otherPolicy := policy.Clone()
			otherPolicy.Tenant = "other"
			if _, err := current.Stage(ctx, otherDescriptor, other, otherPolicy); err != nil {
				t.Fatal("unrelated tenant's byte allowance was consumed", err)
			}
			if current.bytes["tenant"] != 0 || current.bytes["other"] == 0 {
				t.Fatal("global sum was stored in local tenant counters")
			}
		})
	}
}

// Bulk signed input simulates an already populated historical DB, avoiding
// thousands of unrelated fsync calls. Open/recover validates these original
// facts; fresh admission below always calls the real Stage/StageModule core.
func persistedSourceRows(t *testing.T, store *SourceStore, db *storage.DB, key ed25519.PrivateKey, n int) SourceDescriptor {
	t.Helper()
	rows := map[string][]byte{}
	var first SourceDescriptor
	for i := 0; i < n; i++ {
		data := []byte(fmt.Sprintf("package checker // original-%d\n", i))
		d := sourceDescriptor("tenant", data)
		if i == 0 {
			first = d
		}
		fact := SourceFact{Schema: 1, Cluster: store.identity.Cluster, Owner: store.identity.Node, Tenant: d.Tenant, SDK: d.SDK, Digest: d.Digest, Length: d.Length}
		fact.Signature = ed25519.Sign(key, SourceFactBytes(fact))
		raw, err := json.Marshal(fact)
		if err != nil || fact.Verify() != nil {
			t.Fatal("invalid persisted historical fixture", err)
		}
		id := sourceObjectKey(d)
		rows[sourceMetaPrefix+id] = raw
		rows[sourcePrefix+"data/"+id] = data
	}
	if err := db.Write(rows); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Recover(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	return first
}
func TestCheckerSourceCacheBudgetKeyChangeDoesNotResetEntryCapOrFreeClosedBytes(t *testing.T) {
	ctx := context.Background()
	group := &SourceCacheBudget{}
	old, oldDB, key := groupedSourceStore(t, group, [32]byte{1}, 33)
	current, _, currentKey := groupedSourceStore(t, group, [32]byte{1}, 34)
	first := persistedSourceRows(t, old, oldDB, key, maxSourceEntries-1)
	archive := moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte("package safe\n")})
	policy, d, _ := resolverInput([]byte("package checker\n"), []ModuleArchive{archive}, "example.invalid/safe")
	policy.Resolver.SourceCacheBytes = 64 << 20
	module, err := current.StageModule(ctx, d, archive, policy)
	if err != nil {
		t.Fatal("last shared cache slot unavailable", err)
	}
	raw := []byte("package checker // one too many\n")
	descriptor := sourceDescriptor("tenant", raw)
	if _, err = current.Stage(ctx, descriptor, raw, policy); err == nil {
		t.Fatal("new owner reset node source/module entry limit")
	}
	if hit, err := current.StageModule(ctx, d, archive, policy); err != nil || !bytes.Equal(hit.Signature, module.Signature) {
		t.Fatal("full cache prevented exact module reuse", err)
	}
	original, err := old.Recover(ctx, first)
	if err != nil || original.Owner != old.identity.Node {
		t.Fatal(err)
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = current.Stage(ctx, descriptor, raw, policy); err == nil {
		t.Fatal("closing historical namespace freed its persisted cache")
	}
	if err = current.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen all original namespaces into a fresh startup group. No key/fact or
	// per-DB identity is replaced; only their common admission lock is new.
	nextGroup := &SourceCacheBudget{}
	reopened, err := OpenSourcesInCacheBudget(oldDB, old.identity.Cluster, key, nextGroup)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := OpenSourcesInCacheBudget(current.db, current.identity.Cluster, currentKey, nextGroup)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err = next.Stage(ctx, descriptor, raw, policy); err == nil {
		t.Fatal("startup with historical/current DB reset aggregate entry cap")
	}
	restored, err := reopened.Recover(ctx, first)
	if err != nil || !bytes.Equal(restored.Signature, original.Signature) {
		t.Fatal("reopen replaced historical signed fact", err)
	}
}

func TestCheckerSourceCacheBudgetUncertainWriteBlocksFreshAllocationUntilOriginalRecovery(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			ctx := context.Background()
			group := &SourceCacheBudget{}
			old, db, key := groupedSourceStore(t, group, [32]byte{1}, 35)
			current, _, _ := groupedSourceStore(t, group, [32]byte{1}, 36)
			policy := sourcePolicy()
			policy.Resolver.SourceCacheBytes = MaxScriptBytes
			existing := []byte("package checker // current\n")
			existingDescriptor := sourceDescriptor("tenant", existing)
			currentFact, err := current.Stage(ctx, existingDescriptor, existing, policy)
			if err != nil {
				t.Fatal(err)
			}
			pending := bytes.Repeat([]byte("p"), 200<<10)
			d := sourceDescriptor("tenant", pending)
			id := [32]byte{9}
			if err = old.BeginUpload(ctx, d, id); err != nil {
				t.Fatal(err)
			}
			release, err := old.HoldUpload(ctx, d, id, false)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			// Simulate a DB commit whose acknowledgement was lost. The same real DB,
			// sync/recovery and original hold are used; no second quota algorithm is
			// injected, and no cache counter is fabricated to hide the pending bytes.
			var original SourceFact
			if committed {
				original = SourceFact{Schema: 1, Cluster: old.identity.Cluster, Owner: old.identity.Node, Tenant: d.Tenant, SDK: d.SDK, Digest: d.Digest, Length: d.Length}
				original.Signature = ed25519.Sign(key, SourceFactBytes(original))
				raw, _ := json.Marshal(original)
				if err = db.Write(map[string][]byte{sourceMetaPrefix + sourceObjectKey(d): raw, sourcePrefix + "data/" + sourceObjectKey(d): pending}); err != nil {
					t.Fatal(err)
				}
			}
			old.mu.Lock()
			old.uncertain = true
			old.mu.Unlock()
			next := bytes.Repeat([]byte("n"), 100<<10)
			nextDescriptor := sourceDescriptor("tenant", next)
			if _, err = current.Stage(ctx, nextDescriptor, next, policy); !errors.Is(err, ErrSourceUncertain) {
				t.Fatal("another namespace spent unmeasured pending bytes", err)
			}
			if _, err = old.Stage(ctx, d, pending, policy); !errors.Is(err, ErrSourceUncertain) {
				t.Fatal("own uncertain write bypassed explicit Recover", err)
			}
			hit, err := current.Stage(ctx, existingDescriptor, existing, policy)
			if err != nil || !bytes.Equal(hit.Signature, currentFact.Signature) {
				t.Fatal("another namespace's exact hit allocated new bytes", err)
			}
			if _, err = current.Recover(ctx, existingDescriptor); err != nil {
				t.Fatal(err)
			}
			if _, err = current.Stage(ctx, nextDescriptor, next, policy); !errors.Is(err, ErrSourceUncertain) {
				t.Fatal("recovering unrelated namespace cleared original uncertainty", err)
			}
			recovered, err := old.Recover(ctx, d)
			if !committed {
				if !errors.Is(err, storage.ErrMissing) {
					t.Fatal("uncommitted original became available", err)
				}
				if _, err = current.Stage(ctx, nextDescriptor, next, policy); err != nil {
					t.Fatal("positive original missing did not release admission fence", err)
				}
				return
			}
			if err != nil || !bytes.Equal(recovered.Signature, original.Signature) {
				t.Fatal("original unknown commit changed receipt", err)
			}
			if _, err = current.Stage(ctx, nextDescriptor, next, policy); err == nil || errors.Is(err, ErrSourceUncertain) {
				t.Fatal("recovered original was not charged as known bytes", err)
			}
			uploaded, err := old.UploadedFact(ctx, d, id, false)
			if err != nil {
				t.Fatal(err)
			}
			dead := cacheRetentionCatalog(t, policy, uploaded, true)
			if got := collectRetention(t, old, dead); got.Sources != 0 {
				t.Fatal("unsettled original upload lost GC protection", got)
			}
			if _, err = current.Stage(ctx, nextDescriptor, next, policy); err == nil {
				t.Fatal("protected old bytes were counted free")
			}
			release()
			if got := collectRetention(t, old, dead); got.Sources != 1 {
				t.Fatal("settled original not collected", got)
			}
			if _, err = current.Stage(ctx, nextDescriptor, next, policy); err != nil {
				t.Fatal("actual GC did not make shared capacity available", err)
			}
		})
	}
}

func TestCheckerSourceCacheBudgetConcurrentAdmissionsShareAtomicQuota(t *testing.T) {
	group := &SourceCacheBudget{}
	a, _, _ := groupedSourceStore(t, group, [32]byte{1}, 37)
	b, _, _ := groupedSourceStore(t, group, [32]byte{1}, 38)
	policy := sourcePolicy()
	policy.Resolver.SourceCacheBytes = MaxScriptBytes
	begin := make(chan struct{})
	result := make(chan error, 2)
	var wg sync.WaitGroup
	for i, store := range []*SourceStore{a, b} {
		wg.Add(1)
		go func(i int, store *SourceStore) {
			defer wg.Done()
			<-begin
			data := bytes.Repeat([]byte{byte('a' + i)}, 200<<10)
			_, err := store.Stage(context.Background(), sourceDescriptor("tenant", data), data, policy)
			result <- err
		}(i, store)
	}
	close(begin)
	wg.Wait()
	close(result)
	accepted := 0
	for err := range result {
		if err == nil {
			accepted++
		}
	}
	if accepted != 1 || a.bytes["tenant"]+b.bytes["tenant"] > policy.Resolver.SourceCacheBytes {
		t.Fatal("concurrent original namespaces both spent the same capacity", accepted)
	}
}
