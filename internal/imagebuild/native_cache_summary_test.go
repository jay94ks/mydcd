// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestCacheInventoryUsesOriginalObservationWhenRepresentativeHasNeverStarted(t *testing.T) {
	f, sdk, _ := cacheCleanupFixture(t)
	if _, err := f.jobs.sampleCacheUsage(context.Background(), f.spec, sdk); err != nil {
		t.Fatal(err)
	}
	queued := f.spec.Own()
	queued.ID = "new-queued-representative"
	if _, err := f.jobs.Record(queued); err != ErrNativeMissing {
		t.Fatal("fixture unexpectedly has a new native job", err)
	}
	summary, err := f.jobs.ReadCacheSummary(queued)
	if err != nil || !summary.Available || !summary.Recorded || !summary.Allocated || !summary.Borrowed || summary.ObservedBy != f.spec.Digest() || summary.Count != 3 || summary.ReportedBytes != 51 {
		t.Fatal(summary, err)
	}
	items, err := f.jobs.ReadCacheScope(queued, 0, [32]byte{})
	if err != nil || !items.Available || items.ObservedBy != f.spec.Digest() || len(items.Entries) != 3 || items.Snapshot != summary.Snapshot {
		t.Fatal("queued representative hid original items", items, err)
	}
	f.reopen()
	if restored, err := f.jobs.ReadCacheSummary(queued); err != nil || restored.Snapshot != summary.Snapshot {
		t.Fatal("original cache lost after reopen", restored, err)
	}
	other := queued.Own()
	other.Policy.BuilderImage = "docker.io/moby/buildkit@sha256:" + strings.Repeat("b", 64)
	var before int
	if err := f.db.View(func(tx *bolt.Tx) error { before = tx.Bucket(nativeBucket).Stats().KeyN; return nil }); err != nil {
		t.Fatal(err)
	}
	empty, err := f.jobs.ReadCacheSummary(other)
	if err != nil || empty.Recorded || empty.Allocated || empty.Available || empty.Borrowed {
		t.Fatal("new scope invented an actual cache", empty, err)
	}
	if err := f.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(nativeBucket).Stats().KeyN != before {
			t.Error("read materialized native state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(nativeBucket).Delete(nativeKey(f.spec)) }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.ReadCacheSummary(queued); err == nil {
		t.Fatal("observation with missing original job silently accepted")
	}
	if _, err := f.jobs.ReadCacheScope(queued, 0, [32]byte{}); err != ErrStorage {
		t.Fatal("scope read fabricated unobserved cache after original loss", err)
	}
	if _, err := f.jobs.ReadCacheUsage(f.spec, 0, [32]byte{}); err != ErrStorage {
		t.Fatal("job read fabricated unobserved cache after original loss", err)
	}
}
