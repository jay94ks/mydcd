// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"math"
	"sync"
)

// SourceCacheBudget joins the original SourceStore namespaces of ONE logical
// node. Runtime opens all current/historical stores with the same zero-value
// group during startup, before serving IO. It owns no DB, key, quota policy or
// second accounting log: admission derives usage from the loaded stores.
// Closing one namespace does not free its still-persisted cache bytes.
// A failed joined open requires abandoning that startup group and reopening
// the original stores; its unmeasured durable state is never treated as free.
type SourceCacheBudget struct {
	mu      sync.Mutex
	cluster [32]byte
	stores  []*SourceStore
	failed  bool
}

// The zero value keeps existing standalone SourceStore test/diagnostic values
// usable. A constructed store switches to its immutable group lock before it
// is published. Every existing read/write/GC/recovery uses that SAME mutex;
// there is no store->group/group->store lock order or nested member lock.
type sourceCacheLock struct {
	local sync.Mutex
	group *sync.Mutex
}

func (m *sourceCacheLock) Lock() {
	if m.group != nil {
		m.group.Lock()
	} else {
		m.local.Lock()
	}
}
func (m *sourceCacheLock) Unlock() {
	if m.group != nil {
		m.group.Unlock()
	} else {
		m.local.Unlock()
	}
}
func (m *sourceCacheLock) TryLock() bool {
	if m.group != nil {
		return m.group.TryLock()
	}
	return m.local.TryLock()
}

type sourceCacheUsage struct {
	source, compiled, preparation                                          uint64
	sourceEntries, compiledEntries, collections, diagnostics, preparations uint64
}

func cacheUsageAdd(total *uint64, n uint64) error {
	if n > math.MaxUint64-*total {
		return ErrSourceUncertain
	}
	*total += n
	return nil
}

// Caller holds m.mu, which is every member's group mutex. Per-store counters
// stay local; adding global usage back into one member would double charge it.
// Any uncertain participant blocks fresh allocation even if its current maps
// omit bytes from an incompletely acknowledged write or partial recovery.
func (m *SourceStore) cacheUsage(tenant string) (sourceCacheUsage, error) {
	var out sourceCacheUsage
	stores := []*SourceStore{m}
	if m.cacheBudget != nil {
		if m.cacheBudget.failed {
			return out, ErrSourceUncertain
		}
		stores = m.cacheBudget.stores
	}
	for _, store := range stores {
		if store.uncertain {
			return sourceCacheUsage{}, ErrSourceUncertain
		}
		for _, item := range []struct {
			total *uint64
			n     uint64
		}{
			{&out.source, store.bytes[tenant]}, {&out.compiled, store.compiledBytes[tenant]},
			{&out.preparation, store.preparationBytes},
			{&out.sourceEntries, uint64(len(store.entries)) + uint64(len(store.modules))},
			{&out.compiledEntries, uint64(len(store.compiled))}, {&out.collections, uint64(len(store.collections))},
			{&out.diagnostics, uint64(store.compiledDiagnostics)}, {&out.preparations, uint64(len(store.preparations))},
		} {
			if err := cacheUsageAdd(item.total, item.n); err != nil {
				return sourceCacheUsage{}, err
			}
		}
	}
	return out, nil
}
