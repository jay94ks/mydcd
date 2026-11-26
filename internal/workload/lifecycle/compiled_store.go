// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"

	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

const compiledPrefix = sourcePrefix + "compiled/"
const compiledMetaPrefix = compiledPrefix + "metadata/"
const compiledDataPrefix = compiledPrefix + "data/"
const collectionMetaPrefix = compiledPrefix + "collection/"
const compiledDiagnosticPrefix = compiledPrefix + "diagnostic/"
const maxCompiledEntries = 4096

var ErrCompiledCapacity = errors.New("tenant compiled cache capacity exhausted")
var ErrCompiledConflict = errors.New("original compiled recipe has different cached bytes")

func compiledObjectKey(tenant string, key [32]byte) string {
	return tenant + "/" + hex.EncodeToString(key[:])
}
func compiledCollectionKey(tenant string, job [32]byte) string { return compiledObjectKey(tenant, job) }
func compiledDiagnosticKey(tenant string, job, key [32]byte) string {
	return compiledCollectionKey(tenant, job) + "/" + hex.EncodeToString(key[:])
}

func (m *SourceStore) loadCompiled() error {
	rows, err := m.db.ScanBounded(compiledMetaPrefix, maxCompiledEntries, maxCompiledEntries*(MaxCompiledFactBytes+256))
	if err != nil {
		return err
	}
	compiled := map[string]CompiledFact{}
	sizes := map[string]uint64{}
	for key, raw := range rows {
		f, err := schema.Decode[CompiledFact](raw)
		if err != nil || f.Verify() != nil || f.Owner != m.identity.Node || f.Build.Cluster != m.identity.Cluster || key != compiledMetaPrefix+compiledObjectKey(f.Build.Recipe.Tenant, f.Build.Recipe.Key()) {
			return ErrSourceStore
		}
		id := key[len(compiledMetaPrefix):]
		compiled[id] = f
		cost := f.Build.Length + uint64(len(raw))
		if cost > math.MaxUint64-sizes[f.Build.Recipe.Tenant] {
			return ErrSourceStore
		}
		sizes[f.Build.Recipe.Tenant] += cost
	}
	for key, known := range m.compiled {
		actual, ok := compiled[key]
		if !ok || actual.Digest() != known.Digest() {
			return ErrSourceStore
		}
	}
	evictedRows, err := m.db.ScanBounded(evictedCompiledPrefix, maxCompiledEntries, maxCompiledEntries*320)
	if err != nil {
		return err
	}
	evicted := map[string][32]byte{}
	for key, raw := range evictedRows {
		id := key[len(evictedCompiledPrefix):]
		f, ok := compiled[id]
		digest := f.Digest()
		if !ok || len(raw) != 32 || !bytes.Equal(raw, digest[:]) {
			return ErrSourceStore
		}
		evicted[id] = f.Digest()
		if sizes[f.Build.Recipe.Tenant] < f.Build.Length {
			return ErrSourceStore
		}
		sizes[f.Build.Recipe.Tenant] -= f.Build.Length
	}
	data, err := m.db.SizesBounded(compiledDataPrefix, maxCompiledEntries, maxCompiledEntries*256)
	if err != nil || len(data)+len(evicted) != len(compiled) {
		return errors.Join(ErrSourceStore, err)
	}
	for key, f := range compiled {
		if _, gone := evicted[key]; gone {
			if _, exists := data[compiledDataPrefix+key]; exists {
				return ErrSourceStore
			}
			continue
		}
		if data[compiledDataPrefix+key] != f.Build.Length {
			return ErrSourceStore
		}
	}
	collections, err := m.db.SizesBounded(collectionMetaPrefix, maxBuildJobs, maxBuildJobs*256)
	if err != nil {
		return err
	}
	diagnostics, err := m.db.SizesBounded(compiledDiagnosticPrefix, maxCompiledEntries, maxCompiledEntries*384)
	if err != nil {
		return err
	}
	expected := map[string]uint64{}
	index := map[string][32]byte{}
	for key, size := range collections {
		if size == 0 || size > MaxCompiledCollectionBytes {
			return ErrSourceStore
		}
		raw, err := m.db.GetBounded(key, MaxCompiledCollectionBytes)
		if err != nil {
			return err
		}
		c, err := schema.Decode[CompiledCollection](raw)
		if err != nil || c.Verify() != nil || c.Cluster != m.identity.Cluster || c.Owner != m.identity.Node || key != collectionMetaPrefix+compiledCollectionKey(c.Tenant, c.Job) {
			return ErrSourceStore
		}
		index[key[len(collectionMetaPrefix):]] = c.Digest()
		for _, item := range c.Items {
			if item.Status == "cached" {
				f, ok := compiled[compiledObjectKey(c.Tenant, item.Key)]
				if !ok || f.Digest() != item.Cached {
					return ErrSourceStore
				}
			}
			if item.Diagnostic.StoredBytes > 0 {
				id := compiledDiagnosticPrefix + compiledDiagnosticKey(c.Tenant, c.Job, item.Key)
				expected[id] = item.Diagnostic.StoredBytes
				if item.Diagnostic.StoredBytes > math.MaxUint64-sizes[c.Tenant] {
					return ErrSourceStore
				}
				sizes[c.Tenant] += item.Diagnostic.StoredBytes
			}
		}
	}
	if len(diagnostics) != len(expected) {
		return ErrSourceStore
	}
	for key, size := range expected {
		if diagnostics[key] != size {
			return ErrSourceStore
		}
	}
	m.compiled, m.compiledBytes, m.collections, m.evicted = compiled, sizes, index, evicted
	m.compiledDiagnostics = len(expected)
	return nil
}

// Byte eviction is an explicit durable state, never inference from missing
// data. Validate the original fact/marker on lookup and exact rehydration.
func (m *SourceStore) evictedFact(id string) (CompiledFact, error) {
	expected, ok := m.evicted[id]
	if !ok {
		return CompiledFact{}, ErrSourceStore
	}
	raw, err := m.db.GetBounded(compiledMetaPrefix+id, MaxCompiledFactBytes)
	if err != nil {
		return CompiledFact{}, errors.Join(ErrSourceStore, err)
	}
	f, err := schema.Decode[CompiledFact](raw)
	if err != nil || f.Verify() != nil || f.Digest() != expected || f.Owner != m.identity.Node || f.Build.Cluster != m.identity.Cluster || compiledObjectKey(f.Build.Recipe.Tenant, f.Build.Recipe.Key()) != id {
		return CompiledFact{}, ErrSourceStore
	}
	marker, err := m.db.GetBounded(evictedCompiledPrefix+id, 32)
	if err != nil || !bytes.Equal(marker, expected[:]) {
		return CompiledFact{}, errors.Join(ErrSourceStore, err)
	}
	if _, err := m.db.GetBounded(compiledDataPrefix+id, 1); !errors.Is(err, storage.ErrMissing) {
		return CompiledFact{}, errors.Join(ErrSourceStore, err)
	}
	return f, nil
}

func (m *SourceStore) readCompiled(tenant string, key [32]byte) (CompiledFact, []byte, error) {
	id := compiledObjectKey(tenant, key)
	if _, evicted := m.evicted[id]; evicted {
		if _, err := m.evictedFact(id); err != nil {
			return CompiledFact{}, nil, err
		}
		return CompiledFact{}, nil, storage.ErrMissing
	}
	raw, err := m.readMetadata(compiledMetaPrefix+id, compiledDataPrefix+id, MaxCompiledFactBytes)
	if err != nil {
		if _, known := m.compiled[id]; known {
			return CompiledFact{}, nil, errors.Join(ErrSourceStore, err)
		}
		return CompiledFact{}, nil, err
	}
	f, err := schema.Decode[CompiledFact](raw)
	if err != nil || f.Verify() != nil || f.Owner != m.identity.Node || f.Build.Cluster != m.identity.Cluster || f.Build.Recipe.Tenant != tenant || f.Build.Recipe.Key() != key {
		return CompiledFact{}, nil, ErrSourceStore
	}
	data, err := m.db.GetBounded(compiledDataPrefix+id, MaxCompiledArtifactBytes)
	if err != nil || uint64(len(data)) != f.Build.Length || sha256.Sum256(data) != f.Build.Digest || verifyCompileELF(bytes.NewReader(data), f.Build.Recipe.GOARCH) != nil {
		clear(data)
		return CompiledFact{}, nil, errors.Join(ErrSourceStore, err)
	}
	return f, data, nil
}

// stageCompiled holds the same owner lock as root/module/collection writes.
// Data is an owned, already bounded slice. Native closure/current authority
// are proved by the consuming node adapter, never by a signature alone.
func (m *SourceStore) stageCompiled(ctx context.Context, d SourceDescriptor, p TenantPolicy, build CompiledBuild, data []byte, reserved uint64) (CompiledFact, error) {
	if m.closed || m.uncertain {
		return CompiledFact{}, ErrSourceUncertain
	}
	if ctx == nil || ctx.Err() != nil {
		return CompiledFact{}, context.Canceled
	}
	if !p.AllowsDescriptor(d) || build.Verify() != nil || build.Cluster != m.identity.Cluster || build.Recipe.Tenant != d.Tenant || build.Recipe.Source != d.ContentDigest() || build.Length != uint64(len(data)) || build.Digest != sha256.Sum256(data) || verifyCompileELF(bytes.NewReader(data), build.Recipe.GOARCH) != nil {
		return CompiledFact{}, ErrSourceStore
	}
	key := build.Recipe.Key()
	id := compiledObjectKey(d.Tenant, key)
	if original, gone := m.evicted[id]; gone {
		f, err := m.evictedFact(id)
		if err != nil {
			return CompiledFact{}, err
		}
		if original != f.Digest() || f.Build.Digest != build.Digest || f.Build.Length != build.Length {
			return CompiledFact{}, ErrCompiledConflict
		}
		usage, err := m.cacheUsage(d.Tenant)
		if err != nil {
			return CompiledFact{}, err
		}
		used := usage.compiled
		if used > p.CompiledCacheBytes || reserved > p.CompiledCacheBytes-used || build.Length > p.CompiledCacheBytes-used-reserved {
			return CompiledFact{}, ErrCompiledCapacity
		}
		if err := m.db.Write(map[string][]byte{compiledDataPrefix + id: data, evictedCompiledPrefix + id: nil}); err != nil {
			m.uncertain = true
			return CompiledFact{}, errors.Join(ErrSourceUncertain, err)
		}
		delete(m.evicted, id)
		m.compiledBytes[d.Tenant] += build.Length
		return f.Clone(), nil
	}
	f, old, err := m.readCompiled(d.Tenant, key)
	clear(old)
	_, known := m.compiled[id]
	if err == nil {
		if !known {
			return CompiledFact{}, ErrSourceStore
		}
		if f.Build.Digest != build.Digest || f.Build.Length != build.Length {
			return CompiledFact{}, ErrCompiledConflict
		}
		return f, nil // preserve original builder/job and cache signature
	}
	if known || !errors.Is(err, storage.ErrMissing) || errors.Is(err, ErrSourceStore) {
		return CompiledFact{}, errors.Join(ErrSourceStore, err)
	}
	usage, err := m.cacheUsage(d.Tenant)
	if err != nil {
		return CompiledFact{}, err
	}
	if usage.compiledEntries >= maxCompiledEntries {
		return CompiledFact{}, ErrCompiledCapacity
	}
	f = CompiledFact{Schema: 1, Owner: m.identity.Node, Build: build.Clone()}
	f.Signature = ed25519.Sign(m.private, CompiledFactBytes(f))
	raw, err := json.Marshal(f)
	if err != nil || f.Verify() != nil {
		return CompiledFact{}, ErrSourceStore
	}
	cost, used := build.Length+uint64(len(raw)), usage.compiled
	if used > p.CompiledCacheBytes || reserved > p.CompiledCacheBytes-used || cost > p.CompiledCacheBytes-used-reserved {
		return CompiledFact{}, ErrCompiledCapacity
	}
	if err := ctx.Err(); err != nil {
		return CompiledFact{}, err
	}
	if err := m.db.Write(map[string][]byte{compiledMetaPrefix + id: raw, compiledDataPrefix + id: data}); err != nil {
		m.uncertain = true
		return CompiledFact{}, errors.Join(ErrSourceUncertain, err)
	}
	m.compiled[id] = f.Clone()
	m.compiledBytes[d.Tenant] += cost
	return f, nil
}

// StageCompiled is receiver cache adoption, not a claim to be the builder.
// The original authenticated build signature is retained inside the local fact.
func (m *SourceStore) StageCompiled(ctx context.Context, d SourceDescriptor, p TenantPolicy, build CompiledBuild, data []byte) (CompiledFact, error) {
	if ctx == nil || len(data) == 0 || len(data) > MaxCompiledArtifactBytes || uint64(len(data)) != build.Length || build.Verify() != nil {
		return CompiledFact{}, ErrSourceStore
	}
	d, p, build, data = d.Clone(), p.Clone(), build.Clone(), bytes.Clone(data)
	defer clear(data)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stageCompiled(ctx, d, p, build, data, 0)
}

func (m *SourceStore) CompiledArtifact(ctx context.Context, tenant string, key [32]byte) (CompiledFact, []byte, error) {
	if ctx == nil || !name(tenant) || key == ([32]byte{}) {
		return CompiledFact{}, nil, ErrSourceStore
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.uncertain {
		return CompiledFact{}, nil, ErrSourceUncertain
	}
	if err := ctx.Err(); err != nil {
		return CompiledFact{}, nil, err
	}
	return m.readCompiled(tenant, key)
}
func (m *SourceStore) RecoverCompiled(ctx context.Context, tenant string, key [32]byte) (CompiledFact, error) {
	if ctx == nil || !name(tenant) || key == ([32]byte{}) {
		return CompiledFact{}, ErrSourceStore
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return CompiledFact{}, ErrSourceStore
	}
	if err := ctx.Err(); err != nil {
		return CompiledFact{}, err
	}
	if err := m.recover(); err != nil {
		return CompiledFact{}, err
	}
	f, data, err := m.readCompiled(tenant, key)
	clear(data)
	if err == nil || errors.Is(err, storage.ErrMissing) && !errors.Is(err, ErrSourceStore) {
		m.uncertain = false
	}
	return f, err
}

func (m *SourceStore) readCollection(tenant string, job [32]byte, verifyData bool) (CompiledCollection, error) {
	key := compiledCollectionKey(tenant, job)
	raw, err := m.db.GetBounded(collectionMetaPrefix+key, MaxCompiledCollectionBytes)
	if err != nil {
		if _, known := m.collections[key]; known || !errors.Is(err, storage.ErrMissing) {
			return CompiledCollection{}, errors.Join(ErrSourceStore, err)
		}
		return CompiledCollection{}, storage.ErrMissing
	}
	c, err := schema.Decode[CompiledCollection](raw)
	if err != nil || c.Verify() != nil || c.Cluster != m.identity.Cluster || c.Owner != m.identity.Node || c.Tenant != tenant || c.Job != job || m.collections[key] != c.Digest() {
		return CompiledCollection{}, ErrSourceStore
	}
	for _, item := range c.Items {
		if item.Status == "cached" {
			var fact CompiledFact
			_, evicted := m.evicted[compiledObjectKey(tenant, item.Key)]
			if verifyData && !evicted {
				var data []byte
				fact, data, err = m.readCompiled(tenant, item.Key)
				clear(data)
			} else {
				var ok bool
				fact, ok = m.compiled[compiledObjectKey(tenant, item.Key)]
				if !ok {
					err = ErrSourceStore
				}
			}
			if err != nil || fact.Digest() != item.Cached {
				return CompiledCollection{}, errors.Join(ErrSourceStore, err)
			}
		}
		if item.Diagnostic.StoredBytes > 0 {
			data, err := m.db.GetBounded(compiledDiagnosticPrefix+compiledDiagnosticKey(tenant, job, item.Key), 64<<10)
			valid := err == nil && uint64(len(data)) == item.Diagnostic.StoredBytes && sha256.Sum256(data) == item.Diagnostic.Stored
			clear(data)
			if !valid {
				return CompiledCollection{}, errors.Join(ErrSourceStore, err)
			}
		}
	}
	return c, nil
}

func (m *SourceStore) CompiledCollection(ctx context.Context, tenant string, job [32]byte) (CompiledCollection, error) {
	if ctx == nil || !name(tenant) || job == ([32]byte{}) {
		return CompiledCollection{}, ErrSourceStore
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return CompiledCollection{}, ErrSourceStore
	}
	if err := ctx.Err(); err != nil {
		return CompiledCollection{}, err
	}
	if err := m.recover(); err != nil {
		return CompiledCollection{}, err
	}
	c, err := m.readCollection(tenant, job, true)
	if err == nil || errors.Is(err, storage.ErrMissing) && !errors.Is(err, ErrSourceStore) {
		m.uncertain = false
	}
	return c, err
}

// Private diagnostics require the caller's original tenant/job read grant.
// The node adapter never publishes these bytes in ordinary app/status replies.
func (m *SourceStore) CompiledDiagnostic(ctx context.Context, tenant string, job, key [32]byte) ([]byte, error) {
	if ctx == nil || !name(tenant) || job == ([32]byte{}) || key == ([32]byte{}) {
		return nil, ErrSourceStore
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.uncertain {
		return nil, ErrSourceUncertain
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := m.readCollection(tenant, job, false)
	if err != nil {
		return nil, err
	}
	for _, item := range c.Items {
		if item.Key != key {
			continue
		}
		if item.Diagnostic.StoredBytes == 0 {
			return nil, storage.ErrMissing
		}
		return m.db.GetBounded(compiledDiagnosticPrefix+compiledDiagnosticKey(tenant, job, key), 64<<10)
	}
	return nil, storage.ErrMissing
}
