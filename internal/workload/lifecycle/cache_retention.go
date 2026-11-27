// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

const uploadPrefix = sourcePrefix + "upload/"
const seenPrefix = sourcePrefix + "published/"
const evictedCompiledPrefix = compiledPrefix + "evicted/"
const maxRetentionBytes = 32 << 20

// UploadHold is local, durable protection for one original authenticated upload.
// Consumed is a floor, never an instruction to repeat a send. There is no TTL:
// a disconnect or expired login cannot prove that publication did not happen.
type UploadHold struct {
	Schema   uint8
	ID       [32]byte
	Source   SourceDescriptor
	Consumed bool
}

func uploadKey(tenant string, id [32]byte) string { return tenant + "/" + hex.EncodeToString(id[:]) }
func (h UploadHold) valid() bool {
	return h.Schema == 1 && h.ID != ([32]byte{}) && h.Source.Validate() == nil
}
func (m *SourceStore) loadCacheRetention() error {
	index := map[string][32]byte{}
	rows, err := m.db.ScanBounded(uploadPrefix, maxSourceEntries, maxRetentionBytes)
	if err != nil {
		return err
	}
	for key, raw := range rows {
		index[key] = sha256.Sum256(raw)
		h, err := schema.Decode[UploadHold](raw)
		if err != nil || !h.valid() || key != uploadPrefix+uploadKey(h.Source.Tenant, h.ID) {
			return ErrSourceStore
		}
	}
	seen, err := m.db.ScanBounded(seenPrefix, maxSourceEntries, maxRetentionBytes)
	if err != nil {
		return err
	}
	for key, raw := range seen {
		index[key] = sha256.Sum256(raw)
		d, err := schema.Decode[SourceDescriptor](raw)
		if err != nil || d.Validate() != nil || key != seenPrefix+sourceObjectKey(d) {
			return ErrSourceStore
		}
	}
	for key, old := range m.retentionExpected {
		actual, present := index[key]
		if present && actual == old {
			continue
		}
		next, writing := m.retentionPending[key]
		if !writing || next == nil && present || next != nil && (!present || actual != *next) {
			return ErrSourceStore
		}
	}
	for key, next := range m.retentionPending {
		if _, known := m.retentionExpected[key]; known {
			continue
		}
		if actual, present := index[key]; present && (next == nil || actual != *next) {
			return ErrSourceStore
		}
	}
	m.retentionExpected = index
	m.retentionPending = nil
	return nil
}
func (m *SourceStore) writeRetention(changes map[string][]byte) error {
	pending := map[string]*[32]byte{}
	for key, raw := range changes {
		if !strings.HasPrefix(key, uploadPrefix) && !strings.HasPrefix(key, seenPrefix) {
			continue
		}
		if raw == nil {
			pending[key] = nil
		} else {
			digest := sha256.Sum256(raw)
			pending[key] = &digest
		}
	}
	m.retentionPending = pending
	if err := m.db.Write(changes); err != nil {
		m.uncertain = true
		return errors.Join(ErrSourceUncertain, err)
	}
	for key, next := range pending {
		if next == nil {
			delete(m.retentionExpected, key)
		} else {
			m.retentionExpected[key] = *next
		}
	}
	m.retentionPending = nil
	return nil
}

func (m *SourceStore) readUpload(d SourceDescriptor, id [32]byte) (UploadHold, error) {
	key := uploadPrefix + uploadKey(d.Tenant, id)
	raw, err := m.db.GetBounded(key, 17<<10)
	known, exists := m.retentionExpected[key]
	if err != nil {
		if exists {
			return UploadHold{}, errors.Join(ErrSourceStore, err)
		}
		return UploadHold{}, err
	}
	if exists && sha256.Sum256(raw) != known {
		return UploadHold{}, ErrSourceStore
	}
	h, err := schema.Decode[UploadHold](raw)
	if err != nil || !h.valid() || h.ID != id || h.Source.ContentDigest() != d.ContentDigest() {
		return UploadHold{}, ErrSourceStore
	}
	return h, nil
}

// BeginUpload runs before the receiver accepts input bytes, including modules.
func (m *SourceStore) BeginUpload(ctx context.Context, d SourceDescriptor, id [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || d.Validate() != nil || id == ([32]byte{}) {
		return ErrSourceStore
	}
	if m.closed || m.uncertain {
		return ErrSourceUncertain
	}
	h, err := m.readUpload(d, id)
	if err == nil {
		if h.Consumed {
			return ErrReference
		}
		return nil
	}
	if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	rows, err := m.db.SizesBounded(uploadPrefix, maxSourceEntries, maxSourceEntries*256)
	if err != nil || len(rows) >= maxSourceEntries {
		return errors.Join(ErrSourceStore, err)
	}
	h = UploadHold{Schema: 1, ID: id, Source: d.Clone()}
	raw, _ := json.Marshal(h)
	var size uint64
	for _, n := range rows {
		size += n
	}
	if size+uint64(len(raw)) > maxRetentionBytes {
		return ErrSourceStore
	}
	if err = m.writeRetention(map[string][]byte{uploadPrefix + uploadKey(d.Tenant, id): raw}); err != nil {
		m.uncertain = true
		return errors.Join(ErrSourceUncertain, err)
	}
	return nil
}

// HoldUpload covers the receiver's entire stream, not merely the final write.
// The durable hold was established before this in-memory join fence.
func (m *SourceStore) HoldUpload(ctx context.Context, d SourceDescriptor, id [32]byte, recover bool) (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || d.Validate() != nil || id == ([32]byte{}) || m.closed {
		return nil, ErrSourceStore
	}
	if recover {
		if err := m.recover(); err != nil {
			return nil, err
		}
		m.uncertain = false
	}
	if m.uncertain {
		return nil, ErrSourceUncertain
	}
	h, err := m.readUpload(d, id)
	if err != nil {
		return nil, err
	}
	if h.Consumed && !recover {
		return nil, ErrReference
	}
	if m.busy == nil {
		m.busy = map[string]int{}
	}
	key := sourceObjectKey(d)
	m.busy[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.busy[key]--
			if m.busy[key] == 0 {
				delete(m.busy, key)
			}
		})
	}, nil
}

// UploadedFact reads durable bytes under the original hold; deterministic
// signatures preserve recovery without persisting another copy of the source.
func (m *SourceStore) UploadedFact(ctx context.Context, d SourceDescriptor, id [32]byte, recover bool) (SourceFact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || d.Validate() != nil || id == ([32]byte{}) || m.closed {
		return SourceFact{}, ErrSourceStore
	}
	if recover {
		if err := m.recover(); err != nil {
			return SourceFact{}, err
		}
		m.uncertain = false
	}
	if m.uncertain {
		return SourceFact{}, ErrSourceUncertain
	}
	h, err := m.readUpload(d, id)
	if err != nil {
		return SourceFact{}, err
	}
	// A consumed hold can be queried, but BeginUpload never reopens it.
	f, data, err := m.read(d)
	clear(data)
	if err != nil {
		return SourceFact{}, err
	}
	token := h.ID
	f.Upload = &token
	f.Signature = ed25519.Sign(m.private, SourceFactBytes(f))
	return f, nil
}

// CacheReference protects an original local use independently of newer shared
// permissions. The runtime supplies unresolved runs/execs/preparations here.
type CacheReference struct {
	Tenant  string
	Content [32]byte
}
type CacheRetention struct {
	Catalog Catalog
	Local   []CacheReference
}
type CacheCollection struct {
	Sources, Modules, Compiled int
	Bytes                      uint64
}

// CollectCache serializes with staging/materialization/collection. The callback
// obtains a CURRENT quorum fence while this owner lock is held. It must not
// call back into SourceStore or CompilerOwner. No local/stale view permits GC.
func (m *SourceStore) CollectCache(ctx context.Context, current func(context.Context) (CacheRetention, error)) (CacheCollection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out CacheCollection
	if ctx == nil || current == nil {
		return out, ErrSourceStore
	}
	if m.closed || m.uncertain {
		return out, ErrSourceUncertain
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	// Verify inventories before treating absence as eligibility. A write error
	// leaves this owner uncertain; recovery must reload the same durable state.
	if err := m.recover(); err != nil {
		return out, err
	}
	roots, err := current(ctx)
	if err != nil {
		return out, err
	}
	c := roots.Catalog
	if c.Cluster() != m.identity.Cluster || c.Validate() != nil {
		return out, ErrSourceStore
	}
	live := map[string]bool{}
	for key, n := range m.busy {
		if n > 0 {
			live[key] = true
		}
	}
	published := map[string]SourceDescriptor{}
	remember := func(f SourceFact, keep bool) {
		d := f.Descriptor()
		key := sourceObjectKey(d)
		published[key] = d
		if keep {
			live[key] = true
		}
	}
	for _, r := range c.d.Scripts {
		for _, v := range r.Versions {
			remember(v.Source, !v.Deleted)
		}
	}
	for _, u := range c.d.Uses {
		for _, f := range u.Sources {
			remember(f, true)
		}
		for _, ref := range u.Scripts {
			v, ok := c.version(u.Tenant, ref)
			if !ok {
				return out, ErrSourceStore
			}
			remember(v.Source, true)
		}
	}
	for _, j := range c.d.Builds {
		if j.Phase != "closed" {
			for _, f := range j.Intent.Selection.Sources {
				remember(f, true)
			}
			for _, ref := range j.Intent.Selection.Scripts {
				v, ok := c.version(j.Intent.Tenant, ref)
				if !ok {
					return out, ErrSourceStore
				}
				remember(v.Source, true)
			}
		}
	}
	compilerRefs, err := m.localCompilerCacheReferences()
	if err != nil {
		return out, err
	}
	roots.Local = append(roots.Local, compilerRefs...)
	for _, ref := range roots.Local {
		if !name(ref.Tenant) || ref.Content == ([32]byte{}) {
			return out, ErrSourceStore
		}
		live[ref.Tenant+"/"+hex.EncodeToString(ref.Content[:])] = true
	}
	for key, content := range c.d.Publications {
		tenant, ok := publicationTenant(key)
		if !ok {
			return out, ErrSourceStore
		}
		id := tenant + "/" + hex.EncodeToString(content[:])
		if f, ok := m.entries[id]; ok {
			published[id] = f.Descriptor()
		}
	}
	wasPublished := func(h UploadHold) bool {
		return c.d.Publications[publicationKey(h.Source.Tenant, m.identity.Node, h.ID)] == h.Source.ContentDigest()
	}
	changes := map[string][]byte{}
	seen, err := m.db.ScanBounded(seenPrefix, maxSourceEntries, maxRetentionBytes)
	if err != nil {
		return out, err
	}
	for key, raw := range seen {
		d, e := schema.Decode[SourceDescriptor](raw)
		if e != nil || d.Validate() != nil || key != seenPrefix+sourceObjectKey(d) {
			return out, ErrSourceStore
		}
		published[sourceObjectKey(d)] = d
	}
	// Only locally present content needs a historical publication marker. This
	// does not grow once bytes are collected; tombstones stay in the Raft catalog.
	for key, f := range m.entries {
		if _, ok := published[key]; ok {
			if _, exists := seen[seenPrefix+key]; !exists {
				raw, _ := json.Marshal(f.Descriptor())
				changes[seenPrefix+key] = raw
			}
		}
	}
	holds, err := m.db.ScanBounded(uploadPrefix, maxSourceEntries, maxRetentionBytes)
	if err != nil {
		return out, err
	}
	for key, raw := range holds {
		h, e := schema.Decode[UploadHold](raw)
		if e != nil || !h.valid() || key != uploadPrefix+uploadKey(h.Source.Tenant, h.ID) {
			return out, ErrSourceStore
		}
		if !h.Consumed && wasPublished(h) {
			h.Consumed = true
			value, _ := json.Marshal(h)
			changes[key] = value
		}
		if !h.Consumed {
			live[sourceObjectKey(h.Source)] = true
		}
	}
	// Every remaining root and pending upload protects its full module lock.
	keepModules := map[string]bool{}
	moduleCandidates := map[string]bool{}
	for key, d := range published {
		for _, pin := range d.Modules {
			moduleCandidates[moduleObjectKey(d.Tenant, pin)] = true
		}
		if live[key] {
			for _, pin := range d.Modules {
				keepModules[moduleObjectKey(d.Tenant, pin)] = true
			}
		}
	}
	for _, raw := range holds {
		h, _ := schema.Decode[UploadHold](raw)
		if !h.Consumed && !wasPublished(h) {
			for _, pin := range h.Source.Modules {
				keepModules[moduleObjectKey(h.Source.Tenant, pin)] = true
			}
		}
	}
	for key, f := range m.entries {
		if _, known := published[key]; !known || live[key] {
			for _, pin := range f.Modules {
				keepModules[moduleObjectKey(f.Tenant, pin)] = true
			}
			continue
		}
		changes[sourceMetaPrefix+key] = nil
		changes[sourcePrefix+"data/"+key] = nil
		changes[seenPrefix+key] = nil
		out.Sources++
		out.Bytes += f.Length
	}
	for key, f := range m.modules {
		if moduleCandidates[key] && !keepModules[key] {
			changes[moduleMetaPrefix+key] = nil
			changes[moduleDataPrefix+key] = nil
			out.Modules++
			out.Bytes += f.Module.Length
		}
	}
	for key, f := range m.compiled {
		root := f.Build.Recipe.Tenant + "/" + hex.EncodeToString(f.Build.Recipe.Source[:])
		if _, known := published[root]; !known || live[root] {
			continue
		}
		if _, evicted := m.evicted[key]; evicted {
			continue
		}
		// Keep the signed fact and collection/diagnostics as historical evidence.
		digest := f.Digest()
		changes[evictedCompiledPrefix+key] = digest[:]
		changes[compiledDataPrefix+key] = nil
		out.Compiled++
		out.Bytes += f.Build.Length
	}
	if err := ctx.Err(); err != nil {
		return CacheCollection{}, err
	}
	if len(changes) == 0 {
		return out, nil
	}
	if err = m.writeRetention(changes); err != nil {
		m.uncertain = true
		return CacheCollection{}, errors.Join(ErrSourceUncertain, err)
	}
	if err = m.load(); err != nil {
		m.uncertain = true
		return CacheCollection{}, errors.Join(ErrSourceUncertain, err)
	}
	return out, nil
}
