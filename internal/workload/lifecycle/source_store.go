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
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

var ErrSourceStore = errors.New("lifecycle source artifact unavailable or inconsistent")
var ErrSourceUncertain = errors.New("original lifecycle source persistence requires recovery")

const sourcePrefix = "checker/source/"
const sourceMetaPrefix = sourcePrefix + "metadata/"
const maxSourceEntries = 4096

type sourceStoreIdentity struct {
	Schema        uint8
	Cluster, Node [32]byte
}

// SourceStore uses an existing node DB. Facts and bytes publish atomically;
// Close only closes this owner and clears its key, never the borrowed DB.
// Automatic collection joins current shared references and durable upload holds.
// Publication uncertainty and original build evidence survive byte eviction.
type SourceStore struct {
	mu                  sourceCacheLock
	cacheBudget         *SourceCacheBudget
	editor              chan struct{}
	db                  *storage.DB
	identity            sourceStoreIdentity
	private             ed25519.PrivateKey
	entries             map[string]SourceFact
	modules             map[string]ModuleFact
	bytes               map[string]uint64
	compiled            map[string]CompiledFact
	evicted             map[string][32]byte
	compiledBytes       map[string]uint64
	collections         map[string][32]byte
	compiledDiagnostics int
	busy                map[string]int
	retentionExpected   map[string][32]byte
	retentionPending    map[string]*[32]byte
	preparations        map[string][32]byte
	preparationWrites   map[string][32]byte
	preparationBytes    uint64
	closed, uncertain   bool
}

func sourceObjectKey(d SourceDescriptor) string {
	digest := d.ContentDigest()
	return d.Tenant + "/" + hex.EncodeToString(digest[:])
}

// OpenSources preserves the original single-namespace constructor.
func OpenSources(db *storage.DB, cluster [32]byte, private ed25519.PrivateKey) (*SourceStore, error) {
	return OpenSourcesInCacheBudget(db, cluster, private, &SourceCacheBudget{})
}

// OpenSourcesInCacheBudget opens an unchanged original namespace in the node's
// startup group. Facts, identity checks, recovery and DB ownership are unchanged.
// All namespaces must be opened before Runtime exposes any of them for IO.
func OpenSourcesInCacheBudget(db *storage.DB, cluster [32]byte, private ed25519.PrivateKey, budget *SourceCacheBudget) (*SourceStore, error) {
	if db == nil || budget == nil || cluster == ([32]byte{}) || len(private) != ed25519.PrivateKeySize {
		return nil, ErrSourceStore
	}
	derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	validKey := bytes.Equal(derived, private)
	clear(derived)
	if !validKey {
		return nil, ErrSourceStore
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.failed || budget.cluster != ([32]byte{}) && budget.cluster != cluster {
		return nil, ErrSourceStore
	}
	for _, store := range budget.stores {
		if store.db == db {
			return nil, ErrSourceStore
		}
	}
	budget.cluster = cluster
	m := &SourceStore{cacheBudget: budget, editor: make(chan struct{}, 1), db: db, identity: sourceStoreIdentity{1, cluster, [32]byte(private.Public().(ed25519.PublicKey))}, private: bytes.Clone(private)}
	m.mu.group = &budget.mu
	want, _ := json.Marshal(m.identity)
	raw, err := db.GetBounded(sourcePrefix+"identity", 1024)
	if errors.Is(err, storage.ErrMissing) {
		entries, e := db.ScanBounded(sourcePrefix, 1, 1024)
		if e != nil || len(entries) != 0 {
			budget.failed = true
			clear(m.private)
			return nil, ErrSourceStore
		}
		err = db.Write(map[string][]byte{sourcePrefix + "identity": want})
	} else if err == nil && !bytes.Equal(raw, want) {
		err = ErrSourceStore
	}
	if err == nil {
		err = m.load()
	}
	if err == nil {
		err = db.Sync()
	}
	if err != nil {
		budget.failed = true
		clear(m.private)
		return nil, err
	}
	budget.stores = append(budget.stores, m)
	return m, nil
}

func (m *SourceStore) load() error {
	rows, err := m.db.ScanBounded(sourceMetaPrefix, maxSourceEntries, maxSourceEntries*(17<<10))
	if err != nil {
		return err
	}
	entries := map[string]SourceFact{}
	sizes := map[string]uint64{}
	for key, raw := range rows {
		fact, err := schema.Decode[SourceFact](raw)
		if err != nil || fact.Verify() != nil || fact.Cluster != m.identity.Cluster || fact.Owner != m.identity.Node || key != sourceMetaPrefix+sourceObjectKey(fact.Descriptor()) {
			return ErrSourceStore
		}
		entries[key[len(sourceMetaPrefix):]] = fact
		sizes[fact.Tenant] += fact.Length + uint64(len(raw))
	}
	moduleRows, err := m.db.ScanBounded(moduleMetaPrefix, maxSourceEntries, maxSourceEntries*2304)
	if err != nil {
		return err
	}
	if len(entries)+len(moduleRows) > maxSourceEntries {
		return ErrSourceStore
	}
	modules := map[string]ModuleFact{}
	for key, raw := range moduleRows {
		fact, err := schema.Decode[ModuleFact](raw)
		if err != nil || fact.Verify() != nil || fact.Cluster != m.identity.Cluster || fact.Owner != m.identity.Node || key != moduleMetaPrefix+moduleObjectKey(fact.Tenant, fact.Module) {
			return ErrSourceStore
		}
		modules[key[len(moduleMetaPrefix):]] = fact
		sizes[fact.Tenant] += fact.Module.Length + fact.ExpandedBytes + uint64(len(raw))
	}
	rootData, err := m.db.SizesBounded(sourcePrefix+"data/", maxSourceEntries, maxSourceEntries*256)
	if err != nil {
		return errors.Join(ErrSourceStore, err)
	}
	moduleData, err := m.db.SizesBounded(moduleDataPrefix, maxSourceEntries, maxSourceEntries*256)
	if err != nil {
		return errors.Join(ErrSourceStore, err)
	}
	if len(rootData) != len(entries) || len(moduleData) != len(modules) {
		return ErrSourceStore
	}
	for key, fact := range entries {
		size, ok := rootData[sourcePrefix+"data/"+key]
		if !ok || size != fact.Length {
			return ErrSourceStore
		}
	}
	for key, fact := range modules {
		size, ok := moduleData[moduleDataPrefix+key]
		if !ok || size != fact.Module.Length {
			return ErrSourceStore
		}
	}
	m.entries, m.modules, m.bytes = entries, modules, sizes
	if err := m.loadCompiled(); err != nil {
		return err
	}
	if err := m.loadPreparations(); err != nil {
		return err
	}
	return m.loadCacheRetention()
}

func validSourceBytes(d SourceDescriptor, data []byte) bool {
	return d.Validate() == nil && uint64(len(data)) == d.Length && utf8.Valid(data) && !bytes.ContainsRune(data, 0) && sha256.Sum256(data) == d.Digest
}

func (m *SourceStore) read(d SourceDescriptor) (SourceFact, []byte, error) {
	key := sourceObjectKey(d)
	raw, err := m.readMetadata(sourceMetaPrefix+key, sourcePrefix+"data/"+key, 17<<10)
	if err != nil {
		return SourceFact{}, nil, err
	}
	fact, err := schema.Decode[SourceFact](raw)
	if err != nil || fact.Verify() != nil || fact.Cluster != m.identity.Cluster || fact.Owner != m.identity.Node || fact.Tenant != d.Tenant || fact.ContentDigest() != d.ContentDigest() {
		return SourceFact{}, nil, ErrSourceStore
	}
	data, err := m.db.GetBounded(sourcePrefix+"data/"+key, MaxScriptBytes)
	if err != nil || !validSourceBytes(d, data) {
		return SourceFact{}, nil, errors.Join(ErrSourceStore, err)
	}
	return fact, data, nil
}

// Stage accepts exact complete source, not executable readiness. The caller
// obtains the current quorum permit after receiving all authenticated bytes.
func (m *SourceStore) Stage(ctx context.Context, d SourceDescriptor, data []byte, policy TenantPolicy) (SourceFact, error) {
	if ctx == nil || d.Validate() != nil || uint64(len(data)) != d.Length {
		return SourceFact{}, ErrSourceStore
	}
	d, data, policy = d.Clone(), bytes.Clone(data), policy.Clone()
	defer clear(data)
	if !validSourceBytes(d, data) || !policy.AllowsDescriptor(d) {
		return SourceFact{}, ErrSourceStore
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.uncertain {
		return SourceFact{}, ErrSourceUncertain
	}
	if err := ctx.Err(); err != nil {
		return SourceFact{}, err
	}
	key := sourceObjectKey(d)
	existing, _, readErr := m.read(d)
	_, known := m.entries[key]
	if readErr == nil {
		if !known {
			return SourceFact{}, ErrSourceStore
		}
		return existing, nil
	}
	if known || !errors.Is(readErr, storage.ErrMissing) || errors.Is(readErr, ErrSourceStore) {
		return SourceFact{}, errors.Join(ErrSourceStore, readErr)
	}
	usage, err := m.cacheUsage(d.Tenant)
	if err != nil {
		return SourceFact{}, err
	}
	if usage.sourceEntries >= maxSourceEntries {
		return SourceFact{}, ErrSourceStore
	}
	fact := SourceFact{Schema: 1, Cluster: m.identity.Cluster, Owner: m.identity.Node, Tenant: d.Tenant, Digest: d.Digest, Length: d.Length, SDK: d.SDK, Modules: d.Modules}
	fact.Signature = ed25519.Sign(m.private, SourceFactBytes(fact))
	raw, err := json.Marshal(fact)
	if err != nil || fact.Verify() != nil {
		return SourceFact{}, ErrSourceStore
	}
	size := d.Length + uint64(len(raw))
	used := usage.source
	if used > policy.Resolver.SourceCacheBytes || size > policy.Resolver.SourceCacheBytes-used {
		return SourceFact{}, ErrSourceStore
	}
	if err := ctx.Err(); err != nil {
		return SourceFact{}, err
	}
	if err = m.db.Write(map[string][]byte{sourceMetaPrefix + key: raw, sourcePrefix + "data/" + key: data}); err != nil {
		m.uncertain = true
		return SourceFact{}, errors.Join(ErrSourceUncertain, err)
	}
	m.entries[key] = fact.Clone()
	m.bytes[d.Tenant] += size
	return fact, nil
}

// Recover sends no source bytes and never re-stages missing content. Sync and
// reload settle the original local DB state after a lost/failed write response.
func (m *SourceStore) Recover(ctx context.Context, d SourceDescriptor) (SourceFact, error) {
	if ctx == nil || d.Validate() != nil {
		return SourceFact{}, ErrSourceStore
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return SourceFact{}, ErrSourceStore
	}
	if err := ctx.Err(); err != nil {
		return SourceFact{}, err
	}
	if err := m.recover(); err != nil {
		return SourceFact{}, err
	}
	fact, _, err := m.read(d)
	if err == nil || errors.Is(err, storage.ErrMissing) && !errors.Is(err, ErrSourceStore) {
		m.uncertain = false
	}
	return fact, err
}

// Read verifies actual bytes on every use; a historical SourceFact alone is
// neither content availability nor current policy/runner permission.
func (m *SourceStore) Read(ctx context.Context, d SourceDescriptor) ([]byte, error) {
	_, data, err := m.SourceArtifact(ctx, d)
	return data, err
}

func (m *SourceStore) SourceArtifact(ctx context.Context, d SourceDescriptor) (SourceFact, []byte, error) {
	if ctx == nil || d.Validate() != nil {
		return SourceFact{}, nil, ErrSourceStore
	}
	d = d.Clone()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.uncertain {
		return SourceFact{}, nil, ErrSourceUncertain
	}
	if err := ctx.Err(); err != nil {
		return SourceFact{}, nil, err
	}
	return m.read(d)
}

func (m *SourceStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	clear(m.private)
	return nil
}
