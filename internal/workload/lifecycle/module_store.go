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
	"slices"

	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

const moduleMetaPrefix = sourcePrefix + "modules/metadata/"
const moduleDataPrefix = sourcePrefix + "modules/data/"

// ModuleFact attests exact locally stored ZIP bytes and inspected expanded
// length. It grants no current permission, root binding or executable readiness.
type ModuleFact struct {
	Schema         uint8
	Cluster, Owner [32]byte
	Tenant         string
	Module         ModulePin
	ExpandedBytes  uint64
	Signature      []byte
}

func ModuleFactBytes(f ModuleFact) []byte {
	f.Signature = nil
	raw, _ := json.Marshal(f)
	return append([]byte("sfc-checker-module-fact-1\x00"), raw...)
}
func (f ModuleFact) Verify() error {
	if f.Schema != 1 || f.Cluster == ([32]byte{}) || f.Owner == ([32]byte{}) || !name(f.Tenant) || !f.Module.valid() || f.Module.Length > MaxModuleBytes || f.ExpandedBytes > MaxModuleBytes-f.Module.Length || !ed25519.Verify(f.Owner[:], ModuleFactBytes(f), f.Signature) {
		return ErrSourceStore
	}
	return nil
}
func (f ModuleFact) Clone() ModuleFact { f.Signature = bytes.Clone(f.Signature); return f }

func moduleObjectKey(tenant string, pin ModulePin) string {
	raw, _ := json.Marshal(pin)
	digest := sha256.Sum256(append([]byte("sfc-checker-module-key-1\x00"), raw...))
	return tenant + "/" + hex.EncodeToString(digest[:])
}

func (m *SourceStore) readModule(tenant string, pin ModulePin) (ModuleFact, []byte, error) {
	key := moduleObjectKey(tenant, pin)
	raw, err := m.readMetadata(moduleMetaPrefix+key, moduleDataPrefix+key, 2048)
	if err != nil {
		return ModuleFact{}, nil, err
	}
	fact, err := schema.Decode[ModuleFact](raw)
	if err != nil || fact.Verify() != nil || fact.Cluster != m.identity.Cluster || fact.Owner != m.identity.Node || fact.Tenant != tenant || fact.Module != pin {
		return ModuleFact{}, nil, ErrSourceStore
	}
	data, err := m.db.GetBounded(moduleDataPrefix+key, MaxModuleBytes)
	if err != nil || uint64(len(data)) != pin.Length || sha256.Sum256(data) != pin.Digest {
		return ModuleFact{}, nil, errors.Join(ErrSourceStore, err)
	}
	return fact, data, nil
}

// StageModule uses the same owner, DB identity and tenant source cache budget
// as root sources. No root fact or source Ready is synthesized by this write.
func (m *SourceStore) StageModule(ctx context.Context, d SourceDescriptor, archive ModuleArchive, policy TenantPolicy) (ModuleFact, error) {
	if ctx == nil || !policy.AllowsDescriptor(d) || !slices.Contains(d.Modules, archive.Pin) || archive.Pin.Length > MaxModuleBytes || archive.Pin.Length != uint64(len(archive.ZIP)) {
		return ModuleFact{}, ErrSourceStore
	}
	d, policy = d.Clone(), policy.Clone()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.uncertain {
		return ModuleFact{}, ErrSourceUncertain
	}
	if err := ctx.Err(); err != nil {
		return ModuleFact{}, err
	}
	archive.ZIP = bytes.Clone(archive.ZIP)
	defer clear(archive.ZIP)
	if sha256.Sum256(archive.ZIP) != archive.Pin.Digest {
		return ModuleFact{}, ErrSourceStore
	}
	key := moduleObjectKey(d.Tenant, archive.Pin)
	fact, _, readErr := m.readModule(d.Tenant, archive.Pin)
	_, known := m.modules[key]
	if readErr == nil {
		if !known {
			return ModuleFact{}, ErrSourceStore
		}
		return fact, nil
	}
	if known || !errors.Is(readErr, storage.ErrMissing) || errors.Is(readErr, ErrSourceStore) {
		return ModuleFact{}, errors.Join(ErrSourceStore, readErr)
	}
	usage, err := m.cacheUsage(d.Tenant)
	if err != nil {
		return ModuleFact{}, err
	}
	if usage.sourceEntries >= maxSourceEntries {
		return ModuleFact{}, ErrSourceStore
	}
	used := usage.source
	if used > policy.Resolver.SourceCacheBytes {
		return ModuleFact{}, ErrSourceStore
	}
	image, err := inspectModuleArchive(ctx, archive, policy.Resolver.SourceCacheBytes-used)
	if err != nil {
		return ModuleFact{}, err
	}
	fact = ModuleFact{Schema: 1, Cluster: m.identity.Cluster, Owner: m.identity.Node, Tenant: d.Tenant, Module: archive.Pin, ExpandedBytes: image.expanded}
	fact.Signature = ed25519.Sign(m.private, ModuleFactBytes(fact))
	raw, err := json.Marshal(fact)
	if err != nil || fact.Verify() != nil || len(raw) > 2048 {
		return ModuleFact{}, ErrSourceStore
	}
	cost := archive.Pin.Length + image.expanded + uint64(len(raw))
	if cost > policy.Resolver.SourceCacheBytes-used {
		return ModuleFact{}, ErrSourceStore
	}
	if err := ctx.Err(); err != nil {
		return ModuleFact{}, err
	}
	if err := m.db.Write(map[string][]byte{moduleMetaPrefix + key: raw, moduleDataPrefix + key: archive.ZIP}); err != nil {
		m.uncertain = true
		return ModuleFact{}, errors.Join(ErrSourceUncertain, err)
	}
	m.modules[key] = fact.Clone()
	m.bytes[d.Tenant] += cost
	return fact, nil
}

// RecoverModule never uploads or repairs bytes. The caller authorizes the
// original tenant/pin under current cleanup rights, including revoked policies.
func (m *SourceStore) RecoverModule(ctx context.Context, tenant string, pin ModulePin) (ModuleFact, error) {
	if ctx == nil || !name(tenant) || !pin.valid() || pin.Length > MaxModuleBytes {
		return ModuleFact{}, ErrSourceStore
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ModuleFact{}, ErrSourceStore
	}
	if err := ctx.Err(); err != nil {
		return ModuleFact{}, err
	}
	if err := m.recover(); err != nil {
		return ModuleFact{}, err
	}
	fact, _, err := m.readModule(tenant, pin)
	if err == nil || errors.Is(err, storage.ErrMissing) && !errors.Is(err, ErrSourceStore) {
		m.uncertain = false
	}
	return fact, err
}

func (m *SourceStore) ReadModule(ctx context.Context, tenant string, pin ModulePin) ([]byte, error) {
	_, data, err := m.ModuleArtifact(ctx, tenant, pin)
	return data, err
}
func (m *SourceStore) ModuleArtifact(ctx context.Context, tenant string, pin ModulePin) (ModuleFact, []byte, error) {
	if ctx == nil || !name(tenant) || !pin.valid() || pin.Length > MaxModuleBytes {
		return ModuleFact{}, nil, ErrSourceStore
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.uncertain {
		return ModuleFact{}, nil, ErrSourceUncertain
	}
	if err := ctx.Err(); err != nil {
		return ModuleFact{}, nil, err
	}
	return m.readModule(tenant, pin)
}

// Resolve consumes this store's actual root/module bytes and the same source
// resolver used for interpreted/compiled execution. Permissions are rechecked
// by the node adapter before starting any helper or compiler.
func (m *SourceStore) Resolve(ctx context.Context, d SourceDescriptor, policy TenantPolicy, target ResolverTarget) (*ResolvedSource, error) {
	if ctx == nil || !policy.AllowsDescriptor(d) {
		return nil, ErrSourceStore
	}
	d, policy = d.Clone(), policy.Clone()
	m.mu.Lock()
	if m.closed || m.uncertain {
		m.mu.Unlock()
		return nil, ErrSourceUncertain
	}
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	_, root, err := m.read(d)
	archives := make([]ModuleArchive, 0, len(d.Modules))
	expected := d.Length
	if err == nil {
		for _, pin := range d.Modules {
			if ctx.Err() != nil {
				err = ctx.Err()
				break
			}
			limit := min(uint64(maxResolveBytes), policy.Resolver.SourceCacheBytes)
			if expected > limit || pin.Length > limit-expected {
				err = ErrSourceStore
				break
			}
			fact, data, readErr := m.readModule(d.Tenant, pin)
			if readErr != nil {
				err = readErr
				break
			}
			if fact.ExpandedBytes > limit-expected-pin.Length {
				clear(data)
				err = ErrSourceStore
				break
			}
			expected += pin.Length + fact.ExpandedBytes
			archives = append(archives, ModuleArchive{Pin: pin, ZIP: data})
		}
	}
	m.mu.Unlock()
	defer func() {
		clear(root)
		for _, a := range archives {
			clear(a.ZIP)
		}
	}()
	if err != nil {
		return nil, err
	}
	source, err := ResolveSource(ctx, policy, d, root, archives, target)
	if err != nil {
		return nil, err
	}
	if source.MaterializedBytes() != expected {
		return nil, ErrSourceStore
	}
	return source, nil
}

// A metadata-less data record is corruption/uncertainty, never positive
// missing. A one-byte bound probes existence without loading a large artifact.
func (m *SourceStore) readMetadata(meta, data string, limit int) ([]byte, error) {
	raw, err := m.db.GetBounded(meta, limit)
	if errors.Is(err, storage.ErrMissing) {
		_, dataErr := m.db.GetBounded(data, 1)
		if errors.Is(dataErr, storage.ErrMissing) {
			return nil, storage.ErrMissing
		}
		return nil, errors.Join(ErrSourceStore, dataErr)
	}
	if err != nil {
		return nil, errors.Join(ErrSourceStore, err)
	}
	return raw, nil
}

func (m *SourceStore) recover() error {
	if err := m.db.Sync(); err != nil {
		m.uncertain = true
		return errors.Join(ErrSourceUncertain, err)
	}
	if err := m.load(); err != nil {
		m.uncertain = true
		return errors.Join(ErrSourceUncertain, err)
	}
	return nil
}
