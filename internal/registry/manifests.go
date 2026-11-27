// SPDX-License-Identifier: Apache-2.0

// Package registry owns storage and serving adapters for one tenant registry.
// A caller must hold the original registry Volume writer before opening its DB.
package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/distribution/reference"
	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

var ErrStorage = errors.New("registry storage unavailable or inconsistent")

// ErrOffset is a read offset outside the stored item.
var ErrOffset = errors.New("registry read offset is outside the item")

type Scope struct {
	Schema           uint8
	Cluster, Node    [32]byte
	Tenant, Registry string
}

type MetadataLimits struct {
	ManifestBytes int
	Records       int
	TotalBytes    int
}

func (s Scope) valid() bool {
	return s.Schema == 1 && s.Cluster != ([32]byte{}) && s.Node != ([32]byte{}) && scopeName(s.Tenant) && scopeName(s.Registry)
}
func (l MetadataLimits) valid() bool {
	return l.ManifestBytes > 0 && l.ManifestBytes <= 8<<20 && l.Records > 0 && l.Records <= 16384 && l.TotalBytes >= l.ManifestBytes && l.TotalBytes <= 256<<20
}

// Metadata borrows a registry-owned synchronous DB. It never closes that DB,
// changes a shared Raft object, claims a Volume writer or advertises readiness.
type Metadata struct {
	mu             sync.Mutex
	db             *storage.DB
	scope          Scope
	limits         MetadataLimits
	failed, closed bool
	fresh          bool
}

var _ oci.ManifestStore = (*Metadata)(nil)

const manifestPrefix = "registry/manifest/"

func scopeName(s string) bool {
	if s == "" || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func OpenMetadata(db *storage.DB, owner Scope, limits MetadataLimits) (*Metadata, error) {
	if db == nil || !owner.valid() || !limits.valid() {
		return nil, ErrStorage
	}
	m := &Metadata{db: db, scope: owner, limits: limits}
	raw, err := db.GetBounded("registry/owner", 4096)
	if errors.Is(err, storage.ErrMissing) {
		// A missing owner is only a new DB when the registry namespace is empty.
		rows, e := db.SizesBounded("registry/", 1, 4096)
		if e != nil || len(rows) != 0 {
			return nil, ErrStorage
		}
		value, _ := json.Marshal(owner)
		m.fresh = true
		if db.Write(map[string][]byte{"registry/owner": value}) != nil {
			return nil, ErrStorage
		}
	} else if err != nil {
		return nil, ErrStorage
	} else if got, e := schema.Decode[Scope](raw); e != nil || got != owner {
		return nil, ErrStorage
	}
	if _, err := m.inventory(); err != nil {
		return nil, err
	}
	if err := m.validateMaintenanceReceipts(); err != nil {
		return nil, err
	}
	if err := m.validateStored(); err != nil {
		return nil, err
	}
	return m, nil
}

func repoID(repo string) (string, error) {
	if !registryclient.ValidRepository(repo) || strings.ContainsAny(repo, "\\\x00\r\n") {
		return "", ErrStorage
	}
	n, err := reference.WithName(repo)
	if err != nil || n.Name() != repo {
		return "", ErrStorage
	}
	h := sha256.Sum256([]byte(repo))
	return hex.EncodeToString(h[:]), nil
}

func manifestReference(repo, target string) bool {
	if strings.Contains(target, ":") {
		h, err := v1.NewHash(target)
		return err == nil && h.Algorithm == "sha256"
	}
	n, err := reference.WithName(repo)
	if err != nil {
		return false
	}
	_, err = reference.WithTag(n, target)
	return err == nil
}

func (m *Metadata) enter(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || m.closed || m.failed {
		return ErrStorage
	}
	return nil
}

func (m *Metadata) inventory() (map[string]uint64, error) {
	rows := map[string]uint64{}
	for _, prefix := range []string{manifestPrefix, imageDeletePrefix, gcPrefix, pushPrefix} {
		found, err := m.db.SizesBounded(prefix, m.limits.Records, m.limits.TotalBytes)
		if err != nil {
			return nil, ErrStorage
		}
		for key, n := range found {
			rows[key] = n
		}
	}
	if len(rows) > m.limits.Records {
		return nil, ErrStorage
	}
	var size uint64
	for k, n := range rows {
		size += uint64(len(k)) + n
		if size > uint64(m.limits.TotalBytes) {
			return nil, ErrStorage
		}
	}
	return rows, nil
}

func (m *Metadata) GetManifest(ctx context.Context, repo, target string) (oci.ManifestData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getManifest(ctx, repo, target)
}

func (m *Metadata) getManifest(ctx context.Context, repo, target string) (oci.ManifestData, error) {
	if m.enter(ctx) != nil || !manifestReference(repo, target) {
		return oci.ManifestData{}, ErrStorage
	}
	id, err := repoID(repo)
	if err != nil {
		return oci.ManifestData{}, err
	}
	name, err := m.db.GetBounded(manifestPrefix+"repo/"+id, 255)
	if errors.Is(err, storage.ErrMissing) {
		return oci.ManifestData{}, oci.ErrNameUnknown
	}
	if err != nil || string(name) != repo {
		return oci.ManifestData{}, ErrStorage
	}
	digest, err := m.db.GetBounded(manifestPrefix+"ref/"+id+"/"+target, 71)
	if errors.Is(err, storage.ErrMissing) {
		return oci.ManifestData{}, oci.ErrNotFound
	}
	if err != nil {
		return oci.ManifestData{}, ErrStorage
	}
	raw, err := m.db.GetBounded(manifestPrefix+"data/"+id+"/"+string(digest), m.limits.ManifestBytes*2+4096)
	if err != nil {
		return oci.ManifestData{}, ErrStorage
	}
	data, err := schema.Decode[oci.ManifestData](raw)
	if err != nil || len(data.Body) > m.limits.ManifestBytes {
		return oci.ManifestData{}, ErrStorage
	}
	h, _, err := v1.SHA256(bytes.NewReader(data.Body))
	if err != nil || h.String() != string(digest) || strings.Contains(target, ":") && target != string(digest) {
		return oci.ManifestData{}, ErrStorage
	}
	return data, nil
}

func (m *Metadata) PutManifest(ctx context.Context, repo, target, digest string, data oci.ManifestData) error {
	return m.putManifest(ctx, repo, target, digest, data, nil)
}
func (m *Metadata) putManifest(ctx context.Context, repo, target, digest string, data oci.ManifestData, blobs *Blobs) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if blobs != nil {
		blobs.mu.Lock()
		defer blobs.mu.Unlock()
		if blobs.scope != m.scope || blobs.enter(ctx, true) != nil {
			return ErrStorage
		}
	}
	if m.enter(ctx) != nil || len(data.Body) > m.limits.ManifestBytes || len(data.Body) == 0 || !manifestReference(repo, target) || !manifestReference(repo, digest) || !strings.HasPrefix(digest, "sha256:") || !json.Valid(data.Body) {
		return ErrStorage
	}
	media := types.MediaType(data.ContentType)
	if !media.IsImage() && !media.IsIndex() {
		return ErrStorage
	}
	id, err := repoID(repo)
	if err != nil {
		return err
	}
	h, _, err := v1.SHA256(bytes.NewReader(data.Body))
	if err != nil || h.String() != digest || strings.Contains(target, ":") && target != digest {
		return oci.ErrDigestMismatch
	}
	dataKey := manifestPrefix + "data/" + id + "/" + digest
	if _, err := m.getManifest(ctx, repo, target); err != nil && !errors.Is(err, oci.ErrNameUnknown) && !errors.Is(err, oci.ErrNotFound) {
		return ErrStorage
	}
	raw, _ := json.Marshal(data)
	old, err := m.db.GetBounded(dataKey, m.limits.ManifestBytes*2+4096)
	if err == nil && !bytes.Equal(old, raw) {
		return ErrStorage
	}
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return ErrStorage
	}
	dataNew := errors.Is(err, storage.ErrMissing)
	changes := map[string][]byte{manifestPrefix + "repo/" + id: []byte(repo), dataKey: raw, manifestPrefix + "ref/" + id + "/" + digest: []byte(digest), manifestPrefix + "ref/" + id + "/" + target: []byte(digest)}
	// Publication time belongs to the accepted ref update, not image config
	// Created. An idempotent push/legacy read must not fabricate a new time.
	now := uint64(time.Now().UnixMilli())
	for _, ref := range []string{digest, target} {
		refKey := manifestPrefix + "ref/" + id + "/" + ref
		oldRef, e := m.db.GetBounded(refKey, 71)
		if e != nil && !errors.Is(e, storage.ErrMissing) {
			return ErrStorage
		}
		if ref == digest && !dataNew || e == nil && string(oldRef) == digest {
			continue
		}
		stamp, _ := json.Marshal(manifestPublication{Schema: 1, Digest: digest, At: now})
		changes[manifestPrefix+"published/"+id+"/"+ref] = stamp
	}
	if blobs != nil {
		published, e := directManifestBlobs(data)
		if e != nil {
			return e
		}
		for _, blob := range published {
			key, _ := blobKey(repo, blob.Digest)
			record, ok := blobs.blobs[key]
			if !ok || record.Size != blob.Size {
				return ErrStorage
			}
			record.Unpublished = false
			raw, _ := json.Marshal(record)
			changes[key] = raw
		}
	}
	rows, err := m.inventory()
	if err != nil {
		return err
	}
	for k, v := range changes {
		if !strings.HasPrefix(k, blobPrefix) {
			rows[k] = uint64(len(v))
		}
	}
	if len(rows) > m.limits.Records {
		return ErrStorage
	}
	var total uint64
	for k, n := range rows {
		total += uint64(len(k)) + n
		if total > uint64(m.limits.TotalBytes) {
			return ErrStorage
		}
	}
	if ctx.Err() != nil {
		return ErrStorage
	}
	if err = m.db.Write(changes); err != nil {
		m.failed = true
		if blobs != nil {
			blobs.failed = true
		}
		return ErrStorage
	}
	if blobs != nil {
		for key, raw := range changes {
			if strings.HasPrefix(key, blobPrefix) {
				value, _ := schema.Decode[blobRecord](raw)
				blobs.blobs[key] = value
			}
		}
	}
	return nil
}

// No implicit OCI delete/GC: app down and server stop retain registry images.
func (m *Metadata) DeleteManifest(context.Context, string, string) error { return oci.ErrReadOnly }

func (m *Metadata) ManifestReferences(ctx context.Context, repo string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.manifestReferences(ctx, repo)
}
func (m *Metadata) manifestReferences(ctx context.Context, repo string) ([]string, error) {
	if m.enter(ctx) != nil {
		return nil, ErrStorage
	}
	id, err := repoID(repo)
	if err != nil {
		return nil, err
	}
	raw, err := m.db.GetBounded(manifestPrefix+"repo/"+id, 255)
	if errors.Is(err, storage.ErrMissing) {
		return nil, oci.ErrNameUnknown
	}
	if err != nil || string(raw) != repo {
		return nil, ErrStorage
	}
	prefix := manifestPrefix + "ref/" + id + "/"
	rows, err := m.db.ScanBounded(prefix, m.limits.Records, m.limits.TotalBytes)
	if err != nil {
		return nil, ErrStorage
	}
	refs := make([]string, 0, len(rows))
	for k, v := range rows {
		ref := strings.TrimPrefix(k, prefix)
		if !manifestReference(repo, ref) || !manifestReference(repo, string(v)) || !strings.HasPrefix(string(v), "sha256:") {
			return nil, ErrStorage
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func (m *Metadata) Repositories(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.repositories(ctx)
}
func (m *Metadata) repositories(ctx context.Context) ([]string, error) {
	if m.enter(ctx) != nil {
		return nil, ErrStorage
	}
	prefix := manifestPrefix + "repo/"
	rows, err := m.db.ScanBounded(prefix, m.limits.Records, m.limits.TotalBytes)
	if err != nil {
		return nil, ErrStorage
	}
	result := make([]string, 0, len(rows))
	for k, v := range rows {
		id, err := repoID(string(v))
		if err != nil || k != prefix+id {
			return nil, ErrStorage
		}
		result = append(result, string(v))
	}
	return result, nil
}

func (m *Metadata) Close() error { m.mu.Lock(); defer m.mu.Unlock(); m.closed = true; return nil }
