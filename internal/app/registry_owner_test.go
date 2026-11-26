// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/registry"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// The caller-owned writer is a fixture. Real Store/reader FD and the node's
// actual observations DB are used; this is not shared quorum/native closure.
func TestRegistryOwnerQuiesceJoinsStoreReadersAndPreservesSameRunPinAndData(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{84}, 32))
	node := [32]byte(private.Public().(ed25519.PublicKey))
	cluster := [32]byte{1}
	ctx := context.Background()
	observations, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer observations.Close()
	spec := registry.Specification{Schema: 1, Tenant: "tenant", ID: "private", Node: "node-a", Address: "127.0.0.1:5443", Authority: "registry.example.test:5443", Volume: volumes.Scope{Cluster: cluster, Tenant: "tenant", Registry: "private", ID: "images", Generation: 1}, Enabled: true, Metadata: registry.MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}, Blobs: registry.BlobLimits{BlobBytes: 1024, TotalBytes: 4096, Records: 64}, Budget: workload.Resources{CPU: 1, Memory: 16 << 20}, MaxRequests: 2, MaxHeaderBytes: 8192, RequestTimeoutMS: 3000, TokenSeconds: 60}
	row := registryOwnerRecord{Schema: 1, Cluster: cluster, Owner: node, DataOwner: node, Spec: spec, Generation: 1, SpecRevision: 1, Phase: "serving", KnownData: true, PinAttempted: true, Pin: &volumes.NativeLease{Key: "original-volume", Consumer: "registry/tenant/private/1", Scope: spec.Volume, Pin: reconcile.Lease{Generation: 1, Token: 1}}, Run: &control.RegistryRunRef{Generation: 1, SpecRevision: 1, Spec: spec, Owner: node}}
	path, err := os.MkdirTemp(t.TempDir(), "private-registry-")
	if err != nil {
		t.Fatal(err)
	}
	store, err := registry.OpenStore(ctx, path, registry.Scope{Schema: 1, Cluster: cluster, Node: node, Tenant: spec.Tenant, Registry: spec.ID}, spec.Metadata, spec.Blobs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if store != nil {
			_ = store.Close()
		}
	}()
	data := []byte("retained image bytes")
	hash := sha256.Sum256(data)
	u, err := store.Blobs.Begin(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Blobs.Append(ctx, "app", u.ID, 0, int64(len(data)), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	digest := v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(hash[:])}
	if _, err = store.Blobs.Commit(ctx, "app", u.ID, digest.String()); err != nil {
		t.Fatal(err)
	}
	reader, err := store.Blobs.Get(ctx, "app", digest)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	r := &Runtime{Identity: &identity.Identity{Private: private, Public: node}, reports: observations, registryRecords: map[string]registryOwnerRecord{}, registrySessions: map[string]*registrySession{spec.Key(): {store: store}}}
	if err = r.saveRegistry(row); err != nil {
		t.Fatal(err)
	}
	if _, err = r.quiesceRegistry(ctx, row); !errors.Is(err, registry.ErrReaders) {
		t.Fatal("unjoined reader became closure", err)
	}
	if r.registryRecords[spec.Key()].Phase != "serving" || r.registryRecords[spec.Key()].PinReturned {
		t.Fatal("returned original pin while reader live")
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	row, err = r.quiesceRegistry(ctx, row)
	if err != nil {
		t.Fatal(err)
	}
	if row.Phase != "quiesced" || row.IOClosed || row.PinReturned || row.Pin == nil || !row.KnownData {
		t.Fatal("daemon quiesce became shared terminal closure")
	}
	store, err = registry.OpenStore(ctx, path, registry.Scope{Schema: 1, Cluster: cluster, Node: node, Tenant: spec.Tenant, Registry: spec.ID}, spec.Metadata, spec.Blobs)
	if err != nil {
		t.Fatal(err)
	}
	status, err := store.Blobs.Status(ctx, "app", u.ID)
	if err != nil || status.Digest != digest.String() || status.Offset != int64(len(data)) {
		t.Fatal("original receipt lost", status, err)
	}
}
