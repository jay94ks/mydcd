// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	oci "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Real Store/metadata/blob DB and ordinary files. The original writer/run is
// supplied, not evidence of quorum, native Volume activation or BuildKit.
func TestOriginalRegistryMetadataReadNeedsNoListenerAndNeverReopensClosedStore(t *testing.T) {
	ctx := context.Background()
	cluster, node := [32]byte{1}, [32]byte{2}
	spec := registry.Specification{Schema: 1, Tenant: "tenant", ID: "private", Node: "node-a", Address: "127.0.0.1:5443", Authority: "registry.example:5443", Volume: volumes.Scope{Cluster: cluster, Tenant: "tenant", Registry: "private", ID: "images", Generation: 1}, Enabled: true, Metadata: registry.MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}, Blobs: registry.BlobLimits{BlobBytes: 4096, TotalBytes: 16384, Records: 64}, Budget: workload.Resources{CPU: 1, Memory: 16 << 20}, MaxRequests: 2, MaxHeaderBytes: 8192, RequestTimeoutMS: 3000, TokenSeconds: 60}
	dir, err := os.MkdirTemp(t.TempDir(), "private-registry-")
	if err != nil {
		t.Fatal(err)
	}
	store, err := registry.OpenStore(ctx, dir, registry.Scope{Schema: 1, Cluster: cluster, Node: node, Tenant: spec.Tenant, Registry: spec.ID}, spec.Metadata, spec.Blobs)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config, err := empty.Image.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := empty.Image.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	upload, err := store.Blobs.Begin(ctx, "team/app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Blobs.Append(ctx, "team/app", upload.ID, 0, int64(len(config)), bytes.NewReader(config)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Blobs.Commit(ctx, "team/app", upload.ID, digest.String()); err != nil {
		t.Fatal(err)
	}
	raw, err := empty.Image.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	media, err := empty.Image.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	data := oci.ManifestData{ContentType: string(media), Body: raw}
	manifestDigest, err := empty.Image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Metadata.PutManifest(ctx, "team/app", "release", manifestDigest.String(), data); err != nil {
		t.Fatal(err)
	}
	run := control.RegistryRunRef{Generation: 1, SpecRevision: 1, Spec: spec, Owner: node}
	r := &Runtime{registryRecords: map[string]registryOwnerRecord{spec.Key(): {Schema: 1, Cluster: cluster, Owner: node, DataOwner: node, Spec: spec, Generation: 1, SpecRevision: 1, Phase: "quiesced", KnownData: true, Run: &run}}, registrySessions: map[string]*registrySession{spec.Key(): {store: store}}}
	before, err := os.ReadFile(filepath.Join(dir, "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.readRegistryManifest(ctx, run, "team/app", "release", false)
	if err != nil || got.ContentType != data.ContentType || !bytes.Equal(got.Body, raw) {
		t.Fatal("retained Store could not observe original", err)
	}
	if _, err := r.readRegistryManifest(ctx, run, "team/app", "release", true); err == nil {
		t.Fatal("stopped listener advertised as serving")
	}
	changed := run
	changed.Generation++
	if _, err := r.readRegistryManifest(ctx, changed, "team/app", "release", false); err == nil {
		t.Fatal("another run borrowed same Store")
	}
	changed = run
	changed.Spec.Volume.Generation++
	if _, err := r.readRegistryManifest(ctx, changed, "team/app", "release", false); err == nil {
		t.Fatal("another data namespace borrowed same Store")
	}
	after, err := os.ReadFile(filepath.Join(dir, "registry.db"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read changed original DB", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	r.registrySessions[spec.Key()].store = nil
	if _, err := r.readRegistryManifest(ctx, run, "team/app", "release", false); err == nil {
		t.Fatal("closed original Store reopened by observation")
	}
	if r.registrySessions[spec.Key()].store != nil || r.registrySessions[spec.Key()].server != nil {
		t.Fatal("observation started an owner or listener")
	}
}
