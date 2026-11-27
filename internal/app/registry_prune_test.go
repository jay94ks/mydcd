// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

func ownerPruneFixture(t *testing.T) (*Runtime, control.RegistryMaintenanceChange, registryclient.PrunePreview) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	owner := [32]byte(private.Public().(ed25519.PublicKey))
	r := &Runtime{Identity: &identity.Identity{Public: owner, Private: private}, controlPolicy: control.Policy{Cluster: [32]byte{1}, TrustRoot: owner}, reports: db}
	image := registryclient.ImageMetadata{Repository: "team/app", Reference: "old", Digest: "sha256:" + strings.Repeat("a", 64), MediaType: string(types.OCIManifestSchema1), ManifestBytes: 128, ImageBytes: 10}
	preview, err := registryclient.BuildPrunePreview(registryclient.PruneInventory{Schema: 1, Authority: "registry.example", Live: true, Images: []registryclient.ImageMetadata{image}}, registryclient.PruneConditions{})
	if err != nil {
		t.Fatal(err)
	}
	change := control.RegistryMaintenanceChange{Tenant: "tenant", Operation: "original-prune", Run: control.RegistryRunRef{Owner: r.Identity.Public}}
	change.Run.Spec.Authority = "registry.example"
	fact := control.RegistryPruneFact{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Target: change.PruneBase().DigestValue(), Conditions: control.PruneConditionsDigest(preview.Conditions), Preview: preview.Digest(), Public: control.RegistryPrunePreviewPublicDigest(preview), Tenant: change.Tenant, Items: uint32(len(preview.Items)), Retained: uint32(len(preview.Retained)), ImageBytes: preview.ImageBytes, Live: true, At: 1}
	fact.Signature = ed25519.Sign(private, control.RegistryPruneFactBytes(fact))
	change.Prune = &control.RegistryPruneTarget{Conditions: preview.Conditions, Fact: fact}
	return r, change, preview
}

func TestPruneOwnerCacheKeepsStartedUnknownAndAtomicallyAdvancesOriginalItem(t *testing.T) {
	r, change, preview := ownerPruneFixture(t)
	if err := r.stageRegistryPrunePreview(state.State{}, change, preview, 1); err != nil {
		t.Fatal(err)
	}
	work := control.RegistryMaintenanceWork{Operation: change.Operation, Change: change}
	local, err := r.loadRegistryMaintenance(work)
	if err != nil {
		t.Fatal(err)
	}
	local.Prune = &registryPruneProgress{Preview: registryPrunePreviewKey(change.Prune.Fact.Target, change.Prune.Fact.Preview), Sent: true}
	local.Sent = true
	if err = r.saveRegistryMaintenance(local); err != nil {
		t.Fatal(err)
	}
	// Stage another preview after expiry; the actually started original is
	// protected by its durable owner intent even with a stale shared snapshot.
	other := change
	other.Operation = "another"
	other.Run.Generation++
	if err = r.stageRegistryPrunePreview(state.State{}, other, preview, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err = r.loadRegistryPrunePreview(change); err != nil {
		t.Fatal("started artifact evicted", err)
	}
	reopened, err := r.loadRegistryMaintenance(work)
	if err != nil || !reopened.Prune.Sent || !reopened.Sent {
		t.Fatal("uncertain original reset", reopened, err)
	}
	result := nativeMaintenanceResult("OK", 10, struct{ Original string }{change.Operation}, 0)
	if err = r.saveRegistryPruneItem(&reopened, preview.Items[0], result); err != nil {
		t.Fatal(err)
	}
	done, err := r.loadRegistryMaintenance(work)
	if err != nil || done.Prune.Next != 1 || done.Prune.Sent || done.Prune.Summary.Deleted != 1 || !done.Sent {
		t.Fatal("item/progress not committed together", done, err)
	}
	raw, err := r.reports.GetBounded(registryPruneItemKey(change.Operation, 0), 16<<10)
	row, cause := schema.Decode[control.RegistryPruneRow](raw)
	if err != nil || cause != nil || row.ID != preview.Items[0].ItemID() || row.Code != "OK" || row.Native != result.Native {
		t.Fatal("original immutable item result", row, err, cause)
	}
	stale := local
	if err = r.saveRegistryPruneItem(&stale, preview.Items[0], result); err == nil {
		t.Fatal("old ordinal overwrote an original result")
	}
	bad := change
	bad.Run.Generation++
	if _, err = r.loadRegistryPrunePreview(bad); err == nil {
		t.Fatal("preview adopted into another target")
	}
	// A corrupted local counter is not permission to skip unprocessed items.
	done.Prune.Next++
	raw, _ = json.Marshal(done)
	if err = r.reports.Write(map[string][]byte{registryMaintenanceReceiptKey(done.Operation): raw}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.loadRegistryMaintenance(work); err == nil {
		t.Fatal("corrupt progress accepted")
	}
}

func TestPruneOwnerCacheExpiresOnlyUnstartedArtifacts(t *testing.T) {
	r, change, preview := ownerPruneFixture(t)
	if err := r.stageRegistryPrunePreview(state.State{}, change, preview, 1); err != nil {
		t.Fatal(err)
	}
	other := change
	other.Run.Generation++
	if err := r.stageRegistryPrunePreview(state.State{}, other, preview, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := r.loadRegistryPrunePreview(change); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("unstarted expired preview retained", err)
	}
}
