// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Genuine user operations, signatures, FSM and restore. Native artifact,
// registry and Volume closure facts are injected; no actual disposal is claimed.
func TestCacheDisposalRequiresOriginalTenantRetirementAndAllSharedSettlement(t *testing.T) {
	f, plan := buildJobFixture(t)
	owner := plan.Spec.Scope.Root.Key
	if _, err := f.p.ImageBuildCacheRetirementGrant(f.s, owner, plan.Spec); err == nil {
		t.Fatal("active tenant authorized physical cache disposal")
	}
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	f.apply("manager", "cancel-image-build", 1, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
	book, _ := f.p.ImageBuilds(f.s)
	job, _ := book.Job("tenant", plan.Spec.ID)
	f.apply("manager", "delete-image-build-job", job.Run.Revision, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	f.apply("manager", "delete-build-version", plan.Spec.Number, ImageBuildVersionSelection{Tenant: "tenant", ID: plan.Spec.Version}, state.Applied)
	book, _ = f.p.ImageBuilds(f.s)
	upload, _ := book.Upload("tenant", "retained")
	reclaimed := imagebuild.ReclaimReceipt{Schema: 1, Scope: upload.Scope.Hash(), Version: upload.Version, Native: sha256.Sum256([]byte("injected original artifact closure")), At: 5}
	reclaimed.Signature = ed25519.Sign(f.node, imagebuild.ReclaimReceiptBytes(reclaimed))
	imageBuildOwnerTestReport(t, f, ImageBuildOwnerReport{Tenant: "tenant", Upload: "retained", Action: "reclaimed", Reclaimed: &reclaimed}, state.Applied)
	f.apply("manager", "delete-build-context", 1, ImageBuildSelection{Tenant: "tenant", ID: "source"}, state.Applied)
	f.apply("manager", "delete-image-build-policy", 1, ImageBuildSelection{Tenant: "tenant"}, state.Applied)
	if _, err := f.p.ImageBuildCacheRetirementGrant(f.s, owner, plan.Spec); err == nil {
		t.Fatal("context/policy deletion authorized physical cache disposal")
	}
	registries, _ := f.p.Registries(f.s)
	registry, _ := registries.Entry("tenant", plan.Spec.Policy.Registry)
	f.apply("manager", "stop-registry", registry.Revision, RegistrySelection{Tenant: "tenant", ID: registry.Spec.ID}, state.Applied)
	registry = registryEntry(t, f, registry.Spec)
	run := *registry.Active
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: registry.Spec.ID, Action: "drain", SpecRevision: run.SpecRevision, Generation: run.Generation}, state.Applied)
	run = *registryEntry(t, f, registry.Spec).Active
	gone, budget := registryClosureFixture(f, run.Reference())
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: registry.Spec.ID, Action: "closed", SpecRevision: run.SpecRevision, Generation: run.Generation, Gone: gone, Budget: budget}, state.Applied)
	registry = registryEntry(t, f, registry.Spec)
	f.apply("manager", "delete-registry", registry.Revision, RegistrySelection{Tenant: "tenant", ID: registry.Spec.ID}, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	tenant, _ := catalog.Tenant("tenant")
	selection := TenantRetirementSelection{Tenant: "tenant", Operation: "retire-tenant"}
	f.apply("admin", "begin-tenant-retirement", tenant.Revision, selection, state.Applied)
	if _, err := f.p.ImageBuildCacheRetirementGrant(f.s, owner, plan.Spec); err == nil {
		t.Fatal("remaining retained Volume skipped")
	}
	volumeCatalog, _ := f.p.Volumes(f.s)
	volume, _ := volumeCatalog.Volume(registry.Spec.Volume)
	f.apply("manager", "delete-volume", volume.Revision(), registry.Spec.Volume, state.Applied)
	work, err := f.p.VolumeDeletePermit(f.s, owner, registry.Spec.Volume)
	if err != nil {
		t.Fatal(err)
	}
	proof := volumes.NativeRemoved{Schema: 1, Scope: registry.Spec.Volume, Owner: work.Native.Owner, Key: volumes.NativeKey(work.Native.Spec), Generation: work.Native.Generation, DeleteRevision: work.Revision}
	proof.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(proof))
	raw, _ := json.Marshal(VolumeDeleteReport{Operation: "delete", Schema: 1, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, At: 6, Proof: proof})
	cmd, err := f.p.ResolveVolumeDeleteReport(f.s, owner, raw)
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	f.s = next
	grant, err := f.p.ImageBuildCacheRetirementGrant(f.s, owner, plan.Spec)
	if err != nil || !grant.Valid() || grant.Operation != selection.Operation || grant.Source.Digest() != plan.Spec.Digest() || grant.Index != f.s.Index() {
		t.Fatal("original retirement did not derive exact source grant", grant, err)
	}
	if _, err := f.p.ImageBuildCacheRetirementGrant(f.s, [32]byte{99}, plan.Spec); err == nil {
		t.Fatal("another owner obtained cache grant")
	}
	bad := plan.Spec.Own()
	bad.ID = "another-original"
	if _, err := f.p.ImageBuildCacheRetirementGrant(f.s, owner, bad); err == nil {
		t.Fatal("unrecorded source obtained cache grant")
	}
	catalog, _ = f.p.Catalog(f.s)
	user, _ := catalog.User("manager")
	revision := user.Revision
	user.Revision, user.Enabled = 0, false
	f.apply("admin", "put-user", revision, user, state.Applied)
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := f.p.ImageBuildCacheRetirementGrant(restored, owner, plan.Spec)
	if err != nil || retained.Operation != grant.Operation || retained.StartedRevision != grant.StartedRevision || retained.InventoryHash != grant.InventoryHash || retained.OwnersHash != grant.OwnersHash {
		t.Fatal("restore/account revocation replaced original tenant closure authority", err)
	}
}
