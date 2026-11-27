// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/secrets"
)

func addRegistryInputFixture(t *testing.T, f *fixture) Source {
	t.Helper()
	f.add("tenant", secrets.Object{ID: "registry-group", Parent: "root", Kind: secrets.Group})
	tree := f.trees["tenant"]
	object, _ := tree.Object("registry-group")
	tree, err := tree.BeginPasswordChange(f.c, "admin", object.ID, "set-registry-password", object.Revision)
	f.tree("tenant", tree, err)
	object, _ = tree.Object(object.ID)
	tree, err = tree.ActivatePassword(f.c, "admin", object.ID, object.PasswordChange, "registry-verifier", true, object.Revision)
	f.tree("tenant", tree, err)
	f.add("tenant", secrets.Object{ID: "registry-login", Parent: "registry-group", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "vault", Object: "tenant/registry-login", Revision: 1, Keys: []string{"DB_HOST", "DB_PASSWORD", "password", "username"}}})
	return Source{"tenant", "registry-login"}
}

func TestRegistryAuxiliaryInputsShareApprovalAndLifetimeWithoutAppKeyOverride(t *testing.T) {
	f := makeFixture(t)
	n := f.web()
	n.RegistrySources = []Source{addRegistryInputFixture(t, f)}
	targets := f.approveAll(n)
	if len(targets) != 2 {
		t.Fatal("registry group was not approved together with original app group", len(targets))
	}
	r := f.reserve(n)
	b := r.Bindings[0]
	if len(b.Needs().RegistrySources) != 1 || !slices.Equal(b.Needs().Sources, n.Sources) {
		t.Fatal("registry refs replaced original source order")
	}
	values := f.values(n)
	defer func() {
		for _, value := range values {
			for _, data := range value.Value.Values {
				clear(data)
			}
		}
	}()
	stage, err := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, values, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Destroy()
	files := stage.Files()
	defer func() {
		for _, file := range files {
			clear(file.Data)
		}
	}()
	if len(files) != 2 || string(files[0].Data) != "private-db-value" || string(files[1].Data) != "tenant-overrides-DB_HOST" {
		t.Fatal("auxiliary auth overwrote app projection")
	}
	for _, file := range files {
		if bytes.Contains(file.Data, []byte("private-registry")) {
			t.Fatal("registry credential projected into app")
		}
	}
	if len(b.ProjectionGrants()) != 1 || len(b.RegistryGrants()) != 1 || b.RegistryGrants()[0].Consumer == b.ProjectionGrants()[0].Consumer {
		t.Fatal("auth and app grants share a revocation boundary")
	}
	combined := n
	combined.Sources = n.ApprovalSources()
	combined.RegistrySources = nil
	allValues := f.values(combined)
	defer func() {
		for _, value := range allValues {
			for _, data := range value.Value.Values {
				clear(data)
			}
		}
	}()
	for _, value := range allValues {
		if value.Value.Secret == "registry-login" {
			value.Value.Values["DB_HOST"] = []byte("private-registry-host")
			value.Value.Values["DB_PASSWORD"] = []byte("private-registry-password")
		}
	}
	if _, err = b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, allValues, 4096); err == nil {
		t.Fatal("registry bytes entered normal projection readset")
	}
	plans := map[string]secrets.UsePlan{}
	for realm, use := range approvalRealmUses(n) {
		batch, err := f.trees[realm].Plan(f.c, []secrets.Use{use})
		if err != nil {
			t.Fatal(err)
		}
		plans[realm] = batch.Uses[0]
	}
	prepared, err := materializeInputs(n, plans, allValues, 4096, b.Digest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := materializeInputs(n, plans, values, 4096, b.Digest()); err == nil {
		t.Fatal("prepared target skipped exact auxiliary validation")
	}
	defer prepared.Destroy()
	preparedFiles := prepared.Files()
	defer func() {
		for _, file := range preparedFiles {
			clear(file.Data)
		}
	}()
	if len(preparedFiles) != 2 || string(preparedFiles[1].Data) != "tenant-overrides-DB_HOST" {
		t.Fatal("preparation exposed auxiliary precedence")
	}
	registryGrant := b.RegistryGrants()[0]
	if _, err = f.a.ReadSet(f.c, f.trees["tenant"], registryGrant, 100); err != nil {
		t.Fatal("approved registry read denied", err)
	}
	tree := f.trees["tenant"]
	object, _ := tree.Object("registry-login")
	tree, err = tree.SetACL(f.c, "admin", object.ID, object.Revision, secrets.ACL{DenyUsers: []string{"alice"}})
	f.tree("tenant", tree, err)
	if _, err = f.a.ReadSet(f.c, tree, registryGrant, 100); err == nil {
		t.Fatal("revoked registry grant still permits a new read")
	}
	unchanged, err := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, values, 4096)
	if err != nil {
		t.Fatal("registry revocation broke unrelated running app inputs", err)
	}
	unchanged.Destroy()
	closure := f.closure(b)
	closed, err := f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, closure)
	if err != nil || len(closed.Inventory.Live()) != 0 {
		t.Fatal("original binding did not close auxiliary usage", err)
	}
}

func TestRegistryOnlyInputPublishesNoAppValuesAndRetainsOptionalSchemaOneBytes(t *testing.T) {
	f := makeFixture(t)
	n := f.web()
	n.Sources = nil
	n.Files = nil
	n.RegistrySources = []Source{addRegistryInputFixture(t, f)}
	f.approveAll(n)
	r := f.reserve(n)
	stage, err := r.Bindings[0].Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, f.values(n), 4096)
	if err != nil || len(stage.Files()) != 0 {
		t.Fatal("registry-only source became app projection", err)
	}
	stage.Destroy()
	legacy := f.web()
	raw, _ := json.Marshal(legacy)
	if bytes.Contains(raw, []byte("RegistrySources")) {
		t.Fatal("absent optional source changed schema1 bytes")
	}
	copy := r.Bindings[0].Needs()
	copy.RegistrySources[0].Object = "other"
	if r.Bindings[0].Needs().RegistrySources[0].Object != "registry-login" {
		t.Fatal("mutable auxiliary source alias")
	}
}

func TestBlueprintRegistrySourcesUseSameSelectionForPlanningAndPreparation(t *testing.T) {
	f := makeFixture(t)
	ctx := contextFor(t, f)
	input := smallCompose(t)
	source := imagesource.Source{Tenant: "tenant", ID: "docker", Authority: "docker.io", Repository: "library/**", Enabled: true, Auth: "password", Credential: &imagesource.Credential{Realm: "tenant", ID: "registry-login", UsernameKey: "username", PasswordKey: "password"}}
	ctx.ExternalRegistries = []imagesource.Definition{{Spec: imagesource.Own(source)}}
	plan, err := Compile(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.d.RegistrySources) != len(input.Services) || plan.CheckRegistrySources(ctx.ExternalRegistries) != nil {
		t.Fatal("frozen app auth scope missing")
	}
	raw, err := plan.Encode()
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := DecodeBlueprint(raw)
	if err != nil || reopened.CheckRegistrySources(ctx.ExternalRegistries) != nil {
		t.Fatal("reopened plan lost original registry refs", err)
	}
	ctx.ExternalRegistries[0].Spec.Credential.ID = "different-secret"
	if reopened.CheckRegistrySources(ctx.ExternalRegistries) == nil {
		t.Fatal("prepared target borrowed new unapproved credential")
	}
	ctx.ExternalRegistries[0].Spec = imagesource.Own(source)
	ctx.ExternalRegistries[0].Deleted = true
	if reopened.CheckRegistrySources(ctx.ExternalRegistries) == nil {
		t.Fatal("revoked source used by frozen preparation")
	}
}
