// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagesource"
)

func TestExternalRegistryCASRetainsRevocationAndReopensFromSameCheckpoint(t *testing.T) {
	f, _ := registryFixture(t)
	spec := imagesource.Source{Tenant: "tenant", ID: "private", Authority: "ghcr.io", Repository: "**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	image, err := access.PinImage("ghcr.io/team/app@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := f.p.ExternalRegistryForImage(f.s, "tenant", image)
	if err != nil || selected == nil || !imagesource.Equal(*selected, spec) {
		t.Fatal("missing exact source", err)
	}
	if selected, err = f.p.ExternalRegistryForImage(f.s, "foreign", image); err != nil || selected != nil {
		t.Fatal("foreign credential selected", err)
	}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.ConditionFailed)
	narrow := imagesource.Own(spec)
	narrow.ID = "team"
	narrow.Repository = "team/**"
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{narrow}, state.Applied)
	f.apply("manager", "delete-external-registry", 1, RegistrySelection{Tenant: "tenant", ID: "team"}, state.Applied)
	if _, err = f.p.ExternalRegistryForImage(f.s, "tenant", image); err == nil {
		t.Fatal("deleted narrow credential fell back to broad source")
	}
	changed := imagesource.Own(narrow)
	changed.Authority = "other.example"
	f.apply("manager", "put-external-registry", 2, ExternalRegistryPut{changed}, state.ConditionFailed)
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.ExternalRegistryForImage(f.s, "tenant", image); err == nil {
		t.Fatal("snapshot lost revocation")
	}
	f.apply("manager", "put-external-registry", 2, ExternalRegistryPut{narrow}, state.Applied)
	selected, err = f.p.ExternalRegistryForImage(f.s, "tenant", image)
	if err != nil || selected == nil || selected.ID != "team" {
		t.Fatal("explicit same scope restoration", err)
	}
	rows, next, err := f.p.ExternalRegistryPage(f.s, f.sessions["manager"], 2, "tenant", "")
	if err != nil || len(rows) != 2 || next != "" {
		t.Fatal("public reference projection", rows, next, err)
	}
	public, _ := json.Marshal(rows)
	if strings.Contains(string(public), "Session") || strings.Contains(string(public), "Signature") {
		t.Fatal("public projection leaked original grants")
	}
	readOnly := f.sessions["manager"]
	readOnly.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	readOnly.Signature = ed25519.Sign(f.node, access.SessionBytes(readOnly))
	f.sessions["manager"] = readOnly
	f.apply("manager", "delete-external-registry", 3, RegistrySelection{Tenant: "tenant", ID: "team"}, state.Forbidden)
	if _, _, err = f.p.ExternalRegistryPage(f.s, readOnly, 2, "foreign", ""); err == nil {
		t.Fatal("foreign page exposed")
	}
}

func TestExternalRegistryRejectsManagedAuthorityAndDuplicateSelector(t *testing.T) {
	f, managed := registryFixture(t)
	spec := imagesource.Source{Tenant: "tenant", ID: "external", Authority: managed.Authority, Repository: "**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	f.apply("manager", "put-registry", 0, RegistryPut{managed}, state.ConditionFailed)
	f.apply("manager", "delete-external-registry", 1, RegistrySelection{Tenant: "tenant", ID: "external"}, state.Applied)
	f.apply("manager", "put-registry", 0, RegistryPut{managed}, state.ConditionFailed)
	other := imagesource.Own(spec)
	other.ID = "duplicate"
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{other}, state.ConditionFailed)
	f2, managed2 := registryFixture(t)
	f2.apply("manager", "put-registry", 0, RegistryPut{managed2}, state.Applied)
	f2.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.ConditionFailed)
}

func TestExternalRegistrySelectionSharesActualAppPermitAndBlocksRevokedPull(t *testing.T) {
	f, q, owner := registryImageTaskFixture(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageRegistry)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	spec := imagesource.Source{Tenant: "tenant", ID: "docker", Authority: "docker.io", Repository: "library/**", Enabled: true, Auth: "none"}
	originalTask, originalApps := f.s.Object(q.Task.Key), f.s.Object(AppsKey)
	managedDNSChange(t, f, "external-registry-definition", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	permit, err := f.p.RegistryImagePermit(f.s, owner, q)
	if err != nil || permit.Registry != nil || permit.External == nil || !imagesource.Equal(*permit.External, spec) {
		t.Fatal("actual app permit did not select scoped reference", err)
	}
	if f.s.Object(q.Task.Key) != originalTask || f.s.Object(AppsKey) != originalApps {
		t.Fatal("registry definition rewrote original task/binding")
	}
	spec.Auth = "password"
	spec.Credential = &imagesource.Credential{Realm: "tenant", ID: "registry-login", UsernameKey: "username", PasswordKey: "password"}
	managedDNSChange(t, f, "external-registry-protected", "put-external-registry", 1, ExternalRegistryPut{spec}, state.Applied)
	if _, err = f.p.RegistryImagePermit(f.s, owner, q); err == nil {
		t.Fatal("old task borrowed a newly configured unapproved secret")
	}
	managedDNSChange(t, f, "external-registry-revocation", "delete-external-registry", 2, RegistrySelection{Tenant: "tenant", ID: "docker"}, state.Applied)
	if _, err = f.p.RegistryImagePermit(f.s, owner, q); err == nil {
		t.Fatal("revoked source permitted anonymous pull")
	}
	if f.s.Object(q.Task.Key) != originalTask || f.s.Object(AppsKey) != originalApps {
		t.Fatal("source revocation retired original app")
	}
}

func TestExternalRegistryManagementInputRejectsSecretValuesAndMissingEnabled(t *testing.T) {
	good := `{"schema":1,"action":"put-external-registry","expected":0,"payload":{"Spec":{"Tenant":"tenant","ID":"private","Authority":"ghcr.io","Repository":"**","Enabled":true,"Auth":"none"}}}`
	change, err := InputChange([]byte(good), "admin")
	if err != nil || CommandKey(change.Action) != ExternalRegistriesKey {
		t.Fatal("typed public reference input", err)
	}
	for _, bad := range []string{
		strings.Replace(good, `"Enabled":true,`, "", 1),
		strings.Replace(good, `"Auth":"none"`, `"Auth":"none","Password":"secret-value"`, 1),
		strings.Replace(good, `"Auth":"none"`, `"Auth":"none","Token":"secret-value"`, 1),
	} {
		if _, err := InputChange([]byte(bad), "admin"); err == nil {
			t.Fatal("unsafe registry metadata document accepted")
		}
	}
}

func TestExternalRegistryReducerPreservesCredentialActionCeiling(t *testing.T) {
	f, _ := registryFixture(t)
	spec := imagesource.Source{Tenant: "tenant", ID: "private", Authority: "ghcr.io", Repository: "**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := c.User("manager")
	c, err = c.SetAccountScope("admin", u.Revision, access.AccountScope{User: "manager", Add: []string{"put-external-registry"}})
	if err != nil {
		t.Fatal(err)
	}
	writes, code := f.p.checkpoint(f.s, c)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.checkpoint(CatalogKey, writes)
	u, _ = c.User("manager")
	session := f.sessions["manager"]
	session.ID = "restricted-manager"
	session.AccountRevision = u.Revision
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	f.apply("manager", "delete-external-registry", 1, RegistrySelection{Tenant: "tenant", ID: "private"}, state.Forbidden)
	f.apply("manager", "put-external-registry", 1, ExternalRegistryPut{spec}, state.Applied)
}

func TestClusterExternalRegistryNeedsManageClusterAndIsSharedReadOnly(t *testing.T) {
	f, _ := registryFixture(t)
	spec := imagesource.Source{ID: "mirror", Authority: "ghcr.io", Repository: "**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Forbidden)
	f.apply("admin", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	image, err := access.PinImage("ghcr.io/team/app@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := f.p.ExternalRegistryForImage(f.s, "tenant", image)
	if err != nil || selected == nil || !selected.Cluster() || selected.ID != "mirror" {
		t.Fatal("workspace did not use the cluster source", selected, err)
	}
	rows, _, err := f.p.ExternalRegistryPage(f.s, f.sessions["manager"], 2, "tenant", "")
	if err != nil || len(rows) != 1 || !rows[0].Spec.Cluster() {
		t.Fatal("workspace page did not list the cluster source", rows, err)
	}
	if _, _, err = f.p.ExternalRegistryPage(f.s, f.sessions["manager"], 2, "", ""); err == nil {
		t.Fatal("cluster page without ManageCluster")
	}
	if rows, _, err = f.p.ExternalRegistryPage(f.s, f.sessions["admin"], 2, "", ""); err != nil || len(rows) != 1 {
		t.Fatal("cluster page", rows, err)
	}
	// The workspace's own source for the same authority wins.
	own := imagesource.Source{Tenant: "tenant", ID: "own", Authority: "ghcr.io", Repository: "**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{own}, state.Applied)
	if selected, err = f.p.ExternalRegistryForImage(f.s, "tenant", image); err != nil || selected == nil || selected.ID != "own" {
		t.Fatal("cluster source beat the workspace source", selected, err)
	}
	f.apply("manager", "delete-external-registry", 1, RegistrySelection{ID: "mirror"}, state.Forbidden)
	f.apply("admin", "delete-external-registry", 1, RegistrySelection{ID: "mirror"}, state.Applied)
}
