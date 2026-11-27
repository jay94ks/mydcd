// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagesource"
)

func TestRegistryCatalogueReusesApprovedReaderAndInvalidatesNarrowerSource(t *testing.T) {
	f, _ := registryFixture(t)
	session := f.sessions["manager"]
	session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.Deploy)
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	spec := imagesource.Source{Tenant: "tenant", ID: "source", Authority: "registry.example", Repository: "team/**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	bind, err := f.p.PlanExternalRegistryBind(f.s, session, 2, "tenant", "source", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "bind-external-registry", bind.Expected, bind.Selection, state.Applied)
	q := RegistryCatalogueQuery{Kind: "external", ID: "source"}
	read, err := f.p.PlanRegistryCatalogue(f.s, session, 2, "tenant", q, "")
	if err != nil || read.Target.External == nil || read.Target.ReadSet == ([32]byte{}) || read.Target.Managed != nil || !f.p.RegistryCatalogueRepositoryAllowed(f.s, read, "team/app") || f.p.RegistryCatalogueRepositoryAllowed(f.s, read, "foreign/app") {
		t.Fatal(read, err)
	}
	// Read-only users obtain public results through the existing approved reader;
	// that permission does not grant raw SecretFetch or a new source approval.
	reader := session
	reader.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	reader.Signature = ed25519.Sign(f.node, access.SessionBytes(reader))
	public, err := f.p.PlanRegistryCatalogue(f.s, reader, 2, "tenant", q, "")
	if err != nil || public.Basis() == read.Basis() {
		t.Fatal("read projection/signed ceiling", err)
	}
	for _, tc := range []struct {
		tenant string
		q      RegistryCatalogueQuery
		after  string
	}{
		{"other", q, ""}, {"tenant", RegistryCatalogueQuery{Kind: "external", ID: "source", Repository: "foreign/app"}, ""}, {"tenant", q, "not-a-cursor"}, {"tenant", RegistryCatalogueQuery{Kind: "managed", ID: "source"}, ""},
	} {
		if _, err = f.p.PlanRegistryCatalogue(f.s, session, 2, tc.tenant, tc.q, tc.after); err == nil {
			t.Fatal("foreign/invalid catalogue selection accepted", tc)
		}
	}
	narrow := spec
	narrow.ID = "narrow"
	narrow.Repository = "team/private"
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{narrow}, state.Applied)
	if f.p.RegistryCatalogueRepositoryAllowed(f.s, read, "team/private") {
		t.Fatal("broad source exposed narrower repository")
	}
	if _, err = f.p.CurrentRegistryCatalogue(f.s, read, 2); err == nil {
		t.Fatal("narrower source did not fence old catalogue")
	}
	fresh, err := f.p.PlanRegistryCatalogue(f.s, session, 2, "tenant", q, "")
	if err != nil || fresh.Target.Definitions == read.Target.Definitions {
		t.Fatal("definition basis not updated", err)
	}
	f.apply("manager", "delete-external-registry", 1, RegistrySelection{Tenant: "tenant", ID: "narrow"}, state.Applied)
	if f.p.RegistryCatalogueRepositoryAllowed(f.s, fresh, "team/private") {
		t.Fatal("deleted narrower source fell back to broad credential")
	}
}

func TestManagedCatalogueBasisIgnoresReadinessRefreshButRequiresSameEnabledRun(t *testing.T) {
	f, spec := readyMaintenanceRegistry(t)
	read, err := f.p.PlanRegistryCatalogue(f.s, f.sessions["manager"], 3, spec.Tenant, RegistryCatalogueQuery{Kind: "managed", ID: spec.ID, Repository: "team/app"}, "")
	if err != nil || read.Target.Managed == nil || read.Target.Managed.Ready != nil {
		t.Fatal(read, err)
	}
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "serving", SpecRevision: 1, Generation: 1, Observation: &RegistryObservation{Boot: [32]byte{9}, Certificate: [32]byte{2}}}, state.Applied)
	current, err := f.p.CurrentRegistryCatalogue(f.s, read, 3)
	if err != nil || current.Basis() != read.Basis() {
		t.Fatal("readiness/boot refresh invalidated unchanged image metadata", err)
	}
	f.apply("manager", "stop-registry", 1, RegistrySelection{Tenant: spec.Tenant, ID: spec.ID}, state.Applied)
	if _, err = f.p.CurrentRegistryCatalogue(f.s, read, 3); err == nil {
		t.Fatal("disabled original run still authorized catalogue read")
	}
}
