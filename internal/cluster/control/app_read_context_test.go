// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

func TestAppPlanningBorrowedRecipesReturnOwnedPrograms(t *testing.T) {
	f, _, _, _, _ := checkerProbePermitFixture(t)
	permitAppsDecoded.Store(nil)
	first, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil || len(first.CheckerPrograms) == 0 {
		t.Fatal("accepted checker recipe", err)
	}
	cached := permitAppsDecoded.Load()
	if cached == nil {
		t.Fatal("planning did not reuse checked Apps")
	}
	want := map[deployment.AppScope][]byte{}
	for scope, program := range first.CheckerPrograms {
		want[scope], err = json.Marshal(program)
		if err != nil {
			t.Fatal(err)
		}
		if len(program.Program.Checks) == 0 || len(program.Policy.Execution.Capabilities) == 0 {
			t.Fatal("mutable checker metadata missing from fixture")
		}
		program.Program.Checks[0].ID = "caller-mutation"
		program.Policy.Execution.Capabilities[0] = "caller-mutation"
		first.CheckerPrograms[scope] = program
	}
	again, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil || len(again.CheckerPrograms) != len(want) || permitAppsDecoded.Load() != cached {
		t.Fatal("planning leaked its borrowed recipe", err)
	}
	for scope, program := range again.CheckerPrograms {
		got, _ := json.Marshal(program)
		if !bytes.Equal(got, want[scope]) {
			t.Fatal("caller mutation changed the original accepted checker recipe")
		}
	}
}

func TestAppDeliveryBorrowedPermitOwnsOutputAndRechecksAuthority(t *testing.T) {
	f := deliveryControlFixture(t)
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	q := AppDeliveryRequest{Tenant: "tenant", App: "source-app", TargetCAS: true}
	permitAppsDecoded.Store(nil)
	first, err := f.p.AppDeliveryPermit(f.s, owner, q)
	if err != nil || first.Ticket == nil || first.Target == nil {
		t.Fatal("original pending source", err)
	}
	cached := permitAppsDecoded.Load()
	want, _ := json.Marshal(first)
	first.Policy.Source.Repository = "https://caller.invalid/replaced"
	first.Ticket.Sequence++
	first.Target[0] ^= 1
	again, err := f.p.AppDeliveryPermit(f.s, owner, q)
	got, _ := json.Marshal(again)
	if err != nil || !bytes.Equal(got, want) || cached == nil || permitAppsDecoded.Load() != cached {
		t.Fatal("source permit leaked borrowed state", err)
	}
	foreign := owner
	foreign[0] ^= 1
	if _, err := f.p.AppDeliveryPermit(f.s, foreign, q); err == nil {
		t.Fatal("cached source admitted a foreign member")
	}
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User("admin")
	expected := u.Revision
	u.Revision, u.Username = 0, "renamed-admin"
	c, err = c.PutUser("admin", expected, u)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := c.Encode()
	writes, code := writeCheckpoint(f.s, CatalogKey, f.p.Cluster, f.p.BootstrapKey, c.Revision(), raw)
	if code != state.Applied {
		t.Fatal(code)
	}
	changed := permitDecodeWrites(t, f.s, CatalogKey, writes)
	if _, err := f.p.AppDeliveryPermit(changed, owner, q); err == nil {
		t.Fatal("cached source bypassed current accepted authority")
	}
}

func TestPlanningAndDeliveryRejectChangedCurrentResources(t *testing.T) {
	f := deliveryControlFixture(t)
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	q := AppDeliveryRequest{Tenant: "tenant", App: "source-app", TargetCAS: true}
	want, err := f.p.AppDeliveryPermit(f.s, owner, q)
	if err != nil {
		t.Fatal("original source permission", err)
	}
	wantBytes, _ := json.Marshal(want)
	for _, key := range []string{ResourcesKey, VolumesKey, MembersKey, LifecycleKey} {
		t.Run(key, func(t *testing.T) {
			// Keep the accepted Apps/ticket identical, but change another current
			// checkpoint. Reusing decoding must not reuse its previous authority.
			changed := permitDecodeWrites(t, f.s, key, map[string][]byte{key: []byte("invalid-current-resource")})
			if changed.Object(AppsKey) != f.s.Object(AppsKey) {
				t.Fatal("counterexample changed the accepted source")
			}
			if _, err := f.p.AppPlanning(changed, "admin", "tenant"); err == nil {
				t.Fatal("planning ignored changed current checkpoint")
			}
			if _, err := f.p.AppDeliveryPermit(changed, owner, q); err == nil {
				t.Fatal("source permission ignored changed current checkpoint")
			}
			got, err := f.p.AppDeliveryPermit(f.s, owner, q)
			gotBytes, _ := json.Marshal(got)
			if err != nil || !bytes.Equal(gotBytes, wantBytes) {
				t.Fatal("another view contaminated original source/ticket", err)
			}
		})
	}
}

func TestAppCandidateValidationBorrowRechecksObjectsAndCatalog(t *testing.T) {
	f, _, q := permitDecodeFixture(t)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	permitAppsDecoded.Store(nil)
	if err := f.p.ValidateManaged(f.s, f.s, state.Command{}); err != nil {
		t.Fatal("original candidate", err)
	}
	cached := permitAppsDecoded.Load()
	if err := f.p.ValidateManaged(f.s, f.s, state.Command{}); err != nil || cached == nil || permitAppsDecoded.Load() != cached {
		t.Fatal("unchanged candidate", err)
	}
	changed, result, err := state.Apply(f.s, f.s.Index()+1, state.Command{Actor: "anchor", Epoch: 1, RequestID: "task-counterexample", Key: q.Task.Key, Expected: f.s.Object(q.Task.Key).Revision, Value: "{}"})
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	if err := f.p.ValidateManaged(f.s, changed, state.Command{}); err == nil {
		t.Fatal("cached Apps concealed a changed Task")
	}
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User("admin")
	u.Revision = 0
	empty, _ := access.New(f.p.BootstrapKey)
	empty, err = empty.Enroll(f.p.BootstrapKey, u)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := empty.Encode()
	writes, code := writeCheckpoint(f.s, CatalogKey, f.p.Cluster, f.p.BootstrapKey, empty.Revision(), raw)
	if code != state.Applied {
		t.Fatal(code)
	}
	changed = permitDecodeWrites(t, f.s, CatalogKey, writes)
	if err := f.p.ValidateManaged(f.s, changed, state.Command{}); err == nil {
		t.Fatal("cached Apps concealed a missing current tenant")
	}
	if _, err := f.p.AppPlanning(changed, "admin", "tenant"); err == nil {
		t.Fatal("planning reused a removed tenant")
	}
}

func TestRuntimeAppsReadViewOwnsOutputsAndChecksCurrentState(t *testing.T) {
	f, owner, q := permitDecodeFixture(t)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	permitAppsDecoded.Store(nil)
	a, err := f.p.ReadApps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	cached := permitAppsDecoded.Load()
	if cached == nil {
		t.Fatal("runtime did not share checked interpretation")
	}
	before, err := f.p.AppTaskMaterial(f.s, q.Task)
	if err != nil {
		t.Fatal(err)
	}
	wantMaterial, _ := json.Marshal(before)
	wantRecords, _ := json.Marshal(a.Records())
	origin, ok := a.Origin("tenant", "first")
	if !ok || len(origin.Signature) == 0 || len(origin.Change.Payload) == 0 {
		t.Fatal("origin fixture")
	}
	origin.Signature[0] ^= 1
	origin.Change.Payload[0] ^= 1
	source, ok := a.BindingSource(q.Digest)
	if !ok {
		t.Fatal("binding source fixture")
	}
	if len(source.Origin.Signature) != 0 {
		source.Origin.Signature[0] ^= 1
	}
	execution, ok := a.Execution("tenant", "first")
	if !ok {
		t.Fatal("execution fixture")
	}
	steps := execution.Steps()
	if len(steps) == 0 {
		t.Fatal("execution steps fixture")
	}
	steps[0].Key = "caller-mutated"
	_, rows, ok := a.NetworkDNS(owner)
	if !ok || len(rows) == 0 || rows[0].Managed == nil {
		t.Fatal("DNS fixture")
	}
	wantDNS, _ := json.Marshal(rows)
	rows[0].Managed.Node = "caller-mutated"
	rows[0].Config.Zone = "caller.invalid"
	// The mutating reducer entry point continues to return an owned decode.
	owned, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	delete(owned.entries, appKey("tenant", "first"))
	again, err := f.p.ReadApps(f.s)
	if err != nil || permitAppsDecoded.Load() != cached {
		t.Fatal("same checked runtime view", err)
	}
	gotRecords, _ := json.Marshal(again.Records())
	material, err := f.p.AppTaskMaterial(f.s, q.Task)
	gotMaterial, _ := json.Marshal(material)
	_, rows, ok = again.NetworkDNS(owner)
	gotDNS, _ := json.Marshal(rows)
	if err != nil || !ok || !bytes.Equal(wantRecords, gotRecords) || !bytes.Equal(wantMaterial, gotMaterial) || !bytes.Equal(wantDNS, gotDNS) {
		t.Fatal("runtime output aliases shared interpretation", err)
	}
	// A hit must still read the current root/parts and current outside state.
	corrupt := permitDecodeWrites(t, f.s, AppsKey, map[string][]byte{AppsKey: []byte("{}")})
	if _, err := f.p.ReadApps(corrupt); err == nil {
		t.Fatal("cached Apps bypassed current checkpoint")
	}
	catalog, _ := f.p.Catalog(f.s)
	user, _ := catalog.User("admin")
	user.Revision = 0
	empty, _ := access.New(f.p.BootstrapKey)
	empty, err = empty.Enroll(f.p.BootstrapKey, user)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := empty.Encode()
	writes, code := writeCheckpoint(f.s, CatalogKey, f.p.Cluster, f.p.TrustRoot, empty.Revision(), raw)
	if code != state.Applied {
		t.Fatal(code)
	}
	changed := permitDecodeWrites(t, f.s, CatalogKey, writes)
	if _, err := f.p.ReadApps(changed); err == nil {
		t.Fatal("cached Apps bypassed current tenant")
	}
}

func TestRuntimeAppsReadViewOwnsDeliveryMetadata(t *testing.T) {
	f := deliveryControlFixture(t)
	permitAppsDecoded.Store(nil)
	a, err := f.p.ReadApps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	records := a.Records()
	if len(records) != 1 || records[0].CD == nil {
		t.Fatal("delivery fixture")
	}
	want, _ := json.Marshal(records)
	records[0].CD.Policy.Source.Path = "caller-mutated.yaml"
	if records[0].CD.Candidate != nil {
		records[0].CD.Candidate.Commit = "caller-mutated"
	}
	registration, ok := a.CDRegistration("tenant", "source-app")
	if !ok || len(registration.Signature) == 0 {
		t.Fatal("registration fixture")
	}
	registration.Signature[0] ^= 1
	again, err := f.p.ReadApps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(again.Records())
	if !bytes.Equal(want, got) {
		t.Fatal("runtime delivery metadata aliases shared interpretation")
	}
}
