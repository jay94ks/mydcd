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
	"github.com/jay94ks/seafield/internal/secrets"
)

// Signatures/checkpoints/reducers are real; owner join is simulated here and
// must also be tested at the Runtime I/O boundary in RQ6's final batch.
func TestSourceReaderBindDrainOwnerClosureAndSnapshot(t *testing.T) {
	f, _ := registryFixture(t)
	session := f.sessions["manager"]
	session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.Deploy)
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	spec := imagesource.Source{Tenant: "tenant", ID: "source", Authority: "ghcr.io", Repository: "team/**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	plan, err := f.p.PlanExternalRegistryBind(f.s, session, 2, "tenant", "source", "node-a")
	if err != nil || plan.Expected != 1 || len(plan.Uses) != 0 {
		t.Fatal("anonymous reader plan", plan, err)
	}
	f.apply("manager", "bind-external-registry", plan.Expected, plan.Selection, state.Applied)
	entries, err := f.p.ExternalRegistries(f.s)
	if err != nil || len(entries) != 1 || entries[0].Reader == nil {
		t.Fatal("reader not committed", err)
	}
	reader := *entries[0].Reader
	selection := ExternalRegistryReadSelection{Tenant: "tenant", ID: "source", Generation: reader.Generation}
	work, err := f.p.ExternalRegistryWork(f.s, reader.Owner, ExternalRegistryWorkRequest{selection, 2})
	if err != nil || work.Inputs.ReadSet == ([32]byte{}) || len(work.Inputs.Entries) != 0 {
		t.Fatal("owner work", err)
	}
	probe, err := f.p.PlanExternalRegistryProbe(f.s, session, 2, "tenant", ExternalRegistryProbeQuery{ID: "source", Image: "ghcr.io/team/app:latest"})
	if err != nil || probe.Selection != selection {
		t.Fatal("app-free login/pull plan", err)
	}
	for _, q := range []ExternalRegistryProbeQuery{{ID: "source", Image: "ghcr.io/foreign/app:latest"}, {ID: "source", Image: "foreign.example/team/app:latest"}} {
		if _, err = f.p.PlanExternalRegistryProbe(f.s, session, 2, "tenant", q); err == nil {
			t.Fatal("probe expanded repository scope")
		}
	}
	proof := ExternalRegistryReaderClosed{Schema: 1, Cluster: f.p.Cluster, Owner: reader.Owner, Tenant: "tenant", ID: "source", Generation: reader.Generation, Index: f.s.Index(), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(ExternalRegistriesKey).Revision, At: 3, Closed: true}
	applyProof := func(want state.Code) {
		t.Helper()
		proof.Signature = ed25519.Sign(f.node, ExternalRegistryReaderClosedBytes(proof))
		cmd, err := proof.Command()
		if err != nil {
			t.Fatal(err)
		}
		next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != want {
			t.Fatal("closure", result.Code, want, err)
		}
		f.s = next
	}
	applyProof(state.Forbidden)
	f.apply("manager", "unbind-external-registry", 2, RegistrySelection{"tenant", "source"}, state.Applied)
	if _, err = f.p.ExternalRegistryWork(f.s, reader.Owner, ExternalRegistryWorkRequest{selection, 3}); err == nil {
		t.Fatal("drain allowed fresh secret read")
	}
	if _, err = f.p.ExternalRegistryProbeOwner(f.s, probe, 3); err == nil {
		t.Fatal("old public query remained authorized")
	}
	if _, err = f.p.PlanExternalRegistryBind(f.s, session, 3, "tenant", "source", "node-a"); err == nil {
		t.Fatal("metadata drain treated as joined")
	}
	proof.Index, proof.RootRevision = f.s.Index(), f.s.Object(ExternalRegistriesKey).Revision
	proof.Pending = 1
	applyProof(state.Forbidden)
	proof.Index = f.s.Index()
	proof.Pending = 0
	applyProof(state.Applied)
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	entries, err = f.p.ExternalRegistries(f.s)
	if err != nil || entries[0].Reader != nil || entries[0].Closed == nil || entries[0].Revision != 3 {
		t.Fatal("original closure/CAS lost", err)
	}
	plan, err = f.p.PlanExternalRegistryBind(f.s, session, 3, "tenant", "source", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "bind-external-registry", plan.Expected, plan.Selection, state.Applied)
	rows, _, err := f.p.ExternalRegistryPage(f.s, session, 3, "tenant", "")
	if err != nil || rows[0].Reader == nil || rows[0].Reader.Generation <= reader.Generation {
		t.Fatal("explicit next reader", err)
	}
	public, _ := json.Marshal(rows)
	for _, secret := range []string{"Grants", "Signature", "Session", "RequesterKey"} {
		if strings.Contains(string(public), secret) {
			t.Fatal("public reader exposed signed approval", secret)
		}
	}
}

func TestSourceReaderReservesAndReturnsOriginalVaultUsageAtomically(t *testing.T) {
	f, _ := registryFixture(t)
	session := f.sessions["manager"]
	session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.Deploy)
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := secrets.NewTree(f.p.Cluster, "tenant", "root")
	if err != nil {
		t.Fatal(err)
	}
	tree, err = tree.Create(c, "manager", tree.Revision(), secrets.Object{ID: "login", Parent: "root", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "vault", Object: "tenant/login", Revision: 1, Keys: []string{"password", "username"}}})
	if err != nil {
		t.Fatal(err)
	}
	vault.Trees["tenant"] = tree
	writes, code := f.p.vaultCheckpoint(f.s, vault)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.checkpoint(VaultKey, writes)
	spec := imagesource.Source{Tenant: "tenant", ID: "source", Authority: "ghcr.io", Repository: "team/**", Enabled: true, Auth: "password", Credential: &imagesource.Credential{Realm: "tenant", ID: "login", UsernameKey: "username", PasswordKey: "password"}}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	plan, err := f.p.PlanExternalRegistryBind(f.s, session, 2, "tenant", "source", "node-a")
	query := ExternalRegistryBindQuery{ID: "source", Node: "node-a"}
	if err != nil || !plan.Valid(session, "tenant", query) || len(plan.Uses["tenant"]) != 1 {
		t.Fatal("exact public use plan", err)
	}
	bad := plan
	bad.Uses = map[string][]secrets.Use{"tenant": {plan.Uses["tenant"][0]}}
	bad.Uses["tenant"][0].Purpose = ""
	if bad.Valid(session, "tenant", query) {
		t.Fatal("plan borrowed mount purpose")
	}
	before := f.s.Object(VaultKey)
	wrong := plan.Selection
	wrong.Definition[0] ^= 1
	f.apply("manager", "bind-external-registry", plan.Expected, wrong, state.ConditionFailed)
	if f.s.Object(VaultKey) != before {
		t.Fatal("failed source CAS leaked a Vault reservation")
	}
	f.apply("manager", "bind-external-registry", plan.Expected, plan.Selection, state.Applied)
	entries, err := f.p.ExternalRegistries(f.s)
	if err != nil || len(entries) != 1 || entries[0].Reader == nil {
		t.Fatal(err)
	}
	reader := *entries[0].Reader
	if len(reader.Grants) != 1 || reader.Grants[0].Use.Purpose != secrets.PurposeRegistrySource {
		t.Fatal("source usage not reserved")
	}
	vault, err = f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vault.Approvals.Usage(reader.Grants[0]); !ok {
		t.Fatal("source and Vault not committed together")
	}
	current, err := f.p.Current(f.s)
	if err != nil {
		t.Fatal(err)
	}
	uses, err := current.approvalUsesFor(f.s, session, 2, &reader.Origin, nil)
	if err != nil || uses["tenant"][0].Purpose != secrets.PurposeRegistrySource {
		t.Fatal("accepted original approval identity lost", err)
	}
	f.apply("manager", "delete-external-registry", 2, RegistrySelection{"tenant", "source"}, state.Applied)
	vault, err = f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vault.Approvals.Usage(reader.Grants[0]); !ok {
		t.Fatal("metadata delete returned unjoined usage")
	}
	proof := ExternalRegistryReaderClosed{Schema: 1, Cluster: f.p.Cluster, Owner: reader.Owner, Tenant: "tenant", ID: "source", Generation: reader.Generation, Index: f.s.Index(), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(ExternalRegistriesKey).Revision, At: 3, Closed: true}
	for _, grant := range reader.Grants {
		use := grant.Use
		gone := secrets.UseGone{Purpose: use.Purpose, Cluster: f.p.Cluster, Realm: grant.Realm, Tenant: use.Tenant, App: use.App, Deployment: use.Deployment, Consumer: grant.Consumer, Generation: grant.Generation, NodeKey: reader.Owner, Selection: grant.Selection, Lifetime: grant.Lifetime, Stopped: true, MountsGone: true}
		gone.Signature = ed25519.Sign(f.node, secrets.UseGoneBytes(gone))
		proof.Secrets = append(proof.Secrets, gone)
	}
	proof.Signature = ed25519.Sign(f.node, ExternalRegistryReaderClosedBytes(proof))
	cmd, err := proof.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("owner closure", result.Code, err)
	}
	f.s = next
	vault, err = f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vault.Approvals.Usage(reader.Grants[0]); ok {
		t.Fatal("joined usage not returned")
	}
	if _, ok := vault.Trees["tenant"].Object("login"); !ok {
		t.Fatal("closure deleted original Secret")
	}
	if entries, err = f.p.ExternalRegistries(f.s); err != nil || entries[0].Reader != nil || !entries[0].Deleted {
		t.Fatal("revocation/receipt not preserved", err)
	}
}
