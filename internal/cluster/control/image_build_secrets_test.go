// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/secrets"
)

func buildSecretFixture(t *testing.T) (*nodeStorageFixture, ImageBuildJobPlan) {
	t.Helper()
	f, first := buildJobFixture(t)
	session := f.sessions["manager"]
	session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.Deploy)
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := secrets.NewTree(f.p.Cluster, "tenant", "root")
	if err != nil {
		t.Fatal(err)
	}
	tree, err = tree.SetWriteProfile(c, "admin", tree.Revision(), secrets.WriteProfile{ID: "values", Node: "node-a", Key: first.Spec.Scope.Root.Key, Enabled: true, Values: true, Mode: "local-file"})
	if err != nil {
		t.Fatal(err)
	}
	tree, err = tree.Create(c, "manager", tree.Revision(), secrets.Object{ID: "signing", Parent: "root", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "values", Object: "tenant/signing", Revision: 1, Keys: []string{"empty", "private"}}})
	if err != nil {
		t.Fatal(err)
	}
	v.Trees["tenant"] = tree
	writes, code := f.p.vaultCheckpoint(f.s, v)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.checkpoint(VaultKey, writes)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	context, ok := b.Context("tenant", "source")
	if !ok {
		t.Fatal("missing context")
	}
	context.Spec.Secrets = []imagebuild.SecretMount{{ID: "signer", Realm: "tenant", Secret: "signing", Key: "private"}, {ID: "empty", Realm: "tenant", Secret: "signing", Key: "empty"}}
	f.apply("manager", "put-build-context", context.Revision, ImageBuildContextPut{Spec: context.Spec}, state.Applied)
	plan, err := f.p.ImageBuildJobPlan(f.s, session, 2, "tenant", ImageBuildJobQuery{ID: "build-one", Context: "source", Version: first.Spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	return f, plan
}

// Real signatures/reducer/Vault usage/snapshot, with an explicitly injected
// native closure. Actual SecretFetch/TAR/build/push is RQ6 final adapter proof.
func TestBuildSecretReservationProviderPermitAndClosureAreOneOriginalLifetime(t *testing.T) {
	f, plan := buildSecretFixture(t)
	if !ValidImageBuildSecretUses(plan, f.sessions["manager"]) || len(plan.Uses) != 1 || len(plan.Uses["tenant"]) != 1 || plan.Uses["tenant"][0].Purpose != secrets.PurposeImageBuild || len(plan.Uses["tenant"][0].Sources) != 1 {
		t.Fatal("invalid/doubled purpose plan")
	}
	bad := plan
	bad.Uses = map[string][]secrets.Use{"tenant": {plan.Uses["tenant"][0]}}
	bad.Uses["tenant"][0].Purpose = ""
	if ValidImageBuildSecretUses(bad, f.sessions["manager"]) {
		t.Fatal("borrowed app approval namespace")
	}
	before := f.s.Object(VaultKey)
	wrong := plan.Change
	wrong.Snapshot[0] ^= 1
	f.apply("manager", "begin-image-build", 0, wrong, state.ConditionFailed)
	if f.s.Object(VaultKey) != before {
		t.Fatal("rejected job leaked usage")
	}
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := b.Job("tenant", "build-one")
	if !ok || len(row.Grants) != 1 {
		t.Fatal("missing original grant")
	}
	v, err := f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	grant := row.Grants[0]
	if _, ok := v.Approvals.Usage(grant); !ok {
		t.Fatal("job/Vault not committed atomically")
	}
	current, err := f.p.Current(f.s)
	if err != nil {
		t.Fatal(err)
	}
	uses, err := current.approvalUsesFor(f.s, f.sessions["manager"], 3, &row.Origin, nil)
	if err != nil || !buildJSONEqual(uses, plan.Uses) {
		t.Fatal("accepted original approval identity changed", err)
	}
	q := ImageBuildSecretRequest{Selection: ImageBuildSecretSelection{Tenant: "tenant", Job: "build-one", Snapshot: plan.Spec.Digest()}, At: 3}
	if _, err := f.p.ImageBuildSecretInputs(f.s, plan.Spec.Scope.Root.Key, q); err == nil {
		t.Fatal("queued job fetched values")
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "begin"}, state.Applied)
	inputs, err := f.p.ImageBuildSecretInputs(f.s, plan.Spec.Scope.Root.Key, q)
	if err != nil || inputs.Inputs.ReadSet == ([32]byte{}) || len(inputs.Inputs.Entries) != 1 {
		t.Fatal("deduplicated exact provider input", err)
	}
	input := inputs.Inputs.Entries[0]
	fetch := AppInputFetch{Schema: 1, Consumer: plan.Spec.Scope.Root.Key, Binding: AppBindingRequest{At: 3}, ReadSet: inputs.Inputs.ReadSet, MinimumIndex: inputs.Index, Realm: "tenant", Secret: "signing", ImageBuild: &q.Selection}
	if _, err := f.p.AppInputFetchPermit(f.s, input.Provider.Key, fetch); err != nil {
		t.Fatal("original provider read denied", err)
	}
	for _, edit := range []func(*AppInputFetch){func(q *AppInputFetch) { q.Secret = "other" }, func(q *AppInputFetch) { q.Consumer = [32]byte{9} }, func(q *AppInputFetch) {
		q.ExternalRegistry = &ExternalRegistryReadSelection{Tenant: "tenant", ID: "other", Generation: 1}
	}, func(q *AppInputFetch) { q.Binding.Task.Key = "workload/task/tenant/app/web" }} {
		bad := fetch
		edit(&bad)
		if _, err := f.p.AppInputFetchPermit(f.s, input.Provider.Key, bad); err == nil {
			t.Fatal("foreign/mixed provider read accepted")
		}
	}
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := c.User("manager")
	u.Enabled = false
	revision := u.Revision
	u.Revision = 0
	c, err = c.PutUser("admin", revision, accountFields(u))
	if err != nil {
		t.Fatal(err)
	}
	writes, code := f.p.checkpoint(f.s, c)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.checkpoint(CatalogKey, writes)
	if _, err := f.p.ImageBuildSecretInputs(f.s, plan.Spec.Scope.Root.Key, q); err == nil {
		t.Fatal("revoked account fetched old values")
	}
	v, err = f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Approvals.Usage(grant); !ok {
		t.Fatal("revocation returned original usage")
	}
	f.apply("admin", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: "tenant", ID: "build-one"}, state.Applied)
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	report := ImageBuildJobReport{Job: "build-one", Action: "complete", Closure: &closure}
	buildJobReportFixture(t, f, report, state.Forbidden)
	use := grant.Use
	proof := secrets.UseGone{Purpose: use.Purpose, Cluster: f.p.Cluster, Realm: grant.Realm, Tenant: use.Tenant, App: use.App, Deployment: use.Deployment, Consumer: grant.Consumer, Generation: grant.Generation, NodeKey: plan.Spec.Scope.Root.Key, Selection: grant.Selection, Lifetime: grant.Lifetime, Stopped: true, MountsGone: true}
	proof.Signature = ed25519.Sign(f.node, secrets.UseGoneBytes(proof))
	report.Secrets = []secrets.UseGone{proof}
	badProof := proof
	badProof.Purpose = ""
	badProof.Signature = ed25519.Sign(f.node, secrets.UseGoneBytes(badProof))
	report.Secrets[0] = badProof
	buildJobReportFixture(t, f, report, state.Forbidden)
	report.Secrets[0] = proof
	// A valid UseGone cannot erase a live job's usage in a separate commit.
	forgedVault, err := f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	forgedVault.Approvals, err = forgedVault.Approvals.ReleaseUse(proof)
	if err != nil {
		t.Fatal(err)
	}
	forgedWrites, code := f.p.vaultCheckpoint(f.s, forgedVault)
	if code != state.Applied {
		t.Fatal(code)
	}
	cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "bad-build-usage-release", Key: VaultKey, Expected: f.s.Object(VaultKey).Revision, Value: "fixture"}
	next, result, _ := state.ApplyReduced(f.s, f.s.Index()+1, cmd, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return forgedWrites, state.Applied })
	if result.Code == state.Applied || next.Object(VaultKey) != f.s.Object(VaultKey) {
		t.Fatal("standalone Vault write dropped original live job pin", result.Code)
	}
	buildJobReportFixture(t, f, report, state.Applied)
	v, err = f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Approvals.Usage(grant); ok {
		t.Fatal("terminal cleanup did not return usage")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("original secret closure restore", err)
	}
	public, err := f.p.ImageBuildPage(f.s, f.sessions["admin"], 4, "tenant", ImageBuildQuery{Part: "jobs"}, "")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{`"Grants"`, `"RequesterKey"`, `"Session"`, `"Pins"`} {
		if bytes.Contains(encoded, []byte(name)) {
			t.Fatal("private approval state in public job page", name)
		}
	}
}
