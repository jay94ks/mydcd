// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagesource"
	"github.com/jay94ks/mydcd/internal/secrets"
)

func orderOperation(t *testing.T, f *nodeStorageFixture, id, action string, expected uint64, payload any, at int64) UserOperation {
	t.Helper()
	raw, err := ChangeBytes(action, "manager", expected, payload)
	if err != nil {
		t.Fatal(err)
	}
	var change Change
	if err = json.Unmarshal(raw, &change); err != nil {
		t.Fatal(err)
	}
	op := UserOperation{Schema: 1, Session: f.sessions["manager"], At: at, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: f.s.Object(CommandKey(action)).Revision, Change: change}
	op.Signature = ed25519.Sign(f.manager, OperationBytes(op))
	return op
}
func applyOrderOperation(t *testing.T, f *nodeStorageFixture, op UserOperation, want state.Code) {
	t.Helper()
	cmd, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(op.Change.Action, result.Code, want, err)
	}
	f.s = next
}
func protectOrderVault(t *testing.T, f *nodeStorageFixture, age int64) {
	t.Helper()
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tree := v.Trees["tenant"]
	root, _ := tree.Object("root")
	tree, err = tree.BeginPasswordChange(c, "admin", "root", "order-password", root.Revision)
	if err != nil {
		t.Fatal(err)
	}
	root, _ = tree.Object("root")
	// Inject a completed protected-provider result. Password verification/native
	// storage are separate adapter claims; the temporal reducer inputs are real.
	tree, err = tree.ActivatePassword(c, "admin", "root", "order-password", "order-verifier", true, root.Revision)
	if err != nil {
		t.Fatal(err)
	}
	root, _ = tree.Object("root")
	tree, err = tree.SetApprovalAge(c, "admin", "root", root.Revision, age)
	if err != nil {
		t.Fatal(err)
	}
	v.Trees["tenant"] = tree
	v.Approvals, err = v.Approvals.SetIssuer(c, "admin", v.Approvals.Revision(), [32]byte(f.node.Public().(ed25519.PublicKey)), true)
	if err != nil {
		t.Fatal(err)
	}
	writes, code := f.p.vaultCheckpoint(f.s, v)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.checkpoint(VaultKey, writes)
}
func commitOrderUses(t *testing.T, f *nodeStorageFixture, uses map[string][]secrets.Use, at int64) {
	t.Helper()
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	for realm, rows := range uses {
		v, err := f.p.Vault(f.s)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := v.Trees[realm].Plan(c, rows)
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range plan.Required {
			v, err = f.p.Vault(f.s)
			if err != nil {
				t.Fatal(err)
			}
			issuer, _ := v.Approvals.Issuer([32]byte(f.node.Public().(ed25519.PublicKey)))
			target.IssuerPolicy = issuer.Policy
			target.ApprovalID = "order-" + target.Group
			approval := secrets.Approval{Schema: 1, Issuer: issuer.Key, Payload: secrets.ApprovalPayload{ApprovedAt: at, Fact: "secret-group-use-approved", Target: target}}
			approval.Signature = ed25519.Sign(f.node, secrets.ApprovalBytes(approval))
			op := orderOperation(t, f, "commit-"+target.ApprovalID, "vault-commit-approval", v.Approvals.Revision(), VaultApproval{Realm: realm, Approval: approval, Capacity: 8}, at)
			applyOrderOperation(t, f, op, state.Applied)
		}
	}
}

func TestBuildOriginalSignedAtTwoAcceptsCommittedGroupAtThree(t *testing.T) {
	f, plan := buildSecretFixture(t)
	protectOrderVault(t, f, 1)
	original := orderOperation(t, f, "original-build-submit", "begin-image-build", 0, plan.Change, 2)
	operationJSON, _ := json.Marshal(original)
	command, err := original.Command()
	if err != nil {
		t.Fatal(err)
	}
	// The original is staged before approval; do not submit a failing command and
	// then mint a replacement ID to evade its immutable result.
	writes, code := f.p.reduceImageBuilds(f.s, command)
	if code != state.ConditionFailed || len(writes) != 0 {
		t.Fatal("unapproved original accepted", code)
	}
	commitOrderUses(t, f, plan.Uses, 3)
	applyOrderOperation(t, f, original, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := b.Job("tenant", "build-one")
	storedJSON, _ := json.Marshal(row.Origin)
	if !ok || !bytes.Equal(operationJSON, storedJSON) || row.Run.Spec.Digest() != plan.Spec.Digest() || row.Run.Spec.CreatedAt != 2 || row.acquisitionAt() != 2 || len(row.Grants) != 1 || len(row.Grants[0].Pins) != 1 {
		t.Fatal("approval re-signed or changed original job/plan")
	}
	current, err := f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok = current.Approvals.Usage(row.Grants[0]); !ok {
		t.Fatal("job/Vault reservation not atomic")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("later approval/original job restore", err)
	}
	f.s = restored
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "begin", At: 3}, state.Applied)
	q := ImageBuildSecretRequest{Selection: ImageBuildSecretSelection{Tenant: "tenant", Job: "build-one", Snapshot: plan.Spec.Digest()}, At: 3}
	if _, err = f.p.ImageBuildSecretInputs(f.s, plan.Spec.Scope.Root.Key, q); err != nil {
		t.Fatal("current approved provider read denied", err)
	}
	q.At = 5
	if _, err = f.p.ImageBuildSecretInputs(f.s, plan.Spec.Scope.Root.Key, q); err == nil {
		t.Fatal("acquisition time replaced current worker max-age")
	}
	current, err = f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok = current.Approvals.Usage(row.Grants[0]); !ok {
		t.Fatal("expired read returned original usage")
	}
}

func TestRegistryBindOriginalAtTwoAcceptsCommittedGroupAtThree(t *testing.T) {
	f, _ := buildSecretFixture(t)
	protectOrderVault(t, f, 1)
	spec := imagesource.Source{Tenant: "tenant", ID: "late-source", Authority: "ghcr.io", Repository: "team/**", Enabled: true, Auth: "password", Credential: &imagesource.Credential{Realm: "tenant", ID: "signing", UsernameKey: "empty", PasswordKey: "private"}}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	plan, err := f.p.PlanExternalRegistryBind(f.s, f.sessions["manager"], 2, "tenant", spec.ID, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	original := orderOperation(t, f, "original-source-bind", "bind-external-registry", plan.Expected, plan.Selection, 2)
	originalJSON, _ := json.Marshal(original)
	commitOrderUses(t, f, plan.Uses, 3)
	applyOrderOperation(t, f, original, state.Applied)
	entries, err := f.p.ExternalRegistries(f.s)
	if err != nil {
		t.Fatal(err)
	}
	var reader *ExternalRegistryReader
	for _, entry := range entries {
		if entry.Spec.ID == spec.ID {
			reader = entry.Reader
		}
	}
	if reader == nil || len(reader.Grants) != 1 {
		t.Fatal("missing original source reader")
	}
	got, _ := json.Marshal(reader.Origin)
	if !bytes.Equal(got, originalJSON) {
		t.Fatal("source approval replaced original signed bind")
	}
	selection := ExternalRegistryReadSelection{Tenant: "tenant", ID: spec.ID, Generation: reader.Generation}
	if _, err = f.p.ExternalRegistryWork(f.s, reader.Owner, ExternalRegistryWorkRequest{selection, 3}); err != nil {
		t.Fatal("later-approved source read denied", err)
	}
	if _, err = f.p.ExternalRegistryWork(f.s, reader.Owner, ExternalRegistryWorkRequest{selection, 5}); err == nil {
		t.Fatal("source reader ignored current maximum approval age")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("original source/approval restore", err)
	}
	vault, err := f.p.Vault(restored)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vault.Approvals.Usage(reader.Grants[0]); !ok {
		t.Fatal("restore lost original source usage")
	}
}

func TestBuildLaterApprovalCannotBypassCurrentRevocationOrReplaceUsage(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprint(revoke), func(t *testing.T) {
			f, plan := buildSecretFixture(t)
			protectOrderVault(t, f, 30)
			original := orderOperation(t, f, "original-approval-check", "begin-image-build", 0, plan.Change, 2)
			commitOrderUses(t, f, plan.Uses, 3)
			if revoke {
				v, err := f.p.Vault(f.s)
				if err != nil {
					t.Fatal(err)
				}
				f.apply("admin", "vault-revoke-approval", v.Approvals.Revision(), VaultApprovalSelection{ID: "order-root"}, state.Applied)
				before := f.s.Object(VaultKey)
				applyOrderOperation(t, f, original, state.ConditionFailed)
				if before != f.s.Object(VaultKey) {
					t.Fatal("rejected revoked approval created usage")
				}
				return
			}
			applyOrderOperation(t, f, original, state.Applied)
			b, err := f.p.ImageBuilds(f.s)
			if err != nil {
				t.Fatal(err)
			}
			row, _ := b.Job("tenant", "build-one")
			v, err := f.p.Vault(f.s)
			if err != nil {
				t.Fatal(err)
			}
			f.apply("admin", "vault-revoke-approval", v.Approvals.Revision(), VaultApprovalSelection{ID: "order-root"}, state.Applied)
			work, err := f.p.ImageBuildJobWork(f.s, plan.Spec.Scope.Root.Key, ImageBuildJobWorkQuery{Tenant: "tenant", ID: "build-one", At: 4})
			if err != nil || work.Allowed {
				t.Fatal("worker started after Group revocation", err)
			}
			v, err = f.p.Vault(f.s)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := v.Approvals.Usage(row.Grants[0]); !ok {
				t.Fatal("Group revocation returned accepted job usage")
			}
		})
	}
}

// The approval realm's secret manager revokes it (Jay 2026-11-26); the same
// manager without ManageSecrets in the session scope cannot.
func TestRealmManagerRevokesApproval(t *testing.T) {
	f, plan := buildSecretFixture(t)
	protectOrderVault(t, f, 30)
	commitOrderUses(t, f, plan.Uses, 3)
	v, err := f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "vault-revoke-approval", v.Approvals.Revision(), VaultApprovalSelection{ID: "order-root"}, state.Forbidden)
	session := f.sessions["manager"]
	session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.ManageSecrets)
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	before := v.Approvals.Revision()
	f.apply("manager", "vault-revoke-approval", before, VaultApprovalSelection{ID: "order-root"}, state.Applied)
	if v, err = f.p.Vault(f.s); err != nil || v.Approvals.Revision() == before {
		t.Fatal("not revoked", err)
	}
}
