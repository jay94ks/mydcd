// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"testing"
)

func commitOrderApproval(t *testing.T, f fixture, target Target, at int64, id string) fixture {
	t.Helper()
	approval := signed(f, target)
	approval.Payload.ApprovedAt = at
	approval.Payload.Target.ApprovalID = id
	approval.Signature = ed25519.Sign(f.issuer, ApprovalBytes(approval))
	next, err := f.a.Commit(f.c, "alice", f.t, f.a.Revision(), approval, at, 8)
	f.a = mustBook(t, next, err)
	return f
}
func approvalOrderFixture(t *testing.T, age int64) (fixture, Use) {
	t.Helper()
	f := makeFixture(t)
	for _, id := range []string{"app", "common"} {
		o, _ := f.t.Object(id)
		tree, err := f.t.SetApprovalAge(f.c, "alice", id, o.Revision, age)
		f.t = mustTree(t, tree, err)
	}
	use := web(f)
	use.Purpose = PurposeImageBuild
	use.Sources = []string{"runtime"}
	for i, target := range plan(t, f, use).Required {
		f = commitOrderApproval(t, f, target, 101+int64(i), "original-"+target.Group)
	}
	return f, use
}

func TestCommittedUseTimeConsumesLaterSignedFactsWithoutChangingOriginalJSON(t *testing.T) {
	f, use := approvalOrderFixture(t, 30)
	if _, _, err := f.a.Acquire(f.c, f.t, use, "original-build", 1, f.a.Revision(), 100); err == nil {
		t.Fatal("original timestamp unexpectedly accepted later approval")
	}
	before := encodedBook(t, f.a)
	at, err := f.a.CommittedUseTime(f.c, map[string]Tree{"tenant": f.t}, map[string][]Use{"tenant": {use}}, 100)
	if err != nil || at != 102 {
		t.Fatal("later committed nested facts not consumed", at, err)
	}
	if !bytes.Equal(before, encodedBook(t, f.a)) {
		t.Fatal("time selection mutated signed approval/usage JSON")
	}
	next, grant, err := f.a.Acquire(f.c, f.t, use, "original-build", 1, f.a.Revision(), at)
	if err != nil {
		t.Fatal(err)
	}
	f.a = next
	if _, err = f.a.ReadSet(f.c, f.t, grant, at); err != nil {
		t.Fatal("first read used another time", err)
	}
	if _, err = f.a.ReadSet(f.c, f.t, grant, 100); err == nil {
		t.Fatal("future check was globally bypassed")
	}
	raw := encodedBook(t, f.a)
	restored, err := DecodeApprovals(raw)
	if err != nil || !bytes.Equal(raw, encodedBook(t, restored)) {
		t.Fatal("schema1 original JSON restore", err)
	}
	at, err = restored.CommittedUseTime(f.c, map[string]Tree{"tenant": f.t}, map[string][]Use{"tenant": {use}}, 100)
	if err != nil || at != 102 {
		t.Fatal("restored committed fact changed", at, err)
	}
	if _, err = restored.ReadSet(f.c, f.t, grant, 133); err == nil {
		t.Fatal("current max-age no longer enforced")
	}
}

func TestCommittedUseTimeRequiresCurrentCommittedExactApprovalFacts(t *testing.T) {
	f := makeFixture(t)
	use := web(f)
	use.Purpose = PurposeImageBuild
	use.Sources = []string{"runtime"}
	trees := map[string]Tree{"tenant": f.t}
	uses := map[string][]Use{"tenant": {use}}
	// A valid but uncommitted signature must not be accepted as a clock input.
	_ = signed(f, plan(t, f, use).Required[0])
	if _, err := f.a.CommittedUseTime(f.c, trees, uses, 99); err == nil {
		t.Fatal("missing/uncommitted approval supplied a time")
	}
	app := use
	app.Purpose = ""
	for _, target := range plan(t, f, app).Required {
		f = commitOrderApproval(t, f, target, 101, "app-"+target.Group)
	}
	if _, err := f.a.CommittedUseTime(f.c, trees, uses, 99); err == nil {
		t.Fatal("app purpose supplied a build time")
	}
	for _, target := range plan(t, f, use).Required {
		f = commitOrderApproval(t, f, target, 102, "build-"+target.Group)
	}
	foreign := use
	foreign.RequesterKey = [32]byte{88}
	if _, err := f.a.CommittedUseTime(f.c, trees, map[string][]Use{"tenant": {foreign}}, 99); err == nil {
		t.Fatal("foreign target supplied a time")
	}
	raw := encodedBook(t, f.a)
	for _, kind := range []string{"revoked", "issuer-disabled", "account-disabled"} {
		t.Run(kind, func(t *testing.T) {
			a, err := DecodeApprovals(raw)
			if err != nil {
				t.Fatal(err)
			}
			catalog := f.c
			switch kind {
			case "revoked":
				a, err = a.Revoke(catalog, "alice", "build-app", a.Revision())
			case "issuer-disabled":
				a, err = a.SetIssuer(catalog, "admin", a.Revision(), public(f.issuer), false)
			case "account-disabled":
				user, _ := catalog.User("alice")
				user.Enabled = false
				revision := user.Revision
				user.Revision = 0
				catalog, err = catalog.PutUser("admin", revision, user)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.CommittedUseTime(catalog, trees, uses, 99); err == nil {
				t.Fatal("noncurrent approval supplied acquisition authority")
			}
		})
	}
}

func TestCommittedUseTimeUsesOneTimeAcrossRealmsAndEarlierGroupAge(t *testing.T) {
	for _, age := range []int64{5, 30} {
		t.Run(fmt.Sprint(age), func(t *testing.T) {
			f, use := approvalOrderFixture(t, age)
			tenantTree := f.t
			global := f
			tree, err := NewTree(f.t.Cluster(), "", "global-root")
			global.t = mustTree(t, tree, err)
			root, _ := global.t.Object("global-root")
			tree, err = global.t.SetACL(f.c, "admin", root.ID, root.Revision, ACL{TenantGrants: []string{"tenant"}})
			global.t = mustTree(t, tree, err)
			tree, err = global.t.Create(f.c, "admin", global.t.Revision(), Object{ID: "global-secret", Parent: "global-root", Kind: Secret, Reference: Reference{Profile: "vault", Object: "global/secret", Revision: 1, Keys: []string{"key"}}})
			global.t = mustTree(t, tree, err)
			global = protect(t, global, "global-root")
			globalUse := use
			globalUse.Sources = []string{"global-secret"}
			for _, target := range plan(t, global, globalUse).Required {
				global = commitOrderApproval(t, global, target, 110, "global-"+target.Group)
			}
			f.a = global.a
			trees := map[string]Tree{"tenant": tenantTree, "": global.t}
			uses := map[string][]Use{"tenant": {use}, "": {globalUse}}
			before := encodedBook(t, f.a)
			at, err := f.a.CommittedUseTime(f.c, trees, uses, 100)
			if !bytes.Equal(before, encodedBook(t, f.a)) {
				t.Fatal("failed/planned acquisition changed reservations")
			}
			if age == 5 {
				if err == nil {
					t.Fatal("later realm approval revived expired earlier Group", at)
				}
				return
			}
			if err != nil || at != 110 {
				t.Fatal("realms did not converge on last required fact", at, err)
			}
			for _, realm := range []string{"", "tenant"} {
				next, grant, err := f.a.Acquire(f.c, trees[realm], uses[realm][0], "same-build", 1, f.a.Revision(), at)
				if err != nil {
					t.Fatal(err)
				}
				f.a = next
				if _, err = f.a.ReadSet(f.c, trees[realm], grant, at); err != nil {
					t.Fatal("realm read used different approval time", err)
				}
			}
		})
	}
}

func TestCommittedApprovalTimeCannotReplaceAnExistingGrantPin(t *testing.T) {
	f, use := approvalOrderFixture(t, 30)
	next, original, err := f.a.Acquire(f.c, f.t, use, "original-build", 1, f.a.Revision(), 102)
	if err != nil {
		t.Fatal(err)
	}
	f.a = next
	for _, target := range plan(t, f, use).Required {
		f = commitOrderApproval(t, f, target, 110, "replacement-"+target.Group)
	}
	f.a, err = f.a.Revoke(f.c, "alice", original.Pins[0].ApprovalID, f.a.Revision())
	if err != nil {
		t.Fatal(err)
	}
	before := encodedBook(t, f.a)
	at, err := f.a.CommittedUseTime(f.c, map[string]Tree{"tenant": f.t}, map[string][]Use{"tenant": {use}}, 110)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.a.Acquire(f.c, f.t, use, original.Consumer, original.Generation, f.a.Revision(), at); err == nil {
		t.Fatal("replacement approval adopted original usage")
	}
	if !bytes.Equal(before, encodedBook(t, f.a)) {
		t.Fatal("rejected reacquisition changed original pins")
	}
	if _, ok := f.a.Usage(original); !ok {
		t.Fatal("current revoke returned original reservation")
	}
	restored, err := DecodeApprovals(before)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restored.ReadSet(f.c, f.t, original, 110); err == nil {
		t.Fatal("restore replaced original revoked pin")
	}
	if _, ok := restored.Usage(original); !ok {
		t.Fatal("restore lost original usage")
	}
}
