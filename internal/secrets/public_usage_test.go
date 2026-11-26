// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func assertPublicVaultFields(t *testing.T, value any, allowed string) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	keys := strings.Fields(allowed)
	if len(fields) != len(keys) {
		t.Fatal("public Vault shape changed; review private-field boundary", string(raw))
	}
	for key := range fields {
		if !slices.Contains(keys, key) {
			t.Fatal("unexpected public Vault field", key)
		}
	}
	for _, private := range []string{"tenant/runtime", "credential-common", "password-common"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private provider/verifier reference escaped public Vault metadata")
		}
	}
}

// Reuse the existing exact native receipt fixture, including the purpose that
// namespaces image-build usages independently from ordinary app grants.
func publicUsageGone(f fixture, grant Grant) UseGone {
	proof := useGone(f, grant)
	proof.Purpose = grant.Use.Purpose
	key := f.na
	if proof.NodeKey == public(f.nb) {
		key = f.nb
	}
	proof.Signature = ed25519.Sign(key, UseGoneBytes(proof))
	return proof
}

func TestPublicApprovalsAgeOwnershipAndOriginalRevocation(t *testing.T) {
	f, use := approvalOrderFixture(t, 30)
	f, grant := acquire(t, f, use, "original-public-use", 7)
	before := encodedBook(t, f.a)
	rows := f.a.PublicApprovals(f.t, use.App)
	if len(rows) != len(grant.Pins) || len(rows) != 2 {
		t.Fatal("committed nested approvals not listed", rows)
	}
	for _, row := range rows {
		record := f.a.records[row.ID].Approval
		target := record.Payload.Target
		if row.Realm != f.t.Realm() || row.Tenant != use.Tenant || row.User != use.User || row.App != use.App || row.Deployment != use.Deployment || row.Group != target.Group || row.Purpose != use.Purpose || row.ApprovedAt != record.Payload.ApprovedAt || row.ExpiresAt != row.ApprovedAt+30 || row.Issuer != record.Issuer || row.Revoking || row.Consumers != 1 || !slices.Equal(row.Services, []string{use.Service}) || !slices.Equal(row.Nodes, []string{use.Node}) {
			t.Fatal("public approval differs from original signed target/current age", row)
		}
		assertPublicVaultFields(t, row, "ID Realm Tenant Group User App Standalone Deployment Purpose Services Nodes ApprovedAt ExpiresAt Issuer Revoking Consumers")
	}
	rows[0].Services[0], rows[0].Nodes[0] = "mutated-service", "mutated-node"
	rows[0].Issuer[0] ^= 1
	if !bytes.Equal(before, encodedBook(t, f.a)) || reflect.DeepEqual(rows, f.a.PublicApprovals(f.t, use.App)) {
		t.Fatal("public approval aliases original signed record")
	}
	if len(f.a.PublicApprovals(f.t, "another-app")) != 0 {
		t.Fatal("app filter exposed another deployment")
	}
	// Expiry is projected from current policy; it is not a new authorization
	// lease and expired original metadata is not silently erased.
	group, _ := f.t.Object("common")
	nextTree, err := f.t.SetApprovalAge(f.c, "alice", group.ID, group.Revision, 5)
	f.t = mustTree(t, nextTree, err)
	for _, row := range f.a.PublicApprovals(f.t, use.App) {
		if row.Group == group.ID && row.ExpiresAt != row.ApprovedAt+5 {
			t.Fatal("expiry ignored current Group policy", row)
		}
	}
	if _, err = f.a.ReadSet(f.c, f.t, grant, 110); err == nil {
		t.Fatal("public expiry projection replaced actual read authorization")
	}
	id := grant.Pins[0].ApprovalID
	next, err := f.a.Revoke(f.c, "alice", id, f.a.Revision())
	f.a = mustBook(t, next, err)
	revokedRows := f.a.PublicApprovals(f.t, use.App)
	index := slices.IndexFunc(revokedRows, func(row PublicApproval) bool { return row.ID == id })
	if index < 0 || !revokedRows[index].Revoking || revokedRows[index].Consumers != 1 || !f.a.RevocationPending(id) {
		t.Fatal("approval revoke hid a live original consumer", revokedRows)
	}
	next, err = f.a.ReleaseUse(publicUsageGone(f, grant))
	f.a = mustBook(t, next, err)
	for _, row := range f.a.PublicApprovals(f.t, use.App) {
		if row.Consumers != 0 || row.ID == id && (!row.Revoking || f.a.RevocationPending(id)) {
			t.Fatal("original closure did not settle approval listing", row)
		}
	}
}

func TestPublicVaultListsSeparateRealmsFromOneApprovalBook(t *testing.T) {
	f, use := approvalOrderFixture(t, 30)
	f, _ = acquire(t, f, use, "tenant-use", 1)
	tenantTree := f.t
	global := f
	tree, err := NewTree(f.t.Cluster(), "", "global-root")
	global.t = mustTree(t, tree, err)
	root, _ := global.t.Object("global-root")
	tree, err = global.t.SetACL(f.c, "admin", root.ID, root.Revision, ACL{TenantGrants: []string{"tenant"}})
	global.t = mustTree(t, tree, err)
	// The same logical leaf name exists in both realms, so name filtering
	// alone cannot accidentally make this isolation assertion pass.
	tree, err = global.t.Create(f.c, "admin", global.t.Revision(), Object{ID: "runtime", Parent: "global-root", Kind: Secret, Reference: Reference{Profile: "vault", Object: "global/runtime", Revision: 1, Keys: []string{"KEY"}}})
	global.t = mustTree(t, tree, err)
	global = protect(t, global, "global-root")
	for _, target := range plan(t, global, use).Required {
		global = commitOrderApproval(t, global, target, 105, "global-"+target.Group)
	}
	global, _ = acquire(t, global, use, "cluster-use", 1)
	for _, tree := range []Tree{tenantTree, global.t} {
		want := 2
		if tree.Realm() == "" {
			want = 1
		}
		rows := global.a.PublicApprovals(tree, use.App)
		if len(rows) != want {
			t.Fatal("realm approval filter omitted own or included foreign rows", tree.Realm(), rows)
		}
		for _, row := range rows {
			if row.Realm != tree.Realm() {
				t.Fatal("foreign realm approval exposed", row)
			}
		}
		usages := global.a.PublicUsages(tree, "runtime")
		if len(usages) != 1 || usages[0].Realm != tree.Realm() || !slices.Equal(usages[0].Secrets, []string{"runtime"}) {
			t.Fatal("same-name foreign realm usage exposed", usages)
		}
	}
}

func TestPublicUsagesRetainNestedOriginalDependenciesUntilSignedClosure(t *testing.T) {
	f, use := approvalOrderFixture(t, 30)
	f, first := acquire(t, f, use, "original-first", 1)
	f, second := acquire(t, f, use, "original-second", 2)
	assertUses := func(want int) {
		t.Helper()
		for _, id := range []string{"app", "common", "runtime"} {
			object, _ := f.t.Object(id)
			rows := f.a.PublicUsages(f.t, id)
			if len(rows) != want || f.a.LiveReferences(f.t, id, object.Generation) != want {
				t.Fatal("public users diverged from original retirement fence", id, rows, want)
			}
			for _, row := range rows {
				if row.Realm != "tenant" || row.Tenant != use.Tenant || row.User != use.User || row.App != use.App || row.Deployment != use.Deployment || row.Service != use.Service || row.Node != use.Node || row.Purpose != use.Purpose || !row.Live || !slices.Equal(row.Secrets, []string{"runtime"}) || row.Generation == 0 || row.ID == "" {
					t.Fatal("nested/direct-leaf usage lost original identity", row)
				}
				assertPublicVaultFields(t, row, "ID Realm Tenant User App Standalone Deployment Service Node Purpose Generation Secrets Live")
			}
		}
	}
	assertUses(2)
	before := encodedBook(t, f.a)
	rows := f.a.PublicUsages(f.t, "common")
	rows[0].Secrets[0] = "mutated-secret"
	if !bytes.Equal(before, encodedBook(t, f.a)) || f.a.PublicUsages(f.t, "common")[0].Secrets[0] != "runtime" {
		t.Fatal("public usage aliases retained dependency plan")
	}
	if len(f.a.PublicUsages(f.t, "missing")) != 0 {
		t.Fatal("missing source exposed unrelated uses")
	}
	leaf, _ := f.t.Object("runtime")
	nextTree, err := f.t.Revoke(f.c, "alice", leaf.ID, leaf.Revision)
	f.t = mustTree(t, nextTree, err)
	leaf, _ = f.t.Object(leaf.ID)
	if _, err = f.t.Retire(f.c, "alice", leaf.ID, leaf.Revision, f.a); err == nil {
		t.Fatal("live public usage did not fence source retirement")
	}
	next, err := f.a.Revoke(f.c, "alice", "original-common", f.a.Revision())
	f.a = mustBook(t, next, err)
	assertUses(2)
	// A single approval receipt returns only that pin, never the complete
	// source lifetime. The original whole-use receipt settles that consumer.
	for _, pin := range first.Pins {
		if pin.ApprovalID == "original-common" {
			next, err = f.a.Release(gone(f, first, pin))
			f.a = mustBook(t, next, err)
		}
	}
	assertUses(2)
	wrongPurpose := publicUsageGone(f, first)
	wrongPurpose.Purpose = ""
	wrongPurpose.Signature = ed25519.Sign(f.na, UseGoneBytes(wrongPurpose))
	if _, err = f.a.ReleaseUse(wrongPurpose); err != ErrPolicy {
		t.Fatal("valid original node signature bypassed purpose-scoped usage identity", err)
	}
	assertUses(2)
	bad := publicUsageGone(f, first)
	bad.MountsGone = false
	bad.Signature = ed25519.Sign(f.na, UseGoneBytes(bad))
	if _, err = f.a.ReleaseUse(bad); err == nil {
		t.Fatal("unclosed native mount erased public usage")
	}
	assertUses(2)
	firstReceipt := publicUsageGone(f, first)
	next, err = f.a.ReleaseUse(firstReceipt)
	f.a = mustBook(t, next, err)
	assertUses(1)
	// ReleaseUse is a strict resource primitive: it deletes this usageKey
	// after settlement, so the same receipt returns ErrPolicy unchanged.
	// This does not assert that a retained original operation replay fails;
	// operation-result idempotency belongs to its existing journal/FSM.
	settled := encodedBook(t, f.a)
	next, err = f.a.ReleaseUse(firstReceipt)
	if err != ErrPolicy || !bytes.Equal(settled, encodedBook(t, next)) || !bytes.Equal(settled, encodedBook(t, f.a)) {
		t.Fatal("duplicate receipt did not preserve settled book and other original consumer", err)
	}
	assertUses(1)
	next, err = f.a.ReleaseUse(publicUsageGone(f, second))
	f.a = mustBook(t, next, err)
	assertUses(0)
	nextTree, err = f.t.Retire(f.c, "alice", leaf.ID, leaf.Revision, f.a)
	f.t = mustTree(t, nextTree, err)
	retired, _ := f.t.Object(leaf.ID)
	if retired.Status != Retired || !reflect.DeepEqual(retired.Reference, leaf.Reference) {
		t.Fatal("retirement deleted original provider metadata")
	}
	assertUses(0)
}
