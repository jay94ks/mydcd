// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

type fixture struct {
	c              access.Catalog
	t              Tree
	a              Approvals
	issuer, na, nb ed25519.PrivateKey
}

func private(n byte) ed25519.PrivateKey {
	b := make([]byte, 32)
	b[0] = n
	return ed25519.NewKeyFromSeed(b)
}
func public(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }
func mustTree(t *testing.T, v Tree, err error) Tree {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func mustBook(t *testing.T, v Approvals, err error) Approvals {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func account(id string, admin bool) access.User {
	return access.User{ID: id, Username: id, Enabled: true, SystemAdmin: admin, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: public(private(id[0])), Enabled: true}}}
}
func makeFixture(t *testing.T) fixture {
	t.Helper()
	cluster := [32]byte{9}
	c, err := access.New(public(private(1)))
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Enroll(public(private(1)), account("admin", true))
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.PutUser("admin", 0, account("alice", false))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"tenant", "other"} {
		c, err = c.CreateTenant("admin", id, 0)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := c.Tenant(id)
		c, err = c.SetNodes("admin", id, v.Revision, []string{"node-a", "node-b"})
		if err != nil {
			t.Fatal(err)
		}
	}
	c, err = c.SetMembership("admin", 0, access.Membership{Tenant: "tenant", User: "alice", Role: access.Manager, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	tree, err := NewTree(cluster, "tenant", "root")
	tree = mustTree(t, tree, err)
	book, err := NewApprovals(cluster)
	book = mustBook(t, book, err)
	f := fixture{c, tree, book, private(10), private(11), private(12)}
	f.a, err = f.a.SetIssuer(c, "admin", f.a.Revision(), public(f.issuer), true)
	f.a = mustBook(t, f.a, err)
	for _, o := range []Object{
		{ID: "app", Parent: "root", Kind: Group}, {ID: "common", Parent: "app", Kind: Group}, {ID: "db-admin", Parent: "app", Kind: Group, ACL: ACL{Services: []string{"db"}}},
		{ID: "defaults", Parent: "root", Kind: Secret, Reference: Reference{Profile: "vault", Object: "tenant/defaults", Revision: 1, Keys: []string{"DB_HOST", "EMPTY", "Mixed"}}},
		{ID: "runtime", Parent: "common", Kind: Secret, Reference: Reference{Profile: "vault", Object: "tenant/runtime", Revision: 1, Keys: []string{"DB_HOST", "DB_PASSWORD"}}},
		{ID: "overrides", Parent: "app", Kind: Secret, Reference: Reference{Profile: "vault", Object: "tenant/overrides", Revision: 1, Keys: []string{"DB_HOST"}}},
		{ID: "root-password", Parent: "db-admin", Kind: Secret, Reference: Reference{Profile: "vault", Object: "tenant/root-password", Revision: 1, Keys: []string{"MYSQL_ROOT_PASSWORD"}}},
	} {
		f.t, err = f.t.Create(c, "alice", f.t.Revision(), o)
		f.t = mustTree(t, f.t, err)
	}
	for _, id := range []string{"app", "common", "db-admin"} {
		f = protect(t, f, id)
	}
	return f
}
func protect(t *testing.T, f fixture, id string) fixture {
	t.Helper()
	o, _ := f.t.Object(id)
	n, err := f.t.BeginPasswordChange(f.c, "admin", id, "password-"+id, o.Revision)
	f.t = mustTree(t, n, err)
	o, _ = f.t.Object(id)
	n, err = f.t.ActivatePassword(f.c, "admin", id, o.PasswordChange, "credential-"+id, true, o.Revision)
	f.t = mustTree(t, n, err)
	return f
}
func web(f fixture) Use {
	return Use{Tenant: "tenant", User: "alice", App: "php-mysql", Deployment: "stable-deploy", Service: "web", Node: "node-a", RequesterKey: public(private(13)), NodeKey: public(f.na), Sources: []string{"defaults", "common", "overrides"}}
}
func db(f fixture) Use {
	u := web(f)
	u.Service = "db"
	u.Node = "node-b"
	u.NodeKey = public(f.nb)
	u.Sources = []string{"defaults", "common", "db-admin"}
	return u
}
func plan(t *testing.T, f fixture, uses ...Use) BatchPlan {
	t.Helper()
	p, err := f.t.Plan(f.c, uses)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func signed(f fixture, want Target) Approval {
	want = ownTarget(want)
	want.ApprovalID = "approval-" + want.Group
	i, _ := f.a.Issuer(public(f.issuer))
	want.IssuerPolicy = i.Policy
	a := Approval{Schema: 1, Issuer: public(f.issuer), Payload: ApprovalPayload{ApprovedAt: 100, Fact: approvalFact, Target: want}}
	a.Signature = ed25519.Sign(f.issuer, ApprovalBytes(a))
	return a
}
func commit(t *testing.T, f fixture, a Approval) fixture {
	t.Helper()
	n, err := f.a.Commit(f.c, "alice", f.t, f.a.Revision(), a, 100, 8)
	f.a = mustBook(t, n, err)
	return f
}
func approved(t *testing.T) fixture {
	t.Helper()
	f := makeFixture(t)
	p := plan(t, f, web(f), db(f))
	for _, want := range p.Required {
		f = commit(t, f, signed(f, want))
	}
	return f
}
func acquire(t *testing.T, f fixture, u Use, id string, generation uint64) (fixture, Grant) {
	t.Helper()
	a, g, err := f.a.Acquire(f.c, f.t, u, id, generation, f.a.Revision(), 110)
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	return f, g
}
func encodedTree(t *testing.T, v Tree) []byte {
	t.Helper()
	b, err := v.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func encodedBook(t *testing.T, v Approvals) []byte {
	t.Helper()
	b, err := v.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSecretSourcesOrderedMergeChecksOverwrittenAncestors(t *testing.T) {
	f := makeFixture(t)
	u := web(f)
	u.Sources = append(u.Sources, "common")
	p := plan(t, f, u)
	if len(p.Uses[0].Leaves) != 4 || len(p.Required) != 2 {
		t.Fatal("source positions or password gates deduped incorrectly")
	}
	values := []Fetched{}
	for _, id := range []string{"defaults", "runtime", "overrides"} {
		o, _ := f.t.Object(id)
		v := map[string][]byte{}
		for _, k := range o.Reference.Keys {
			v[k] = []byte(id + "-" + k)
		}
		if id == "defaults" {
			v["EMPTY"] = []byte{}
			v["Mixed"] = []byte("case")
		}
		values = append(values, Fetched{id, o.Reference, v})
	}
	keyset, err := Merge(p.Uses[0], values, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyset.Values["DB_HOST"]) != "runtime-DB_HOST" || keyset.Provenance["DB_HOST"].SourcePosition != 3 || len(keyset.Values["EMPTY"]) != 0 || string(keyset.Values["Mixed"]) != "case" {
		t.Fatal("last source/empty/case/provenance")
	}
	values[1].Values["DB_HOST"][0] = 'x'
	if keyset.Values["DB_HOST"][0] == 'x' {
		t.Fatal("private keyset alias")
	}
	o, _ := f.t.Object("defaults")
	n, err := f.t.SetACL(f.c, "alice", o.ID, o.Revision, ACL{DenyUsers: []string{"alice"}})
	f.t = mustTree(t, n, err)
	if blocked, err := f.t.Plan(f.c, []Use{web(f)}); err == nil || len(blocked.Uses) != 0 {
		t.Fatal("overwritten unauthorized source skipped")
	}
}
func TestSecretSelectionDoesNotExposeRestrictedChildOrForeignRealm(t *testing.T) {
	f := makeFixture(t)
	u := web(f)
	u.Sources = []string{"app"}
	if _, err := f.t.Plan(f.c, []Use{u}); err != access.ErrDenied {
		t.Fatal("restricted child skipped", err)
	}
	u = web(f)
	u.Sources = []string{"runtime"}
	p := plan(t, f, u)
	if len(p.Required) != 2 || p.Required[0].Group != "app" || p.Required[1].Group != "common" {
		t.Fatal("direct leaf bypassed ancestors")
	}
	u.Tenant = "other"
	if _, err := f.t.Plan(f.c, []Use{u}); err != access.ErrDenied {
		t.Fatal("other tenant source")
	}
	global, err := NewTree(f.t.cluster, "", "root")
	global = mustTree(t, global, err)
	global, err = global.Create(f.c, "admin", global.Revision(), Object{ID: "global", Parent: "root", Kind: Secret, Reference: Reference{Profile: "vault", Object: "system/global", Revision: 1, Keys: []string{"KEY"}}})
	global = mustTree(t, global, err)
	u = web(f)
	u.Sources = []string{"global"}
	if _, err = global.Plan(f.c, []Use{u}); err != access.ErrDenied {
		t.Fatal("global implicit grant")
	}
	root, _ := global.Object("root")
	global, err = global.SetACL(f.c, "admin", "root", root.Revision, ACL{TenantGrants: []string{"tenant"}})
	global = mustTree(t, global, err)
	if _, err = global.Plan(f.c, []Use{u}); err != nil {
		t.Fatal("explicit grant", err)
	}
	if _, err = global.Create(f.c, "alice", global.Revision(), Object{ID: "takeover", Parent: "root", Kind: Group}); err != access.ErrDenied {
		t.Fatal("manager changed global tree")
	}
}
func TestSecretTreeMovesReorderCyclesAndPendingSnapshot(t *testing.T) {
	f := makeFixture(t)
	before := encodedTree(t, f.t)
	o, _ := f.t.Object("app")
	n, err := f.t.Move(f.c, "alice", "app", "common", o.Revision)
	if err == nil || !bytes.Equal(before, encodedTree(t, n)) {
		t.Fatal("cycle changed state")
	}
	o, _ = f.t.Object("common")
	n, err = f.t.Move(f.c, "alice", "common", "root", o.Revision)
	f.t = mustTree(t, n, err)
	u := web(f)
	u.Sources = []string{"runtime"}
	p := plan(t, f, u)
	if len(p.Required) != 1 || p.Required[0].Group != "common" {
		t.Fatal("move ancestor path stale")
	}
	root, _ := f.t.Object("root")
	if len(root.Entries) < 2 {
		t.Fatal("root needs two entries to reorder", root.Entries)
	}
	last := root.Entries[len(root.Entries)-1]
	want := append([]string{last}, root.Entries[:len(root.Entries)-1]...)
	n, err = f.t.Reorder(f.c, "alice", "root", root.Revision, last, "")
	f.t = mustTree(t, n, err)
	root, _ = f.t.Object("root")
	if !slices.Equal(root.Entries, want) {
		t.Fatal("entry not moved to the front", root.Entries, want)
	}
	// The same move again, an unknown entry, or a stale revision is refused.
	if _, err = f.t.Reorder(f.c, "alice", "root", root.Revision, last, ""); err != access.ErrConflict {
		t.Fatal("no-op move accepted", err)
	}
	if _, err = f.t.Reorder(f.c, "alice", "root", root.Revision, "missing", ""); err != access.ErrConflict {
		t.Fatal("unknown entry moved", err)
	}
	if _, err = f.t.Reorder(f.c, "alice", "root", root.Revision-1, want[1], ""); err != access.ErrConflict {
		t.Fatal("stale reorder accepted", err)
	}
	n, err = f.t.Reorder(f.c, "alice", "root", root.Revision, last, want[len(want)-1])
	f.t = mustTree(t, n, err)
	root, _ = f.t.Object("root")
	if root.Entries[len(root.Entries)-1] != last {
		t.Fatal("entry not moved after the last", root.Entries)
	}
	n, err = f.t.BeginPasswordChange(f.c, "alice", "root", "root-change", root.Revision)
	f.t = mustTree(t, n, err)
	if _, err = DecodeTree(encodedTree(t, f.t)); err != nil {
		t.Fatal("pending root lost", err)
	}
	if _, err = f.t.Plan(f.c, []Use{web(f)}); err != access.ErrDenied {
		t.Fatal("pending password allowed selection")
	}
}
func TestSecretPasswordGroupsPromptOnceAndPartialApprovalResume(t *testing.T) {
	f := makeFixture(t)
	p := plan(t, f, web(f), db(f))
	if len(p.Required) != 3 {
		t.Fatal("password prompt count", len(p.Required))
	}
	for _, g := range p.Required {
		if g.Group == "db-admin" && len(g.Services) != 1 || g.Group != "db-admin" && len(g.Services) != 2 {
			t.Fatal("group scope widened or split", g)
		}
	}
	f = commit(t, f, signed(f, p.Required[0]))
	missing := f.a.Missing(f.c, f.t, p, 110)
	if len(missing) != 2 {
		t.Fatal("resume re-prompts approved group")
	}
	before := encodedBook(t, f.a)
	candidate, _, err := f.a.Acquire(f.c, f.t, web(f), "web-instance", 1, f.a.Revision(), 110)
	if err == nil || !bytes.Equal(before, encodedBook(t, candidate)) {
		t.Fatal("partial approval borrowed pins")
	}
	for _, want := range missing {
		f = commit(t, f, signed(f, want))
	}
	if len(f.a.Missing(f.c, f.t, p, 10000)) != 0 {
		t.Fatal("restart/time alone expired approvals")
	}
	var g Grant
	f, g = acquire(t, f, web(f), "web-instance", 1)
	if len(g.Pins) != 2 {
		t.Fatal("wrong consumer gates")
	}
	f, g2 := acquire(t, f, web(f), "web-instance", 1)
	if len(g2.Pins) != len(g.Pins) || g2.Pins[0] != g.Pins[0] {
		t.Fatal("same consumer got another pin")
	}
	if _, err = f.a.ReadSet(f.c, f.t, g, 10000); err != nil {
		t.Fatal("valid persistent scope unavailable", err)
	}
}
func TestSecretApprovalPayloadBindingIssuerAndScope(t *testing.T) {
	f := makeFixture(t)
	p := plan(t, f, web(f))
	a := signed(f, p.Required[0])
	var top map[string]json.RawMessage
	if json.Unmarshal(ApprovalBytes(a)[len("sfc-secret-group-approval-1\x00"):], &top) != nil || len(top) != 3 || top["approved_at"] == nil || top["fact"] == nil || top["target"] == nil {
		t.Fatal("approval payload not exactly three fields")
	}
	for _, mutate := range []func(*Approval){func(a *Approval) { a.Payload.Fact = "other" }, func(a *Approval) { a.Payload.Target.Cluster = [32]byte{1} }, func(a *Approval) { a.Payload.Target.RequesterKey = [32]byte{} }, func(a *Approval) { a.Payload.Target.Path[0].PolicyRevision++ }, func(a *Approval) { a.Payload.Target.UserPolicy++ }, func(a *Approval) { a.Payload.Target.MembershipPolicy++ }, func(a *Approval) { a.Payload.Target.IssuerPolicy++ }, func(a *Approval) { a.Payload.ApprovedAt = 101 }} {
		bad := ownApproval(a)
		mutate(&bad)
		bad.Signature = ed25519.Sign(f.issuer, ApprovalBytes(bad))
		if _, err := f.a.Commit(f.c, "alice", f.t, f.a.Revision(), bad, 100, 8); err == nil {
			t.Fatal("bad approval accepted")
		}
	}
	bad := ownApproval(a)
	bad.Issuer = public(f.na)
	bad.Signature = ed25519.Sign(f.na, ApprovalBytes(bad))
	if _, err := f.a.Commit(f.c, "alice", f.t, f.a.Revision(), bad, 100, 8); err == nil {
		t.Fatal("unregistered issuer")
	}
	f = approved(t)
	u := web(f)
	u.Service = "another-service"
	if len(f.a.Missing(f.c, f.t, plan(t, f, u), 110)) == 0 {
		t.Fatal("service scope copied")
	}
	u = web(f)
	u.RequesterKey = public(private(99))
	if len(f.a.Missing(f.c, f.t, plan(t, f, u), 110)) == 0 {
		t.Fatal("requester key scope copied")
	}
}
func TestSecretReferenceChangesReuseApprovalButPolicyChangesDoNot(t *testing.T) {
	f := approved(t)
	var g Grant
	f, g = acquire(t, f, web(f), "web-instance", 1)
	o, _ := f.t.Object("runtime")
	ref := o.Reference
	ref.Revision++
	n, err := f.t.PublishReference(f.c, "alice", "runtime", o.Revision, ref)
	f.t = mustTree(t, n, err)
	if len(f.a.Missing(f.c, f.t, plan(t, f, web(f), db(f)), 110)) != 0 {
		t.Fatal("value revision reprompted namespace")
	}
	if _, err = f.a.ReadSet(f.c, f.t, g, 110); !errors.Is(err, ErrRevisionChanged) || !errors.Is(err, ErrPolicy) {
		t.Fatal("mixed old/new provider revision", err)
	}
	old := g
	f, g = acquire(t, f, web(f), "web-instance", 2)
	if _, err = f.a.ReadSet(f.c, f.t, g, 110); err != nil {
		t.Fatal(err)
	}
	o, _ = f.t.Object("common")
	n, err = f.t.BeginPasswordChange(f.c, "alice", "common", "change-again", o.Revision)
	f.t = mustTree(t, n, err)
	if _, err = f.t.Plan(f.c, []Use{web(f)}); err == nil {
		t.Fatal("pending password bypass")
	}
	if _, err = f.a.ReadSet(f.c, f.t, old, 110); err == nil || errors.Is(err, ErrRevisionChanged) {
		t.Fatal("policy change reported as a revision change", err)
	}
	o, _ = f.t.Object("common")
	n, err = f.t.ActivatePassword(f.c, "alice", "common", o.PasswordChange, "next-verifier", true, o.Revision)
	f.t = mustTree(t, n, err)
	if len(f.a.Missing(f.c, f.t, plan(t, f, web(f)), 110)) != 1 {
		t.Fatal("old password approval reused")
	}
	f = approved(t)
	book, err := f.a.SetIssuer(f.c, "admin", f.a.Revision(), public(f.issuer), false)
	f.a = mustBook(t, book, err)
	if len(f.a.Missing(f.c, f.t, plan(t, f, web(f)), 110)) != 2 {
		t.Fatal("revoked issuer reused")
	}
	book, err = f.a.SetIssuer(f.c, "admin", f.a.Revision(), public(f.issuer), true)
	f.a = mustBook(t, book, err)
	if len(f.a.Missing(f.c, f.t, plan(t, f, web(f)), 110)) != 2 {
		t.Fatal("issuer epoch replay")
	}
}
func gone(f fixture, g Grant, pin Pin) ConsumerGone {
	p := ConsumerGone{Cluster: f.t.cluster, ApprovalID: pin.ApprovalID, Consumer: g.Consumer, Generation: g.Generation, NodeKey: g.Use.NodeKey, Lease: pin.Lease, Stopped: true, MountsGone: true}
	k := f.na
	if p.NodeKey == public(f.nb) {
		k = f.nb
	}
	p.Signature = ed25519.Sign(k, ConsumerGoneBytes(p))
	return p
}
func TestSecretApprovalRevocationWaitsForOriginalConsumerLeases(t *testing.T) {
	f := approved(t)
	var webGrant, dbGrant Grant
	f, webGrant = acquire(t, f, web(f), "web-instance", 1)
	f, dbGrant = acquire(t, f, db(f), "db-instance", 1)
	book, err := f.a.Revoke(f.c, "alice", "approval-common", f.a.Revision())
	f.a = mustBook(t, book, err)
	if !f.a.RevocationPending("approval-common") {
		t.Fatal("live consumer vanished on revoke")
	}
	if _, err = f.a.ReadSet(f.c, f.t, webGrant, 110); err == nil {
		t.Fatal("revoked read accepted")
	}
	find := func(g Grant) Pin {
		for _, p := range g.Pins {
			if p.ApprovalID == "approval-common" {
				return p
			}
		}
		t.Fatal("missing common pin")
		return Pin{}
	}
	p := gone(f, webGrant, find(webGrant))
	bad := p
	bad.MountsGone = false
	bad.Signature = ed25519.Sign(f.na, ConsumerGoneBytes(bad))
	if _, err = f.a.Release(bad); err == nil {
		t.Fatal("live mount returned pin")
	}
	book, err = f.a.Release(p)
	f.a = mustBook(t, book, err)
	if !f.a.RevocationPending("approval-common") {
		t.Fatal("one receipt freed both consumers")
	}
	if _, err = f.a.Release(p); err == nil {
		t.Fatal("duplicate consumed another lease")
	}
	book, err = DecodeApprovals(encodedBook(t, f.a))
	f.a = mustBook(t, book, err)
	book, err = f.a.Release(gone(f, dbGrant, find(dbGrant)))
	f.a = mustBook(t, book, err)
	if f.a.RevocationPending("approval-common") {
		t.Fatal("final exact consumer did not retire")
	}
}
func TestSecretSnapshotsAndMergeRejectMalformedInputsWithoutValues(t *testing.T) {
	f := approved(t)
	var g Grant
	f, g = acquire(t, f, web(f), "web-instance", 1)
	treeBytes := encodedTree(t, f.t)
	bookBytes := encodedBook(t, f.a)
	if _, err := DecodeTree(treeBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeApprovals(bookBytes); err != nil {
		t.Fatal(err)
	}
	var tr treeRecord
	json.Unmarshal(treeBytes, &tr)
	for i := range tr.Objects {
		if tr.Objects[i].ID == "common" {
			tr.Objects[i].Parent = "common"
		}
	}
	bad, _ := json.Marshal(tr)
	if _, err := DecodeTree(bad); err == nil {
		t.Fatal("snapshot cycle")
	}
	var ar approvalsRecord
	json.Unmarshal(bookBytes, &ar)
	ar.Records[0].Approval.Signature[0] ^= 1
	bad, _ = json.Marshal(ar)
	if _, err := DecodeApprovals(bad); err == nil {
		t.Fatal("forged approval snapshot")
	}
	o, _ := f.t.Object("runtime")
	o.Reference.Keys[0] = "changed"
	o.ACL.Users = append(o.ACL.Users, "evil")
	if !bytes.Equal(treeBytes, encodedTree(t, f.t)) {
		t.Fatal("metadata getter alias")
	}
	p, err := f.a.ReadSet(f.c, f.t, g, 110)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Merge(p, nil, 4096); err == nil {
		t.Fatal("missing provider data")
	}
	if strings.Contains(string(treeBytes), "secret-value-marker") || strings.Contains(string(bookBytes), "secret-value-marker") {
		t.Fatal("private data serialized")
	}
	private := Fetched{Secret: "runtime", Values: map[string][]byte{"DB_PASSWORD": []byte("secret-value-marker")}}
	keyset := Keyset{Values: private.Values}
	for _, v := range []any{private, keyset} {
		if _, err = json.Marshal(v); err == nil {
			t.Fatal("private wrapper was serializable")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if output := fmt.Sprintf(format, v); strings.Contains(output, "secret-value-marker") || !strings.Contains(output, "redacted") {
				t.Fatal("private material diagnostic", output)
			}
		}
	}
}

// ChangeACL sends only the change: a listed name cannot be added again, an
// unlisted one cannot be removed, and an empty change is refused.
func TestChangeACLAppliesOnlyTheDelta(t *testing.T) {
	f := makeFixture(t)
	o, _ := f.t.Object("defaults")
	n, err := f.t.ChangeACL(f.c, "alice", o.ID, o.Revision, ACL{Users: []string{"bob", "alice"}, Services: []string{"web"}}, ACL{})
	f.t = mustTree(t, n, err)
	o, _ = f.t.Object("defaults")
	if !slices.Equal(o.ACL.Users, []string{"alice", "bob"}) || !slices.Equal(o.ACL.Services, []string{"web"}) {
		t.Fatal("added names", o.ACL)
	}
	for _, c := range []struct {
		add, remove ACL
		want        error
	}{
		{ACL{Users: []string{"bob"}}, ACL{}, access.ErrConflict},
		{ACL{}, ACL{DenyUsers: []string{"bob"}}, access.ErrConflict},
		{ACL{}, ACL{}, ErrPolicy},
		{ACL{Services: []string{"api"}}, ACL{Services: []string{"api"}}, ErrPolicy},
	} {
		if _, err := f.t.ChangeACL(f.c, "alice", o.ID, o.Revision, c.add, c.remove); err != c.want {
			t.Fatal("delta", c, err)
		}
	}
	if _, err := f.t.ChangeACL(f.c, "alice", o.ID, o.Revision-1, ACL{DenyUsers: []string{"eve"}}, ACL{}); err != access.ErrConflict {
		t.Fatal("stale revision", err)
	}
	n, err = f.t.ChangeACL(f.c, "alice", o.ID, o.Revision, ACL{DenyUsers: []string{"eve"}}, ACL{Users: []string{"bob"}})
	f.t = mustTree(t, n, err)
	o, _ = f.t.Object("defaults")
	if !slices.Equal(o.ACL.Users, []string{"alice"}) || !slices.Equal(o.ACL.DenyUsers, []string{"eve"}) || !slices.Equal(o.ACL.Services, []string{"web"}) {
		t.Fatal("other names changed", o.ACL)
	}
}
