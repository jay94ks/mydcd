// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func key(v byte) [32]byte { var k [32]byte; k[0] = v; return k }
func user(id string, admin bool) User {
	return User{ID: id, Username: id, Enabled: true, SystemAdmin: admin, Credentials: []Credential{{ID: "key", Method: PrivateKey, PublicKey: key(byte(id[0])), Enabled: true}}}
}
func must(t *testing.T, c Catalog, err error) Catalog {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func enrolled(t *testing.T) Catalog {
	t.Helper()
	c, err := New(key(1))
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Enroll(key(1), user("admin", true))
	return must(t, c, err)
}
func put(t *testing.T, c Catalog, actor string, u User) Catalog {
	t.Helper()
	old, exists := c.User(u.ID)
	u.Revision = 0
	if !exists {
		n, err := c.PutUser(actor, 0, u)
		return must(t, n, err)
	}
	// a fixture's whole-record edit (the wire has only account changes)
	if !c.SystemAllowed(actor) {
		t.Fatal("not an administrator", actor)
	}
	n, err := c.replaceUser(old.Revision, u)
	return must(t, n, err)
}
func tenant(t *testing.T, c Catalog, id string) Catalog {
	t.Helper()
	n, err := c.CreateTenant("admin", id, 0)
	return must(t, n, err)
}
func member(t *testing.T, c Catalog, tenant, id string, role Role, enabled bool) Catalog {
	t.Helper()
	old, _ := c.Membership(tenant, id)
	n, err := c.SetMembership("admin", old.Revision, Membership{Tenant: tenant, User: id, Role: role, Enabled: enabled})
	return must(t, n, err)
}

func TestBlankCatalogEnrollmentAndImmutableCandidates(t *testing.T) {
	c, err := New(key(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.users)+len(c.tenants)+len(c.members) != 0 || !c.AwaitingAdmin() {
		t.Fatal("init seeded operating state")
	}
	if _, err = c.Enroll(key(2), user("admin", true)); err != ErrDenied {
		t.Fatal(err)
	}
	u := user("admin", true)
	n, err := c.Enroll(key(1), u)
	n = must(t, n, err)
	u.Credentials[0].Enabled = false
	if !c.AwaitingAdmin() || len(c.users) != 0 || n.AwaitingAdmin() || !n.SystemAllowed("admin") {
		t.Fatal("aliased enrollment")
	}
	got, _ := n.User("admin")
	if !got.Credentials[0].Enabled {
		t.Fatal("input alias")
	}
	got.Credentials[0].Enabled = false
	if again, _ := n.User("admin"); !again.Credentials[0].Enabled {
		t.Fatal("getter alias")
	}
	if _, err = n.Enroll(key(1), user("other", true)); err != ErrDenied {
		t.Fatal("anchor reused")
	}
	for _, original := range []Catalog{c, n} {
		b, _ := original.Encode()
		restored, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		back, _ := restored.Encode()
		if !bytes.Equal(b, back) {
			t.Fatal("snapshot changed")
		}
	}
}

func TestMultipleTenantsAndCurrentMembership(t *testing.T) {
	c := enrolled(t)
	c = put(t, c, "admin", user("alice", false))
	c = put(t, c, "admin", user("bob", false))
	c = tenant(t, c, "first")
	c = tenant(t, c, "second")
	c = member(t, c, "first", "alice", Manager, true)
	c = member(t, c, "second", "alice", Viewer, true)
	if len(c.VisibleTenants("alice")) != 2 || len(c.VisibleTenants("bob")) != 0 {
		t.Fatal("tenant read leak")
	}
	for _, action := range []Action{ManageNetwork, Deploy, ManageSecrets, ManageVolumes, ManageRoutes, ManageServices, ManageCD, ManageRegistry, ManageTrust, ManageMembers} {
		if c.Authorize("alice", "first", action, "") != nil || c.Authorize("alice", "second", action, "") == nil {
			t.Fatal(action)
		}
	}
	if c.Authorize("alice", "second", Read, "") != nil || c.Authorize("admin", "second", ManageRegistry, "") != nil {
		t.Fatal("viewer/admin")
	}
	c = tenant(t, c, "new-tenant")
	if c.Authorize("admin", "new-tenant", ManageSecrets, "") != nil {
		t.Fatal("implicit admin scope")
	}
	c = member(t, c, "first", "alice", Manager, false)
	if c.Authorize("alice", "first", Deploy, "") != ErrDenied {
		t.Fatal("stale membership")
	}
	if c.Authorize("admin", "first", Action("unknown"), "") != ErrDenied {
		t.Fatal("unknown action")
	}
	if _, err := c.PutUser("alice", 0, user("evil", true)); err != ErrDenied {
		t.Fatal("manager privilege escalation")
	}
}

func TestAccountCredentialAndLastAdminInvariants(t *testing.T) {
	c := enrolled(t)
	a, _ := c.User("admin")
	expected := a.Revision
	a.Revision = 0
	a.Enabled = false
	if _, err := c.replaceUser(expected, a); err != ErrDenied {
		t.Fatal("last admin disabled")
	}
	a.Enabled = true
	a.SystemAdmin = false
	if _, err := c.replaceUser(expected, a); err != ErrDenied {
		t.Fatal("last admin demoted")
	}
	for _, method := range []Method{Password, PrivateKey, Token} {
		u := user(string(method), true)
		u.Credentials[0].Method = method
		if method != PrivateKey {
			u.Credentials[0].PublicKey = [32]byte{}
			u.Credentials[0].VerifierRef = "system-credentials/" + string(method)
		}
		c = put(t, c, "admin", u)
		u.Credentials[0].Enabled = false
		old, _ := c.User(u.ID)
		if _, err := c.replaceUser(old.Revision, u); err != ErrInvalid {
			t.Fatal("last administrator auth removed", method, err)
		}
		u.SystemAdmin = false
		if _, err := c.replaceUser(old.Revision, u); err != nil {
			t.Fatal("an ordinary account may end with no method on", method, err)
		}
	}
	u := user("duplicate", false)
	u.Username = "admin"
	if _, err := c.PutUser("admin", 0, u); err != ErrConflict {
		t.Fatal("username reused")
	}
	u = user("invalid", false)
	u.Credentials = append(u.Credentials, u.Credentials[0])
	if _, err := c.PutUser("admin", 0, u); err != ErrInvalid {
		t.Fatal("duplicate credential")
	}
	c = put(t, c, "admin", user("backup", true))
	c = put(t, c, "backup", a)
	if c.SystemAllowed("admin") || !c.SystemAllowed("backup") {
		t.Fatal("admin rotation")
	}
	b, _ := c.Encode()
	restored, err := Decode(b)
	if err != nil || restored.SystemAllowed("admin") {
		t.Fatal("revocation lost", err)
	}
}

func TestTrustDefaultRevocationAndNodeScope(t *testing.T) {
	c := tenant(t, enrolled(t), "first")
	c = put(t, c, "admin", user("alice", false))
	c = member(t, c, "first", "alice", Manager, true)
	tenantBefore, _ := c.Tenant("first")
	if len(tenantBefore.AllowedNodes) != 0 || len(tenantBefore.ImageSources) != 1 || tenantBefore.ImageSources[0] != (TrustRule{"docker.io", "**"}) {
		t.Fatal("tenant defaults")
	}
	nodes := []string{"node-a"}
	next, err := c.SetNodes("admin", "first", tenantBefore.Revision, nodes)
	c = must(t, next, err)
	nodes[0] = "foreign"
	digest := "@sha256:" + strings.Repeat("a", 64)
	for _, ref := range []string{"alpine" + digest, "docker.io/library/alpine" + digest, "index.docker.io/library/alpine" + digest} {
		if img, err := c.CheckImage("alice", "first", "node-a", ref); err != nil || img.Registry != "docker.io" || img.Repository != "library/alpine" {
			t.Fatal(ref, img, err)
		}
	}
	for _, ref := range []string{"evil.example/alpine" + digest, "docker.io.evil/alpine" + digest, "alpine:latest", "sha256:" + strings.Repeat("a", 64)} {
		if _, err := c.CheckImage("alice", "first", "node-a", ref); err == nil {
			t.Fatal("untrusted image", ref)
		}
	}
	if _, err := c.CheckImage("alice", "first", "foreign", "alpine"+digest); err != ErrDenied {
		t.Fatal("node scope")
	}
	if _, err := c.CheckImageTrust("first", "alpine"+digest); err != nil {
		t.Fatal("trust diagnostic confused node grant with repository trust", err)
	}
	tenantNow, _ := c.Tenant("first")
	next, err = c.ChangeTrust("alice", "first", tenantNow.Revision, nil, tenantNow.ImageSources)
	c = must(t, next, err)
	if _, err := c.CheckImage("alice", "first", "node-a", "alpine"+digest); err != ErrDenied {
		t.Fatal("revoked cached source")
	}
	if _, err := c.CheckImageTrust("first", "alpine"+digest); err != ErrDenied {
		t.Fatal("current trust diagnostic adopted an old cached grant")
	}
	b, _ := c.Encode()
	c, err = Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if now, _ := c.Tenant("first"); len(now.ImageSources) != 0 {
		t.Fatal("Hub silently reinserted")
	}
	tenantNow, _ = c.Tenant("first")
	rules := []TrustRule{{"private.example:5443", "team/php"}}
	next, err = c.ChangeTrust("alice", "first", tenantNow.Revision, rules, nil)
	c = must(t, next, err)
	rules[0].Repository = "**"
	if _, err := c.CheckImage("alice", "first", "node-a", "private.example:5443/team/php"+digest); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CheckImage("alice", "first", "node-a", "private.example:5443/team/mysql"+digest); err != ErrDenied {
		t.Fatal("repository scope")
	}
	if len(tenantBefore.ImageSources) != 1 {
		t.Fatal("mutated old view")
	}
}

func TestCanonicalRestoreRejectsForgedState(t *testing.T) {
	c := tenant(t, enrolled(t), "first")
	b, _ := c.Encode()
	var record catalogRecord
	if err := json.Unmarshal(b, &record); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*catalogRecord){
		func(r *catalogRecord) { r.Schema = 2 }, func(r *catalogRecord) { r.Anchor = key(1) },
		func(r *catalogRecord) { r.Users[0].SystemAdmin = false },
		func(r *catalogRecord) { r.Users = append(r.Users, r.Users[0]) },
		func(r *catalogRecord) { r.Tenants[0].ImageSources = []TrustRule{{"docker.io", "bad*"}} },
		func(r *catalogRecord) {
			r.Members = []Membership{{Tenant: "foreign", User: "admin", Enabled: true, Role: Manager, Revision: 1}}
		},
	} {
		var r catalogRecord
		_ = json.Unmarshal(b, &r)
		mutate(&r)
		raw, _ := json.Marshal(r)
		if _, err := Decode(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	for _, raw := range [][]byte{append(b, ' '), append(b, b...), bytes.Replace(b, []byte(`"Schema":1`), []byte(`"Schema":1,"Schema":1`), 1)} {
		if _, err := Decode(raw); err == nil {
			t.Fatal("noncanonical snapshot")
		}
	}
	for _, rules := range [][]TrustRule{{{"docker.io", "**"}, {"docker.io", "**"}}, {{"index.docker.io", "**"}}, {{"https://evil.example", "**"}}, {{"docker.io", "../foreign"}}} {
		if _, err := CanonicalTrust(rules); err == nil {
			t.Fatal("bad trust rule", rules)
		}
	}
}

// ChangeTrust carries only the changed rules. A delta made from an older
// list (adding a trusted rule, removing an untrusted one) conflicts.
func TestChangeTrustDelta(t *testing.T) {
	c := tenant(t, enrolled(t), "first")
	hub := TrustRule{"docker.io", "**"}
	php := TrustRule{"private.example", "team/php"}
	v, _ := c.Tenant("first")
	if _, err := c.ChangeTrust("admin", "first", v.Revision, nil, nil); err != ErrInvalid {
		t.Fatal("empty delta", err)
	}
	if _, err := c.ChangeTrust("admin", "first", v.Revision, []TrustRule{hub}, nil); err != ErrConflict {
		t.Fatal("added a trusted rule", err)
	}
	if _, err := c.ChangeTrust("admin", "first", v.Revision, nil, []TrustRule{php}); err != ErrConflict {
		t.Fatal("removed an untrusted rule", err)
	}
	if _, err := c.ChangeTrust("admin", "first", v.Revision, []TrustRule{php}, []TrustRule{php}); err != ErrConflict {
		t.Fatal("added and removed the same rule", err)
	}
	if _, err := c.ChangeTrust("admin", "first", v.Revision+1, []TrustRule{php}, nil); err != ErrConflict {
		t.Fatal("stale revision", err)
	}
	next, err := c.ChangeTrust("admin", "first", v.Revision, []TrustRule{php}, []TrustRule{hub})
	c = must(t, next, err)
	now, _ := c.Tenant("first")
	if !slices.Equal(now.ImageSources, []TrustRule{php}) || now.Revision == v.Revision {
		t.Fatal("swapped rules", now)
	}
	next, err = c.ChangeTrust("admin", "first", now.Revision, []TrustRule{hub}, nil)
	c = must(t, next, err)
	if now, _ = c.Tenant("first"); !slices.Equal(now.ImageSources, []TrustRule{hub, php}) {
		t.Fatal("added rule kept canonical order", now.ImageSources)
	}
}
