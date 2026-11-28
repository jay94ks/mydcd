// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func private(n byte) ed25519.PrivateKey    { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
func public(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }
func account(id string, admin bool) access.User {
	return access.User{ID: id, Username: id, Enabled: true, SystemAdmin: admin, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: public(private(id[0])), Enabled: true}}}
}

type fixture struct {
	t              *testing.T
	cluster        [32]byte
	c              access.Catalog
	trees          map[string]secrets.Tree
	a              secrets.Approvals
	v              map[string]volumes.State
	issuer, na, nb ed25519.PrivateKey
	bindings       Bindings
}

func (f *fixture) tree(realm string, t secrets.Tree, e error) {
	f.t.Helper()
	if e != nil {
		f.t.Fatal(e)
	}
	f.trees[realm] = t
}
func (f *fixture) add(realm string, o secrets.Object) {
	f.t.Helper()
	t := f.trees[realm]
	n, e := t.Create(f.c, "admin", t.Revision(), o)
	f.tree(realm, n, e)
}
func makeFixture(t *testing.T) *fixture {
	return makeFixtureCluster(t, [32]byte{9})
}
func makeFixtureCluster(t *testing.T, cluster [32]byte) *fixture {
	t.Helper()
	root := public(private(1))
	c, e := access.New(root)
	if e != nil {
		t.Fatal(e)
	}
	c, e = c.Enroll(root, account("admin", true))
	if e != nil {
		t.Fatal(e)
	}
	c, e = c.PutUser("admin", 0, account("alice", false))
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"tenant", "other"} {
		c, e = c.CreateTenant("admin", id, 0)
		if e != nil {
			t.Fatal(e)
		}
		v, _ := c.Tenant(id)
		c, e = c.SetNodes("admin", id, v.Revision, []string{"node-a", "node-b"})
		if e != nil {
			t.Fatal(e)
		}
	}
	c, e = c.SetMembership("admin", 0, access.Membership{Tenant: "tenant", User: "alice", Role: access.Manager, Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{t: t, cluster: cluster, c: c, trees: map[string]secrets.Tree{}, issuer: private(20), na: private(21), nb: private(22)}
	for _, realm := range []string{"", "tenant"} {
		tree, e := secrets.NewTree(f.cluster, realm, "root")
		f.tree(realm, tree, e)
	}
	global := f.trees[""]
	r, _ := global.Object("root")
	global, e = global.SetACL(c, "admin", "root", r.Revision, secrets.ACL{TenantGrants: []string{"tenant"}})
	f.tree("", global, e)
	f.add("tenant", secrets.Object{ID: "common", Parent: "root", Kind: secrets.Group})
	f.add("tenant", secrets.Object{ID: "db-admin", Parent: "root", Kind: secrets.Group, ACL: secrets.ACL{Services: []string{"db"}}})
	for _, o := range []secrets.Object{
		{ID: "defaults", Parent: "root", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "vault", Object: "tenant/defaults", Revision: 1, Keys: []string{"DB_HOST"}}},
		{ID: "runtime", Parent: "common", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "vault", Object: "tenant/runtime", Revision: 1, Keys: []string{"DB_HOST", "DB_PASSWORD"}}},
		{ID: "overrides", Parent: "root", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "vault", Object: "tenant/overrides", Revision: 1, Keys: []string{"DB_HOST"}}},
		{ID: "root-password", Parent: "db-admin", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "vault", Object: "tenant/root-password", Revision: 1, Keys: []string{"MYSQL_ROOT_PASSWORD"}}},
	} {
		f.add("tenant", o)
	}
	f.add("", secrets.Object{ID: "overrides", Parent: "root", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "global-vault", Object: "shared/overrides", Revision: 1, Keys: []string{"DB_HOST"}}})
	for _, id := range []string{"common", "db-admin"} {
		tree := f.trees["tenant"]
		o, _ := tree.Object(id)
		tree, e = tree.BeginPasswordChange(c, "admin", id, "put-"+id, o.Revision)
		f.tree("tenant", tree, e)
		o, _ = tree.Object(id)
		tree, e = tree.ActivatePassword(c, "admin", id, o.PasswordChange, "credential-"+id, true, o.Revision)
		f.tree("tenant", tree, e)
	}
	f.bindings, e = NewBindings(f.cluster)
	if e != nil {
		t.Fatal(e)
	}
	f.a, e = secrets.NewApprovals(f.cluster)
	if e != nil {
		t.Fatal(e)
	}
	f.a, e = f.a.SetIssuer(c, "admin", f.a.Revision(), public(f.issuer), true)
	if e != nil {
		t.Fatal(e)
	}
	volume, e := volumes.New(c, "alice", volumes.Scope{Cluster: f.cluster, Tenant: "tenant", App: "php-mysql", ID: "mysql-data", Generation: 8}, volumes.Owner{Node: "node-b", Key: public(f.nb), Native: "sfc-mysql-original"}, 2)
	if e != nil {
		t.Fatal(e)
	}
	f.v = map[string]volumes.State{VolumeKey(volume.Scope()): volume}
	return f
}
func (f *fixture) web() Needs {
	return Needs{Consumer: "web-task", Generation: 4, Use: secrets.Use{Tenant: "tenant", User: "alice", App: "php-mysql", Deployment: "deploy", Service: "web", Node: "node-a", RequesterKey: public(private(30)), NodeKey: public(f.na)}, Sources: []Source{{Realm: "tenant", Object: "defaults"}, {Realm: "tenant", Object: "common"}, {Realm: "tenant", Object: "overrides"}}, Files: []Projection{{Key: "DB_PASSWORD", Target: "/run/secrets/db-password", UID: 10001, GID: 10001, Mode: 0400}, {Key: "DB_HOST", Target: "/run/secrets/db-host", UID: 10001, GID: 10001, Mode: 0400}}}
}
func (f *fixture) db() Needs {
	n := f.web()
	n.Consumer = "db-task"
	n.Use.Service = "db"
	n.Use.Node = "node-b"
	n.Use.NodeKey = public(f.nb)
	n.Sources = []Source{{Realm: "tenant", Object: "defaults"}, {Realm: "tenant", Object: "common"}, {Realm: "tenant", Object: "db-admin"}}
	n.Volumes = []VolumeNeed{{"tenant/php-mysql/mysql-data", true}}
	n.Files = []Projection{{Key: "DB_PASSWORD", Target: "/run/secrets/db-password", UID: 10001, GID: 10001, Mode: 0400}, {Key: "MYSQL_ROOT_PASSWORD", Target: "/run/secrets/db-root-password", UID: 10001, GID: 10001, Mode: 0400}}
	return n
}
func (f *fixture) approve(target secrets.Target) {
	f.t.Helper()
	issuer, _ := f.a.Issuer(public(f.issuer))
	target.IssuerPolicy = issuer.Policy
	prefix := "cluster"
	if target.Realm != "" {
		prefix = target.Realm
	}
	target.ApprovalID = prefix + "-" + target.Group
	if target.Purpose != "" {
		target.ApprovalID += "-" + target.Purpose
	}
	v := secrets.Approval{Schema: 1, Issuer: public(f.issuer), Payload: secrets.ApprovalPayload{ApprovedAt: 100, Fact: "secret-group-use-approved", Target: target}}
	v.Signature = ed25519.Sign(f.issuer, secrets.ApprovalBytes(v))
	var e error
	f.a, e = f.a.Commit(f.c, "alice", f.trees[target.Realm], f.a.Revision(), v, 100, 32)
	if e != nil {
		f.t.Fatal(e)
	}
}
func (f *fixture) approveAll(needs ...Needs) []secrets.Target {
	f.t.Helper()
	targets, e := Required(f.cluster, f.c, f.trees, needs)
	if e != nil {
		f.t.Fatal(e)
	}
	for _, g := range targets {
		f.approve(g)
	}
	return targets
}
func (f *fixture) reserve(needs ...Needs) Reservation {
	f.t.Helper()
	r, e := f.bindings.Reserve(f.bindings.Revision(), f.c, f.trees, f.a, f.v, needs, 100, nil)
	if e != nil {
		f.t.Fatal(e)
	}
	f.a = r.Approvals
	f.v = r.Volumes
	raw, e := r.Inventory.Encode()
	if e != nil {
		f.t.Fatal(e)
	}
	f.bindings, e = DecodeBindings(raw)
	if e != nil {
		f.t.Fatal(e)
	}
	return r
}
func (f *fixture) values(n Needs) []Fetched {
	var out []Fetched
	us := realmUses(n)
	for _, realm := range realms(n) {
		plan, e := f.trees[realm].Plan(f.c, []secrets.Use{us[realm]})
		if e != nil {
			f.t.Fatal(e)
		}
		seen := map[string]bool{}
		for _, leaf := range plan.Uses[0].Leaves {
			if seen[leaf.Secret] {
				continue
			}
			seen[leaf.Secret] = true
			values := map[string][]byte{}
			for _, key := range leaf.Reference.Keys {
				v := realm + "-" + leaf.Secret + "-" + key
				if key == "DB_PASSWORD" {
					v = "private-db-value"
				}
				if key == "MYSQL_ROOT_PASSWORD" {
					v = "private-root-value"
				}
				values[key] = []byte(v)
			}
			out = append(out, Fetched{realm, secrets.Fetched{Secret: leaf.Secret, Reference: leaf.Reference, Values: values}})
		}
	}
	return out
}
func deny(t *testing.T, e error) {
	t.Helper()
	if e == nil {
		t.Fatal("unsafe inputs accepted")
	}
}
func (f *fixture) closure(b Binding) Closure {
	k := f.na
	if b.d.Needs.Use.NodeKey == public(f.nb) {
		k = f.nb
	}
	out := Closure{}
	for _, g := range b.Grants() {
		p := secrets.UseGone{Purpose: g.Use.Purpose, Cluster: f.cluster, Realm: g.Realm, Tenant: g.Use.Tenant, App: g.Use.App, Deployment: g.Use.Deployment, Consumer: g.Consumer, Generation: g.Generation, NodeKey: g.Use.NodeKey, Selection: g.Selection, Lifetime: g.Lifetime, Stopped: true, MountsGone: true}
		p.Signature = ed25519.Sign(k, secrets.UseGoneBytes(p))
		out.Secrets = append(out.Secrets, p)
	}
	for _, pin := range b.Pins() {
		p := volumes.Gone{Scope: pin.Scope, Consumer: pin.Consumer, Stopped: true, MountsGone: true}
		p.Signature = ed25519.Sign(k, volumes.GoneBytes(p))
		out.Volumes = append(out.Volumes, p)
	}
	return out
}

func TestAppInputsPromptOnceAndReserveWholePHPMySQLBatch(t *testing.T) {
	f := makeFixture(t)
	web, db := f.web(), f.db()
	targets, e := Required(f.cluster, f.c, f.trees, []Needs{web, db})
	if e != nil || len(targets) != 2 {
		t.Fatal("required groups", e, targets)
	}
	common := targets[0]
	if common.Group != "common" || len(common.Services) != 2 || len(common.Nodes) != 2 {
		t.Fatal("prompt did not combine both nodes/services")
	}
	f.approve(common)
	missing, e := Missing(f.cluster, f.c, f.trees, f.a, []Needs{web, db}, 100)
	if e != nil || len(missing) != 1 || missing[0].Group != "db-admin" {
		t.Fatal("partial prompt resume", e)
	}
	before, _ := f.a.Encode()
	_, e = f.bindings.Reserve(f.bindings.Revision(), f.c, f.trees, f.a, f.v, []Needs{web, db}, 100, nil)
	deny(t, e)
	after, _ := f.a.Encode()
	if !bytes.Equal(before, after) || len(f.v[db.Volumes[0].Key].Consumers()) != 0 {
		t.Fatal("partial approval published pins")
	}
	f.approve(targets[1])
	missing, e = Missing(f.cluster, f.c, f.trees, f.a, []Needs{web, db}, 100)
	if e != nil || len(missing) != 0 {
		t.Fatal("already approved Group prompted again", e)
	}
	r := f.reserve(web, db)
	if len(r.Bindings) != 2 || len(r.Bindings[0].Pins()) != 0 || len(r.Bindings[1].Pins()) != 1 {
		t.Fatal("wrong batch")
	}
	for i, b := range r.Bindings {
		n := []Needs{web, db}[i]
		stage, e := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, f.values(n), 4096)
		if e != nil {
			t.Fatal(e)
		}
		files := stage.Files()
		if len(files) != 2 || stage.Binding() != b.Digest() {
			t.Fatal("incomplete stage")
		}
		if i == 0 && string(files[1].Data) != "tenant-overrides-DB_HOST" {
			t.Fatal("wrong key precedence")
		}
		if i == 0 {
			for _, file := range files {
				if bytes.Contains(file.Data, []byte("private-root-value")) {
					t.Fatal("web received DB root secret")
				}
			}
		}
		if _, e = json.Marshal(stage); e == nil || bytes.Contains([]byte(fmt.Sprintf("%+v %#v", stage, files)), []byte("private-db-value")) {
			t.Fatal("private stage leaked")
		}
	}
	oldA, _ := f.a.Encode()
	oldV, _ := f.v[db.Volumes[0].Key].Encode()
	resumed := f.reserve(web, db)
	newA, _ := f.a.Encode()
	newV, _ := f.v[db.Volumes[0].Key].Encode()
	if !bytes.Equal(oldA, newA) || !bytes.Equal(oldV, newV) || resumed.Bindings[1].Digest() != r.Bindings[1].Digest() {
		t.Fatal("resume replaced original grants/pins")
	}
}

func TestAppInputsRealmOrderAndSameObjectNamesRemainDistinct(t *testing.T) {
	f := makeFixture(t)
	n := f.web()
	n.Sources = []Source{{Realm: "tenant", Object: "overrides"}, {Realm: "", Object: "overrides"}, {Realm: "tenant", Object: "defaults"}}
	n.Files = []Projection{{Key: "DB_HOST", Target: "/run/secrets/host", UID: 10001, GID: 10001, Mode: 0400}}
	if targets, e := Required(f.cluster, f.c, f.trees, []Needs{n}); e != nil || len(targets) != 0 {
		t.Fatal(e)
	}
	r := f.reserve(n)
	b := r.Bindings[0]
	values := f.values(n)
	stage, e := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, values, 4096)
	if e != nil {
		t.Fatal(e)
	}
	if string(stage.Files()[0].Data) != "tenant-defaults-DB_HOST" || len(b.Grants()) != 2 {
		t.Fatal("group-set sorting replaced source order")
	}
	// Move the global source last: its same-name leaf is a distinct provider object.
	proof := f.closure(b)
	released, e := f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, proof)
	if e != nil {
		t.Fatal(e)
	}
	f.a = released.Approvals
	f.v = released.Volumes
	f.bindings = released.Inventory
	n.Generation++
	n.Sources = []Source{{Realm: "tenant", Object: "overrides"}, {Realm: "tenant", Object: "defaults"}, {Realm: "", Object: "overrides"}}
	r = f.reserve(n)
	stage, e = r.Bindings[0].Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, f.values(n), 4096)
	if e != nil || string(stage.Files()[0].Data) != "-overrides-DB_HOST" {
		t.Fatal("global keyset winner", e)
	}
}

func TestAppInputsRejectForeignClusterEvenForUnprotectedSources(t *testing.T) {
	f := makeFixture(t)
	// Exact same public selection and object/policy generations, different
	// cluster only. A selection-hash mismatch must not hide this boundary.
	raw, e := f.trees["tenant"].Encode()
	if e != nil {
		t.Fatal(e)
	}
	foreignCluster, _ := json.Marshal([32]byte{77})
	originalCluster, _ := json.Marshal(f.cluster)
	foreignRaw := bytes.Replace(raw, append([]byte("\"Cluster\":"), originalCluster...), append([]byte("\"Cluster\":"), foreignCluster...), 1)
	other, e := secrets.DecodeTree(foreignRaw)
	if e != nil {
		t.Fatal(e)
	}
	u := f.web().Use
	u.Sources = []string{"defaults"}
	_, _, e = f.a.Acquire(f.c, other, u, "web-task", 4, f.a.Revision(), 100)
	deny(t, e)
	good := f.trees["tenant"]
	a, g, e := f.a.Acquire(f.c, good, u, "web-task", 4, f.a.Revision(), 100)
	if e != nil {
		t.Fatal(e)
	}
	_, e = a.ReadSet(f.c, other, g, 100)
	deny(t, e)
	n := f.web()
	n.Sources = []Source{{Realm: "tenant", Object: "defaults"}}
	n.Files = n.Files[1:]
	f.trees["tenant"] = other
	_, e = f.bindings.Reserve(f.bindings.Revision(), f.c, f.trees, f.a, f.v, []Needs{n}, 100, nil)
	deny(t, e)
	n.Sources[0].Realm = "other"
	_, e = Required(f.cluster, f.c, f.trees, []Needs{n})
	deny(t, e)
}

func TestAppInputsFailurePublishesNeitherSecretPinsNorSecondWriter(t *testing.T) {
	f := makeFixture(t)
	db := f.db()
	f.approveAll(db)
	before, _ := f.a.Encode()
	original := f.v[db.Volumes[0].Key]
	for _, change := range []func(*Needs, map[string]volumes.State){
		func(n *Needs, _ map[string]volumes.State) { n.Use.Node = "node-a"; n.Use.NodeKey = public(f.na) },
		func(n *Needs, _ map[string]volumes.State) { n.Use.NodeKey = public(f.na) },
		func(n *Needs, v map[string]volumes.State) { delete(v, n.Volumes[0].Key) },
		func(n *Needs, _ map[string]volumes.State) { n.Volumes[0].Key = "other/php-mysql/mysql-data" },
	} {
		n := ownNeeds(db)
		v := copyVolumes(f.v)
		change(&n, v)
		_, e := f.bindings.Reserve(f.bindings.Revision(), f.c, f.trees, f.a, v, []Needs{n}, 100, nil)
		deny(t, e)
	}
	copy := ownNeeds(db)
	copy.Consumer = "competing-task"
	_, e := f.bindings.Reserve(f.bindings.Revision(), f.c, f.trees, f.a, f.v, []Needs{db, copy}, 100, nil)
	deny(t, e)
	after, _ := f.a.Encode()
	if !bytes.Equal(before, after) || len(original.Consumers()) != 0 {
		t.Fatal("failed batch mutated source registries")
	}
	r := f.reserve(db)
	b := r.Bindings[0]
	volume := f.v[db.Volumes[0].Key]
	owner, rev := volume.Owner()
	target := volumes.Owner{Node: "node-a", Key: public(f.na), Native: "move-stage"}
	volume, e = volume.Prepare(f.c, "alice", volume.Revision(), rev, "move", target, [32]byte{5}, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	f.v[db.Volumes[0].Key] = volume
	deny(t, b.Check(f.bindings, f.c, f.trees, f.a, f.v, 100))
	_, e = f.bindings.Reserve(f.bindings.Revision(), f.c, f.trees, f.a, f.v, []Needs{db}, 100, nil)
	deny(t, e)
	// Existing original pin remains for cleanup; a move/Drain cannot restart it.
	if owner.Node != "node-b" || len(volume.Consumers()) != 1 || volume.Consumers()[0] != b.Pins()[0].Consumer {
		t.Fatal("old writer reference lost")
	}
}

func TestAppInputsIncompleteFetchOrProjectionNeverPublishesPartialFiles(t *testing.T) {
	f := makeFixture(t)
	n := f.web()
	f.approveAll(n)
	r := f.reserve(n)
	b := r.Bindings[0]
	good := f.values(n)
	for _, change := range []func([]Fetched) []Fetched{
		func(v []Fetched) []Fetched { return v[:len(v)-1] },
		func(v []Fetched) []Fetched { v[0].Value.Reference.Revision++; return v },
		func(v []Fetched) []Fetched { v[0].Value.Values = map[string][]byte{}; return v },
		func(v []Fetched) []Fetched { return append(v, v[0]) },
		func(v []Fetched) []Fetched { v[0].Realm = "other"; return v },
	} {
		values := slices.Clone(good)
		for i := range values {
			values[i].Value.Reference.Keys = slices.Clone(values[i].Value.Reference.Keys)
		}
		values = change(values)
		stage, e := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, values, 4096)
		deny(t, e)
		if len(stage.Files()) != 0 {
			t.Fatal("partial private stage published")
		}
	}
	_, e := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, good, 1)
	deny(t, e)
	if len(f.v) != 1 {
		t.Fatal("unrelated volume lost")
	}
	for _, target := range []string{"/run/secrets/../escape", "/proc/password", "/run/secrets/", "/run/secrets/a\x00b"} {
		bad := ownNeeds(n)
		bad.Files[0].Target = target
		_, e = Required(f.cluster, f.c, f.trees, []Needs{bad})
		deny(t, e)
	}
	bad := ownNeeds(n)
	bad.Files[1].Target = bad.Files[0].Target
	_, e = Required(f.cluster, f.c, f.trees, []Needs{bad})
	deny(t, e)
	bad = ownNeeds(n)
	bad.Files[0].Mode = 0777
	_, e = Required(f.cluster, f.c, f.trees, []Needs{bad})
	deny(t, e)
}

func TestAppInputsPolicyRevokeBlocksReadButOriginalClosureReleasesWholeBinding(t *testing.T) {
	f := makeFixture(t)
	n := f.db()
	f.approveAll(n)
	r := f.reserve(n)
	b := r.Bindings[0]
	// Missing volume proof must not return an otherwise valid Secret usage pin.
	proof := f.closure(b)
	before, _ := f.a.Encode()
	_, e := f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, Closure{Secrets: proof.Secrets})
	deny(t, e)
	after, _ := f.a.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("partial release")
	}
	bad := f.closure(b)
	bad.Volumes[0].Consumer.Generation++
	bad.Volumes[0].Signature = ed25519.Sign(f.nb, volumes.GoneBytes(bad.Volumes[0]))
	_, e = f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, bad)
	deny(t, e)
	for _, g := range b.Grants() {
		for _, pin := range g.Pins {
			f.a, e = f.a.Revoke(f.c, "alice", pin.ApprovalID, f.a.Revision())
			if e != nil {
				t.Fatal(e)
			}
			if !f.a.RevocationPending(pin.ApprovalID) {
				t.Fatal("lost pending consumer")
			}
		}
	}
	deny(t, b.Check(f.bindings, f.c, f.trees, f.a, f.v, 100))
	u, _ := f.c.User("alice")
	expectedUserRevision := u.Revision
	u.Enabled = false
	u.Revision = 0
	f.c, e = f.c.PutUser("admin", expectedUserRevision, access.User{ID: u.ID, Username: u.Username})
	if e != nil {
		t.Fatal(e)
	}
	released, e := f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, proof)
	if e != nil {
		t.Fatal(e)
	}
	f.a = released.Approvals
	f.v = released.Volumes
	f.bindings = released.Inventory
	if len(f.v[n.Volumes[0].Key].Consumers()) != 0 || !f.v[n.Volumes[0].Key].RetainsData() {
		t.Fatal("writer/data settlement incorrect")
	}
	for _, g := range b.Grants() {
		for _, pin := range g.Pins {
			if f.a.RevocationPending(pin.ApprovalID) {
				t.Fatal("original closure left a Secret lease")
			}
		}
	}
}

func TestAppInputsImmutableRecipeFloorAndBindingInventoryCAS(t *testing.T) {
	f := makeFixture(t)
	n := f.db()
	f.approveAll(n)
	r := f.reserve(n)
	bound := r.Bindings[0]
	for _, change := range []func(*Needs){func(n *Needs) { n.Files[0].Target = "/run/secrets/changed" }, func(n *Needs) { n.Files[0].UID++ }, func(n *Needs) { n.Files[0].Mode = 0440 }, func(n *Needs) { n.Use.Service = "other" }} {
		x := ownNeeds(n)
		change(&x)
		_, e := f.bindings.Reserve(f.bindings.Revision(), f.c, f.trees, f.a, f.v, []Needs{x}, 100, nil)
		deny(t, e)
	}
	forged := Binding{ownBinding(bound.d)}
	forged.d.Needs.Files[0].Target = "/run/secrets/forged"
	deny(t, forged.Check(f.bindings, f.c, f.trees, f.a, f.v, 100))
	_, e := f.bindings.Reserve(0, f.c, f.trees, f.a, f.v, []Needs{n}, 100, nil)
	deny(t, e)
	before, _ := f.bindings.Encode()
	candidate, e := f.bindings.Release(f.bindings.Revision(), bound, f.a, f.v, f.closure(bound))
	if e != nil {
		t.Fatal(e)
	}
	// Fake sync failure keeps the original whole tuple; no release is published.
	after, _ := f.bindings.Encode()
	if !bytes.Equal(before, after) || !f.bindings.Owns(bound) || len(f.v[n.Volumes[0].Key].Consumers()) != 1 {
		t.Fatal("candidate mutated published inventory")
	}
	f.bindings = candidate.Inventory
	f.a = candidate.Approvals
	f.v = candidate.Volumes
	deny(t, bound.Check(f.bindings, f.c, f.trees, f.a, f.v, 100))
	_, e = f.bindings.Reserve(f.bindings.Revision(), f.c, f.trees, f.a, f.v, []Needs{n}, 100, nil)
	deny(t, e)
	raw, e := f.bindings.Encode()
	if e != nil {
		t.Fatal(e)
	}
	f.bindings, e = DecodeBindings(raw)
	if e != nil {
		t.Fatal(e)
	}
	var d bindingsRecord
	if json.Unmarshal(raw, &d) != nil {
		t.Fatal("decode fixture")
	}
	d.Floors = nil
	bad, _ := json.Marshal(d)
	_, e = DecodeBindings(bad)
	deny(t, e)
	n.Generation++
	r = f.reserve(n)
	if r.Bindings[0].Pins()[0].Consumer.Lease.Token <= bound.Pins()[0].Consumer.Lease.Token {
		t.Fatal("original token floor reset")
	}
	missing, e := Missing(f.cluster, f.c, f.trees, f.a, []Needs{n}, 100)
	if e != nil || len(missing) != 0 {
		t.Fatal("same deployment approval not reused", e)
	}
}

func TestAppInputsAllSourcesRemainAuthorizedAndOnlyCurrentNodeStarts(t *testing.T) {
	f := makeFixture(t)
	n := f.web()
	f.approveAll(n)
	r := f.reserve(n)
	b := r.Bindings[0]
	values := f.values(n)
	tree := f.trees["tenant"]
	o, _ := tree.Object("defaults")
	tree, e := tree.SetACL(f.c, "alice", o.ID, o.Revision, secrets.ACL{DenyServices: []string{"web"}})
	f.tree("tenant", tree, e)
	stage, e := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, values, 4096)
	deny(t, e)
	if len(stage.Files()) != 0 {
		t.Fatal("overwritten denied source exposed partial material")
	}
	tenant, _ := f.c.Tenant("tenant")
	f.c, e = f.c.SetNodes("admin", "tenant", tenant.Revision, []string{"node-b"})
	if e != nil {
		t.Fatal(e)
	}
	deny(t, b.Check(f.bindings, f.c, f.trees, f.a, f.v, 100))
	closed, e := f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, f.closure(b))
	if e != nil {
		t.Fatal("original removed node cannot settle", e)
	}
	if len(closed.Inventory.Live()) != 0 {
		t.Fatal("binding did not retire")
	}
}

func TestAppInputsSnapshotsAreMetadataAndRevalidateCurrentSelection(t *testing.T) {
	f := makeFixture(t)
	n := f.db()
	f.approveAll(n)
	r := f.reserve(n)
	b := r.Bindings[0]
	raw, e := b.Encode()
	if e != nil {
		t.Fatal(e)
	}
	saved, e := DecodeBinding(raw)
	if e != nil || saved.Digest() != b.Digest() {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("private-db-value")) || bytes.Contains(raw, []byte("private-root-value")) {
		t.Fatal("private material in binding")
	}
	view := b.Needs()
	view.Files[0].Target = "/outside"
	grants := b.Grants()
	grants[0].Use.Sources[0] = "tampered"
	if e = b.Check(f.bindings, f.c, f.trees, f.a, f.v, 100); e != nil {
		t.Fatal("view alias", e)
	}
	for _, change := range []func(*bindingRecord){func(d *bindingRecord) { d.Schema = 2 }, func(d *bindingRecord) { d.Grants = nil }, func(d *bindingRecord) { d.Pins[0].Scope.Generation++ }, func(d *bindingRecord) { d.Needs.Sources[0].Object = "tampered" }} {
		d := ownBinding(b.d)
		change(&d)
		encoded, _ := json.Marshal(d)
		_, e = DecodeBinding(encoded)
		deny(t, e)
	}
	tree := f.trees["tenant"]
	o, _ := tree.Object("runtime")
	ref := o.Reference
	ref.Revision++
	tree, e = tree.PublishReference(f.c, "alice", o.ID, o.Revision, ref)
	f.tree("tenant", tree, e)
	deny(t, saved.Check(f.bindings, f.c, f.trees, f.a, f.v, 100))
	// Value updates do not destroy original refs or automatically create a new task.
	if len(f.v[n.Volumes[0].Key].Consumers()) != 1 {
		t.Fatal("stale selection erased original writer")
	}
}
