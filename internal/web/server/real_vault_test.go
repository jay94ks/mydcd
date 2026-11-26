// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/web/store"
	"github.com/jay94ks/mydcd/tests/clusterfixture"
	"github.com/jay94ks/mydcd/tests/vaultfixture"
)

// The web's Vault screens on mydcd with a real HashiCorp Vault behind the
// workspace realm: the cluster Vault's init and objects, a workspace
// value write and Group password, the object policy (ACL, move, revoke,
// retire, approval age) and who may see them.
func TestRealServerVault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	vault := vaultfixture.Open(t)
	f, c := newRealFixture(t, ctx, 1, realVaultBackends(t, vault, "shop"))
	op := realOpID()
	alice, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c.Change(0, "shop", "create-tenant", 0, control.TenantID{ID: "shop"})
	c.Change(0, "alice", "put-user", 0, access.User{ID: "u-alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: alice.Public, Enabled: true}}})
	c.Change(0, "alice-shop", "set-membership", 0, access.Membership{Tenant: "shop", User: "u-alice", Role: access.Manager, Enabled: true})
	step := func(method, path string, body map[string]any) map[string]any {
		t.Helper()
		code, out := f.do(method, path, body)
		if s := opState(t, code, out); s != "applied" {
			t.Fatalf("%s %s %v: %s %d %v", method, path, body, s, code, out)
		}
		return out
	}
	row := func(path, id string) map[string]any {
		t.Helper()
		_, out := f.do("GET", path, nil)
		items, _ := out["items"].([]any)
		for _, it := range items {
			if m := it.(map[string]any); m["id"] == id {
				return m
			}
		}
		t.Fatalf("%s not listed: %v", id, out)
		return nil
	}

	// A workspace manager is not a system administrator.
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/vault", nil); code != 403 {
		t.Fatalf("alice cluster list: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/vault/init", map[string]any{"opId": op()}); code == 200 && opState(t, code, out) == "applied" {
		t.Fatalf("alice init: %d %v", code, out)
	}

	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	code, out := f.do("GET", "/api/v1/vault", nil)
	if code != 200 || out["initialized"] != false || len(out["items"].([]any)) != 0 {
		t.Fatalf("empty: %d %v", code, out)
	}
	step("POST", "/api/v1/vault/init", map[string]any{"opId": op()})
	if code, out := f.do("POST", "/api/v1/vault/init", map[string]any{"opId": op()}); code != 409 || errCode(out) != "exists" {
		t.Fatalf("init twice: %d %v", code, out)
	}
	if _, out = f.do("GET", "/api/v1/vault", nil); out["initialized"] != true || out["root"] != "cluster" {
		t.Fatalf("initialized: %v", out)
	}
	step("POST", "/api/v1/vault", map[string]any{"opId": op(), "parent": "cluster", "id": "infra", "kind": "group"})
	step("POST", "/api/v1/vault", map[string]any{"opId": op(), "parent": "infra", "id": "registry", "kind": "secret", "profile": "default", "object": "registry", "keys": []string{"TOKEN"}})
	if code, out := f.do("POST", "/api/v1/vault", map[string]any{"opId": op(), "parent": "nope", "id": "x", "kind": "group"}); code == 200 && opState(t, code, out) == "applied" {
		t.Fatalf("no parent: %v", out)
	}
	if code, out := f.do("POST", "/api/v1/vault", map[string]any{"opId": op(), "realm": "shop", "parent": "cluster", "id": "x", "kind": "group"}); code != 422 {
		t.Fatalf("other realm: %d %v", code, out)
	}
	if sec := row("/api/v1/vault", "registry"); sec["realm"] != "" || sec["parent"] != "infra" || sec["kind"] != "object" || sec["status"] != "reference-pending" {
		t.Fatalf("secret row: %v", sec)
	}
	// The cluster realm has no Vault backend here, so its objects stay
	// pending; groups take the policy changes.
	step("PUT", "/api/v1/vault/approval-age", map[string]any{"opId": op(), "id": "infra", "seconds": 600})
	step("POST", "/api/v1/vault", map[string]any{"opId": op(), "parent": "cluster", "id": "old", "kind": "group"})
	step("POST", "/api/v1/vault/move", map[string]any{"opId": op(), "id": "old", "parent": "infra"})
	if r := row("/api/v1/vault", "old"); r["parent"] != "infra" || r["path"] != "infra/old" {
		t.Fatalf("moved: %v", r)
	}
	if code, out := f.do("GET", "/api/v1/vault/usages", nil); code != 400 {
		t.Fatalf("cluster usages without id: %d %v", code, out)
	}

	// The workspace Vault: an administrator initializes it, its manager
	// keeps the objects.
	c.Change(0, "shop-vault", "vault-init", 0, control.VaultRealm{Realm: "shop", Root: "shop"})
	realVaultProfiles(t, c, "shop")
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	base := "/api/v1/t/shop/vault"
	step("POST", base, map[string]any{"opId": op(), "parent": "shop", "id": "db", "kind": "group"})
	step("POST", base, map[string]any{"opId": op(), "parent": "db", "id": "mysql", "kind": "secret", "profile": "values", "object": "shop/mysql", "keys": []string{"PASSWORD"}})
	for _, b := range []map[string]any{
		{"opId": op(), "parent": "shop", "id": "x", "kind": "secret"},
		{"opId": op(), "parent": "shop", "id": "x", "kind": "group", "keys": []string{"A"}},
		{"opId": op(), "realm": "payments", "parent": "shop", "id": "x", "kind": "group"},
	} {
		if code, out := f.do("POST", base, b); code != 422 {
			t.Fatalf("bad %v: %d %v", b, code, out)
		}
	}
	// The reference stays pending until the first value is written; the
	// web sends the value to node-0, which writes it into Vault.
	r := row(base, "mysql")
	if r["kind"] != "object" || r["status"] != "reference-pending" || r["path"] != "db/mysql" {
		t.Fatalf("pending: %v", r)
	}
	const password = "db-pass-5d1c-7a0e"
	if code, out := f.do("POST", base+"/value", map[string]any{"opId": op(), "path": r["path"]}); code != 400 {
		t.Fatalf("no values: %d %v", code, out)
	}
	wo := op()
	if out := step("POST", base+"/value", map[string]any{"opId": wo, "path": r["path"], "values": map[string]string{"PASSWORD": password}}); out["op"].(map[string]any)["action"] != "vault-value" {
		t.Fatalf("write: %v", out)
	}
	c.Wait("value written", func() bool { return row(base, "mysql")["status"] == "active" })
	var stored struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	vault.API("GET", "kv/data/shop/mysql", nil, &stored, vault.Admin)
	// mydcd stores values base64-encoded next to its write receipt.
	if stored.Data.Data["PASSWORD"] != base64.StdEncoding.EncodeToString([]byte(password)) || stored.Data.Data["_mydc_receipt"] == nil {
		t.Fatalf("not in Vault: %d keys", len(stored.Data.Data))
	}
	// the four step originals, in order
	for i, want := range []string{"vault-prepare-write", "vault-dispatch-write", "vault-observe-write", "vault-publish-write"} {
		o, err := f.store.GetOp("u-alice", stepID(wo, i))
		if err != nil || o.Action != want || o.State != store.OpApplied {
			t.Fatalf("step %d: %v %+v", i, err, o)
		}
	}
	// the same opId again returns the published job without values
	step("POST", base+"/value", map[string]any{"opId": wo, "path": "db/mysql", "keys": []string{"PASSWORD"}})
	// A write names the Secret's keys anew: mydcd publishes the written
	// keys as the Secret's reference.
	step("POST", base+"/value", map[string]any{"opId": op(), "path": "db/mysql", "values": map[string]string{"OTHER": "other-value"}})
	if k := row(base, "mysql")["keys"]; fmt.Sprint(k) != "[OTHER]" {
		t.Fatalf("keys after write: %v", k)
	}
	// the job has no single original to resume
	if code, out := f.do("POST", "/api/v1/ops/"+wo+"/resume", nil); code != 409 {
		t.Fatalf("resume job: %d %v", code, out)
	}
	assertNowhere(t, f, password)

	// A Group password goes to the verifier store as a hash.
	const groupPass = "group-pass-9b3f"
	if code, out := f.do("POST", base+"/password", map[string]any{"opId": op(), "path": "db", "password": "two\nlines"}); code != 400 {
		t.Fatalf("bad password: %d %v", code, out)
	}
	// The first password names the verifier writer profile; mydcd refuses
	// it without one.
	if code, out := f.do("POST", base+"/password", map[string]any{"opId": op(), "path": "db", "password": groupPass}); code != 403 {
		t.Fatalf("no profile: %d %v", code, out)
	}
	if out := step("POST", base+"/password", map[string]any{"opId": op(), "path": "db", "password": groupPass, "profile": "auth"}); out["op"].(map[string]any)["action"] != "vault-password" {
		t.Fatalf("password: %v", out)
	}
	if g := row(base, "db"); g["protected"] != true {
		t.Fatalf("group not protected: %v", g)
	}
	if code, out := f.do("POST", base+"/password", map[string]any{"opId": op(), "path": "db/mysql", "password": "x"}); code < 400 {
		t.Fatalf("secret password: %d %v", code, out)
	}
	assertNowhere(t, f, groupPass)
	if r := row(base, "mysql"); r["parent"] != "db" || r["realm"] != "shop" {
		t.Fatalf("row: %v", r)
	}
	_, out = f.do("GET", base, nil)
	for _, it := range out["items"].([]any) {
		if it.(map[string]any)["realm"] != "shop" {
			t.Fatalf("cluster row in workspace list: %v", it)
		}
	}
	o := op()
	step("PUT", base+"/acl", map[string]any{"opId": o, "id": "mysql", "users": []string{"u-alice"}})
	var acl control.VaultACL
	userPayload(t, f, "u-alice", o, &acl)
	if acl.Realm != "shop" || acl.ID != "mysql" || len(acl.ACL.Users) != 1 {
		t.Fatalf("acl payload: %+v", acl)
	}
	if a := row(base, "mysql")["acl"].(map[string]any); fmt.Sprint(a["users"]) != "[u-alice]" {
		t.Fatalf("acl row: %v", a)
	}
	step("POST", base+"/move", map[string]any{"opId": op(), "id": "mysql", "parent": "shop"})
	if r := row(base, "mysql"); r["parent"] != "shop" || r["path"] != "mysql" {
		t.Fatalf("moved: %v", r)
	}
	if code, out := f.do("POST", base+"/retire", map[string]any{"opId": op(), "id": "mysql"}); code != 409 || errCode(out) != "not-revoking" {
		t.Fatalf("retire early: %d %v", code, out)
	}
	step("POST", base+"/revoke", map[string]any{"opId": op(), "id": "mysql"})
	if code, out := f.do("PUT", base+"/acl", map[string]any{"opId": op(), "id": "mysql", "users": []string{}}); code != 409 || errCode(out) != "not-active" {
		t.Fatalf("acl revoking: %d %v", code, out)
	}
	step("POST", base+"/retire", map[string]any{"opId": op(), "id": "mysql"})
	if r := row(base, "mysql"); r["status"] != "retired" {
		t.Fatalf("retired: %v", r)
	}
	if code, out := f.do("POST", base+"/revoke", map[string]any{"opId": op(), "id": "nope"}); code != 404 {
		t.Fatalf("missing: %d %v", code, out)
	}
	if code, out := f.do("PUT", base+"/approval-age", map[string]any{"opId": op(), "id": "mysql", "seconds": 60}); code != 409 || errCode(out) != "not-group" {
		t.Fatalf("age on object: %d %v", code, out)
	}
	step("PUT", base+"/approval-age", map[string]any{"opId": op(), "id": "db", "seconds": 60})
	// mydcd does not say whether an object it will not show exists.
	if code, out := f.do("GET", base+"/usages?id=nope", nil); code != 403 {
		t.Fatalf("usages of unknown: %d %v", code, out)
	}
	if code, out := f.do("GET", base+"/usages?id=db", nil); code != 200 || len(out["items"].([]any)) != 0 {
		t.Fatalf("usages: %d %v", code, out)
	}
}

// realVaultBackends gives each node the test Vault as the realm's value
// store ("values", under prefix realm/) and Group password verifier store
// ("auth", under groups/realm/), with a token for both.
func realVaultBackends(t *testing.T, v *vaultfixture.Vault, realm string) clusterfixture.Option {
	t.Helper()
	v.API("PUT", "sys/policies/acl/mydc-web-test", map[string]any{"policy": `path "kv/data/` + realm + `/*" { capabilities = ["create","update","read"] } path "kv/data/groups/` + realm + `/*" { capabilities = ["create","update","read"] }`}, nil, v.Admin)
	var issued struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	v.API("POST", "auth/token/create", map[string]any{"policies": []string{"mydc-web-test"}, "no_default_policy": true, "ttl": "30m", "renewable": false}, &issued, v.Admin)
	token := filepath.Join(v.Root, "web-test-token")
	if err := os.WriteFile(token, []byte(issued.Auth.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	return func(n *clusterfixture.Node) {
		n.Config.Vaults = append(n.Config.Vaults,
			config.VaultBackend{Realm: realm, Profile: "values", Address: v.Address, Mount: "kv", Prefix: realm, CAFile: filepath.Join(v.Root, "tls.pem"), TokenFile: token, Values: true},
			config.VaultBackend{Realm: realm, Profile: "auth", Address: v.Address, Mount: "kv", Prefix: "groups/" + realm, CAFile: filepath.Join(v.Root, "tls.pem"), TokenFile: token, Verifiers: true})
	}
}

// realVaultProfiles lets node-0 write the realm's values and verifiers.
func realVaultProfiles(t *testing.T, c *clusterfixture.Cluster, realm string) {
	t.Helper()
	for _, p := range []secrets.WriteProfile{{ID: "values", Node: "node-0", Key: c.Nodes[0].Key, Enabled: true, Values: true}, {ID: "auth", Node: "node-0", Key: c.Nodes[0].Key, Enabled: true, Verifiers: true}} {
		v, err := c.Policy.Vault(c.State())
		if err != nil {
			t.Fatal(err)
		}
		c.Change(0, "vault-profile-"+realm+"-"+p.ID, "vault-set-profile", v.Trees[realm].Revision(), control.VaultProfile{Realm: realm, Profile: p})
	}
}
