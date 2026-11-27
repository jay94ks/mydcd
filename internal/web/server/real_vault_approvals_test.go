// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/tests/clusterfixture"
	"github.com/jay94ks/seafield/tests/vaultfixture"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
)

// realProtectedShop prepares "shop" with a real Vault: alice manages it, a
// Group shop-db with a password holds the Secret mysql (DB_PASSWORD), and
// node-0 is the approval issuer. alice is logged in; it returns the password.
func realProtectedShop(t *testing.T, f *fixture, c *clusterfixture.Cluster, op func() string) string {
	t.Helper()
	realShop(t, c)
	alice, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c.Change(0, "alice", "put-user", 0, access.User{ID: "u-alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: alice.Public, Enabled: true}}})
	c.Change(0, "alice-shop", "set-membership", 0, access.Membership{Tenant: "shop", User: "u-alice", Role: access.Manager, Enabled: true})
	c.Change(0, "shop-vault", "vault-init", 0, control.VaultRealm{Realm: "shop", Root: "shop"})
	realVaultProfiles(t, c, "shop")
	v, err := c.Policy.Vault(c.State())
	if err != nil {
		t.Fatal(err)
	}
	c.Change(0, "issuer", "vault-set-issuer", v.Approvals.Revision(), control.VaultIssuer{Key: c.Nodes[0].Key, Enabled: true})
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	step := func(path string, body map[string]any) {
		t.Helper()
		if code, out := f.do("POST", "/api/v1/t/shop/vault"+path, body); opState(t, code, out) != "applied" {
			t.Fatalf("%s %v: %d %v", path, body, code, out)
		}
	}
	const password = "open-sesame-41c2"
	step("", map[string]any{"opId": op(), "parent": "shop", "id": "shop-db", "kind": "group"})
	step("", map[string]any{"opId": op(), "parent": "shop-db", "id": "mysql", "kind": "secret", "profile": "values", "object": "shop/mysql", "keys": []string{"DB_PASSWORD"}})
	step("/value", map[string]any{"opId": op(), "path": "shop-db/mysql", "values": map[string]string{"DB_PASSWORD": "db-value-77aa"}})
	step("/password", map[string]any{"opId": op(), "path": "shop-db", "password": password, "profile": "auth"})
	return password
}

// realSecretApp is an app on node-1 whose web service takes DB_PASSWORD
// from Group shop-db.
func realSecretApp(t *testing.T, c *clusterfixture.Cluster) string {
	t.Helper()
	image := "docker.io/library/nginx@sha256:" + strings.Repeat("c", 64)
	var cfg dockerspec.DockerOCIImage
	cfg.Config.User, cfg.Config.Cmd = "10001:10001", []string{"/web"}
	c.Nodes[1].Engine.Publish(cfg, image)
	return "name: web\nservices:\n web:\n  image: " + image + "\n  cpus: 0.1\n  mem_limit: 16m\n  networks: {app: {}}\n  x-sfc:\n   node: node-1\n   secrets_from: [group/shop-db]\n   secret_env: [{source: db, name: DB_PASSWORD}]\nsecrets:\n db:\n  x-sfc: {key: DB_PASSWORD}\nnetworks:\n app: {external: true, name: lan}\n"
}

// A deploy that uses a Group with a password waits for its approval; the
// approval with the password lets node-1 start the container with the
// value; the granted approval is listed and revoked (devel/refactor/16).
func TestRealServerDeployGroupApproval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	vault := vaultfixture.Open(t)
	f, c := newRealFixture(t, ctx, 2, realVaultBackends(t, vault, "shop"))
	op := realOpID()
	password := realProtectedShop(t, f, c, op)
	doc := realSecretApp(t, c)

	opID := op()
	code, out := f.do("POST", "/api/v1/t/shop/apps/deploy", map[string]any{"opId": opID, "yaml": doc, "deployment": "prod"})
	o := out["op"].(map[string]any)
	ap, _ := o["approvals"].([]any)
	if code != 202 || o["errorCode"] != "approval-required" || len(ap) != 1 {
		t.Fatalf("deploy: %d %v", code, out)
	}
	if a := ap[0].(map[string]any); a["group"] != "shop-db" || a["realm"] != "shop" || a["state"] != "required" || a["services"].([]any)[0] != "web" {
		t.Fatalf("approval: %v", a)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/deploy", map[string]any{"opId": opID, "yaml": doc, "deployment": "prod"}); code != 202 || out["op"].(map[string]any)["errorCode"] != "approval-required" {
		t.Fatalf("again: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/t/shop/vault/approvals", nil)
	if items := out["items"].([]any); len(items) != 1 || items[0].(map[string]any)["opId"] != opID {
		t.Fatalf("list: %v", out)
	}
	base := "/api/v1/t/shop/apps/deploy/" + opID + "/approve"
	if code, out := f.do("POST", base, map[string]any{"group": "shop-db", "password": "wrong-pass"}); code != 403 || errCode(out) != "approval-denied" {
		t.Fatalf("wrong password: %d %v", code, out)
	}
	if code, out := f.do("POST", base, map[string]any{"group": "other", "password": "x"}); code != 409 || errCode(out) != "not-required" {
		t.Fatalf("other group: %d %v", code, out)
	}
	code, out = f.do("POST", base, map[string]any{"group": "shop-db", "password": password})
	o = out["op"].(map[string]any)
	if code != 200 || o["state"] != "applied" || o["approvals"].([]any)[0].(map[string]any)["state"] != "approved" {
		t.Fatalf("approve: %d %v", code, out)
	}
	assertNowhere(t, f, password)
	assertNowhere(t, f, "wrong-pass")
	assertNowhere(t, f, "db-value-77aa")
	if _, out = f.do("GET", "/api/v1/t/shop/vault/approvals", nil); len(out["items"].([]any)) != 0 {
		t.Fatalf("list after: %v", out)
	}
	if code, out := f.do("POST", base, map[string]any{"group": "shop-db", "password": password}); code != 409 {
		t.Fatalf("after done: %d %v", code, out)
	}

	// node-1 fetches the value from Vault and starts the container with it.
	c.Wait("deploy succeeded", func() bool {
		_, out = f.do("GET", "/api/v1/t/shop/apps", nil)
		app := out["items"].([]any)[0].(map[string]any)
		return app["operation"].(map[string]any)["status"] == "Succeeded"
	})
	ids := c.Nodes[1].Engine.Containers(map[string]string{"org.sfc.key": "workload/task/shop/web/web"})
	if len(ids) != 1 || !slices.Contains(c.Nodes[1].Engine.Env(ids[0]), "DB_PASSWORD=db-value-77aa") {
		t.Fatalf("container env: %v", ids)
	}

	// The usage and the granted approval are listed; revoking it starts
	// releasing the consumers.
	if code, out := f.do("GET", "/api/v1/t/shop/vault/usages?id=shop-db", nil); code != 200 || len(out["items"].([]any)) == 0 {
		t.Fatalf("usages: %d %v", code, out)
	}
	code, out = f.do("GET", "/api/v1/t/shop/vault/approvals/granted", nil)
	items, _ := out["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("granted: %d %v", code, out)
	}
	row := items[0].(map[string]any)
	if row["group"] != "shop-db" || row["app"] != "web" || row["revoking"] != false || len(row["issuer"].(string)) != 64 {
		t.Fatalf("granted row: %v", row)
	}
	// The workspace's secret manager revokes it (as the approval realm's
	// manager; Jay 2026-11-26).
	revoke := op()
	if code, out := f.do("POST", "/api/v1/t/shop/vault/approvals/granted/"+row["id"].(string)+"/revoke", map[string]any{"opId": revoke}); opState(t, code, out) != "applied" {
		t.Fatalf("revoke: %d %v", code, out)
	}
	var sel control.VaultApprovalSelection
	userPayload(t, f, "u-alice", revoke, &sel)
	if sel.ID != row["id"] {
		t.Fatalf("revoke payload: %+v", sel)
	}
	if _, out := f.do("GET", "/api/v1/t/shop/vault/approvals/granted", nil); len(out["items"].([]any)) != 0 && out["items"].([]any)[0].(map[string]any)["revoking"] != true {
		t.Fatalf("after revoke: %v", out)
	}
}
