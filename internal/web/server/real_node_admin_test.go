// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// Storage roots on a server through the web on sfcd: add, refusals,
// policy, drain and remove, the workspace view and who may change them.
func TestRealServerNodeStorage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	realShop(t, c)
	c.Change(0, "payments", "create-tenant", 0, control.TenantID{ID: "payments"})
	dir := t.TempDir()
	nvme := filepath.Join(dir, "nvme")
	if err := os.MkdirAll(nvme, 0o700); err != nil {
		t.Fatal(err)
	}

	// add: tenants are sorted and de-duplicated
	o := op()
	code, out := f.do("POST", "/api/v1/nodes/node-0/storage", map[string]any{"opId": o, "id": "nvme", "path": nvme, "tenants": []string{"shop", "payments", "shop"}, "capacityBytes": 8 << 30})
	if opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "add-node-storage" {
		t.Fatalf("add: %d %v", code, out)
	}
	var d nodestorage.Definition
	userPayload(t, f, "u-admin", o, &d)
	if !slices.Equal(d.Tenants, []string{"payments", "shop"}) || d.Node != "node-0" || d.CapacityBytes != 8<<30 || d.Path != nvme {
		t.Fatalf("payload: %+v", d)
	}
	// node-0 attests the root
	var row map[string]any
	c.Wait("root attested", func() bool {
		row = storageItem(t, f, "/api/v1/nodes/node-0/storage", "nvme")
		return row != nil && row["attested"] == true
	})
	if row["volumes"] != float64(0) || row["closed"] != false || row["capacityBytes"] != float64(8<<30) || row["allTenants"] != false || row["default"] != false {
		t.Fatalf("nvme row: %v", row)
	}
	if code, out := f.do("GET", "/api/v1/nodes/node-0/storage/nvme/space", nil); code != 200 || out["node"] != "node-0" || out["id"] != "nvme" {
		t.Fatalf("space: %d %v", code, out)
	}
	if storageItem(t, f, "/api/v1/storage", "nvme") == nil {
		t.Fatal("not in the cluster list")
	}

	// bad input is refused before signing
	for _, b := range []map[string]any{
		{"opId": op(), "id": "Bad", "path": "/srv/x"},
		{"opId": op(), "id": "x", "path": "/srv/../x"},
		{"opId": op(), "id": "x", "path": "/srv/x", "capacityBytes": uint64(1) << 61},
		{"opId": op(), "id": "x", "path": "/srv/x", "tenants": []string{"No"}}, {"opId": op(), "id": "x", "path": "/srv/x", "allTenants": true, "tenants": []string{"shop"}},
	} {
		if code, out := f.do("POST", "/api/v1/nodes/node-0/storage", b); code != 422 {
			t.Fatalf("bad %v: %d %v", b, code, out)
		}
	}
	// a path inside another root on the node fails in sfcd
	if code, out := f.do("POST", "/api/v1/nodes/node-0/storage", map[string]any{"opId": op(), "id": "inner", "path": filepath.Join(nvme, "a")}); opState(t, code, out) != "failed" {
		t.Fatalf("nested: %d %v", code, out)
	}

	// policy: a stale expected fails, the current one applies
	rev := row["revision"].(float64)
	if code, out := f.do("PATCH", "/api/v1/nodes/node-0/storage/nvme", map[string]any{"opId": op(), "removeTenants": []string{"payments"}, "capacityBytes": 4 << 30, "expected": rev - 1}); opState(t, code, out) != "failed" {
		t.Fatalf("stale policy: %d %v", code, out)
	}
	o = op()
	if code, out := f.do("PATCH", "/api/v1/nodes/node-0/storage/nvme", map[string]any{"opId": o, "removeTenants": []string{"payments"}, "capacityBytes": 4 << 30, "expected": rev}); opState(t, code, out) != "applied" {
		t.Fatalf("policy: %d %v", code, out)
	}
	var q control.NodeStoragePolicy
	userPayload(t, f, "u-admin", o, &q)
	if q.Node != "node-0" || q.ID != "nvme" || q.CapacityBytes == nil || *q.CapacityBytes != 4<<30 || !slices.Equal(q.RemoveTenants, []string{"payments"}) || len(q.AddTenants) != 0 {
		t.Fatalf("policy payload: %+v", q)
	}
	row = storageItem(t, f, "/api/v1/storage", "nvme")
	if row["capacityBytes"] != float64(4<<30) {
		t.Fatalf("after policy: %v", row)
	}

	// the workspace view: the allowed root without its path
	alice, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c.Change(0, "alice", "put-user", 0, access.User{ID: "u-alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: alice.Public, Enabled: true}}})
	c.Change(0, "alice-shop", "set-membership", 0, access.Membership{Tenant: "shop", User: "u-alice", Role: access.Manager, Enabled: true})
	c.Change(0, "alice-payments", "set-membership", 0, access.Membership{Tenant: "payments", User: "u-alice", Role: access.Viewer, Enabled: true})
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	code, out = f.do("GET", "/api/v1/t/shop/storage", nil)
	items, _ := out["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("shop storage: %d %v", code, out)
	}
	if r := items[0].(map[string]any); r["node"] != "node-0" || r["id"] != "nvme" || r["allowed"] != true || r["path"] != nil {
		t.Fatalf("shop row: %v", r)
	}
	if code, out := f.do("GET", "/api/v1/t/payments/storage", nil); code != 403 {
		t.Fatalf("payments viewer: %d %v", code, out)
	}
	// a workspace manager is refused by sfcd
	if code, out := f.do("POST", "/api/v1/nodes/node-0/storage", map[string]any{"opId": op(), "id": "mine", "path": filepath.Join(dir, "mine")}); code == 200 && opState(t, code, out) == "applied" {
		t.Fatalf("manager add: %d %v", code, out)
	}

	// remove before a drain fails; drain, then remove
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	rev = row["revision"].(float64)
	if code, out := f.do("DELETE", "/api/v1/nodes/node-0/storage/nvme", map[string]any{"opId": op(), "expected": rev}); opState(t, code, out) != "failed" {
		t.Fatalf("remove undrained: %d %v", code, out)
	}
	drain := op()
	if code, out := f.do("POST", "/api/v1/nodes/node-0/storage/nvme/drain", map[string]any{"opId": drain, "expected": rev}); opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "drain-node-storage" {
		t.Fatalf("drain: %d %v", code, out)
	}
	// draining at once; node-0 then reports the root closed
	if row = storageItem(t, f, "/api/v1/storage", "nvme"); row["draining"] != true {
		t.Fatalf("draining row: %v", row)
	}
	c.Wait("root closed", func() bool {
		row = storageItem(t, f, "/api/v1/storage", "nvme")
		return row["closed"] == true
	})
	// the same opId on DELETE is a different change
	if code, out := f.do("DELETE", "/api/v1/nodes/node-0/storage/nvme", map[string]any{"opId": drain, "expected": row["revision"]}); code != 409 || errCode(out) != "op-conflict" {
		t.Fatalf("opId reuse: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-0/storage/nvme/remove", map[string]any{"opId": op(), "expected": row["revision"]}); opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "remove-node-storage" {
		t.Fatalf("remove: %d %v", code, out)
	}
	if storageItem(t, f, "/api/v1/storage", "nvme") != nil {
		t.Fatal("removed root still listed")
	}
}

// A workspace's per-server limit through the web on sfcd.
func TestRealServerTenantNodeLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	realShop(t, c) // node-wide and shop limits: 2 CPUs, 1 GiB, 2 networks, 8 consumers

	l := limitItem(t, f, "shop", "node-1")
	if l == nil || l["cpus"] != float64(2) || l["nodeCpus"] != float64(2) || l["nodeMemoryBytes"] != float64(1<<30) {
		t.Fatalf("limit row: %v", l)
	}
	// change CPUs and memory: the other fields are carried over
	o := op()
	code, out := f.do("PUT", "/api/v1/t/shop/limits/node-1", map[string]any{"opId": o, "cpus": 1.5, "memoryBytes": 512 << 20, "expected": l["revision"]})
	if opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "set-node-quota" {
		t.Fatalf("set: %d %v", code, out)
	}
	var v tenancy.NodeLimit
	userPayload(t, f, "u-admin", o, &v)
	if v.Tenant != "shop" || v.Node != "node-1" || v.Capacity.CPU != 1_500_000_000 || v.Capacity.Memory != 512<<20 || v.Networks != 2 || v.MaxConsumers != 8 {
		t.Fatalf("payload: %+v", v)
	}
	if l = limitItem(t, f, "shop", "node-1"); l["cpus"] != 1.5 || l["memoryBytes"] != float64(512<<20) {
		t.Fatalf("after set: %v", l)
	}
	// over the node-wide limit: 422 with the ceiling, nothing stored
	over := op()
	code, out = f.do("PUT", "/api/v1/t/shop/limits/node-1", map[string]any{"opId": over, "cpus": 3, "memoryBytes": 1 << 20, "expected": l["revision"]})
	e, _ := out["error"].(map[string]any)
	if code != 422 || errCode(out) != "limit-over-node" || e["max"].(map[string]any)["cpus"] != float64(2) {
		t.Fatalf("over: %d %v", code, out)
	}
	if _, err := f.store.GetOp("u-admin", over); err == nil {
		t.Fatal("refused limit was stored")
	}
	if code, out := f.do("PUT", "/api/v1/t/shop/limits/node-z", map[string]any{"opId": op(), "cpus": 1, "memoryBytes": 1}); code != 422 || errCode(out) != "limit-over-node" {
		t.Fatalf("unknown node: %d %v", code, out)
	}

	// a workspace manager sees the row without the node-wide ceiling and
	// cannot change it
	alice, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c.Change(0, "alice", "put-user", 0, access.User{ID: "u-alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: alice.Public, Enabled: true}}})
	c.Change(0, "alice-shop", "set-membership", 0, access.Membership{Tenant: "shop", User: "u-alice", Role: access.Manager, Enabled: true})
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	l = limitItem(t, f, "shop", "node-1")
	if l == nil || l["nodeCpus"] != nil {
		t.Fatalf("manager row: %v", l)
	}
	if code, out := f.do("PUT", "/api/v1/t/shop/limits/node-1", map[string]any{"opId": op(), "cpus": 1, "memoryBytes": 1 << 20, "expected": l["revision"]}); code == 200 && opState(t, code, out) == "applied" {
		t.Fatalf("manager set: %d %v", code, out)
	}
}
