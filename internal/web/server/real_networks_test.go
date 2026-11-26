// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// realMembers adds alice (manager) and bob (viewer) of shop; it returns
// their keys.
func realMembers(t *testing.T, c interface {
	Change(int, string, string, uint64, any)
}) (alice, bob *identity.Identity) {
	t.Helper()
	for _, u := range []struct {
		name string
		role access.Role
		key  **identity.Identity
	}{{"alice", access.Manager, &alice}, {"bob", access.Viewer, &bob}} {
		k, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		*u.key = k
		c.Change(0, u.name, "put-user", 0, access.User{ID: "u-" + u.name, Username: u.name, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: k.Public, Enabled: true}}})
		c.Change(0, u.name+"-shop", "set-membership", 0, access.Membership{Tenant: "shop", User: "u-" + u.name, Role: u.role, Enabled: true})
	}
	return alice, bob
}

// A workspace manager creates bridge and TUN networks and sets a TUN
// network's managed DNS through the web on real mydcd.
func TestRealServerNetworks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	realShop(t, c)
	alice, bob := realMembers(t, c)
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}

	body := map[string]any{"opId": op(), "name": "cache-net", "node": "node-1", "cidr": "10.40.0.0/24"}
	code, out := f.do("POST", "/api/v1/t/shop/networks", body)
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "create-network" {
		t.Fatalf("create: %d %v", code, out)
	}
	c.Wait("listed", func() bool {
		_, list := f.do("GET", "/api/v1/t/shop/networks", nil)
		return hasItem(list, "network", "cache-net")
	})
	if code, out := f.do("POST", "/api/v1/t/shop/networks", body); code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("repeat: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": body["opId"], "name": "other", "node": "node-1", "cidr": "10.41.0.0/24"}); code != 409 || errCode(out) != "op-conflict" {
		t.Fatalf("conflict: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": op(), "name": "cache-net", "node": "node-0", "cidr": "10.42.0.0/24"}); opState(t, code, out) != "failed" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	bad := op()
	for _, b := range []map[string]any{
		{"opId": bad, "name": "x", "node": "node-1", "cidr": "10.40.0.1/24"},
		{"opId": bad, "name": "x", "node": "node-1", "cidr": "10.43.0.0/24", "gateway": "10.44.0.1"},
		{"opId": bad, "name": "Bad Name", "node": "node-1", "cidr": "10.43.0.0/24"},
	} {
		if code, out := f.do("POST", "/api/v1/t/shop/networks", b); code != 422 {
			t.Fatalf("bad %v: %d %v", b, code, out)
		}
	}
	if _, err := f.store.GetOp("u-alice", bad); err == nil {
		t.Fatal("refused input was stored")
	}

	// A TUN network on node-0 (one member: two in one process share the
	// kernel's routes) and its managed DNS.
	tun := op()
	code, out = f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": tun, "kind": "tun", "name": "mesh", "tunnelCidr": "10.255.40.0/24", "members": []map[string]any{{"node": "node-0", "cidr": "10.50.1.0/24", "gateway": "10.50.1.254"}}})
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "create-tun-network" {
		t.Fatalf("tun: %d %v", code, out)
	}
	var d tenancy.TUNDefinition
	if err := json.Unmarshal(signedPayload(t, f, tun), &d); err != nil || len(d.Members) != 1 || d.Members[0].Addresses[0].String() != "10.255.40.1/32" || d.Members[0].Pools[0].Gateway.String() != "10.50.1.254" {
		t.Fatalf("tun payload: %v %+v", err, d)
	}
	if n := networkRow(t, f, "mesh"); n["kind"] != "tun" || len(n["nodes"].([]any)) != 1 || n["dns"] != nil {
		t.Fatalf("tun row: %v", n)
	}
	for _, b := range []map[string]any{
		{"opId": op(), "kind": "tun", "name": "x", "members": []map[string]any{{"node": "node-0", "cidr": "10.51.0.0/24"}}},                                                                                                                         // no tunnel address
		{"opId": op(), "kind": "tun", "name": "x", "members": []map[string]any{{"node": "node-0", "cidr": "10.51.0.0/24", "tunnel": "10.51.0.9"}}},                                                                                                  // tunnel inside the pool
		{"opId": op(), "kind": "tun", "name": "x", "tunnelCidr": "10.255.41.0/30", "members": []map[string]any{{"node": "node-0", "cidr": "10.51.0.0/24"}, {"node": "node-1", "cidr": "10.52.0.0/24"}, {"node": "node-2", "cidr": "10.53.0.0/24"}}}, // too few
		{"opId": op(), "kind": "tun", "name": "x", "tunnelCidr": "10.255.41.0/24", "members": []map[string]any{{"node": "node-0", "cidr": "10.51.0.0/24"}, {"node": "node-0", "cidr": "10.52.0.0/24"}}},                                             // same node
		{"opId": op(), "kind": "tun", "name": "x", "tunnelCidr": "10.255.41.0/24", "members": []map[string]any{{"node": "node-0", "cidr": "10.51.0.0/16"}, {"node": "node-1", "cidr": "10.51.2.0/24"}}},                                             // overlap
		{"opId": op(), "kind": "mesh", "name": "x", "node": "node-0", "cidr": "10.51.0.0/24"},
	} {
		if code, out := f.do("POST", "/api/v1/t/shop/networks", b); code != 422 {
			t.Fatalf("bad %v: %d %v", b, code, out)
		}
	}
	dnsOp := op()
	code, out = f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": dnsOp, "zone": "mesh.internal", "upstreams": []string{"1.1.1.1", "9.9.9.9:5353"}})
	if opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "configure-network-dns" {
		t.Fatalf("dns: %d %v", code, out)
	}
	var def services.ManagedDNSDefinition
	if err := json.Unmarshal(signedPayload(t, f, dnsOp), &def); err != nil || def.Policy.Zone != "mesh.internal." || !def.Policy.Enabled || def.Policy.Upstreams[0].String() != "1.1.1.1:53" {
		t.Fatalf("dns payload: %v %+v", err, def)
	}
	var dns map[string]any
	c.Wait("dns row", func() bool { dns, _ = networkRow(t, f, "mesh")["dns"].(map[string]any); return dns != nil })
	if dns["zone"] != "mesh.internal." || dns["enabled"] != true || fmt.Sprint(dns["upstreams"]) != "[1.1.1.1:53 9.9.9.9:5353]" {
		t.Fatalf("dns row: %v", dns)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": op(), "zone": "mesh.internal", "enabled": false}); opState(t, code, out) != "failed" {
		t.Fatalf("stale dns change: %d %v", code, out)
	}
	off := op()
	if code, out := f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": off, "zone": "mesh.internal", "enabled": false, "expected": dns["revision"]}); opState(t, code, out) != "applied" {
		t.Fatalf("dns off: %d %v", code, out)
	}
	if err := json.Unmarshal(signedPayload(t, f, off), &def); err != nil || def.Policy.Enabled || len(def.Policy.Upstreams) != 2 {
		t.Fatalf("dns off payload: %v %+v", err, def)
	}
	c.Wait("dns off row", func() bool {
		d, _ := networkRow(t, f, "mesh")["dns"].(map[string]any)
		return d != nil && d["enabled"] == false
	})
	// a bridge network has no managed DNS in mydcd
	if code, out := f.do("POST", "/api/v1/t/shop/networks/cache-net/dns", map[string]any{"opId": op(), "zone": "cache.internal"}); code == 200 && opState(t, code, out) == "applied" {
		t.Fatalf("bridge dns applied: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": op(), "zone": "bad zone!", "upstreams": []string{"x"}}); code != 422 {
		t.Fatalf("bad dns: %d %v", code, out)
	}

	// a viewer is refused by mydcd
	if code, out := keyLogin(f, "bob", bob.Private); code != 200 {
		t.Fatalf("bob login: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": op(), "name": "bob-net", "node": "node-1", "cidr": "10.45.0.0/24"})
	if opState(t, code, out) != "failed" || out["op"].(map[string]any)["resultCode"] != float64(mydc.ResultForbidden) {
		t.Fatalf("viewer: %d %v", code, out)
	}
}

// Creating volumes through the web: a managed volume for an app, a fixed
// volume a workspace manager names without the storage root's generation
// (it cannot read the roots), and the input the web refuses.
func TestRealServerCreateVolume(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	realShop(t, c)
	alice, _ := realMembers(t, c)
	for _, tenant := range []string{"", "shop"} {
		c.Change(0, "limit-"+tenant, "set-volume-backup-limit", 0, control.VolumeBackupLimit{Tenant: tenant, Node: "node-1", Bytes: 1 << 20, Count: 1, StagingBytes: 1 << 20, StagingCount: 1, Original: &control.OriginalVolumeLimit{Bytes: 4 << 20, Count: 3}})
	}
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	code, out := f.do("POST", "/api/v1/t/shop/volumes", map[string]any{"opId": op(), "kind": "managed", "name": "media", "app": "web", "node": "node-1", "uid": 1000, "gid": 1000, "mode": "0770", "capacityBytes": 1 << 20})
	if opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "begin-volume-create" {
		t.Fatalf("managed: %d %v", code, out)
	}
	c.Wait("listed", func() bool {
		_, list := f.do("GET", "/api/v1/t/shop/volumes", nil)
		return hasItem(list, "name", "media")
	})
	if code, out := f.do("POST", "/api/v1/t/shop/volumes", map[string]any{"opId": op(), "kind": "fixed", "name": "archive", "node": "node-1", "storage": "ssd", "path": "/srv/mydc-ssd/archive"}); code != 422 || errCode(out) != "storage-root-unknown" {
		t.Fatalf("fixed without generation: %d %v", code, out)
	}
	for _, b := range []map[string]any{
		{"opId": op(), "kind": "managed", "name": "x", "app": "web", "node": "node-1", "uid": 0, "gid": 1000},
		{"opId": op(), "kind": "managed", "name": "x", "app": "web", "node": "node-1", "uid": 1000, "gid": 1000, "mode": "0755"},
		{"opId": op(), "kind": "other", "name": "x", "node": "node-1"},
	} {
		if code, out := f.do("POST", "/api/v1/t/shop/volumes", b); code != 422 {
			t.Fatalf("bad %v: %d %v", b, code, out)
		}
	}
}
