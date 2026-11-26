// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

func bobLogin(t *testing.T, f *fixture) {
	t.Helper()
	if code, out := keyLogin(f, "bob", mydc.FixtureKey("bob")); code != 200 {
		t.Fatalf("bob login: %d %v", code, out)
	}
}

// keyLogin runs the browser's key login: challenge, sign the proof, login,
// sign the session approval, approve (R02).
func keyLogin(f *fixture, username string, priv ed25519.PrivateKey) (int, map[string]any) {
	pub := priv.Public().(ed25519.PublicKey)
	code, out := f.do("POST", "/api/v1/auth/key/challenge", map[string]any{"username": username, "publicKey": hex.EncodeToString(pub)})
	if code != 200 {
		return code, out
	}
	proof, _ := base64.StdEncoding.DecodeString(out["proof"].(string))
	code, out = f.do("POST", "/api/v1/auth/key/login", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(ed25519.Sign(priv, proof))})
	if code != 200 || out["approve"] != true {
		return code, out
	}
	approval, _ := base64.StdEncoding.DecodeString(out["approval"].(string))
	return f.do("POST", "/api/v1/auth/key/approve", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(ed25519.Sign(priv, approval))})
}

const (
	opNet1 = "a1b2c3d4-0000-4000-8000-000000000001"
	opNet2 = "a1b2c3d4-0000-4000-8000-000000000002"
	opVol1 = "a1b2c3d4-0000-4000-8000-000000000003"
	opVol2 = "a1b2c3d4-0000-4000-8000-000000000004"
	opVau1 = "a1b2c3d4-0000-4000-8000-000000000005"
	opVau2 = "a1b2c3d4-0000-4000-8000-000000000006"
	opBad  = "a1b2c3d4-0000-4000-8000-000000000007"
)

func opState(t *testing.T, code int, out map[string]any) string {
	t.Helper()
	op, ok := out["op"].(map[string]any)
	if !ok {
		t.Fatalf("no op: %d %v", code, out)
	}
	return op["state"].(string)
}

func hasItem(out map[string]any, field, want string) bool {
	for _, it := range out["items"].([]any) {
		m := it.(map[string]any)
		if inner, ok := m["network"].(map[string]any); ok && field == "network" {
			if inner["name"] == want {
				return true
			}
			continue
		}
		if m[field] == want {
			return true
		}
	}
	return false
}

func TestCreateNetwork(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	body := map[string]any{"opId": opNet1, "name": "cache-net", "node": "node-b", "cidr": "10.40.0.0/24"}
	code, out := f.do("POST", "/api/v1/t/shop/networks", body)
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "create-network" {
		t.Fatalf("create: %d %v", code, out)
	}
	_, list := f.do("GET", "/api/v1/t/shop/networks", nil)
	if !hasItem(list, "network", "cache-net") {
		t.Fatalf("not listed: %v", list)
	}
	// same opId and body: the stored op, nothing sent again
	n := len(fake.Journal())
	if code, out := f.do("POST", "/api/v1/t/shop/networks", body); code != 200 || opState(t, code, out) != "applied" || len(fake.Journal()) != n {
		t.Fatalf("repeat: %d %v", code, out)
	}
	// same opId, another body
	if code, out := f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": opNet1, "name": "other", "node": "node-b", "cidr": "10.41.0.0/24"}); code != 409 || errCode(out) != "op-conflict" {
		t.Fatalf("conflict: %d %v", code, out)
	}
	// the name exists: mydcd's condition fails
	code, out = f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": opNet2, "name": "cache-net", "node": "node-b", "cidr": "10.42.0.0/24"})
	if code != 200 || opState(t, code, out) != "failed" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	// bad input is refused before anything is signed
	for _, b := range []map[string]any{
		{"opId": opBad, "name": "x", "node": "node-b", "cidr": "10.40.0.1/24"},
		{"opId": opBad, "name": "x", "node": "node-b", "cidr": "10.43.0.0/24", "gateway": "10.44.0.1"},
		{"opId": opBad, "name": "Bad Name", "node": "node-b", "cidr": "10.43.0.0/24"},
	} {
		if code, out := f.do("POST", "/api/v1/t/shop/networks", b); code != 422 {
			t.Fatalf("bad %v: %d %v", b, code, out)
		}
	}
	if _, err := f.store.GetOp("u-alice", opBad); err == nil {
		t.Fatal("refused input was stored")
	}
	// a viewer is refused by mydcd
	bobLogin(t, f)
	code, out = f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": opBad, "name": "bob-net", "node": "node-b", "cidr": "10.45.0.0/24"})
	if code != 200 || opState(t, code, out) != "failed" || out["op"].(map[string]any)["resultCode"] != float64(mydc.ResultForbidden) {
		t.Fatalf("viewer: %d %v", code, out)
	}
}

func TestCreateVolume(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	code, out := f.do("POST", "/api/v1/t/shop/volumes", map[string]any{"opId": opVol1, "kind": "managed", "name": "media", "app": "php-shop", "node": "node-b", "uid": 1000, "gid": 1000, "mode": "0770", "capacityBytes": 1 << 30})
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "begin-volume-create" {
		t.Fatalf("managed: %d %v", code, out)
	}
	// a tenant manager cannot read storage roots: the generation
	// comes from the request and mydcd checks it
	fixed := map[string]any{"opId": opVol2, "kind": "fixed", "name": "archive", "node": "node-b", "storage": "ssd", "path": "/srv/mydc-ssd/archive"}
	if code, out := f.do("POST", "/api/v1/t/shop/volumes", fixed); code != 422 || errCode(out) != "storage-root-unknown" {
		t.Fatalf("fixed without generation: %d %v", code, out)
	}
	fixed["rootGeneration"] = 1
	code, out = f.do("POST", "/api/v1/t/shop/volumes", fixed)
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "register-fixed-volume" {
		t.Fatalf("fixed: %d %v", code, out)
	}
	_, list := f.do("GET", "/api/v1/t/shop/volumes", nil)
	if !hasItem(list, "name", "media") || !hasItem(list, "name", "archive") {
		t.Fatalf("not listed: %v", list)
	}
	for _, b := range []map[string]any{
		{"opId": opBad, "kind": "managed", "name": "x", "app": "php-shop", "node": "node-b", "uid": 0, "gid": 1000},
		{"opId": opBad, "kind": "managed", "name": "x", "app": "php-shop", "node": "node-b", "uid": 1000, "gid": 1000, "mode": "0755"},
		{"opId": opBad, "kind": "other", "name": "x", "node": "node-b"},
	} {
		if code, out := f.do("POST", "/api/v1/t/shop/volumes", b); code != 422 {
			t.Fatalf("bad %v: %d %v", b, code, out)
		}
	}
}

func TestCreateFixedVolumeAsAdmin(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	code, out := f.do("POST", "/api/v1/t/shop/volumes", map[string]any{"opId": opVol1, "kind": "fixed", "name": "archive", "node": "node-b", "storage": "ssd", "path": "/srv/mydc-ssd/archive"})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("admin fixed: %d %v", code, out)
	}
	// payments' root is not approved for shop
	if code, out := f.do("POST", "/api/v1/t/shop/volumes", map[string]any{"opId": opBad, "kind": "fixed", "name": "x", "node": "node-c", "storage": "hdd", "path": "/srv/mydc-hdd/x"}); code != 422 {
		t.Fatalf("other workspace's root: %d %v", code, out)
	}
}

func TestCreateVault(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	code, out := f.do("POST", "/api/v1/t/shop/vault", map[string]any{"opId": opVau1, "parent": "root", "id": "cache", "kind": "group"})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("group: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/vault", map[string]any{"opId": opVau2, "parent": "cache", "id": "redis", "kind": "secret", "profile": "default", "object": "redis", "keys": []string{"REDIS_PASSWORD"}})
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "vault-create" {
		t.Fatalf("secret: %d %v", code, out)
	}
	_, list := f.do("GET", "/api/v1/t/shop/vault", nil)
	if !hasItem(list, "path", "cache/redis") {
		t.Fatalf("not listed: %v", list)
	}
	for _, b := range []map[string]any{
		{"opId": opBad, "parent": "root", "id": "x", "kind": "secret"},
		{"opId": opBad, "parent": "root", "id": "x", "kind": "group", "keys": []string{"A"}},
		{"opId": opBad, "realm": "payments", "parent": "root", "id": "x", "kind": "group"},
	} {
		if code, out := f.do("POST", "/api/v1/t/shop/vault", b); code != 422 {
			t.Fatalf("bad %v: %d %v", b, code, out)
		}
	}
}

func networkRow(t *testing.T, f *fixture, name string) map[string]any {
	t.Helper()
	_, list := f.do("GET", "/api/v1/t/shop/networks", nil)
	for _, it := range list["items"].([]any) {
		if n, _ := it.(map[string]any)["network"].(map[string]any); n != nil && n["name"] == name {
			return n
		}
	}
	t.Fatalf("network %s not listed: %v", name, list)
	return nil
}

// signedPayload is the payload of alice's stored signed original.
func signedPayload(t *testing.T, f *fixture, opID string) []byte {
	t.Helper()
	o, err := f.store.GetOp("u-alice", opID)
	if err != nil {
		t.Fatal(err)
	}
	op, err := mydc.DecodeOperation(o.Signed)
	if err != nil {
		t.Fatal(err)
	}
	return op.Change.Payload
}

func TestCreateTUNNetworkAndDNS(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	body := map[string]any{"opId": opNet1, "kind": "tun", "name": "mesh", "tunnelCidr": "10.255.40.0/24", "members": []map[string]any{
		{"node": "node-a", "cidr": "10.50.1.0/24"}, {"node": "node-b", "cidr": "10.50.2.0/24", "gateway": "10.50.2.254"}}}
	code, out := f.do("POST", "/api/v1/t/shop/networks", body)
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "create-tun-network" {
		t.Fatalf("create: %d %v", code, out)
	}
	// the signed payload carries each member's pool and handed-out tunnel address
	var d tenancy.TUNDefinition
	if err := json.Unmarshal(signedPayload(t, f, opNet1), &d); err != nil || len(d.Members) != 2 ||
		d.Members[0].Addresses[0].String() != "10.255.40.1/32" || d.Members[1].Addresses[0].String() != "10.255.40.2/32" ||
		d.Members[1].Pools[0].Gateway.String() != "10.50.2.254" || d.Members[0].Pools[0].MTU != 1500 {
		t.Fatalf("payload: %v %+v", err, d)
	}
	if n := networkRow(t, f, "mesh"); n["kind"] != "tun" || len(n["nodes"].([]any)) != 2 || n["dns"] != nil {
		t.Fatalf("row: %v", n)
	}

	for _, b := range []map[string]any{
		{"opId": opBad, "kind": "tun", "name": "x", "members": []map[string]any{{"node": "node-a", "cidr": "10.51.0.0/24"}}},                                                                                                                         // no tunnel address
		{"opId": opBad, "kind": "tun", "name": "x", "members": []map[string]any{{"node": "node-a", "cidr": "10.51.0.0/24", "tunnel": "10.51.0.9"}}},                                                                                                  // tunnel inside the pool
		{"opId": opBad, "kind": "tun", "name": "x", "tunnelCidr": "10.255.41.0/30", "members": []map[string]any{{"node": "node-a", "cidr": "10.51.0.0/24"}, {"node": "node-b", "cidr": "10.52.0.0/24"}, {"node": "node-c", "cidr": "10.53.0.0/24"}}}, // too few
		{"opId": opBad, "kind": "tun", "name": "x", "tunnelCidr": "10.255.41.0/24", "members": []map[string]any{{"node": "node-a", "cidr": "10.51.0.0/24"}, {"node": "node-a", "cidr": "10.52.0.0/24"}}},                                             // same node
		{"opId": opBad, "kind": "tun", "name": "x", "tunnelCidr": "10.255.41.0/24", "members": []map[string]any{{"node": "node-a", "cidr": "10.51.0.0/16"}, {"node": "node-b", "cidr": "10.51.2.0/24"}}},                                             // overlap
		{"opId": opBad, "kind": "mesh", "name": "x", "node": "node-a", "cidr": "10.51.0.0/24"},
	} {
		if code, out := f.do("POST", "/api/v1/t/shop/networks", b); code != 422 {
			t.Fatalf("bad %v: %d %v", b, code, out)
		}
	}

	// DNS: the first policy has expected 0, a change takes the row's revision
	code, out = f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": opNet2, "zone": "mesh.internal", "upstreams": []string{"1.1.1.1", "9.9.9.9:5353"}})
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "configure-network-dns" {
		t.Fatalf("dns: %d %v", code, out)
	}
	var def services.ManagedDNSDefinition
	if err := json.Unmarshal(signedPayload(t, f, opNet2), &def); err != nil || def.Policy.Zone != "mesh.internal." || !def.Policy.Enabled ||
		len(def.Policy.Upstreams) != 2 || def.Policy.Upstreams[0].String() != "1.1.1.1:53" || def.Policy.TTL != 30 {
		t.Fatalf("dns payload: %v %+v", err, def)
	}
	dns, _ := networkRow(t, f, "mesh")["dns"].(map[string]any)
	if dns["zone"] != "mesh.internal." || dns["enabled"] != true || dns["ttl"] != float64(30) || dns["negativeTtl"] != float64(5) || dns["reverse"] != false ||
		fmt.Sprint(dns["upstreams"]) != "[1.1.1.1:53 9.9.9.9:5353]" {
		t.Fatalf("dns row: %v", dns)
	}
	for _, m := range networkRow(t, f, "mesh")["members"].([]any) {
		if m.(map[string]any)["resolver"] == "" || m.(map[string]any)["resolver"] == nil {
			t.Fatalf("resolver: %v", m)
		}
	}
	code, out = f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": opVol1, "zone": "mesh.internal", "enabled": false})
	if code != 200 || opState(t, code, out) != "failed" {
		t.Fatalf("stale dns change: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": opVol2, "zone": "mesh.internal", "enabled": false, "expected": dns["revision"]})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("dns change: %d %v", code, out)
	}
	// turning it off keeps the rest of the policy
	if err := json.Unmarshal(signedPayload(t, f, opVol2), &def); err != nil || def.Policy.Enabled || len(def.Policy.Upstreams) != 2 || def.Policy.TTL != 30 || def.Policy.MaxQueries != 64 {
		t.Fatalf("dns off payload: %v %+v", err, def)
	}
	if m := networkRow(t, f, "mesh")["members"].([]any)[0].(map[string]any); m["resolver"] != nil {
		t.Fatalf("resolver after off: %v", m)
	}
	// a bridge network has no managed DNS in mydcd
	if code, out := f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": opVau1, "name": "solo", "node": "node-b", "cidr": "10.60.0.0/24"}); code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("bridge: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/networks/solo/dns", map[string]any{"opId": opVau2, "zone": "solo.internal"}); code != 200 || opState(t, code, out) == "applied" {
		t.Fatalf("bridge dns applied: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": opBad, "zone": "bad zone!", "upstreams": []string{"x"}}); code != 422 {
		t.Fatalf("bad dns: %d %v", code, out)
	}
}
