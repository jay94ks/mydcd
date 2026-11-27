// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/web/sfc"
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

// A workspace manager creates one-server and TUN networks and sets a TUN
// network's managed DNS through the web on real sfcd.
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

	body := map[string]any{"opId": op(), "kind": "tun", "name": "cache-net", "toggles": map[string]bool{"local": true}, "members": []map[string]any{{"node": "node-1", "cidr": "10.40.0.0/24"}}}
	code, out := f.do("POST", "/api/v1/t/shop/networks", body)
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "create-tun-network" {
		t.Fatalf("create: %d %v", code, out)
	}
	c.Wait("listed", func() bool {
		_, list := f.do("GET", "/api/v1/t/shop/networks", nil)
		return hasItem(list, "network", "cache-net")
	})
	if code, out := f.do("POST", "/api/v1/t/shop/networks", body); code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("repeat: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": body["opId"], "kind": "tun", "name": "other", "toggles": map[string]bool{"local": true}, "members": []map[string]any{{"node": "node-1", "cidr": "10.41.0.0/24"}}}); code != 409 || errCode(out) != "op-conflict" {
		t.Fatalf("conflict: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": op(), "kind": "tun", "name": "cache-net", "toggles": map[string]bool{"local": true}, "members": []map[string]any{{"node": "node-0", "cidr": "10.42.0.0/24"}}}); opState(t, code, out) != "failed" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	bad := op()
	for _, b := range []map[string]any{
		{"opId": bad, "name": "x", "node": "node-1", "cidr": "10.43.0.0/24"}, // no kind: no bridge networks
		{"opId": bad, "kind": "bridge", "name": "x", "node": "node-1", "cidr": "10.43.0.0/24"},
		{"opId": bad, "kind": "tun", "name": "x", "members": []map[string]any{{"node": "node-1", "cidr": "10.40.0.1/24"}}},
		{"opId": bad, "kind": "tun", "name": "x", "members": []map[string]any{{"node": "node-1", "cidr": "10.43.0.0/24", "gateway": "10.44.0.1"}}},
		{"opId": bad, "kind": "tun", "name": "Bad Name", "members": []map[string]any{{"node": "node-1", "cidr": "10.43.0.0/24"}}},
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
	code, out = f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": tun, "kind": "tun", "name": "mesh", "members": []map[string]any{{"node": "node-0", "cidr": "10.50.1.0/24", "gateway": "10.50.1.254"}}})
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "create-tun-network" {
		t.Fatalf("tun: %d %v", code, out)
	}
	var d tenancy.TUNDefinition
	if err := json.Unmarshal(signedPayload(t, f, tun), &d); err != nil || len(d.Members) != 1 || len(d.Members[0].Addresses) != 0 || d.Members[0].Pools[0].Gateway.String() != "10.50.1.254" {
		t.Fatalf("tun payload: %v %+v", err, d)
	}
	if n := networkRow(t, f, "mesh"); n["kind"] != "tun" || len(n["nodes"].([]any)) != 1 || n["dns"] != nil {
		t.Fatalf("tun row: %v", n)
	}
	for _, b := range []map[string]any{
		{"opId": op(), "kind": "tun", "name": "x", "members": []map[string]any{{"node": "node-0", "cidr": "10.51.0.0/24"}, {"node": "node-0", "cidr": "10.52.0.0/24"}}}, // same node
		{"opId": op(), "kind": "tun", "name": "x", "members": []map[string]any{{"node": "node-0", "cidr": "10.51.0.0/16"}, {"node": "node-1", "cidr": "10.51.2.0/24"}}}, // overlap
		{"opId": op(), "kind": "mesh", "name": "x", "node": "node-0", "cidr": "10.51.0.0/24"},
	} {
		if code, out := f.do("POST", "/api/v1/t/shop/networks", b); code != 422 {
			t.Fatalf("bad %v: %d %v", b, code, out)
		}
	}
	// A local one-server network.
	solo := op()
	code, out = f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": solo, "kind": "tun", "name": "solo", "toggles": map[string]bool{"local": true}, "members": []map[string]any{{"node": "node-0", "cidr": "10.51.0.0/24"}}})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("local tun: %d %v", code, out)
	}
	if err := json.Unmarshal(signedPayload(t, f, solo), &d); err != nil || len(d.Members) != 1 || len(d.Members[0].Addresses) != 0 {
		t.Fatalf("local tun payload: %v %+v", err, d)
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
	// the names tab: real sfcd network-dns-names, no app yet
	if code, names := f.do("GET", "/api/v1/t/shop/networks/mesh/dns/names", nil); code != 200 || names["managed"] != true || names["zone"] != "mesh.internal." || names["enabled"] != true || len(names["names"].([]any)) != 0 || len(names["servers"].([]any)) != len(networkRow(t, f, "mesh")["nodes"].([]any)) {
		t.Fatalf("dns names: %d %v", code, names)
	}
	if code, _ := f.do("GET", "/api/v1/t/shop/networks/nope/dns/names", nil); code != 404 {
		t.Fatalf("unknown network names: %d", code)
	}
	// names added by hand: a delta against the revision they were read at
	recordsURL := "/api/v1/t/shop/networks/mesh/dns/records"
	recs := []map[string]any{{"name": "www", "type": "CNAME", "value": "example.org"}, {"name": "legacy.mesh.internal", "type": "a", "value": "192.0.2.7"}}
	more := []map[string]any{{"name": "legacy", "type": "txt", "value": `say "hi"`, "ttl": 5}, {"name": "legacy", "type": "MX", "value": "10 Mail.Example.org"}}
	for _, b := range []map[string]any{
		{"opId": op(), "add": recs},                 // no expected
		{"opId": op(), "expected": dns["revision"]}, // no change
		{"opId": op(), "expected": dns["revision"], "add": []map[string]any{{"name": "@", "type": "CNAME", "value": "example.org"}}},
		{"opId": op(), "expected": dns["revision"], "add": []map[string]any{{"name": "x", "type": "A", "value": "2001:db8::1"}}},
		{"opId": op(), "expected": dns["revision"], "add": []map[string]any{{"name": "x", "type": "NS", "value": "ns.example.org"}}},
		{"opId": op(), "expected": dns["revision"], "add": []map[string]any{{"name": "x", "type": "MX", "value": "mail.example.org"}}},
		{"opId": op(), "expected": dns["revision"], "remove": []map[string]any{{"name": "x", "type": "A", "value": "192.0.2.1"}}}, // not in the list
	} {
		if code, out := f.do("PATCH", recordsURL, b); code != 422 {
			t.Fatalf("bad records %v: %d %v", b, code, out)
		}
	}
	recOp := op()
	if code, out := f.do("PATCH", recordsURL, map[string]any{"opId": recOp, "expected": dns["revision"], "add": recs}); opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "configure-network-dns" {
		t.Fatalf("records: %d %v", code, out)
	}
	if err := json.Unmarshal(signedPayload(t, f, recOp), &def); err != nil || fmt.Sprint(def.Policy.Records) != "[{legacy.mesh.internal. A 192.0.2.7 0} {www.mesh.internal. CNAME example.org. 0}]" || len(def.Policy.Upstreams) != 2 {
		t.Fatalf("records payload: %v %+v", err, def.Policy)
	}
	c.Wait("records row", func() bool {
		d, _ := networkRow(t, f, "mesh")["dns"].(map[string]any)
		if d != nil && d["revision"] != dns["revision"] {
			dns = d
			return true
		}
		return false
	})
	if code, out := f.do("PATCH", recordsURL, map[string]any{"opId": op(), "expected": dns["revision"].(float64) - 1, "remove": recs[:1]}); code != 409 || errCode(out) != "stale" {
		t.Fatalf("stale records change: %d %v", code, out)
	}
	if code, out := f.do("PATCH", recordsURL, map[string]any{"opId": op(), "expected": dns["revision"], "add": recs[:1]}); code != 422 || errCode(out) != "exists" {
		t.Fatalf("record added twice: %d %v", code, out)
	}
	// change one host record: remove the old, add the new
	editOp := op()
	if code, out := f.do("PATCH", recordsURL, map[string]any{"opId": editOp, "expected": dns["revision"], "remove": []map[string]any{{"name": "legacy", "type": "A", "value": "192.0.2.7"}}, "add": []map[string]any{{"name": "legacy", "type": "A", "value": "192.0.2.8"}}}); opState(t, code, out) != "applied" {
		t.Fatalf("edit record: %d %v", code, out)
	}
	if err := json.Unmarshal(signedPayload(t, f, editOp), &def); err != nil || fmt.Sprint(def.Policy.Records) != "[{legacy.mesh.internal. A 192.0.2.8 0} {www.mesh.internal. CNAME example.org. 0}]" {
		t.Fatalf("edited payload: %v %+v", err, def.Policy.Records)
	}
	c.Wait("edited row", func() bool {
		d, _ := networkRow(t, f, "mesh")["dns"].(map[string]any)
		if d != nil && d["revision"] != dns["revision"] {
			dns = d
			return true
		}
		return false
	})
	// other types, with a TTL of their own
	moreOp := op()
	if code, out := f.do("PATCH", recordsURL, map[string]any{"opId": moreOp, "expected": dns["revision"], "add": more}); opState(t, code, out) != "applied" {
		t.Fatalf("more records: %d %v", code, out)
	}
	if err := json.Unmarshal(signedPayload(t, f, moreOp), &def); err != nil || fmt.Sprint(def.Policy.Records) != `[{legacy.mesh.internal. A 192.0.2.8 0} {legacy.mesh.internal. MX 10 mail.example.org. 0} {legacy.mesh.internal. TXT "say \"hi\"" 5} {www.mesh.internal. CNAME example.org. 0}]` {
		t.Fatalf("more payload: %v %+v", err, def.Policy.Records)
	}
	if code, names := f.do("GET", "/api/v1/t/shop/networks/mesh/dns/names", nil); code != 200 || fmt.Sprint(names["records"]) != `[map[name:legacy.mesh.internal. served:true type:A value:192.0.2.8] map[name:legacy.mesh.internal. served:true type:MX value:10 mail.example.org.] map[name:legacy.mesh.internal. served:true ttl:5 type:TXT value:"say \"hi\""] map[name:www.mesh.internal. served:true type:CNAME value:example.org.]]` {
		t.Fatalf("records readback: %d %v", code, names["records"])
	}
	c.Wait("records row", func() bool {
		d, _ := networkRow(t, f, "mesh")["dns"].(map[string]any)
		if d != nil && d["revision"] != dns["revision"] {
			dns = d
			return true
		}
		return false
	})
	// a new zone takes the hand names along
	moved := op()
	if code, out := f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": moved, "zone": "lan.internal", "expected": dns["revision"]}); opState(t, code, out) != "applied" {
		t.Fatalf("zone move: %d %v", code, out)
	}
	if err := json.Unmarshal(signedPayload(t, f, moved), &def); err != nil || len(def.Policy.Records) != 4 || def.Policy.Records[0].Name != "legacy.lan.internal." || def.Policy.Records[3].Name != "www.lan.internal." {
		t.Fatalf("moved records: %v %+v", err, def.Policy.Records)
	}
	c.Wait("moved row", func() bool {
		d, _ := networkRow(t, f, "mesh")["dns"].(map[string]any)
		if d != nil && d["revision"] != dns["revision"] {
			dns = d
			return true
		}
		return false
	})
	if code, out := f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": op(), "zone": "mesh.internal", "enabled": false}); opState(t, code, out) != "failed" {
		t.Fatalf("stale dns change: %d %v", code, out)
	}
	off := op()
	if code, out := f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": off, "zone": "mesh.internal", "enabled": false, "expected": dns["revision"]}); opState(t, code, out) != "applied" {
		t.Fatalf("dns off: %d %v", code, out)
	}
	if err := json.Unmarshal(signedPayload(t, f, off), &def); err != nil || def.Policy.Enabled || len(def.Policy.Upstreams) != 2 || len(def.Policy.Records) != 4 || def.Policy.Records[0].Name != "legacy.mesh.internal." {
		t.Fatalf("dns off payload: %v %+v", err, def)
	}
	c.Wait("dns off row", func() bool {
		d, _ := networkRow(t, f, "mesh")["dns"].(map[string]any)
		return d != nil && d["enabled"] == false
	})
	if code, out := f.do("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"opId": op(), "zone": "bad zone!", "upstreams": []string{"x"}}); code != 422 {
		t.Fatalf("bad dns: %d %v", code, out)
	}

	// a viewer is refused by sfcd
	if code, out := keyLogin(f, "bob", bob.Private); code != 200 {
		t.Fatalf("bob login: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": op(), "kind": "tun", "name": "bob-net", "toggles": map[string]bool{"local": true}, "members": []map[string]any{{"node": "node-1", "cidr": "10.45.0.0/24"}}})
	if opState(t, code, out) != "failed" || out["op"].(map[string]any)["resultCode"] != float64(sfc.ResultForbidden) {
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
	if code, out := f.do("POST", "/api/v1/t/shop/volumes", map[string]any{"opId": op(), "kind": "fixed", "name": "archive", "node": "node-1", "storage": "ssd", "path": "/srv/sfc-ssd/archive"}); code != 422 || errCode(out) != "storage-root-unknown" {
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
