// SPDX-License-Identifier: Apache-2.0

package server

import (
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
)

// Server lifecycle through the web on three real sfcd nodes: identity
// rotation, diagnostics, isolate/restore, drain, demote and remove, the
// plans and refusals sfcd gives, and that a workspace manager may not.
func TestRealServerNodeLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 3)
	op := realOpID()
	c.Change(0, "shop", "create-tenant", 0, map[string]any{"ID": "shop"})
	alice, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c.Change(0, "alice", "put-user", 0, access.User{ID: "u-alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: alice.Public, Enabled: true}}})
	c.Change(0, "alice-shop", "set-membership", 0, access.Membership{Tenant: "shop", User: "u-alice", Role: access.Manager, Enabled: true})
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	for _, p := range []string{"/api/v1/nodes/node-1/remove-plan", "/api/v1/nodes/node-1/drain-plan", "/api/v1/nodes/node-1/voter-plan"} {
		if code, out := f.do("GET", p, nil); code != 403 {
			t.Fatalf("alice %s: %d %v", p, code, out)
		}
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-1/remove", map[string]any{"opId": op()}); code != 403 {
		t.Fatalf("alice remove: %d %v", code, out)
	}

	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	node := func(id string) map[string]any {
		t.Helper()
		_, out := f.do("GET", "/api/v1/nodes", nil)
		for _, it := range out["items"].([]any) {
			if m := it.(map[string]any); m["id"] == id {
				return m
			}
		}
		return nil
	}

	// Diagnostics: a gzip download from node-1, relayed.
	resp, err := f.hc.Get(f.http.URL + "/api/v1/nodes/node-1/diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/gzip" || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), `attachment; filename="sfcd-diag-node-1-`) || len(resp.Header.Get("X-Sfc-Digest")) != 64 {
		t.Fatalf("diagnostics: %d %v", resp.StatusCode, resp.Header)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err == nil {
		_, err = io.ReadAll(zr)
	}
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Isolate and restore node-1.
	if code, out := f.do("POST", "/api/v1/nodes/node-1/restore", map[string]any{"opId": op()}); code != 409 || errCode(out) != "unchanged" {
		t.Fatalf("restore active: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-1/isolate", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("isolate: %d %v", code, out)
	}
	c.Wait("isolated", func() bool { return node("node-1")["phase"] == "isolated" })
	if m := node("node-1"); m["admitsWork"] != false {
		t.Fatalf("isolated row: %v", m)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-1/isolate", map[string]any{"opId": op()}); code != 409 {
		t.Fatalf("isolate twice: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-1/restore", map[string]any{"opId": op(), "operation": "restore-b"}); opState(t, code, out) != "applied" {
		t.Fatalf("restore: %d %v", code, out)
	}
	c.Wait("restored", func() bool { return node("node-1")["phase"] == "active" })

	// Demote node-2, then remove it.
	if code, vp := f.do("GET", "/api/v1/nodes/node-2/voter-plan", nil); code != 200 || vp["votersAfter"] != 2.0 || vp["faultToleranceAfter"] != 0.0 || vp["code"] != nil || vp["demotable"] != true {
		t.Fatalf("voter plan: %d %v", code, vp)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-2/demote", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("demote: %d %v", code, out)
	}
	c.Wait("demoted", func() bool { return node("node-2")["voter"] == false })
	// sfcd gives no voter plan for a server that is not a voter
	if code, out := f.do("GET", "/api/v1/nodes/node-2/voter-plan", nil); code != 403 {
		t.Fatalf("non-voter plan: %d %v", code, out)
	}
	// node-0 is the one answering: it cannot force itself out
	if code, fp := f.do("GET", "/api/v1/nodes/node-0/force-remove-plan", nil); code != 200 || fp["code"] != "SELF_REMOVAL" || fp["forceable"] != false {
		t.Fatalf("force plan node-0: %d %v", code, fp)
	}
	code, p := f.do("GET", "/api/v1/nodes/node-2/remove-plan", nil)
	if code != 200 || p["removable"] != true || p["votersBefore"] != 2.0 || p["votersAfter"] != 2.0 || p["epoch"] == nil || p["expected"] == nil {
		t.Fatalf("remove plan: %d %v", code, p)
	}
	if code, out := f.do("GET", "/api/v1/nodes/node-zz/remove-plan", nil); code != 403 {
		t.Fatalf("unknown node plan: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-2/remove", map[string]any{"opId": op(), "operation": "Bad_ID"}); code != 422 {
		t.Fatalf("bad operation: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-zz/remove", map[string]any{"opId": op()}); code != 404 {
		t.Fatalf("unknown node: %d %v", code, out)
	}
	rm := op()
	if code, out := f.do("POST", "/api/v1/nodes/node-2/remove", map[string]any{"opId": rm}); opState(t, code, out) != "applied" {
		t.Fatalf("remove: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-2/remove", map[string]any{"opId": rm}); code != 200 {
		t.Fatalf("same opId again: %d %v", code, out)
	}
	c.Wait("removed", func() bool { return node("node-2")["phase"] == "removed" })
	// Drain node-1 (nothing runs there).
	code, dp := f.do("GET", "/api/v1/nodes/node-1/drain-plan", nil)
	if code != 200 || len(dp["plan"].(string)) != 64 || !strings.HasPrefix(dp["operation"].(string), "drain-") {
		t.Fatalf("drain plan: %d %v", code, dp)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-1/drain", map[string]any{"opId": op(), "plan": strings.Repeat("ab", 32), "operation": dp["operation"]}); code != 409 || errCode(out) != "plan-changed" {
		t.Fatalf("stale drain: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-1/drain", map[string]any{"opId": op(), "plan": dp["plan"], "operation": dp["operation"]}); opState(t, code, out) != "applied" {
		t.Fatalf("drain: %d %v", code, out)
	}
	c.Wait("drained", func() bool {
		_, st := f.do("GET", "/api/v1/nodes/node-1/drain-status?operation="+dp["operation"].(string), nil)
		return st["state"] == "Succeeded" && st["operation"] == dp["operation"]
	})
	if d, _ := node("node-1")["drain"].(map[string]any); d == nil || d["operation"] != dp["operation"] || d["state"] != "Succeeded" || node("node-1")["cordoned"] != true {
		t.Fatalf("node row drain: %v", node("node-1"))
	}
	if code, st := f.do("GET", "/api/v1/nodes/node-1/drain-status", nil); code != 200 || st["operation"] != dp["operation"] {
		t.Fatalf("last drain status: %d %v", code, st)
	}
	// a server that has no drain: 404 missing, not a permission error
	if code, out := f.do("GET", "/api/v1/nodes/node-0/drain-status", nil); code != 404 {
		t.Fatalf("no drain: %d %v", code, out)
	}
	// uncordon it again so it admits work
	if code, out := f.do("POST", "/api/v1/nodes/node-1/uncordon", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("uncordon: %d %v", code, out)
	}
	c.Wait("uncordoned", func() bool { return node("node-1")["cordoned"] == false && node("node-1")["admitsWork"] == true })

	// Identity rotation of node-1.
	if code, out := f.do("POST", "/api/v1/nodes/node-1/rotate-identity", map[string]any{"opId": op(), "operation": "Bad"}); code != 422 {
		t.Fatalf("bad operation: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-1/rotate-identity", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("rotate: %d %v", code, out)
	}
	// sfcd accepts the rotation and shows it on the row; in this fixture it
	// stays Preparing (node-1 does not install a new key here), and the
	// server's other changes wait for it.
	c.Wait("rotation on the row", func() bool {
		m := node("node-1")
		id, _ := m["identity"].(map[string]any)
		return id != nil && strings.HasPrefix(id["operation"].(string), "rotate-") && id["phase"] != "" && m["identityRotatedAt"] != nil
	})
}
