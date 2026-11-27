// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/membership"
)

// A server joins through the web on real sfcd: the invite and its
// refusals, the invitation download and summary, then the joining node
// starts with it, becomes ready and is promoted to a voter.
func TestRealServerNodeJoin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 1)
	op := realOpID()
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	member := func() map[string]any {
		t.Helper()
		code, out := f.do("GET", "/api/v1/nodes", nil)
		if code != 200 {
			t.Fatalf("nodes: %d %v", code, out)
		}
		for _, it := range out["items"].([]any) {
			if m := it.(map[string]any); m["id"] == "node-1" {
				return m
			}
		}
		return nil
	}
	n, target := c.Prepare("node-1")
	invite := map[string]any{"id": "node-1", "endpoint": target.Endpoint, "publicKey": target.Key, "joinId": "join-node-1"}
	for field, bad := range map[string]any{"id": "Node D", "endpoint": "not an endpoint", "publicKey": "abc", "joinId": "genesis"} {
		b := map[string]any{"opId": op()}
		for k, v := range invite {
			b[k] = v
		}
		b[field] = bad
		if code, out := f.do("POST", "/api/v1/nodes", b); code != 422 {
			t.Fatalf("bad %s: %d %v", field, code, out)
		}
	}
	dup := map[string]any{"opId": op(), "id": "node-1", "endpoint": c.Nodes[0].Config.Node.Listen, "publicKey": target.Key, "joinId": "join-node-1"}
	if code, out := f.do("POST", "/api/v1/nodes", dup); code != 409 {
		t.Fatalf("taken endpoint: %d %v", code, out)
	}
	invite["opId"] = op()
	if code, out := f.do("POST", "/api/v1/nodes", invite); opState(t, code, out) != "applied" {
		t.Fatalf("invite: %d %v", code, out)
	}
	c.Wait("invited", func() bool { m := member(); return m != nil && m["join"] == "invited" && m["voter"] == false })

	var raw []byte
	c.Wait("invitation", func() bool {
		resp, err := f.hc.Get(f.http.URL + "/api/v1/nodes/node-1/invitation")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode == 200 && resp.Header.Get("Content-Disposition") == `attachment; filename="sfc-invitation-node-1.json"`
	})
	inv, err := membership.DecodeInvitation(raw)
	if err != nil || inv.Target.ID != "node-1" || inv.JoinID != "join-node-1" || inv.Target.Voter {
		t.Fatalf("decode: %v %+v", err, inv)
	}
	code, sum := f.do("GET", "/api/v1/nodes/node-1/invitation/summary", nil)
	if code != 200 || sum["cluster"] != hex.EncodeToString(inv.Cluster[:]) || sum["source"].(map[string]any)["key"] != inv.Source.Key || sum["joinId"] != "join-node-1" {
		t.Fatalf("summary: %d %v", code, sum)
	}
	if code, out := f.do("GET", "/api/v1/nodes/node-0/invitation", nil); code != 403 {
		t.Fatalf("full member: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-1/promote", map[string]any{"opId": op()}); code != 409 {
		t.Fatalf("promote invited: %d %v", code, out)
	}

	c.Join(n, inv)
	c.Wait("ready", func() bool { return member()["join"] == "ready" })
	if code, out := f.do("POST", "/api/v1/nodes/node-1/promote", map[string]any{"opId": op(), "expected": 1}); opState(t, code, out) != "failed" {
		t.Fatalf("stale: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-1/promote", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("promote: %d %v", code, out)
	}
	c.Wait("active voter", func() bool { m := member(); return m["join"] == "active" && m["voter"] == true })
}
