// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
)

// Without CD, the move's protected Group approvals follow begin-volume-move.
func TestVolumeMoveGroupApproval(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	fake.SetAppCD("shop", "php-shop", nil)
	fake.SetGroupPassword("shop", "shop-db", "open-sesame")
	base := "/api/v1/t/shop/volumes/mysql-data"
	_, p := f.do("POST", base+"/move-plan", map[string]any{"node": "node-a"})
	doc := strings.Replace(p["yaml"].(string), "      node: node-b\n", "      node: node-b\n      secrets: {from: [group/shop-db]}\n", 1)
	if doc == p["yaml"] {
		t.Fatalf("no db service node line: %s", doc)
	}
	opID := "f8b2c3d4-0000-4000-8000-000000000001"
	code, out := f.do("POST", base+"/move", map[string]any{"opId": opID, "yaml": doc})
	j := out["op"].(map[string]any)
	ap, _ := j["approvals"].([]any)
	if code != 202 || j["errorCode"] != "approval-required" || len(ap) != 1 || ap[0].(map[string]any)["group"] != "shop-db" {
		t.Fatalf("move: %d %v", code, out)
	}
	if err := fake.FinishVolumeMove("shop", "php-shop", "mysql-data"); err == nil {
		t.Fatal("finished without the approval")
	}
	_, out = f.do("GET", "/api/v1/t/shop/vault/approvals", nil)
	if items := out["items"].([]any); len(items) != 1 || items[0].(map[string]any)["opId"] != opID {
		t.Fatalf("waiting list: %v", out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/apps/deploy/"+opID+"/approve", map[string]any{"group": "shop-db", "password": "open-sesame"})
	if code != 200 || out["op"].(map[string]any)["state"] != "applied" {
		t.Fatalf("approve: %d %v", code, out)
	}
	assertNowhere(t, f, "open-sesame")
	if err := fake.FinishVolumeMove("shop", "php-shop", "mysql-data"); err != nil {
		t.Fatal(err)
	}
}
