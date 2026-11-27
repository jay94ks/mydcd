// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"
	"time"
)

// Deleted webhooks and guidelines stay restorable for the retention
// period; a restore makes the same definition again without the secrets.
func TestTrashWebOwn(t *testing.T) {
	f, _, clock := incidentFixture(t)
	hs := newHookServer(t, f)
	fakeLogin(t, f, "admin")
	if code, h := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "ops", "kind": "external", "url": hs.URL, "role": "notify"}); code != 201 {
		t.Fatalf("create: %d %v", code, h)
	}
	code, del := f.do("DELETE", "/api/v1/webhooks/ops", map[string]any{"confirmName": "ops"})
	ref, _ := del["trash"].(map[string]any)
	if code != 200 || ref == nil || ref["id"] == "" {
		t.Fatalf("delete: %d %v", code, del)
	}
	id := ref["id"].(string)
	list := func() []any {
		t.Helper()
		code, out := f.do("GET", "/api/v1/trash", nil)
		if code != 200 || out["retentionDays"] != float64(7) {
			t.Fatalf("list: %d %v", code, out)
		}
		return out["items"].([]any)
	}
	items := list()
	if len(items) != 1 {
		t.Fatalf("items: %v", items)
	}
	if it := items[0].(map[string]any); it["kind"] != "webhook" || it["name"] != "ops" || it["deletedBy"] != "admin" || it["restore"] != "here" || it["lost"].([]any)[0] != "secret" {
		t.Fatalf("item: %v", it)
	}
	// a workspace manager does not see a cluster webhook
	fakeLogin(t, f, "alice")
	if items := list(); len(items) != 0 {
		t.Fatalf("alice sees: %v", items)
	}
	if code, _ := f.do("POST", "/api/v1/trash/"+id+"/restore", map[string]any{}); code != 404 {
		t.Fatalf("alice restores: %d", code)
	}
	fakeLogin(t, f, "admin")
	// the name is taken again: 409 with what is there, or another name
	if code, h := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "ops", "kind": "external", "url": hs.URL, "role": "notify"}); code != 201 {
		t.Fatalf("new ops: %d %v", code, h)
	}
	if code, out := f.do("POST", "/api/v1/trash/"+id+"/restore", map[string]any{}); code != 409 || errCode(out) != "exists" || out["current"] == nil {
		t.Fatalf("restore over a taken name: %d %v", code, out)
	}
	code, out := f.do("POST", "/api/v1/trash/"+id+"/restore", map[string]any{"name": "ops-old"})
	if code != 200 || out["restored"].(map[string]any)["name"] != "ops-old" || out["secret"].(map[string]any)["value"] == "" {
		t.Fatalf("restore: %d %v", code, out)
	}
	if code, h := f.do("GET", "/api/v1/webhooks/ops-old", nil); code != 200 || h["url"] != hs.URL {
		t.Fatalf("restored webhook: %d %v", code, h)
	}
	if _, err := f.srv.opt.Seal.Get(webhookSecretKey("ops-old")); err != nil {
		t.Fatal("no new secret sealed")
	}
	if len(list()) != 0 {
		t.Fatal("restored item still listed")
	}

	// guidelines come back with their versions
	guidePut(f, "cluster", 0, "# one", nil)
	guidePut(f, "cluster", 1, "# two", nil)
	code, del = f.do("DELETE", "/api/v1/guides/cluster", map[string]any{"confirmName": "cluster"})
	if code != 200 {
		t.Fatalf("delete guide: %d %v", code, del)
	}
	gid := del["trash"].(map[string]any)["id"].(string)
	if code, out := f.do("POST", "/api/v1/trash/"+gid+"/restore", map[string]any{}); code != 200 || out["restored"].(map[string]any)["version"] != float64(2) {
		t.Fatalf("restore guide: %d %v", code, out)
	}
	if code, vs := f.do("GET", "/api/v1/guides/cluster/versions", nil); code != 200 || len(vs["items"].([]any)) != 2 {
		t.Fatalf("versions: %d %v", code, vs)
	}

	// emptied by hand, or gone after the retention period
	_, del = f.do("DELETE", "/api/v1/webhooks/ops", map[string]any{"confirmName": "ops"})
	if code, _ := f.do("DELETE", "/api/v1/trash/"+del["trash"].(map[string]any)["id"].(string), nil); code != 204 || len(list()) != 0 {
		t.Fatalf("empty: %d", code)
	}
	_, del = f.do("DELETE", "/api/v1/webhooks/ops-old", map[string]any{"confirmName": "ops-old"})
	clock.Add(int64(8 * 24 * time.Hour / time.Second))
	if len(list()) != 0 {
		t.Fatal("expired item listed")
	}
	if code, _ := f.do("POST", "/api/v1/trash/"+del["trash"].(map[string]any)["id"].(string)+"/restore", map[string]any{}); code != 404 {
		t.Fatalf("expired restore: %d", code)
	}
}
