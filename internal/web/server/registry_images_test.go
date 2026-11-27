// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/web/store"
)

func TestRegistryImages(t *testing.T) {
	f, fake := newFakeFixture(t)
	op := opSeq("ab12c3d4")
	get := func(path string) map[string]any {
		t.Helper()
		code, out := f.do("GET", path, nil)
		if code != 200 {
			t.Fatalf("%s: %d %v", path, code, out)
		}
		return out
	}
	// every reference row of a repository (all pages)
	refs := func(repo string) map[string]map[string]any {
		t.Helper()
		rows, after := map[string]map[string]any{}, ""
		for {
			out := get("/api/v1/t/shop/registries/builtin/images?refresh=1&repository=" + repo + "&after=" + after)
			for _, it := range out["items"].([]any) {
				rows[it.(map[string]any)["reference"].(string)] = it.(map[string]any)
			}
			if after = out["next"].(string); after == "" {
				return rows
			}
		}
	}
	fakeLogin(t, f, "alice")
	out := get("/api/v1/t/shop/registries/builtin/images")
	if fmt.Sprint(out["repositories"]) != "[shop/php-shop shop/worker]" || out["authority"] != "registry.sfc.local" || out["untaggedComplete"] != true || out["code"] != nil {
		t.Fatalf("repositories: %v", out)
	}
	shop := refs("shop/php-shop")
	if len(shop) != 10 || shop["stable"]["digest"] != shop["1.4.2"]["digest"] || shop["1.4.2"]["uploadedAt"] == nil || shop["1.4.2"]["imageBytes"].(float64) == 0 {
		t.Fatalf("php-shop rows: %v", shop)
	}
	if out := get("/api/v1/t/shop/registries/example/images?external=1"); fmt.Sprint(out["repositories"]) != "[shop/cron]" || out["live"] != true {
		t.Fatalf("external: %v", out)
	}
	if code, out := f.do("GET", "/api/v1/t/shop/registries/builtin/images?repository=UPPER/x", nil); code != 422 {
		t.Fatalf("bad repository: %d %v", code, out)
	}

	// The page comes from the web's memory for 10 minutes; refresh=1 and
	// an expired row read sfcd again; another user never gets it.
	k := imageCacheKey{"u-alice", "shop", "managed", "builtin", "", ""}
	e, ok := f.srv.images.get(k, f.srv.now())
	if !ok {
		t.Fatal("not cached")
	}
	old := time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Second)
	f.srv.images.put(k, imageCacheEntry{e.page, old})
	if out := get("/api/v1/t/shop/registries/builtin/images"); out["cachedAt"] != rfc3339(old) {
		t.Fatalf("cached read: %v", out["cachedAt"])
	}
	if out := get("/api/v1/t/shop/registries/builtin/images?refresh=1"); out["cachedAt"] == rfc3339(old) {
		t.Fatalf("refresh: %v", out["cachedAt"])
	}
	f.srv.images.put(k, imageCacheEntry{e.page, old})
	bobLogin(t, f)
	if out := get("/api/v1/t/shop/registries/builtin/images"); out["cachedAt"] == rfc3339(old) {
		t.Fatalf("bob got alice's cached page: %v", out["cachedAt"])
	}
	if code, _ := f.do("GET", "/api/v1/t/payments/registries/builtin/images", nil); code != 403 {
		t.Fatalf("bob payments: %d", code)
	}
	d140 := shop["1.4.0"]["digest"].(string)
	if code, out := f.do("POST", "/api/v1/t/shop/registries/builtin/images/delete", map[string]any{"opId": op(), "repository": "shop/php-shop", "reference": d140, "digest": d140}); code != 403 {
		t.Fatalf("viewer delete: %d %v", code, out)
	}

	fakeLogin(t, f, "alice")
	// An archived app (web bbolt) names 1.4.1: usage lists it and prune
	// protects its digest.
	src := []byte("name: old-shop\nservices:\n  web:\n    image: registry.sfc.local/shop/php-shop:1.4.1\n  env:\n    image: ${IMAGE}\n")
	if _, err := f.store.PutArchived(&store.ArchivedApp{Tenant: "shop", App: "old-shop", Source: src, DownBy: "alice", DownAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	code, out := f.do("POST", "/api/v1/t/shop/image-usage", map[string]any{"refs": []string{"registry.sfc.local/shop/php-shop:1.4.1", "registry.sfc.local/shop/php-shop:stable", "docker.io/nowhere/x:1"}})
	if code != 200 {
		t.Fatalf("usage: %d %v", code, out)
	}
	items := out["items"].([]any)
	u0, u1, u2 := items[0].(map[string]any), items[1].(map[string]any), items[2].(map[string]any)
	// a tag query: running pinned images of the repository may be it (repository-unknown), none is exactly it
	for _, r := range u0["rows"].([]any) {
		if m := r.(map[string]any)["match"]; m == "exact" || m == "digest" {
			t.Fatalf("1.4.1 in use: %v", u0)
		}
	}
	if len(u0["archived"].([]any)) != 1 || u0["archived"].([]any)[0].(map[string]any)["app"] != "old-shop" {
		t.Fatalf("archived use: %v", u0)
	}
	if len(u1["rows"].([]any)) == 0 || u1["rows"].([]any)[0].(map[string]any)["match"] == nil || len(u1["archived"].([]any)) != 0 {
		t.Fatalf("task use: %v", u1)
	}
	if len(u2["rows"].([]any)) != 0 || len(u2["archived"].([]any)) != 0 {
		t.Fatalf("unknown ref: %v", u2)
	}
	if code, _ := f.do("POST", "/api/v1/t/shop/image-usage", map[string]any{"refs": []string{}}); code != 422 {
		t.Fatalf("no refs: %d", code)
	}

	// delete: plan, accepted job, status; drops the cached pages.
	del := func(body map[string]any) (int, map[string]any) {
		body["opId"] = op()
		return f.do("POST", "/api/v1/t/shop/registries/builtin/images/delete", body)
	}
	if code, out := del(map[string]any{"repository": "shop/php-shop", "reference": "1.4.0", "digest": "sha256:XYZ"}); code != 422 {
		t.Fatalf("bad digest: %d %v", code, out)
	}
	live := shop["1.4.2"]["digest"].(string)
	if code, out := del(map[string]any{"repository": "shop/php-shop", "reference": live, "digest": live}); code != 409 || errCode(out) != "image-in-use" {
		t.Fatalf("in use: %d %v", code, out)
	}
	// Hold keeps the job pending however slow the run (it would be
	// running after 1 s); Finish below releases and settles it.
	fake.HoldRegistryMaintenance(true)
	delID := op()
	code, out = f.do("POST", "/api/v1/t/shop/registries/builtin/images/delete", map[string]any{"opId": delID, "repository": "shop/php-shop", "reference": d140, "digest": d140})
	if opState(t, code, out) != "applied" {
		t.Fatalf("delete: %d %v", code, out)
	}
	status := "/api/v1/t/shop/registry-maintenance/web-" + delID
	if st := get(status); (st["state"] != "queued" && st["state"] != "running") || st["action"] != "delete-registry-image" || st["digest"] != d140 || st["result"] != nil {
		t.Fatalf("pending: %v", st)
	}
	fake.FinishRegistryMaintenance()
	if st := get(status); st["state"] != "done" || st["result"].(map[string]any)["code"] != "ok" || st["result"].(map[string]any)["native"] == nil {
		t.Fatalf("done: %v", st)
	}
	if _, ok := refs("shop/php-shop")["1.4.0"]; ok {
		t.Fatal("1.4.0 still listed")
	}
	if code, _ := f.do("GET", "/api/v1/t/shop/registry-maintenance/web-nope", nil); code < 400 {
		t.Fatalf("unknown operation: %d", code)
	}

	// GC; a second one while it is pending is busy.
	fake.HoldRegistryMaintenance(true)
	gcID := op()
	if code, out := f.do("POST", "/api/v1/t/shop/registries/builtin/gc", map[string]any{"opId": gcID}); opState(t, code, out) != "applied" {
		t.Fatalf("gc: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/registries/builtin/gc", map[string]any{"opId": op()}); code != 409 || errCode(out) != "busy" {
		t.Fatalf("gc again: %d %v", code, out)
	}
	if m := get("/api/v1/t/shop/registries")["items"].([]any)[0].(map[string]any)["maintenance"]; m == nil || m.(map[string]any)["pendingOperation"] != "web-"+gcID {
		t.Fatalf("summary: %v", m)
	}
	fake.HoldRegistryMaintenance(false)
	fake.FinishRegistryMaintenance()
	if st := get("/api/v1/t/shop/registry-maintenance/web-" + gcID); st["state"] != "done" || st["result"].(map[string]any)["reclaimedBytes"].(float64) == 0 {
		t.Fatalf("gc done: %v", st)
	}

	// prune: preview (the archived digest protected), pages, run, results.
	cond := map[string]any{"repositories": []string{"shop/php-shop"}, "keepRecentPerRepository": 1, "includeUntagged": true}
	code, pv := f.do("POST", "/api/v1/t/shop/registries/builtin/prune/preview", map[string]any{"part": "items", "conditions": cond})
	if code != 200 || pv["preview"] == "" || pv["expiresAt"] == nil {
		t.Fatalf("preview: %d %v", code, pv)
	}
	d141 := shop["1.4.1"]["digest"].(string)
	conds := pv["conditions"].(map[string]any)
	if p := conds["protectedDigests"].([]any); len(p) != 1 || p[0] != d141 {
		t.Fatalf("protected: %v", conds)
	}
	code, ret := f.do("POST", "/api/v1/t/shop/registries/builtin/prune/preview", map[string]any{"part": "retained", "conditions": conds, "preview": pv["preview"]})
	if code != 200 || len(ret["retainedRows"].([]any)) == 0 {
		t.Fatalf("retained: %d %v", code, ret)
	}
	codes := map[string]string{}
	for _, r := range ret["retainedRows"].([]any) {
		codes[r.(map[string]any)["image"].(map[string]any)["digest"].(string)] = r.(map[string]any)["code"].(string)
	}
	if codes[d141] != "protected" || codes[live] != "image-in-use" {
		t.Fatalf("retained codes: %v", codes)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/registries/builtin/prune/preview", map[string]any{"conditions": map[string]any{"excludeTags": []string{"a/b"}}}); code != 422 {
		t.Fatalf("bad conditions: %d %v", code, out)
	}
	pruneID := op()
	if code, out := f.do("POST", "/api/v1/t/shop/registries/builtin/prune", map[string]any{"opId": pruneID, "conditions": conds, "preview": pv["preview"]}); opState(t, code, out) != "applied" {
		t.Fatalf("prune: %d %v", code, out)
	}
	fake.FinishRegistryMaintenance()
	st := get("/api/v1/t/shop/registry-maintenance/web-" + pruneID)
	if st["action"] != "prune-registry-images" || st["result"] == nil || st["result"].(map[string]any)["prune"] == nil {
		t.Fatalf("prune status: %v", st)
	}
	res := get("/api/v1/t/shop/registry-maintenance/web-" + pruneID + "/items")
	if len(res["rows"].([]any)) == 0 || res["rows"].([]any)[0].(map[string]any)["code"] == nil {
		t.Fatalf("prune results: %v", res)
	}
	if _, ok := refs("shop/php-shop")["1.4.1"]; !ok {
		t.Fatal("protected image removed")
	}
	if code, out := f.do("POST", "/api/v1/t/shop/registries/builtin/prune", map[string]any{"opId": op(), "conditions": conds, "preview": "%%"}); code != 422 {
		t.Fatalf("bad token: %d %v", code, out)
	}
}

func TestImageCache(t *testing.T) {
	var c imageCache
	now := time.Now()
	for i := range imageCacheRows + 5 {
		c.put(imageCacheKey{"u", "t", "managed", "r", "", fmt.Sprint(i)}, imageCacheEntry{at: now.Add(time.Duration(i) * time.Second)})
	}
	if len(c.rows) != imageCacheRows {
		t.Fatalf("rows: %d", len(c.rows))
	}
	if _, ok := c.get(imageCacheKey{"u", "t", "managed", "r", "", "0"}, now); ok {
		t.Fatal("oldest kept")
	}
	if _, ok := c.get(imageCacheKey{"u", "t", "managed", "r", "", "10"}, now.Add(imageCacheTTL)); !ok {
		t.Fatal("fresh row missing")
	}
	c.put(imageCacheKey{"u", "u", "managed", "r", "", ""}, imageCacheEntry{at: now})
	c.drop("t", "r")
	if len(c.rows) != 1 {
		t.Fatalf("drop: %d", len(c.rows))
	}
}
