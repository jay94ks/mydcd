// SPDX-License-Identifier: Apache-2.0

package server

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestExternalRegistries(t *testing.T) {
	f, fake := newFakeFixture(t)
	op := opSeq("ab12c3d4")
	fakeLogin(t, f, "alice")
	list := func() map[string]map[string]any {
		t.Helper()
		code, out := f.do("GET", "/api/v1/t/shop/external-registries", nil)
		if code != 200 {
			t.Fatalf("list: %d %v", code, out)
		}
		rows := map[string]map[string]any{}
		for _, x := range out["items"].([]any) {
			rows[x.(map[string]any)["id"].(string)] = x.(map[string]any)
		}
		return rows
	}
	ex := list()["example"]
	if ex == nil || ex["credential"].(map[string]any)["passwordKey"] != "password" || ex["repository"] != "shop/**" || ex["auth"] != "password" ||
		ex["reader"].(map[string]any)["node"] != "node-a" || ex["revision"] != float64(2) {
		t.Fatalf("row: %v", ex)
	}
	if p := ex["pulls"].([]any); len(p) != 1 || p[0].(map[string]any)["code"] != "ok" || p[0].(map[string]any)["completedAt"].(float64) > 1e11 {
		t.Fatalf("pulls: %v", ex["pulls"])
	}
	if code, out := f.do("GET", "/api/v1/t/shop/external-registries/example/users", nil); code != 200 || len(out["items"].([]any)) == 0 ||
		out["items"].([]any)[0].(map[string]any)["image"] != "registry.example.com/shop/cron:1.4" {
		t.Fatalf("users: %d %v", code, out)
	}
	code, out := f.do("POST", "/api/v1/t/shop/external-registries/example/test", map[string]any{"image": "registry.example.com/shop/cron:1"})
	if code != 200 || out["code"] != "ok" || out["image"].(map[string]any)["digest"] == "" || out["pull"].(map[string]any)["blobs"] != float64(3) {
		t.Fatalf("test: %d %v", code, out)
	}
	fake.SetRegistryLoginResult("registry.example.com", "unauthorized")
	if _, out := f.do("POST", "/api/v1/t/shop/external-registries/example/test", map[string]any{}); out["code"] != "unauthorized" {
		t.Fatalf("forced test: %v", out)
	}

	put := func(id string, body map[string]any) (int, map[string]any) {
		body["opId"] = op()
		return f.do("PUT", "/api/v1/t/shop/external-registries/"+id, body)
	}
	if code, out := put("ghcr", map[string]any{"authority": "ghcr.io", "repository": "**", "auth": "password"}); code != 422 {
		t.Fatalf("password without credential: %d %v", code, out)
	}
	cred := map[string]any{"realm": "shop", "id": "mysql", "usernameKey": "MYSQL_PASSWORD", "passwordKey": "MYSQL_ROOT_PASSWORD"}
	ghcr := map[string]any{"authority": "ghcr.io", "repository": "shop-org/**", "auth": "token", "credential": cred}
	if code, out := put("ghcr", ghcr); opState(t, code, out) != "applied" {
		t.Fatalf("create: %d %v", code, out)
	}
	if code, out := put("ghcr", map[string]any{"authority": "ghcr.io", "repository": "other/**", "auth": "none"}); code != 409 || errCode(out) != "scope-fixed" {
		t.Fatalf("scope change: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/external-registries/ghcr/test", map[string]any{}); code != 409 || errCode(out) != "not-bound" {
		t.Fatalf("test before bind: %d %v", code, out)
	}

	// bind: the credential is in the protected Group shop-db.
	fake.SetGroupPassword("shop", "shop-db", "open-sesame")
	bindID := op()
	code, out = f.do("POST", "/api/v1/t/shop/external-registries/ghcr/bind", map[string]any{"opId": bindID, "node": "node-a"})
	o := out["op"].(map[string]any)
	if ap, _ := o["approvals"].([]any); code != 202 || o["errorCode"] != "approval-required" || len(ap) != 1 || ap[0].(map[string]any)["group"] != "shop-db" {
		t.Fatalf("bind: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/ops/"+bindID+"/resume", nil); code != 409 || errCode(out) != "approval-required" {
		t.Fatalf("resume: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/t/shop/vault/approvals", nil); len(out["items"].([]any)) != 1 || out["items"].([]any)[0].(map[string]any)["kind"] != "registry-bind" {
		t.Fatalf("approvals list: %v", out)
	}
	base := "/api/v1/t/shop/external-registries/ghcr/bind/" + bindID + "/approve"
	if code, out := f.do("POST", "/api/v1/t/shop/external-registries/example/bind/"+bindID+"/approve", map[string]any{"group": "shop-db", "password": "open-sesame"}); code != 404 {
		t.Fatalf("other source: %d %v", code, out)
	}
	if code, out := f.do("POST", base, map[string]any{"group": "shop-db", "password": "wrong"}); code != 403 || errCode(out) != "approval-denied" {
		t.Fatalf("wrong password: %d %v", code, out)
	}
	if code, out := f.do("POST", base, map[string]any{"group": "shop-db", "password": "open-sesame"}); code != 200 || out["op"].(map[string]any)["state"] != "applied" {
		t.Fatalf("approve: %d %v", code, out)
	}
	assertNowhere(t, f, "open-sesame")
	assertNowhere(t, f, "wrong")
	if r := list()["ghcr"]["reader"]; r == nil || r.(map[string]any)["node"] != "node-a" {
		t.Fatalf("bound: %v", list()["ghcr"])
	}
	if code, out := f.do("POST", "/api/v1/t/shop/external-registries/ghcr/test", map[string]any{}); code != 200 || out["code"] != "ok" {
		t.Fatalf("test after bind: %d %v", code, out)
	}
	// unbind drains the reader; a second unbind is refused
	if code, out := f.do("POST", "/api/v1/t/shop/external-registries/ghcr/unbind", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("unbind: %d %v", code, out)
	}
	if r := list()["ghcr"]["reader"]; r == nil || r.(map[string]any)["draining"] != true {
		t.Fatalf("draining: %v", list()["ghcr"])
	}
	if code, out := f.do("POST", "/api/v1/t/shop/external-registries/ghcr/unbind", map[string]any{"opId": op()}); code != 409 || errCode(out) != "not-bound" {
		t.Fatalf("unbind again: %d %v", code, out)
	}
	fake.CloseExternalRegistryReaders()
	// a source without secrets binds at once
	if code, out := put("pub", map[string]any{"authority": "quay.io", "repository": "**", "auth": "none"}); opState(t, code, out) != "applied" {
		t.Fatalf("create pub: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/external-registries/pub/bind", map[string]any{"opId": op(), "node": "node-a"}); opState(t, code, out) != "applied" {
		t.Fatalf("bind pub: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/external-registries/pub/bind", map[string]any{"opId": op(), "node": "node-a"}); code != 409 || errCode(out) != "not-bindable" {
		t.Fatalf("bind pub again: %d %v", code, out)
	}

	if code, out := f.do("DELETE", "/api/v1/t/shop/external-registries/nope", map[string]any{"opId": op()}); code != 404 {
		t.Fatalf("delete missing: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/t/shop/external-registries/ghcr", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("delete: %d %v", code, out)
	}
	if g := list()["ghcr"]; g != nil && g["deleted"] != true {
		t.Fatalf("after delete: %v", g)
	}
	bobLogin(t, f)
	if code, out := put("x", map[string]any{"authority": "x.io", "repository": "**", "auth": "none"}); opState(t, code, out) == "applied" {
		t.Fatalf("viewer put: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/t/shop/external-registries/example/test", map[string]any{}); code != 403 {
		t.Fatalf("viewer test: %d", code)
	}
}

func TestBuilds(t *testing.T) {
	f, _ := newFakeFixture(t)
	n := 0
	op := func() string { n++; return fmt.Sprintf("ab12c3d4-0000-4000-8000-%012d", n) }
	fakeLogin(t, f, "alice")
	ok := func(what string, code int, out map[string]any) {
		t.Helper()
		if opState(t, code, out) != "applied" {
			t.Fatalf("%s: %d %v", what, code, out)
		}
	}
	items := func(path string) []any {
		t.Helper()
		code, out := f.do("GET", path, nil)
		if code != 200 {
			t.Fatalf("%s: %d %v", path, code, out)
		}
		return out["items"].([]any)
	}
	row := func(path, id string) map[string]any {
		t.Helper()
		for _, it := range items(path) {
			if m := it.(map[string]any); m["id"] == id {
				return m
			}
		}
		t.Fatalf("%s: no %s", path, id)
		return nil
	}

	// Policy: real names, roots by id, the builder kept when not sent.
	code, pol := f.do("GET", "/api/v1/t/shop/build-policy", nil)
	if code != 200 || pol["exists"] != true || !strings.Contains(pol["builderImage"].(string), "@sha256:") || pol["limits"].(map[string]any)["logPageBytes"] != float64(24<<10) {
		t.Fatalf("policy: %d %v", code, pol)
	}
	nodes := []any{}
	for _, x := range pol["nodes"].([]any) {
		m := x.(map[string]any)
		nodes = append(nodes, map[string]any{"node": m["node"], "root": m["root"].(map[string]any)["id"]})
	}
	p := map[string]any{"nodes": nodes, "concurrency": 3, "seconds": 900, "cpuMillis": 2000, "memoryBytes": 1 << 30, "workspaceBytes": 1 << 30,
		"cacheBytes": 1 << 30, "registry": pol["registry"], "platforms": []string{"linux/amd64"}, "cleanup": map[string]any{"highWaterPercent": 80, "unusedDays": 14}}
	code, out := f.do("PUT", "/api/v1/t/shop/build-policy", map[string]any{"opId": op(), "policy": p})
	ok("policy", code, out)
	if _, pol = f.do("GET", "/api/v1/t/shop/build-policy", nil); pol["concurrency"] != float64(3) || pol["cleanup"].(map[string]any)["unusedDays"] != float64(14) {
		t.Fatalf("policy after: %v", pol)
	}
	// a builder by tag is pinned through image-resolve; an untrusted one is refused
	p["builderImage"] = "mysql:8.4"
	code, out = f.do("PUT", "/api/v1/t/shop/build-policy", map[string]any{"opId": op(), "policy": p})
	ok("policy builder by tag", code, out)
	if _, pol := f.do("GET", "/api/v1/t/shop/build-policy", nil); !strings.HasPrefix(pol["builderImage"].(string), "docker.io/library/mysql@sha256:") {
		t.Fatalf("pinned builder: %v", pol["builderImage"])
	}
	p["builderImage"] = "nginx"
	if code, out := f.do("PUT", "/api/v1/t/shop/build-policy", map[string]any{"opId": op(), "policy": p}); code != 422 || errCode(out) != "builder-digest" {
		t.Fatalf("untrusted builder: %d %v", code, out)
	}
	delete(p, "builderImage")
	// a tenant manager picks a new root from tenant-storage.
	p["nodes"] = append(append([]any{}, nodes...), map[string]any{"node": "node-b", "root": "ssd"})
	code, out = f.do("PUT", "/api/v1/t/shop/build-policy", map[string]any{"opId": op(), "policy": p})
	ok("policy with node-b ssd", code, out)
	if _, pol := f.do("GET", "/api/v1/t/shop/build-policy", nil); len(pol["nodes"].([]any)) != 2 {
		t.Fatalf("policy nodes: %v", pol)
	}
	p["nodes"] = []any{map[string]any{"node": "node-b", "root": "nope"}}
	if code, out := f.do("PUT", "/api/v1/t/shop/build-policy", map[string]any{"opId": op(), "policy": p}); code != 422 || out["error"].(map[string]any)["code"] != "root-unknown" {
		t.Fatalf("unknown root: %d %v", code, out)
	}

	ctxs := items("/api/v1/t/shop/build-contexts")
	if len(ctxs) != 3 {
		t.Fatalf("contexts: %v", ctxs)
	}
	worker := row("/api/v1/t/shop/build-contexts", "worker")
	if worker["kind"] != "upload" || worker["version"] != float64(2) || len(worker["versions"].([]any)) != 2 || worker["node"] == "" {
		t.Fatalf("worker: %v", worker)
	}
	if row("/api/v1/t/shop/build-contexts", "cron")["kind"] != "draft" {
		t.Fatalf("cron kind")
	}

	// A new upload context on a policy server; not one outside it.
	node := nodes[0].(map[string]any)["node"].(string)
	cb := map[string]any{"kind": "upload", "node": node, "dockerfile": "Dockerfile", "repository": "shop/tools", "tags": []string{"latest"}, "platforms": []string{"linux/amd64"}}
	code, out = f.do("PUT", "/api/v1/t/shop/build-contexts/tools", map[string]any{"opId": op(), "context": cb})
	ok("create context", code, out)
	cb["node"] = "node-zz"
	if code, out := f.do("PUT", "/api/v1/t/shop/build-contexts/tools2", map[string]any{"opId": op(), "context": cb}); code != 422 {
		t.Fatalf("node outside policy: %d %v", code, out)
	}

	// Version tree and file of worker v2.
	code, tree := f.do("GET", "/api/v1/t/shop/build-contexts/worker/tree?version=2", nil)
	if code != 200 || len(tree["entries"].([]any)) == 0 || len(tree["id"].(string)) != 64 {
		t.Fatalf("tree: %d %v", code, tree)
	}
	var file string
	for _, e := range tree["entries"].([]any) {
		if m := e.(map[string]any); m["directory"] != true {
			file = m["path"].(string)
			break
		}
	}
	res, err := f.hc.Get(f.http.URL + "/api/v1/t/shop/build-contexts/worker/file?version=2&path=" + file)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || len(body) == 0 || res.Header.Get("Content-Security-Policy") != "sandbox" {
		t.Fatalf("file %s: %d %q", file, res.StatusCode, body)
	}
	if code, _ := f.do("GET", "/api/v1/t/shop/build-contexts/worker/tree?version=9", nil); code != 404 {
		t.Fatalf("missing version: %d", code)
	}

	// Build worker's newest version, read the job and its log.
	code, out = f.do("POST", "/api/v1/t/shop/build-contexts/worker/build", map[string]any{"opId": op()})
	ok("build", code, out)
	build := "build-" + fmt.Sprintf("ab12c3d4-0000-4000-8000-%012d", n)
	job := row("/api/v1/t/shop/builds?context=worker", build)
	if job["version"] != float64(2) || job["context"] != "worker" {
		t.Fatalf("job: %v", job)
	}
	code, out = f.do("GET", "/api/v1/t/shop/builds/"+build+"/log", nil)
	if code != 200 || out["text"] == nil || out["phase"] == "" {
		t.Fatalf("log: %d %v", code, out)
	}
	code, tail := f.do("GET", "/api/v1/t/shop/builds/"+build+"/log?tail=1", nil)
	if code != 200 || tail["total"] != out["total"] || tail["offset"].(float64) != max(0, out["total"].(float64)-24<<10) {
		t.Fatalf("log tail: %d %v", code, tail)
	}
	if code, _ := f.do("GET", "/api/v1/t/shop/builds/"+build+"/log?tail=1&after=x", nil); code != 422 {
		t.Fatalf("tail with after: %d", code)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/tools/build", map[string]any{"opId": op()}); code != 409 || out["error"].(map[string]any)["code"] != "no-version" {
		t.Fatalf("no version: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/builds/"+build+"/cancel", map[string]any{"opId": op()}); opState(t, code, out) == "applied" {
		t.Fatalf("cancel finished: %d %v", code, out)
	}

	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/web/verify", nil); code != 200 || out["code"] == nil {
		t.Fatalf("verify: %d %v", code, out)
	}

	// Cache: scopes per server, cleaning accepted then visible.
	code, cache := f.do("GET", "/api/v1/t/shop/build-cache", nil)
	if code != 200 {
		t.Fatalf("cache: %d %v", code, cache)
	}
	scopes := cache["caches"].([]any)
	if len(scopes) == 0 {
		t.Fatalf("no cache scopes: %v", cache)
	}
	sc := scopes[0].(map[string]any)
	if code, out := f.do("GET", "/api/v1/t/shop/build-cache/entries?node="+sc["node"].(string)+"&cache="+sc["cache"].(string), nil); code != 200 || out["entries"] == nil {
		t.Fatalf("entries: %d %v", code, out)
	} else if es := out["entries"].([]any); len(es) > 0 {
		if _, ok := es[0].(map[string]any)["lastUsedAt"].(string); !ok {
			t.Fatalf("entry times: %v", es[0])
		}
	}
	if u, ok := sc["usage"].(map[string]any); ok {
		if _, ok := u["observedAt"].(string); u["observedAt"] != nil && !ok {
			t.Fatalf("usage times: %v", u)
		}
	}
	if code, out := f.do("POST", "/api/v1/t/shop/build-cache/prune", map[string]any{"opId": op(), "node": sc["node"], "cache": sc["cache"], "filter": map[string]any{"mode": "unused"}}); code != 422 {
		t.Fatalf("unused without days: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/build-cache/prune", map[string]any{"opId": op(), "node": sc["node"], "cache": sc["cache"], "filter": map[string]any{"mode": "all"}})
	ok("prune", code, out)
	if _, cache = f.do("GET", "/api/v1/t/shop/build-cache", nil); len(cache["cleaning"].([]any)) == 0 {
		t.Fatalf("cleaning: %v", cache)
	}

	// Deleting the job, then versions before the context.
	code, out = f.do("POST", "/api/v1/t/shop/builds/"+build+"/delete", map[string]any{"opId": op()})
	ok("delete job", code, out)
	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/worker/delete", map[string]any{"opId": op()}); code != 409 || out["error"].(map[string]any)["code"] != "versions-left" {
		t.Fatalf("versions left: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/build-contexts/worker/versions/1/delete", map[string]any{"opId": op()})
	ok("delete version", code, out)
	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/worker/versions/x/delete", map[string]any{"opId": op()}); code != 422 {
		t.Fatalf("bad version: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/build-contexts/tools/delete", map[string]any{"opId": op()})
	ok("delete context", code, out)
	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/tools/delete", map[string]any{"opId": op()}); code != 404 {
		t.Fatalf("gone: %d %v", code, out)
	}
}

// Draft contexts on build-draft (edits are synchronous, not ops; commit
// freezes and publishes) and the one-change zip.
func TestBuildDraft(t *testing.T) {
	f, _ := newFakeFixture(t)
	n := 100
	op := func() string { n++; return fmt.Sprintf("ab12c3d4-0000-4000-8000-%012d", n) }
	fakeLogin(t, f, "alice")
	edit := func(what, method, path string, body map[string]any) map[string]any {
		t.Helper()
		body["opId"] = op()
		code, out := f.do(method, path, body)
		if code != 200 || out["code"] != "OK" {
			t.Fatalf("%s: %d %v", what, code, out)
		}
		return out
	}
	const base = "/api/v1/t/shop/build-contexts/cron"
	code, tree := f.do("GET", base+"/tree", nil)
	if code != 200 || tree["initialized"] != true || len(tree["entries"].([]any)) == 0 {
		t.Fatalf("draft tree: %d %v", code, tree)
	}
	rev := tree["revision"].(float64)
	out := edit("put", "PUT", base+"/files", map[string]any{"path": "run.sh", "text": "#!/bin/sh\necho hi\n", "executable": true})
	if out["revision"] != rev+1 {
		t.Fatalf("put revision: %v", out)
	}
	if code, out := f.do("PUT", base+"/files", map[string]any{"opId": op(), "path": "x", "text": "a", "expected": rev}); code != 409 {
		t.Fatalf("stale expected: %d %v", code, out)
	}
	if code, out := f.do("PUT", base+"/files", map[string]any{"opId": op(), "path": "../x", "text": "a"}); code != 422 {
		t.Fatalf("path outside: %d %v", code, out)
	}
	big := strings.Repeat("y", 60000)
	edit("put big", "PUT", base+"/files", map[string]any{"path": "data.txt", "text": big})
	edit("move", "POST", base+"/files/move", map[string]any{"path": "run.sh", "to": "bin/run.sh"})
	edit("put tmp", "PUT", base+"/files", map[string]any{"path": "tmp", "text": "x"})
	edit("delete", "DELETE", base+"/files", map[string]any{"path": "tmp"})

	res, err := f.hc.Get(f.http.URL + base + "/file?path=data.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != big {
		t.Fatalf("draft file: %d %d bytes %.200s", res.StatusCode, len(body), body)
	}

	before := 0
	_, list := f.do("GET", "/api/v1/t/shop/build-contexts", nil)
	for _, it := range list["items"].([]any) {
		if c := it.(map[string]any); c["id"] == "cron" {
			before = len(c["versions"].([]any))
		}
	}
	code, out = f.do("POST", base+"/commit", map[string]any{"opId": op()})
	if opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "publish-build-draft" {
		t.Fatalf("commit: %d %v", code, out)
	}
	_, list = f.do("GET", "/api/v1/t/shop/build-contexts", nil)
	for _, it := range list["items"].([]any) {
		if c := it.(map[string]any); c["id"] == "cron" && len(c["versions"].([]any)) != before+1 {
			t.Fatalf("published: %v", c)
		}
	}
	res, _ = f.hc.Get(f.http.URL + base + "/file?version=" + fmt.Sprint(before+1) + "&path=bin/run.sh")
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "#!/bin/sh\necho hi\n" || res.Header.Get("X-SFC-Executable") != "1" {
		t.Fatalf("version file: %d %q %v", res.StatusCode, body, res.Header)
	}
	assertNowhere(t, f, big[:200])

	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	fw, _ := zw.Create("Dockerfile")
	fw.Write([]byte("FROM docker.io/library/busybox:1.36\n"))
	zw.Close()
	req, _ := http.NewRequest("PUT", f.http.URL+"/api/v1/t/shop/build-contexts/worker/zip?opId="+op(), bytes.NewReader(zb.Bytes()))
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("X-SFC-Web", "1")
	res, err = f.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), `"applied"`) {
		t.Fatalf("zip: %d %s", res.StatusCode, body)
	}
	// the same opId again: the same op, no second version
	req, _ = http.NewRequest("PUT", req.URL.String(), bytes.NewReader(zb.Bytes()))
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("X-SFC-Web", "1")
	if res, err = f.hc.Do(req); err != nil {
		t.Fatal(err)
	}
	again, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(again), `"applied"`) {
		t.Fatalf("zip again: %d %s", res.StatusCode, again)
	}
	_, out = f.do("GET", "/api/v1/t/shop/build-contexts", nil)
	for _, it := range out["items"].([]any) {
		if c := it.(map[string]any); c["id"] == "worker" && c["version"] != float64(3) {
			t.Fatalf("worker after zip: %v", c)
		}
	}
}
