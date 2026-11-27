// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/tests/clusterfixture"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
)

// The web moves an app's data store from node-1 to node-0 through sfcd:
// the nodes copy the volume's files between their fake engines' real
// mountpoints and the app runs on node-0 (devel/refactor/16 step 5).
func TestRealServerVolumeMove(t *testing.T) {
	// About 100s without the race detector, mostly waiting for the nodes'
	// 30s reports; under -race it can take twice that. Run until shortly
	// before the test binary's own deadline.
	deadline := time.Now().Add(8 * time.Minute)
	if d, ok := t.Deadline(); ok {
		deadline = d.Add(-30 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	f, c := newIsolatedFixture(t, ctx, 2)
	op := realOpID()
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	realShopOn(t, c, "node-0", "node-1")
	doc := realDBApp(t, f, c, op)
	const capacity = realDBCapacity
	// The app's data on node-1, as its container would write it.
	sentinel := filepath.Join(onlyMountpoint(t, c.Nodes[1].Engine.Mountpoints(nil)), "orders.db")
	err := os.WriteFile(sentinel, []byte("order 1\n"), 0o600)
	if err == nil {
		err = os.Chown(sentinel, 10001, 10001)
	}
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/t/shop/volumes/data"
	refuse := func(method, path string, body map[string]any, status int, want string) {
		t.Helper()
		if code, out := f.do(method, base+path, body); code != status || errCode(out) != want {
			t.Fatalf("%s %s: want %d %s, got %d %v", method, path, status, want, code, out)
		}
	}
	detail := func() map[string]any {
		t.Helper()
		code, out := f.do("GET", base, nil)
		if code != 200 {
			t.Fatalf("detail: %d %v", code, out)
		}
		return out["volume"].(map[string]any)
	}
	refuse("POST", "/move-plan", map[string]any{}, 422, "invalid")
	if code, out := f.do("POST", base+"/move-plan", map[string]any{"yaml": doc}); code == 200 {
		t.Fatalf("same node planned: %v", out)
	}
	moved := strings.ReplaceAll(doc, "node-1", "node-0")
	code, plan := f.do("POST", base+"/move-plan", map[string]any{"yaml": moved, "maxBytes": capacity})
	if code != 200 || plan["from"] != "node-1" || plan["to"] != "node-0" || len(plan["digest"].(string)) != 64 {
		t.Fatalf("move plan: %d %v", code, plan)
	}
	refuse("POST", "/move", map[string]any{"opId": op(), "yaml": moved, "digest": strings.Repeat("0", 64), "maxBytes": capacity}, 409, "digest-mismatch")
	// A move cancelled at once leaves the volume where it was.
	code, out := f.do("POST", base+"/move", map[string]any{"opId": op(), "yaml": moved, "digest": plan["digest"], "maxBytes": capacity})
	if state := opState(t, code, out); state != "applied" {
		t.Fatalf("first move: %s %d %v", state, code, out)
	}
	if code, out := f.do("POST", base+"/move/cancel", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("cancel: %d %v", code, out)
	}
	c.Wait("move cancelled", func() bool {
		v := detail()
		return v["node"] == "node-1" && v["phase"] == "Ready" && v["moveID"] == nil
	})
	o := op()
	code, out = f.do("POST", base+"/move", map[string]any{"opId": o, "yaml": moved, "digest": plan["digest"], "maxBytes": capacity})
	if state := opState(t, code, out); state != "applied" || out["op"].(map[string]any)["action"] != "volume-move" || out["op"].(map[string]any)["move"].(map[string]any)["id"] != "mv-"+o {
		t.Fatalf("move: %s %d %v", state, code, out)
	}
	if _, prefs := f.do("GET", "/api/v1/notify-prefs", nil); !slices.Contains(prefs["kinds"].([]any), any("volume-move-started")) {
		t.Fatalf("notify kinds: %v", prefs)
	}
	if _, out := f.do("GET", "/api/v1/ops/"+o+".2", nil); out["op"].(map[string]any)["action"] != "begin-volume-move" {
		t.Fatalf("begin-volume-move step: %v", out)
	}
	// While it moves, the volume says so and another plan waits.
	if v := detail(); v["moveID"] != "mv-"+o || v["targetNode"] != "node-0" {
		t.Fatalf("moving: %v", v)
	}
	refuse("POST", "/move-plan", map[string]any{"yaml": moved}, 409, "moving")
	refuse("POST", "/move/cancel", map[string]any{"opId": op(), "id": "mv-other"}, 409, "not-moving")
	// node-1 stops the app and sends the files over SFCP; node-0 receives
	// them into its own volume, and the app starts there.
	var v map[string]any
	c.Wait("volume moved", func() bool {
		_, out = f.do("GET", "/api/v1/t/shop/volumes", nil)
		v = out["items"].([]any)[0].(map[string]any)
		return v["node"] == "node-0" && v["phase"] == "Ready"
	})
	if retained := fmt.Sprint(v["retained"]); !strings.Contains(retained, "node:node-1") {
		t.Fatalf("source copy on node-1 not retained: %v", v)
	}
	got, err := os.ReadFile(filepath.Join(onlyMountpoint(t, c.Nodes[0].Engine.Mountpoints(nil)), "orders.db"))
	if err != nil || string(got) != "order 1\n" {
		t.Fatalf("moved data: %q %v", got, err)
	}
	c.Wait("app on node-0", func() bool {
		_, out = f.do("GET", "/api/v1/t/shop/apps/db/tasks", nil)
		tasks, _ := out["items"].([]any)
		return len(tasks) == 1 && tasks[0].(map[string]any)["node"] == "node-0" && tasks[0].(map[string]any)["observed"] == "running"
	})
	if running := c.Nodes[1].Engine.Running(); len(running) != 0 {
		t.Fatalf("still running on node-1: %v", running)
	}
	// The retained source copy on node-1 is deleted once.
	if code, out := f.do("DELETE", base+"/retained/mv-"+o, map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("delete retained: %d %v", code, out)
	}
	refuse("DELETE", "/retained/mv-"+o, map[string]any{"opId": op()}, 409, "not-retained")
	if r, _ := detail()["retained"].([]any); len(r) != 0 && r[0].(map[string]any)["state"] == "retained" {
		t.Fatalf("still retained: %v", r)
	}
}

// onlyMountpoint is the data directory of a node's only volume.
func onlyMountpoint(t *testing.T, mounts map[string]string) string {
	t.Helper()
	if len(mounts) != 1 {
		t.Fatalf("volumes: %v", mounts)
	}
	for _, dir := range mounts {
		return dir
	}
	return ""
}

// The web's volume screens and operations on sfcd: the list row and
// detail, a backup the node really writes, a restore into a new volume,
// capacity, backup limits and deleting an unused volume.
func TestRealServerVolumes(t *testing.T) {
	deadline := time.Now().Add(8 * time.Minute)
	if d, ok := t.Deadline(); ok {
		deadline = d.Add(-30 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	realShop(t, c)
	realDBApp(t, f, c, op)
	base := "/api/v1/t/shop/volumes/data"
	applied := func(what string, code int, out map[string]any) {
		t.Helper()
		if state := opState(t, code, out); state != "applied" {
			t.Fatalf("%s: %s %d %v", what, state, code, out)
		}
	}
	rows := func(out map[string]any, key string) []map[string]any {
		var r []map[string]any
		items, _ := out[key].([]any)
		for _, x := range items {
			r = append(r, x.(map[string]any))
		}
		return r
	}

	_, out := f.do("GET", "/api/v1/t/shop/volumes", nil)
	if items := rows(out, "items"); len(items) != 1 || items[0]["name"] != "data" || items[0]["node"] != "node-1" || items[0]["capacityBytes"] != float64(realDBCapacity) || items[0]["consumers"] != float64(1) || items[0]["writer"] != "db/db" {
		t.Fatalf("volume list: %v", out)
	}
	// The running service writes the volume and is on the network.
	if _, out = f.do("GET", base, nil); out["volume"].(map[string]any)["writer"] != "db/db" {
		t.Fatalf("detail writer: %v", out["volume"])
	}
	if _, out = f.do("GET", base+"/users", nil); out["volume"] != "data" || out["apps"] != float64(1) {
		t.Fatalf("volume users: %v", out)
	}
	if _, out = f.do("GET", "/api/v1/t/shop/networks/lan/users", nil); out["network"] != "lan" || out["apps"] != float64(1) {
		t.Fatalf("network users: %v", out)
	}
	if code, out := f.do("GET", "/api/v1/t/shop/volumes/nope", nil); code != 404 || errCode(out) != "not-found" {
		t.Fatalf("missing: %d %v", code, out)
	}
	// Capacity only grows (the web says so before asking sfcd); a volume
	// its app still uses is not deleted.
	if code, out := f.do("PUT", base+"/capacity", map[string]any{"opId": op(), "bytes": realDBCapacity / 2}); code != 422 || errCode(out) != "capacity-grow-only" {
		t.Fatalf("shrink: %d %v", code, out)
	}
	if code, out := f.do("DELETE", base, map[string]any{"opId": op()}); opState(t, code, out) != "failed" {
		t.Fatalf("delete in use: %d %v", code, out)
	}

	// A workspace manager sees that server-wide limits exist but not their
	// values, and sfcd refuses them capacity and limit changes.
	alice, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c.Change(0, "alice", "put-user", 0, access.User{ID: "u-alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: alice.Public, Enabled: true}}})
	c.Change(0, "alice-shop", "set-membership", 0, access.Membership{Tenant: "shop", User: "u-alice", Role: access.Manager, Enabled: true})
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	forbidden := func(what string, code int, out map[string]any) {
		t.Helper()
		if opState(t, code, out) != "failed" || out["op"].(map[string]any)["resultCode"] != float64(sfc.ResultForbidden) {
			t.Fatalf("%s as manager: %d %v", what, code, out)
		}
	}
	code, out := f.do("PUT", base+"/capacity", map[string]any{"opId": op(), "bytes": 2 * realDBCapacity})
	forbidden("capacity", code, out)
	code, out = f.do("PUT", "/api/v1/t/shop/backup-limits/node-1", map[string]any{"opId": op(), "count": 1, "bytes": realDBCapacity, "stagingCount": 1, "stagingBytes": realDBCapacity})
	forbidden("backup limit", code, out)
	_, out = f.do("GET", "/api/v1/t/shop/backup-limits", nil)
	for _, l := range rows(out, "items") {
		if hidden := l["scope"] == "server"; l["hidden"] != hidden || hidden && l["bytes"] != float64(0) {
			t.Fatalf("limit row for a manager: %v", l)
		}
	}
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}

	// A backup copies the volume's files as they are, so sfcd takes one
	// only after the writer stopped cleanly: the app goes down first and the
	// volume stays.
	_, out = f.do("GET", "/api/v1/t/shop/apps", nil)
	app := rows(out, "items")[0]
	code, out = f.do("POST", "/api/v1/t/shop/apps/db/down", map[string]any{"opId": op(), "action": "down-app", "principal": "u-admin", "expected": app["revision"], "payload": control.AppDown{Tenant: "shop", App: "db", Operation: app["operation"].(map[string]any)["id"].(string)}, "volumes": []string{"data"}})
	applied("down", code, out)
	c.Wait("app down", func() bool {
		_, out = f.do("GET", "/api/v1/t/shop/apps", nil)
		items := rows(out, "items")
		return len(items) == 1 && items[0]["operation"].(map[string]any)["status"] == "Retired" && len(c.Nodes[1].Engine.Running()) == 0
	})

	o := op()
	code, out = f.do("POST", base+"/backups", map[string]any{"opId": o})
	applied("backup", code, out)
	var bq control.VolumeBackupBegin
	userPayload(t, f, "u-admin", o, &bq)
	if bq.ID != "b-"+o || bq.Scope.App != "db" || bq.Scope.ID != "data" || bq.MaxBytes != realDBCapacity {
		t.Fatalf("backup payload: %+v", bq)
	}
	c.Wait("backup ready", func() bool {
		_, out = f.do("GET", base, nil)
		b := rows(out, "backups")
		return len(b) == 1 && b[0]["phase"] == "Ready"
	})
	backup := rows(out, "backups")[0]
	if backup["node"] != "node-1" || backup["bytes"].(float64) == 0 {
		t.Fatalf("backup: %v", backup)
	}
	bid := backup["id"].(string)

	// A restore goes into a new volume, at least as large as the backup needs.
	if code, out := f.do("POST", base+"/restore", map[string]any{"opId": op(), "backup": bid, "target": map[string]any{"existing": true}}); code != 422 || errCode(out) != "restore-new-only" {
		t.Fatalf("restore over existing: %d %v", code, out)
	}
	if code, out := f.do("POST", base+"/restore", map[string]any{"opId": op(), "backup": bid, "target": map[string]any{"name": "data-small"}, "capacityBytes": 1024}); code != 422 {
		t.Fatalf("capacity under need: %d %v", code, out)
	}
	o = op()
	code, out = f.do("POST", base+"/restore", map[string]any{"opId": o, "backup": bid, "target": map[string]any{"name": "data-copy"}, "capacityBytes": realDBCapacity})
	applied("restore", code, out)
	var rq control.VolumeRestoreBegin
	userPayload(t, f, "u-admin", o, &rq)
	if rq.ID != "r-"+o[:8] || rq.Target.Scope.ID != "data-copy" || rq.Target.Scope.App != "db" || rq.Target.Node != "node-1" || rq.Backup.ID != bid {
		t.Fatalf("restore payload: %+v", rq)
	}
	c.Wait("restored", func() bool {
		_, out = f.do("GET", base, nil)
		r := rows(out, "restores")
		return len(r) == 1 && r[0]["phase"] == "Restored" && r[0]["target"] == "data-copy"
	})
	_, out = f.do("GET", "/api/v1/t/shop/volumes", nil)
	if items := rows(out, "items"); len(items) != 2 || items[1]["name"] != "data-copy" || items[1]["phase"] != "Ready" {
		t.Fatalf("volume list after restore: %v", out)
	}

	code, out = f.do("PUT", base+"/capacity", map[string]any{"opId": op(), "bytes": 2 * realDBCapacity})
	applied("capacity", code, out)
	if _, out = f.do("GET", base, nil); out["volume"].(map[string]any)["capacityBytes"] != float64(2*realDBCapacity) {
		t.Fatalf("capacity: %v", out["volume"])
	}

	// Each server has a server-wide row and the workspace's row; the backup
	// counts against both on node-1.
	_, out = f.do("GET", "/api/v1/t/shop/backup-limits", nil)
	limits := rows(out, "items")
	if len(limits) != 4 {
		t.Fatalf("backup limits: %v", out)
	}
	for _, l := range limits {
		used := l["used"].(map[string]any)
		if want := float64(map[string]int{"node-0": 0, "node-1": 1}[l["node"].(string)]); used["count"] != want || l["hidden"] != false {
			t.Fatalf("backup limit row: %v", l)
		}
	}
	o = op()
	code, out = f.do("PUT", "/api/v1/t/shop/backup-limits/node-1", map[string]any{"opId": o, "count": 2, "bytes": 2 * realDBCapacity, "stagingCount": 1, "stagingBytes": realDBCapacity})
	applied("backup limit", code, out)
	// The row's move budget (Original) goes back as it was.
	var l sfc.VolumeBackupLimit
	userPayload(t, f, "u-admin", o, &l)
	if l.Tenant != "shop" || l.Node != "node-1" || l.Count != 2 || l.Original == nil || l.Original.Count != 3 {
		t.Fatalf("limit payload: %+v", l)
	}
	_, out = f.do("GET", "/api/v1/t/shop/backup-limits?node=node-1", nil)
	if l := rows(out, "items"); len(l) != 2 || l[0]["scope"] != "workspace" || l[0]["count"] != float64(2) || l[0]["revision"] != float64(2) {
		t.Fatalf("backup limit after change: %v", out)
	}

	if _, out = f.do("GET", base+"/users", nil); out["total"] != float64(0) {
		t.Fatalf("volume users: %v", out)
	}

	code, out = f.do("DELETE", base+"/backups/"+bid, map[string]any{"opId": op()})
	applied("delete backup", code, out)
	code, out = f.do("DELETE", "/api/v1/t/shop/volumes/data-copy", map[string]any{"opId": op()})
	applied("delete volume", code, out)
	// sfcd keeps the deleted backup's row (phase Deleted) while the restore
	// that came from it is listed.
	c.Wait("backup deleted and copy gone", func() bool {
		_, out = f.do("GET", base, nil)
		if b := rows(out, "backups"); len(b) != 1 || b[0]["phase"] != "Deleted" {
			return false
		}
		_, out = f.do("GET", "/api/v1/t/shop/volumes", nil)
		items := rows(out, "items")
		return len(items) == 1 && items[0]["name"] == "data"
	})
	if code, out := f.do("GET", "/api/v1/t/shop/volumes/data-copy", nil); code != 404 || errCode(out) != "not-found" {
		t.Fatalf("deleted volume detail: %d %v", code, out)
	}
}

// realDBCapacity is the db app's volume capacity and the move and backup
// budgets realDBApp sets.
const realDBCapacity = 1 << 20

// realDBApp deploys app "db" (service db, volume "data" mounted at /data)
// to node-1 on "lan" through the web and waits until it succeeds; then, as
// an administrator does before a move or backup, it sets the volume's
// capacity and the servers' backup and staging budgets. It returns the app
// document.
func realDBApp(t *testing.T, f *fixture, c *clusterfixture.Cluster, op func() string) string {
	t.Helper()
	image := "docker.io/library/nginx@sha256:" + strings.Repeat("b", 64)
	var cfg dockerspec.DockerOCIImage
	cfg.Config.User, cfg.Config.Cmd = "10001:10001", []string{"/db"}
	for _, n := range c.Nodes {
		n.Engine.Publish(cfg, image)
	}
	doc := "name: db\nservices:\n db:\n  image: " + image + "\n  cpus: 0.1\n  mem_limit: 16m\n  volumes: [data:/data]\n  networks: {app: {}}\n  x-sfc: {node: node-1}\nvolumes:\n data:\n  x-sfc: {node: node-1, uid: 10001, gid: 10001, mode: \"0750\"}\nnetworks:\n app: {external: true, name: lan}\n"
	code, out := f.do("POST", "/api/v1/t/shop/apps/deploy", map[string]any{"opId": op(), "yaml": doc, "deployment": "prod"})
	if state := opState(t, code, out); state != "applied" {
		t.Fatalf("deploy: %s %d %v", state, code, out)
	}
	c.Wait("deploy succeeded", func() bool {
		_, out = f.do("GET", "/api/v1/t/shop/apps", nil)
		app := out["items"].([]any)[0].(map[string]any)
		return app["operation"].(map[string]any)["status"] == "Succeeded"
	})
	// An administrator sets the volume's capacity and the servers' move
	// staging budgets before a move.
	volumes, err := c.Policy.Volumes(c.State())
	if err != nil {
		t.Fatal(err)
	}
	ready, ok := volumes.Native("shop", "db", "data")
	if !ok {
		t.Fatal("volume not ready")
	}
	volume, _ := volumes.Volume(ready.Spec.Scope)
	const capacity = realDBCapacity
	c.Change(0, "data-capacity", "set-volume-capacity", volume.Revision(), control.VolumeCapacity{Scope: ready.Spec.Scope, Native: control.VolumeNativeDigest(ready), Bytes: capacity})
	for _, node := range []string{"node-0", "node-1"} {
		for _, tenant := range []string{"", "shop"} {
			c.Change(0, "budget-"+node+"-"+tenant, "set-volume-backup-limit", 0, control.VolumeBackupLimit{Tenant: tenant, Node: node, Bytes: capacity, Count: 1, StagingBytes: capacity, StagingCount: 1, Original: &control.OriginalVolumeLimit{Bytes: 4 * capacity, Count: 3}})
		}
	}
	return doc
}

// Files in a workspace's fixed data store through the web on sfcd: put,
// no silent overwrite, overwrite, list, get and delete, and a folder grant
// that lets a viewer work under one prefix only.
func TestRealServerVolumeFiles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	realShop(t, c)
	root := filepath.Join(t.TempDir(), "storage")
	if err := os.MkdirAll(filepath.Join(root, "uploads"), 0o700); err != nil {
		t.Fatal(err)
	}
	c.Change(0, "storage", "add-node-storage", 0, nodestorage.Definition{Node: "node-0", Key: c.Nodes[0].Key, ID: "data", Path: root, Tenants: []string{"shop"}})
	// node-0 attests the root before a volume is registered on it.
	c.Wait("storage attested", func() bool {
		roots, err := c.Policy.NodeStorage(c.State())
		r, ok := roots.Root("node-0", "data")
		return err == nil && ok && r.Attestation != nil
	})
	code, out := f.do("POST", "/api/v1/t/shop/volumes", map[string]any{"opId": op(), "kind": "fixed", "name": "uploads", "node": "node-0", "storage": "data", "path": filepath.Join(root, "uploads")})
	if state := opState(t, code, out); state != "applied" {
		t.Fatalf("register: %s %d %v", state, code, out)
	}
	base := "/api/v1/t/shop/volumes/uploads"
	// node-0 checks the directory and the volume becomes Ready.
	c.Wait("fixed volume ready", func() bool {
		_, out = f.do("GET", base, nil)
		v, _ := out["volume"].(map[string]any)
		return v != nil && v["phase"] == "Ready"
	})
	if v := out["volume"].(map[string]any); v["kind"] != "fixed" || v["storage"] != "data" || v["node"] != "node-0" {
		t.Fatalf("fixed volume: %v", v)
	}
	raw := func(method, path string, body []byte) (int, string, http.Header) {
		t.Helper()
		req, _ := http.NewRequest(method, f.http.URL+path, bytes.NewReader(body))
		req.Header.Set("X-SFC-Web", "1")
		res, err := f.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b), res.Header
	}
	const pre = "sfc-web-backups/"
	const first, second = "first-volume-file-content-7f3c9a1e", "overwritten-volume-file-content-b81d24c6"
	if code, body, _ := raw("PUT", base+"/file?path="+pre+"a.db&opId="+op(), []byte(first)); code != 200 || !strings.Contains(body, `"applied"`) {
		t.Fatalf("put: %d %s", code, body)
	}
	if code, body, _ := raw("PUT", base+"/file?path="+pre+"a.db&opId="+op(), []byte(first)); strings.Contains(body, `"applied"`) {
		t.Fatalf("no overwrite: %d %s", code, body)
	}
	if code, body, _ := raw("PUT", base+"/file?path="+pre+"a.db&overwrite=1&opId="+op(), []byte(second)); code != 200 || !strings.Contains(body, `"applied"`) {
		t.Fatalf("overwrite: %d %s", code, body)
	}
	if code, body, _ := raw("PUT", base+"/file?path="+pre+"b.db&opId="+op(), []byte(first)); code != 200 || !strings.Contains(body, `"applied"`) {
		t.Fatalf("put b: %d %s", code, body)
	}
	// The node wrote the files under the registered directory.
	if got, err := os.ReadFile(filepath.Join(root, "uploads", pre, "a.db")); err != nil || string(got) != second {
		t.Fatalf("on disk: %q %v", got, err)
	}
	if code, out := f.do("DELETE", base+"/file", map[string]any{"opId": op(), "path": pre + "b.db"}); opState(t, code, out) != "applied" {
		t.Fatalf("delete b: %d %v", code, out)
	}
	// The op records hold the path, size and digest, not the content.
	assertNowhere(t, f, first)
	assertNowhere(t, f, second)
	code, out = f.do("GET", base+"/files?prefix="+pre, nil)
	if items, _ := out["items"].([]any); code != 200 || len(items) != 1 || items[0].(map[string]any)["bytes"] != float64(len(second)) {
		t.Fatalf("list: %d %v", code, out)
	}
	code, body, h := raw("GET", base+"/file?path="+pre+"a.db", nil)
	if code != 200 || body != second || h.Get("Content-Disposition") != "attachment" || !strings.HasPrefix(h.Get("X-SFC-Digest"), "sha256:") {
		t.Fatalf("get: %d %q %v", code, body, h)
	}

	// A viewer gets one folder: the four file operations under it, nothing
	// elsewhere, until the grant is revoked.
	bob, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c.Change(0, "bob", "put-user", 0, access.User{ID: "u-bob", Username: "bob", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: bob.Public, Enabled: true}}})
	c.Change(0, "bob-shop", "set-membership", 0, access.Membership{Tenant: "shop", User: "u-bob", Role: access.Viewer, Enabled: true})
	if code, out := f.do("POST", base+"/file-grants", map[string]any{"opId": op(), "prefix": "sfc-web-backups", "user": "u-bob"}); code != 422 {
		t.Fatalf("prefix without /: %d %v", code, out)
	}
	if code, out := f.do("POST", base+"/file-grants", map[string]any{"opId": op(), "prefix": pre, "user": "u-bob"}); opState(t, code, out) != "applied" {
		t.Fatalf("grant: %d %v", code, out)
	}
	if code, out := keyLogin(f, "bob", bob.Private); code != 200 {
		t.Fatalf("bob login: %d %v", code, out)
	}
	if code, out := f.do("GET", base+"/files?prefix="+pre, nil); code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("bob list: %d %v", code, out)
	}
	if code, out := f.do("GET", base+"/files?prefix=other/", nil); code != 403 {
		t.Fatalf("bob outside prefix: %d %v", code, out)
	}
	if code, out := f.do("DELETE", base+"/file", map[string]any{"opId": op(), "path": pre + "a.db"}); opState(t, code, out) != "applied" {
		t.Fatalf("bob delete: %d %v", code, out)
	}
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	if code, out := f.do("DELETE", base+"/file-grants", map[string]any{"opId": op(), "prefix": pre, "user": "u-bob"}); opState(t, code, out) != "applied" {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if code, out := keyLogin(f, "bob", bob.Private); code != 200 {
		t.Fatalf("bob login: %d %v", code, out)
	}
	if code, out := f.do("GET", base+"/files?prefix="+pre, nil); code != 403 {
		t.Fatalf("bob after revoke: %d %v", code, out)
	}
}
