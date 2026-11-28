// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

// The 디스크 tab's data: one server's devices grouped by class, the system
// disk locked, and each filesystem row naming its disk.
func TestFakeNodeDisksCarryDeviceInventory(t *testing.T) {
	f, _ := newFakeFixture(t)
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "admin", "method": "password"})
	if code, out := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "admin"}); code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	code, out := f.do("GET", "/api/v1/nodes/node-a/disks", nil)
	devices, _ := out["devices"].(map[string]any)
	if code != 200 || devices == nil || devices["node"] != "node-a" {
		t.Fatalf("node disks: %d %v", code, out)
	}
	classes := map[string]string{}
	for _, raw := range devices["disks"].([]any) {
		d := raw.(map[string]any)
		classes[d["name"].(string)] = d["class"].(string)
		if (d["class"] == "system") != (d["locked"] == true) {
			t.Fatalf("lock follows class: %v", d)
		}
	}
	if classes["sda"] != "system" || classes["sdb"] != "additional" || classes["sdz"] != "unused" || classes["sdx"] != "bundle-member" || classes["dm-9"] != "additional" {
		t.Fatalf("classes: %v", classes)
	}
	bundles, _ := devices["bundles"].([]any)
	if len(bundles) != 1 || bundles[0].(map[string]any)["state"] != "syncing" || len(bundles[0].(map[string]any)["members"].([]any)) != 2 {
		t.Fatalf("bundles: %v", devices["bundles"])
	}
	if code, out := f.do("GET", "/api/v1/disks", nil); code != 200 || out["devices"] != nil {
		t.Fatalf("cluster-wide disks carry no inventory: %d %v", code, out)
	}
}

// Format/mount/unmount go to the server's own journal: the system disk is
// refused, a reused opId replays its first result, and status reads it.
func TestFakeNodeDiskOperations(t *testing.T) {
	f, _ := newFakeFixture(t)
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "admin", "method": "password"})
	if code, out := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "admin"}); code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	code, out := f.do("POST", "/api/v1/nodes/node-a/disks/sda/format", map[string]any{"opId": "fmt-sys", "part": "sda", "serial": "FAKE-SDA", "size": 1})
	if code != 200 || out["state"] != "failed" || out["code"] != "system-disk" {
		t.Fatalf("system disk format: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/nodes/node-a/disks/sdz/format", map[string]any{"opId": "fmt-1", "part": "sdz", "serial": "FAKE-SDZ", "size": 1 << 40, "label": "data"})
	if code != 200 || out["state"] != "done" || out["part"] != "sdz1" || out["uuid"] == nil {
		t.Fatalf("format: %d %v", code, out)
	}
	uuid := out["uuid"]
	if code, again := f.do("POST", "/api/v1/nodes/node-a/disks/sdz/format", map[string]any{"opId": "fmt-1", "part": "sdz", "serial": "FAKE-SDZ", "size": 1 << 40, "label": "data"}); code != 200 || again["uuid"] != uuid {
		t.Fatalf("replay: %d %v", code, again)
	}
	code, out = f.do("POST", "/api/v1/nodes/node-a/disks/sdz/mount", map[string]any{"opId": "mnt-1", "part": "sdz1", "uuid": uuid})
	if code != 200 || out["mountPath"] != "/var/lib/sfc-disks/sdz1" {
		t.Fatalf("mount: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/disks/sdz/mount", map[string]any{"opId": "mnt-2", "part": "sdz1", "uuid": uuid, "mountPath": "/etc/x"}); code != 422 {
		t.Fatalf("system mount path: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/nodes/node-a/disk-operations/mnt-1", nil); code != 200 || out["action"] != "mount" {
		t.Fatalf("status: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/nodes/node-a/disks/sdy/prepare-storage", map[string]any{"opId": "prep-1", "part": "sdy", "serial": "FAKE-SDY", "size": 1 << 40, "format": true, "subPath": "pool/a"})
	if code != 200 || out["state"] != "done" || out["rootPath"] != "/var/lib/sfc-disks/sdy1/pool/a" {
		t.Fatalf("prepare-storage: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/disks/sdy/prepare-storage", map[string]any{"opId": "prep-2", "part": "sdy1", "uuid": "u", "subPath": "../x"}); code != 422 {
		t.Fatalf("bad sub path: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/nodes/node-a/disk-bundles", map[string]any{"opId": "b-1", "name": "pool", "backend": "lvm", "mode": "mirror", "members": []map[string]any{{"disk": "sdy", "serial": "S-Y", "size": 10}, {"disk": "sdz", "serial": "FAKE-SDZ", "size": 10}}})
	if code != 200 || out["state"] != "done" || out["bundle"] != "pool" || out["mountPath"] != "/var/lib/sfc-disks/pool" {
		t.Fatalf("bundle: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/nodes/node-a/disk-bundles", map[string]any{"opId": "b-2", "name": "slow", "backend": "fuse", "mode": "linear", "allocation": "grow", "members": []map[string]any{{"disk": "sdy", "part": "sdy1", "uuid": "u1", "bytes": 10}, {"disk": "sdz", "part": "sdz1", "uuid": "u2", "bytes": 10}}})
	if code != 200 || out["state"] != "done" || out["device"] != "/dev/loop7" {
		t.Fatalf("fuse bundle: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/disk-bundles", map[string]any{"opId": "b-3", "name": "x", "backend": "lvm", "mode": "linear", "members": []map[string]any{{"disk": "sdy", "serial": "S-Y", "size": 10}}}); code != 422 {
		t.Fatalf("one member: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/nodes/node-a/disk-bundles/backup/replace-member", map[string]any{"opId": "r-1", "old": map[string]any{"disk": "sdw", "serial": "FAKE-SDW"}, "new": map[string]any{"disk": "sdz", "serial": "FAKE-SDZ", "size": 1 << 40}})
	if code != 200 || out["state"] != "done" || out["disk"] != "sdz" {
		t.Fatalf("replace: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/disk-bundles/backup/unbundle", map[string]any{"opId": "u-1"}); code != 200 || out["state"] != "done" {
		t.Fatalf("unbundle: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/disk-bundles/backup/explode", map[string]any{"opId": "u-2"}); code != 404 {
		t.Fatalf("unknown action: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/nodes/node-a/disk-operations/none", nil); code != 404 {
		t.Fatalf("unknown status: %d %v", code, out)
	}
}
