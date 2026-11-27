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
	if classes["sda"] != "system" || classes["sdb"] != "additional" || classes["sdz"] != "unused" {
		t.Fatalf("classes: %v", classes)
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
	if code, out := f.do("GET", "/api/v1/nodes/node-a/disk-operations/none", nil); code != 404 {
		t.Fatalf("unknown status: %d %v", code, out)
	}
}
