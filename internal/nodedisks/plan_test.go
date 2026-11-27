// SPDX-License-Identifier: Apache-2.0

package nodedisks

import (
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
)

func inventory() observability.Devices {
	return observability.Devices{Disks: []observability.BlockDisk{
		{Name: "sda", Class: "system", Size: 100, Serial: "S-A", Table: "gpt", TableID: "t-a", Parts: []observability.BlockPart{
			{Name: "sda1", Number: 1, Filesystem: "ext4", UUID: "u-root", Mounts: []string{"/"}},
			{Name: "sda2", Number: 2, Filesystem: "ext4", UUID: "u-spare"},
		}},
		{Name: "sdb", Class: "additional", Size: 200, Serial: "S-B", Parts: []observability.BlockPart{{Name: "sdb", Filesystem: "ext4", UUID: "u-data", Mounts: []string{"/var/lib/sfc-disks/sdb"}}}},
		{Name: "sdc", Class: "unused", Size: 300, Serial: "S-C", Table: "dos", TableID: "t-c", Parts: []observability.BlockPart{{Name: "sdc1", Number: 1, Filesystem: "ext4", UUID: "u-c1"}}},
		{Name: "sdd", Class: "unused", Size: 400, WWN: "naa.d"},
	}}
}

func code(err error) string {
	var r Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	if err != nil {
		return "?"
	}
	return ""
}

func TestCheckRefusesSystemDiskAndStaleFences(t *testing.T) {
	inv := inventory()
	records := []Record{{Schema: 1, UUID: "u-data", Path: "/var/lib/sfc-disks/sdb", Disk: "sdb", Part: "sdb", Operation: "op-1", At: 1}}
	op := func(action, disk, part string) control.NodeDiskOp {
		return control.NodeDiskOp{Operation: "op-2", Node: "node-a", Action: action, Disk: disk, Part: part}
	}
	for name, c := range map[string]struct {
		op   control.NodeDiskOp
		want string
	}{
		"system format":      {op("format", "sda", "sda2"), "system-disk"},
		"system mount":       {control.NodeDiskOp{Operation: "o", Node: "n", Action: "mount", Disk: "sda", Part: "sda2", UUID: "u-spare"}, "system-disk"},
		"missing disk":       {op("format", "sdx", "sdx"), "not-found"},
		"serial changed":     {control.NodeDiskOp{Operation: "o", Node: "n", Action: "format", Disk: "sdd", Part: "sdd", Serial: "other", Size: 400}, "changed"},
		"size changed":       {control.NodeDiskOp{Operation: "o", Node: "n", Action: "format", Disk: "sdd", Part: "sdd", Size: 1}, "changed"},
		"table changed":      {control.NodeDiskOp{Operation: "o", Node: "n", Action: "format", Disk: "sdc", Part: "sdc", TableID: "other"}, "changed"},
		"uuid changed":       {control.NodeDiskOp{Operation: "o", Node: "n", Action: "mount", Disk: "sdc", Part: "sdc1", UUID: "other"}, "changed"},
		"format mounted":     {op("format", "sdb", "sdb"), "busy"},
		"blank whole format": {control.NodeDiskOp{Operation: "o", Node: "n", Action: "format", Disk: "sdd", Part: "sdd", WWN: "naa.d", Size: 400}, ""},
		"reformat table":     {control.NodeDiskOp{Operation: "o", Node: "n", Action: "format", Disk: "sdc", Part: "sdc", TableID: "t-c", Serial: "S-C", Size: 300}, ""},
		"mount unused":       {control.NodeDiskOp{Operation: "o", Node: "n", Action: "mount", Disk: "sdc", Part: "sdc1", UUID: "u-c1"}, ""},
		"mount blank":        {control.NodeDiskOp{Operation: "o", Node: "n", Action: "mount", Disk: "sdd", Part: "sdd", UUID: "x"}, "not-found"},
		"mount inside disk":  {control.NodeDiskOp{Operation: "o", Node: "n", Action: "mount", Disk: "sdc", Part: "sdc1", UUID: "u-c1", MountPath: "/var/lib/sfc-disks/sdb/x"}, "mount-path"},
		"mount over root":    {control.NodeDiskOp{Operation: "o", Node: "n", Action: "mount", Disk: "sdc", Part: "sdc1", UUID: "u-c1", MountPath: "/srv/data"}, "mount-path"},
		"mount docker":       {control.NodeDiskOp{Operation: "o", Node: "n", Action: "mount", Disk: "sdc", Part: "sdc1", UUID: "u-c1", MountPath: "/data/docker"}, "mount-path"},
		"mount recorded":     {control.NodeDiskOp{Operation: "o", Node: "n", Action: "mount", Disk: "sdc", Part: "sdc1", UUID: "u-c1", MountPath: "/var/lib/sfc-disks/sdb"}, "mount-path"},
		"unmount root on it": {control.NodeDiskOp{Operation: "o", Node: "n", Action: "unmount", Disk: "sdb", Part: "sdb"}, "storage-root"},
		"unmount unmanaged":  {control.NodeDiskOp{Operation: "o", Node: "n", Action: "unmount", Disk: "sdc", Part: "sdc1"}, "not-managed"},
	} {
		roots := []string{"/srv/data/sfc"}
		if name == "unmount root on it" {
			roots = []string{"/var/lib/sfc-disks/sdb/data"}
		}
		_, err := Check(c.op, inv, roots, records, "/data/docker")
		if code(err) != c.want {
			t.Errorf("%s: got %q (%v) want %q", name, code(err), err, c.want)
		}
	}
	plan, err := Check(control.NodeDiskOp{Operation: "o", Node: "n", Action: "unmount", Disk: "sdb", Part: "sdb"}, inv, nil, records, "")
	if err != nil || !plan.Mounted || plan.Path != "/var/lib/sfc-disks/sdb" {
		t.Fatal("unmount plan", plan, err)
	}
	plan, err = Check(control.NodeDiskOp{Operation: "o", Node: "n", Action: "mount", Disk: "sdc", Part: "sdc1", UUID: "u-c1"}, inv, nil, records, "")
	if err != nil || plan.Path != "/var/lib/sfc-disks/sdc1" {
		t.Fatal("default mount path", plan, err)
	}
}

func TestDiskMountPathRules(t *testing.T) {
	for path, ok := range map[string]bool{
		"/var/lib/sfc-disks/a": true, "/data": true, "/srv/big": true,
		"/": false, "/etc/x": false, "/var/lib/docker": false, "/var/lib/sfc": false, "/var/lib/sfc/x": false, "/usr": false, "/var": false, "/var/lib": false,
		"relative": false, "/data/../etc": false, "/data/": false, "/da ta": false,
	} {
		if control.ValidDiskMountPath(path) != ok {
			t.Errorf("%s: want %v", path, ok)
		}
	}
}
