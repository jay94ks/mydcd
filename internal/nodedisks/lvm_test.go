// SPDX-License-Identifier: Apache-2.0

package nodedisks

import (
	"context"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
)

type fakeLVM struct {
	calls []string
	lvs   string
	pvs   string
}

func (f *fakeLVM) lvm() LVM {
	return LVM{Run: func(_ context.Context, args ...string) ([]byte, error) {
		f.calls = append(f.calls, strings.Join(args, " "))
		switch args[0] {
		case "lvs":
			return []byte(f.lvs), nil
		case "pvs":
			return []byte(f.pvs), nil
		}
		return nil, nil
	}}
}

func TestLVMCommandsAndState(t *testing.T) {
	f := &fakeLVM{}
	l := f.lvm()
	if err := l.Create(context.Background(), "my-pool", "mirror", []string{"/dev/sdb", "/dev/sdc"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"pvcreate -ff -y /dev/sdb", "pvcreate -ff -y /dev/sdc", "vgcreate -y --addtag sfc-managed sfc-my-pool /dev/sdb /dev/sdc", "lvcreate -y -W y -Z y -n data -l 100%FREE --type raid1 -m 1 sfc-my-pool"}
	if strings.Join(f.calls, "|") != strings.Join(want, "|") {
		t.Fatal(f.calls)
	}
	if LVMDevice("my-pool") != "mapper/sfc--my--pool-data" {
		t.Fatal(LVMDevice("my-pool"))
	}
	f.calls = nil
	if err := l.Replace(context.Background(), "my-pool", "", "/dev/sdd"); err != nil || !strings.Contains(strings.Join(f.calls, "|"), "lvconvert -y --repair sfc-my-pool/data /dev/sdd|vgreduce --removemissing --force sfc-my-pool") {
		t.Fatal(f.calls, err)
	}
	f.calls, f.lvs = nil, `{"report":[{"lv":[{"vg_name":"sfc-my-pool","lv_name":"data"}]}]}`
	if err := l.Remove(context.Background(), "my-pool", []string{"/dev/sdb"}, true); err != nil || strings.Join(f.calls, "|") != "vgreduce --removemissing --force sfc-my-pool|lvs --reportformat json --units b --nosuffix -a -o vg_name,lv_name|lvremove -y -f sfc-my-pool/data|vgremove -y sfc-my-pool|pvremove -y -ff /dev/sdb" {
		t.Fatal("remove with a member gone", f.calls, err)
	}
	f.calls, f.lvs = nil, `{"report":[{"lv":[]}]}`
	if err := l.Remove(context.Background(), "my-pool", nil, true); err != nil || strings.Contains(strings.Join(f.calls, "|"), "lvremove") {
		t.Fatal("the LV went with the missing member", f.calls, err)
	}
	records := []BundleRecord{{Schema: 1, Name: "my-pool", Backend: "lvm", Mode: "mirror", Operation: "o", At: 1, Members: []BundleMemberRecord{{Disk: "sdb", Serial: "S-B", PVUUID: "pv-b"}, {Disk: "sdc", Serial: "S-C", PVUUID: "pv-c", Syncing: true}}}, {Schema: 1, Name: "lin", Backend: "lvm", Mode: "linear", Operation: "o", At: 1, Members: []BundleMemberRecord{{Disk: "sde", PVUUID: "pv-e"}, {Disk: "sdf", PVUUID: "pv-f"}}}}
	f.lvs = `{"report":[{"lv":[{"vg_name":"sfc-my-pool","lv_name":"data","lv_size":"1000","sync_percent":"42.50","vg_tags":"sfc-managed"},{"vg_name":"sfc-lin","lv_name":"data","lv_size":"2000","sync_percent":"","vg_tags":"sfc-managed"}]}]}`
	f.pvs = `{"report":[{"pv":[{"pv_name":"/dev/sdx","vg_name":"sfc-my-pool","pv_uuid":"pv-b","pv_missing":""},{"pv_name":"/dev/sdc","vg_name":"sfc-my-pool","pv_uuid":"pv-c","pv_missing":""},{"pv_name":"/dev/sde","vg_name":"sfc-lin","pv_uuid":"pv-e","pv_missing":""},{"pv_name":"[unknown]","vg_name":"sfc-lin","pv_uuid":"pv-f","pv_missing":"missing"}]}]}`
	inv := observability.Devices{Disks: []observability.BlockDisk{{Name: "dm-2", Kind: "bundle", Bundle: "my-pool", Class: "additional", Size: 999}}}
	got := l.Bundles(context.Background(), records, inv)
	if len(got) != 2 || got[0].Name != "lin" || got[0].State != "missing" || got[0].Members[1].State != "missing" {
		t.Fatalf("linear %+v", got)
	}
	// Without a recorded PV UUID the member is found by its name.
	records[1].Members[0].PVUUID = ""
	if got := l.Bundles(context.Background(), records, inv); got[0].Members[0].State != "ok" {
		t.Fatalf("by name %+v", got[0])
	}
	m := got[1]
	if m.State != "syncing" || m.SyncPercent != 42 || m.Device != "dm-2" || m.Size != 999 || m.Members[0].Disk != "sdx" || m.Members[1].State != "syncing" {
		t.Fatalf("mirror %+v", m)
	}
}

func TestCheckBundle(t *testing.T) {
	inv := inventory()
	inv.Disks = append(inv.Disks, observability.BlockDisk{Name: "sde", Class: "unused", Size: 500, Serial: "S-E"}, observability.BlockDisk{Name: "sdf", Class: "bundle-member", Bundle: "pool", Size: 100, Serial: "S-F"})
	member := func(disk, serial string, size uint64) control.NodeDiskMember {
		return control.NodeDiskMember{Disk: disk, Serial: serial, Size: size}
	}
	bundle := control.NodeDiskOp{Operation: "o", Node: "n", Action: "bundle", Bundle: "pool2", Backend: "lvm", Mode: "linear", Members: []control.NodeDiskMember{member("sdd", "", 400), member("sde", "S-E", 500)}}
	bundle.Members[0].WWN = "naa.d"
	plan, err := CheckBundle(bundle, inv, nil, nil, nil, nil, "")
	if err != nil || len(plan.Disks) != 2 || plan.Path != "/var/lib/sfc-disks/pool2" {
		t.Fatal("bundle", plan, err)
	}
	records := []BundleRecord{{Schema: 1, Name: "pool", Backend: "lvm", Mode: "mirror", Operation: "o", At: 1, Members: []BundleMemberRecord{{Disk: "sdf", Serial: "S-F", Size: 100}, {Disk: "sdg", Serial: "S-G", Size: 100}}}}
	current := []observability.BlockBundle{{Name: "pool", Backend: "lvm", Mode: "mirror", State: "degraded", Members: []observability.BundleMember{{Disk: "sdf", Serial: "S-F", State: "ok"}, {Disk: "sdg", Serial: "S-G", State: "missing"}}}}
	replace := control.NodeDiskOp{Operation: "o", Node: "n", Action: "replace-member", Bundle: "pool", Old: &control.NodeDiskMember{Disk: "sdg", Serial: "S-G"}, New: &control.NodeDiskMember{Disk: "sde", Serial: "S-E", Size: 500}}
	plan, err = CheckBundle(replace, inv, current, nil, nil, records, "")
	if err != nil || plan.Old != "" || plan.Disks[0].Name != "sde" {
		t.Fatal("replace missing member", plan, err)
	}
	for name, c := range map[string]struct {
		op   control.NodeDiskOp
		want string
	}{
		"system member": {control.NodeDiskOp{Operation: "o", Node: "n", Action: "bundle", Bundle: "x", Backend: "lvm", Mode: "linear", Members: []control.NodeDiskMember{member("sda", "S-A", 100), member("sde", "S-E", 500)}}, "system-disk"},
		"used member":   {control.NodeDiskOp{Operation: "o", Node: "n", Action: "bundle", Bundle: "x", Backend: "lvm", Mode: "linear", Members: []control.NodeDiskMember{member("sdb", "S-B", 200), member("sde", "S-E", 500)}}, "busy"},
		"in a bundle":   {control.NodeDiskOp{Operation: "o", Node: "n", Action: "bundle", Bundle: "x", Backend: "lvm", Mode: "linear", Members: []control.NodeDiskMember{member("sdf", "S-F", 100), member("sde", "S-E", 500)}}, "busy"},
		"changed":       {control.NodeDiskOp{Operation: "o", Node: "n", Action: "bundle", Bundle: "x", Backend: "lvm", Mode: "linear", Members: []control.NodeDiskMember{member("sde", "S-E", 1), member("sdd", "", 400)}}, "changed"},
		"name taken":    {control.NodeDiskOp{Operation: "o", Node: "n", Action: "bundle", Bundle: "pool", Backend: "lvm", Mode: "linear", Members: []control.NodeDiskMember{member("sde", "S-E", 500)}}, "busy"},
		"unknown":       {control.NodeDiskOp{Operation: "o", Node: "n", Action: "unbundle", Bundle: "nope"}, "not-managed"},
		"bigger disk":   {control.NodeDiskOp{Operation: "o", Node: "n", Action: "replace-member", Bundle: "pool", Old: &control.NodeDiskMember{Disk: "sdg", Serial: "S-G"}, New: &control.NodeDiskMember{Disk: "sdd", WWN: "naa.d", Size: 400}}, ""},
		"not a member":  {control.NodeDiskOp{Operation: "o", Node: "n", Action: "replace-member", Bundle: "pool", Old: &control.NodeDiskMember{Disk: "sdz", Serial: "S-Z"}, New: &control.NodeDiskMember{Disk: "sde", Serial: "S-E", Size: 500}}, "changed"},
	} {
		_, err := CheckBundle(c.op, inv, current, nil, nil, records, "")
		if code(err) != c.want {
			t.Errorf("%s: got %q (%v) want %q", name, code(err), err, c.want)
		}
	}
	// The storage root on the bundle blocks unbundle.
	mounts := []Record{{Schema: 1, UUID: "u-p", Path: "/var/lib/sfc-disks/pool", Disk: "dm-2", Part: "dm-2", Bundle: "pool", Operation: "o", At: 1}}
	if _, err := CheckBundle(control.NodeDiskOp{Operation: "o", Node: "n", Action: "unbundle", Bundle: "pool"}, inv, current, []string{"/var/lib/sfc-disks/pool/r"}, mounts, records, ""); code(err) != "storage-root" {
		t.Fatal("unbundle under a root", err)
	}
	records[0].Mode = "linear"
	if _, err := CheckBundle(replace, inv, current, nil, nil, records, ""); code(err) != "not-mirror" {
		t.Fatal("linear replace", err)
	}
	records[0].Mode = "mirror"
	records[0].Members[1].Size = 1000
	if _, err := CheckBundle(replace, inv, current, nil, nil, records, ""); code(err) != "too-small" {
		t.Fatal("small replacement", err)
	}
}

func TestCheckFuseBundle(t *testing.T) {
	inv := inventory()
	inv.Disks = append(inv.Disks, observability.BlockDisk{Name: "sdh", Class: "additional", Size: 1 << 40, Serial: "S-H", Parts: []observability.BlockPart{
		{Name: "sdh1", Filesystem: "xfs", UUID: "u-h1", Mounts: []string{"/srv/h"}, Space: &observability.BlockSpace{Total: 1 << 39, Available: 1 << 30}},
	}})
	inv.Disks[1].Parts[0].Space = &observability.BlockSpace{Total: 1 << 38, Available: 1 << 37}
	member := func(disk, part, uuid string, bytes uint64, copy uint8) control.NodeDiskMember {
		return control.NodeDiskMember{Disk: disk, Part: part, UUID: uuid, Bytes: bytes, Copy: copy}
	}
	mounts := []Record{{Schema: 1, UUID: "u-data", Path: "/var/lib/sfc-disks/sdb", Disk: "sdb", Part: "sdb", Operation: "o", At: 1}}
	op := control.NodeDiskOp{Operation: "o", Node: "n", Action: "bundle", Bundle: "slow", Backend: "fuse", Mode: "mirror", Allocation: "reserve", Members: []control.NodeDiskMember{member("sdb", "sdb", "u-data", 512<<20, 1), member("sdh", "sdh1", "u-h1", 512<<20, 2)}}
	if !op.Valid() {
		t.Fatal("op not valid")
	}
	plan, err := CheckBundle(op, inv, nil, nil, mounts, nil, "")
	if err != nil || len(plan.Fuse) != 2 || plan.Fuse[0].Dir != "/var/lib/sfc-disks/sdb/.sfc-disks/slow" || plan.Fuse[1].Dir != "/srv/h/.sfc-disks/slow" || plan.Fuse[1].Copy != 2 {
		t.Fatal("fuse mirror", plan, err)
	}
	edit := func(f func(*control.NodeDiskOp)) control.NodeDiskOp {
		o := op
		o.Members = append([]control.NodeDiskMember(nil), op.Members...)
		f(&o)
		return o
	}
	for name, c := range map[string]struct {
		op   control.NodeDiskOp
		want string
	}{
		"system part":  {edit(func(o *control.NodeDiskOp) { o.Members[0] = member("sda", "sda1", "u-root", 512<<20, 1) }), "system-disk"},
		"not mounted":  {edit(func(o *control.NodeDiskOp) { o.Members[0] = member("sdc", "sdc1", "u-c1", 512<<20, 1) }), "not-mounted"},
		"uuid changed": {edit(func(o *control.NodeDiskOp) { o.Members[0].UUID = "other" }), "changed"},
		"no room":      {edit(func(o *control.NodeDiskOp) { o.Members[1].Bytes = 2 << 30 }), "too-small"},
		"grow fits":    {edit(func(o *control.NodeDiskOp) { o.Allocation, o.Members[1].Bytes = "grow", 2<<30 }), ""},
		"tiny":         {edit(func(o *control.NodeDiskOp) { o.Members[1].Bytes = 1 << 20 }), "too-small"},
		"copy gap":     {edit(func(o *control.NodeDiskOp) { o.Members[1].Copy = 3 }), "members"},
	} {
		_, err := CheckBundle(c.op, inv, nil, nil, mounts, nil, "")
		if code(err) != c.want {
			t.Errorf("%s: got %q (%v) want %q", name, code(err), err, c.want)
		}
	}
	// Two parts of one disk may not be in different mirror copies.
	inv.Disks[4].Parts = append(inv.Disks[4].Parts, observability.BlockPart{Name: "sdh2", Filesystem: "ext4", UUID: "u-h2", Mounts: []string{"/srv/h2"}})
	shared := edit(func(o *control.NodeDiskOp) { o.Members[0] = member("sdh", "sdh2", "u-h2", 512<<20, 1) })
	if _, err := CheckBundle(shared, inv, nil, nil, mounts, nil, ""); code(err) != "members" {
		t.Fatal("copies share a disk", err)
	}
	// Chunks on a part block its unmount, format and forget.
	rec := BundleRecord{Schema: 1, Name: "slow", Backend: "fuse", Mode: "mirror", ID: "00", Allocation: "reserve", Operation: "o", At: 1, Members: plan.Fuse}
	if !rec.Valid() {
		t.Fatal("record not valid")
	}
	unmount := control.NodeDiskOp{Operation: "u", Node: "n", Action: "unmount", Disk: "sdb", Part: "sdb", UUID: "u-data"}
	p, err := Check(unmount, inv, nil, mounts, "")
	if err != nil {
		t.Fatal(err)
	}
	if code(FuseMemberBusy(unmount, p, []BundleRecord{rec})) != "busy" {
		t.Fatal("unmount of a member")
	}
	mount := control.NodeDiskOp{Operation: "m", Node: "n", Action: "mount", Disk: "sdb", Part: "sdb", UUID: "u-data"}
	if FuseMemberBusy(mount, p, []BundleRecord{rec}) != nil {
		t.Fatal("mount is fine")
	}
	replace := control.NodeDiskOp{Operation: "o", Node: "n", Action: "replace-member", Bundle: "slow", Old: &control.NodeDiskMember{Disk: "sdb", Serial: "S-B"}, New: &control.NodeDiskMember{Disk: "sdd", WWN: "naa.d", Size: 400}}
	if _, err := CheckBundle(replace, inv, nil, nil, mounts, []BundleRecord{rec}, ""); code(err) != "not-supported" {
		t.Fatal("fuse replace", err)
	}
}
