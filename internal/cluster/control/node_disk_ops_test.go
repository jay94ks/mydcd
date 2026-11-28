// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

func TestNodeDiskOpShapeAndSystemAdminOnly(t *testing.T) {
	format := NodeDiskOp{Operation: "op-1", Node: "node-a", Action: "format", Disk: "sdb", Part: "sdb", Serial: "S", Size: 10}
	for name, op := range map[string]NodeDiskOp{
		"format":         format,
		"mount":          {Operation: "op-1", Node: "node-a", Action: "mount", Disk: "sdb", Part: "sdb1", UUID: "u", MountPath: "/data"},
		"unmount":        {Operation: "op-1", Node: "node-a", Action: "unmount", Disk: "nvme0n1", Part: "nvme0n1p1"},
		"status":         {Operation: "op-1", Node: "node-a", Action: "status"},
		"prepare":        {Operation: "op-1", Node: "node-a", Action: "prepare-storage", Disk: "sdb", Part: "sdb1", UUID: "u", SubPath: "pool/a_1.x"},
		"prepare format": {Operation: "op-1", Node: "node-a", Action: "prepare-storage", Disk: "sdb", Part: "sdb", Serial: "S", Size: 10, Format: true, Label: "data"},
		"bundle":         {Operation: "op-1", Node: "node-a", Action: "bundle", Bundle: "pool", Backend: "lvm", Mode: "mirror", Members: []NodeDiskMember{{Disk: "sdb", Serial: "S", Size: 1}, {Disk: "sdc", WWN: "W", Size: 1}}},
		"fuse":           {Operation: "op-1", Node: "node-a", Action: "bundle", Bundle: "slow", Backend: "fuse", Mode: "mirror", Allocation: "grow", Members: []NodeDiskMember{{Disk: "sdb", Part: "sdb1", UUID: "u", Bytes: 1, Copy: 1}, {Disk: "sdc", Part: "sdc1", UUID: "v", Bytes: 1, Copy: 2}}},
		"unbundle":       {Operation: "op-1", Node: "node-a", Action: "unbundle", Bundle: "pool"},
		"replace":        {Operation: "op-1", Node: "node-a", Action: "replace-member", Bundle: "pool", Old: &NodeDiskMember{Disk: "sdb", Serial: "S"}, New: &NodeDiskMember{Disk: "sdd", Serial: "T", Size: 2}},
	} {
		if !op.Valid() {
			t.Fatal("valid", name)
		}
	}
	bad := map[string]NodeDiskOp{}
	b := format
	b.Serial = ""
	bad["format without identity"] = b
	b = format
	b.Part = "sdc1"
	bad["part of another disk"] = b
	b = format
	b.Label = "much-too-long-label"
	bad["label"] = b
	bad["mount system path"] = NodeDiskOp{Operation: "op-1", Node: "node-a", Action: "mount", Disk: "sdb", Part: "sdb1", UUID: "u", MountPath: "/var/lib/sfe/x"}
	bad["status with fields"] = NodeDiskOp{Operation: "op-1", Node: "node-a", Action: "status", Disk: "sdb"}
	bad["unknown action"] = NodeDiskOp{Operation: "op-1", Node: "node-a", Action: "wipe", Disk: "sdb", Part: "sdb"}
	prep := NodeDiskOp{Operation: "op-1", Node: "node-a", Action: "prepare-storage", Disk: "sdb", Part: "sdb1", UUID: "u"}
	for _, sub := range []string{"/abs", "../x", "a/../b", "a//b", "a/", "with space", "한글", "a/b/c/d/e/f/g/h/i"} {
		b = prep
		b.SubPath = sub
		bad["sub path "+sub] = b
	}
	b = prep
	b.Format, b.Serial, b.Size = true, "S", 10
	bad["format a partition"] = b
	b = prep
	b.UUID = ""
	bad["prepare without uuid"] = b
	b = format
	b.SubPath = "x"
	bad["sub path on format"] = b
	lvmBundle := NodeDiskOp{Operation: "op-1", Node: "node-a", Action: "bundle", Bundle: "pool", Backend: "lvm", Mode: "linear", Members: []NodeDiskMember{{Disk: "sdb", Serial: "S", Size: 1}, {Disk: "sdc", WWN: "W", Size: 1}}}
	b = lvmBundle
	b.Members = b.Members[:1]
	bad["one member"] = b
	b = lvmBundle
	b.Members = []NodeDiskMember{{Disk: "sdb", Serial: "S", Size: 1}, {Disk: "sdb", Serial: "S", Size: 1}}
	bad["same member twice"] = b
	b = lvmBundle
	b.Allocation = "grow"
	bad["lvm allocation"] = b
	b = lvmBundle
	b.Bundle = "Pool"
	bad["bundle name"] = b
	b = lvmBundle
	b.Disk = "sdb"
	bad["bundle with a disk"] = b
	bad["fuse without allocation"] = NodeDiskOp{Operation: "op-1", Node: "node-a", Action: "bundle", Bundle: "slow", Backend: "fuse", Mode: "linear", Members: []NodeDiskMember{{Disk: "sdb", Part: "sdb1", UUID: "u", Bytes: 1}, {Disk: "sdc", Part: "sdc1", UUID: "v", Bytes: 1}}}
	bad["replace without new"] = NodeDiskOp{Operation: "op-1", Node: "node-a", Action: "replace-member", Bundle: "pool", Old: &NodeDiskMember{Disk: "sdb", Serial: "S"}}
	b = format
	b.Bundle = "pool"
	bad["format with a bundle"] = b
	for name, op := range bad {
		if op.Valid() {
			t.Fatal("accepted", name)
		}
	}
	f := newBackupCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	read, err := f.p.ReadNodeDisk(f.s, f.session, 10, NodeDiskOp{Operation: "op-1", Node: "node-a", Action: "status"})
	if err != nil || read.Owner == ([32]byte{}) || read.Op.Node != "node-a" {
		t.Fatal("admin read", read, err)
	}
	tenant := f.session
	tenant.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	tenant.Signature = ed25519.Sign(f.node, access.SessionBytes(tenant))
	if _, err := f.p.ReadNodeDisk(f.s, tenant, 10, format); !errors.Is(err, access.ErrDenied) {
		t.Fatal("tenant session changed a disk", err)
	}
}
