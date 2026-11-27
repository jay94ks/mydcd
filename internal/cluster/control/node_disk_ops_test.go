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
		"format":  format,
		"mount":   {Operation: "op-1", Node: "node-a", Action: "mount", Disk: "sdb", Part: "sdb1", UUID: "u", MountPath: "/data"},
		"unmount": {Operation: "op-1", Node: "node-a", Action: "unmount", Disk: "nvme0n1", Part: "nvme0n1p1"},
		"status":  {Operation: "op-1", Node: "node-a", Action: "status"},
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
