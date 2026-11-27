// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/observability"
)

func TestNodeDisksJoinsDeviceInventoryWithStorageRootsForAdminOnly(t *testing.T) {
	f := newBackupCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	public := [32]byte(f.node.Public().(ed25519.PublicKey))
	f.apply("devices-root", "add-node-storage", 0, nodestorage.Definition{Node: "node-a", Key: public, ID: "data", Path: "/data/sfc", Tenants: []string{"tenant"}}, state.Applied)
	sign := func(r observability.Report) observability.Report {
		r.Kind, r.Schema, r.Cluster, r.Node, r.Key, r.Index, r.At = "node-observation", 1, f.p.Cluster, "node-a", public, f.s.Index(), 10000
		r.Signature = ed25519.Sign(f.node, observability.SigningBytes(r))
		if !r.Valid() {
			t.Fatal("signed observation fixture", r.Source())
		}
		return r
	}
	devices := observability.Devices{Disks: []observability.BlockDisk{
		{Name: "sda", Class: "system", Size: 100, Table: "gpt", TableID: "id", Parts: []observability.BlockPart{
			{Name: "sda1", Number: 1, Size: 10, Filesystem: "vfat", Mounts: []string{"/boot/efi"}},
			{Name: "sda2", Number: 2, Size: 80, Filesystem: "ext4", Mounts: []string{"/"}},
			{Name: "sda3", Number: 3, Size: 10, Filesystem: "swap", Swap: true},
		}},
		{Name: "sdb", Class: "additional", Size: 100, Parts: []observability.BlockPart{{Name: "sdb", Size: 100, Filesystem: "ext4", Mounts: []string{"/data"}}}},
		{Name: "sdc", Class: "unused", Size: 100},
	}}
	system := observability.Disk{Source: "system", ID: observability.FilesystemID("node-a", "root"), Mount: "/", Filesystem: "ext4", Total: 10, Used: 5, Free: 5, Available: 5}
	runtime := system
	runtime.Source = "container-runtime"
	reports := []observability.Report{sign(observability.Report{Devices: &devices}), sign(observability.Report{Disk: &system}), sign(observability.Report{Disk: &runtime})}
	page, err := f.p.NodeDisks(f.s, f.session, 10, "", "node-a", "", reports)
	if err != nil || page.Devices == nil || page.Devices.Stale || len(page.Devices.Disks) != 3 {
		t.Fatal("admin inventory", page.Devices, err)
	}
	sda, sdb := page.Devices.Disks[0], page.Devices.Disks[1]
	if !slices.Equal(sda.Parts[1].Purposes, []string{"container-runtime", "system"}) || !slices.Equal(sda.Parts[2].Purposes, []string{"swap"}) || !slices.Equal(sda.Purposes, []string{"container-runtime", "swap", "system"}) {
		t.Fatal("system disk purposes", sda)
	}
	if !slices.Equal(sdb.Parts[0].StorageRoots, []string{"data"}) || !slices.Equal(sdb.Purposes, []string{"storage-root"}) {
		t.Fatal("storage root on additional disk", sdb)
	}
	for _, row := range page.Disks {
		if row.Mount == "/" && (row.BlockDevice != "sda" || row.BlockClass != "system") {
			t.Fatal("filesystem row not linked to its disk", row)
		}
	}
	if all, err := f.p.NodeDisks(f.s, f.session, 10, "", "", "", reports); err != nil || all.Devices != nil {
		t.Fatal("inventory without a selected server", all.Devices, err)
	}
	if none, err := f.p.NodeDisks(f.s, f.session, 10, "", "node-a", "", nil); err != nil || none.Devices == nil || !none.Devices.Stale || len(none.Devices.Disks) != 0 {
		t.Fatal("missing inventory must read as unknown", none.Devices, err)
	}
	tenant, err := f.p.NodeDisks(f.s, f.session, 10, "tenant", "node-a", "", reports)
	if err != nil || tenant.Devices != nil {
		t.Fatal("tenant view received the device inventory", err)
	}
}
