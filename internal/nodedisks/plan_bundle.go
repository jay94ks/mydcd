// SPDX-License-Identifier: Apache-2.0

package nodedisks

import (
	"path/filepath"
	"slices"
	"strconv"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
)

// BundlePlan is what one checked bundle operation will touch.
type BundlePlan struct {
	// Disks are the member disks to wipe (bundle), or the new member
	// (replace-member).
	Disks []observability.BlockDisk
	// Record is the existing bundle (unbundle, replace-member).
	Record *BundleRecord
	// Current is the bundle as read now.
	Current *observability.BlockBundle
	// Path is the mount point (bundle) or the recorded one (unbundle).
	Path string
	// Mount is the bundle's mount record (unbundle); Mounted says it is
	// mounted now.
	Mount   *Record
	Mounted bool
	// Old is the member leaving (replace-member); "" when it is gone.
	Old string
	// Fuse are the fuse members (bundle), each with its chunk directory.
	Fuse []BundleMemberRecord
}

// FuseDir is a fuse bundle's chunk directory on a member mounted at mount.
func FuseDir(mount, bundle string) string { return filepath.Join(mount, ".sfc-disks", bundle) }

// fuseMinBytes is the least a fuse member gives.
const fuseMinBytes = 64 << 20

// CheckBundle decides whether a bundle operation may run now. bundles are
// this server's bundle records; current their state as read now.
func CheckBundle(op control.NodeDiskOp, inventory observability.Devices, current []observability.BlockBundle, roots []string, records []Record, bundles []BundleRecord, dockerRoot string) (BundlePlan, error) {
	var plan BundlePlan
	for i := range bundles {
		if bundles[i].Name == op.Bundle {
			plan.Record = &bundles[i]
		}
	}
	for i := range current {
		if current[i].Name == op.Bundle {
			plan.Current = &current[i]
		}
	}
	unusedDisk := func(m control.NodeDiskMember) (observability.BlockDisk, error) {
		for _, d := range inventory.Disks {
			if d.Name != m.Disk {
				continue
			}
			switch {
			case d.Class == "system":
				return d, refuse("system-disk", "the system disk is changed by hand on the server only")
			case m.Serial != "" && m.Serial != d.Serial || m.WWN != "" && m.WWN != d.WWN || m.Size != 0 && m.Size != d.Size:
				return d, refuse("changed", "disk "+d.Name+" is not the one shown")
			case d.Kind != "" || d.Bundle != "" || d.Class != "unused" || d.ReadOnly:
				return d, refuse("busy", d.Name+" is not an unused disk")
			}
			for _, p := range d.Parts {
				if p.Busy() {
					return d, refuse("busy", p.Name+" is mounted, swap or used by another device")
				}
				for _, r := range records {
					if p.UUID != "" && r.UUID == p.UUID {
						return d, refuse("busy", p.Name+" is set to be mounted at "+r.Path+"; unmount it first")
					}
				}
			}
			return d, nil
		}
		return observability.BlockDisk{}, refuse("not-found", "no disk "+m.Disk)
	}
	switch op.Action {
	case "bundle":
		if plan.Record != nil {
			return BundlePlan{}, refuse("busy", "a bundle named "+op.Bundle+" exists")
		}
		for _, d := range inventory.Disks {
			if d.Bundle == op.Bundle {
				return BundlePlan{}, refuse("busy", "a volume group for "+op.Bundle+" exists")
			}
		}
		if op.Backend == "fuse" {
			members, err := fuseMembers(op, inventory, records)
			if err != nil {
				return BundlePlan{}, err
			}
			plan.Fuse = members
		} else {
			for _, m := range op.Members {
				d, err := unusedDisk(m)
				if err != nil {
					return BundlePlan{}, err
				}
				plan.Disks = append(plan.Disks, d)
			}
		}
		plan.Path = op.MountPath
		if plan.Path == "" {
			plan.Path = control.DefaultDiskMountPath(op.Bundle)
		}
		if err := checkMountPoint(plan.Path, observability.BlockPart{}, inventory, roots, records, dockerRoot); err != nil {
			return BundlePlan{}, err
		}
	case "unbundle", "replace-member":
		if plan.Record == nil {
			return BundlePlan{}, refuse("not-managed", "no bundle "+op.Bundle)
		}
		if op.Action == "replace-member" && plan.Record.Backend != "lvm" {
			return BundlePlan{}, refuse("not-supported", "a member of a "+plan.Record.Backend+" bundle cannot be replaced yet; unbundle and bundle again")
		}
	}
	switch op.Action {
	case "unbundle":
		for i := range records {
			if records[i].Bundle == op.Bundle {
				plan.Mount = &records[i]
				plan.Path = records[i].Path
			}
		}
		if plan.Mount != nil {
			for _, root := range roots {
				if under(root, plan.Path) {
					return BundlePlan{}, refuse("storage-root", "storage root "+root+" is on bundle "+op.Bundle+"; drain and remove it first")
				}
			}
			if dockerRoot != "" && under(dockerRoot, plan.Path) {
				return BundlePlan{}, refuse("busy", "the Docker data root is on bundle "+op.Bundle)
			}
		}
		for _, d := range inventory.Disks {
			if d.Kind == "bundle" && d.Bundle == op.Bundle {
				for _, p := range d.Parts {
					for _, m := range p.Mounted() {
						if plan.Mount != nil && m == plan.Path {
							plan.Mounted = true
						} else {
							return BundlePlan{}, refuse("busy", "bundle "+op.Bundle+" is also mounted at "+m)
						}
					}
					if p.Swap {
						return BundlePlan{}, refuse("busy", "bundle "+op.Bundle+" is swap")
					}
				}
			}
			for _, p := range d.Parts {
				for _, m := range p.Mounted() {
					if plan.Mount != nil && m != plan.Path && under(m, plan.Path) {
						return BundlePlan{}, refuse("busy", m+" is mounted inside "+plan.Path)
					}
				}
			}
		}
	case "replace-member":
		if plan.Record.Mode != "mirror" {
			return BundlePlan{}, refuse("not-mirror", "only a mirror member can be replaced")
		}
		var old *BundleMemberRecord
		for i, m := range plan.Record.Members {
			if op.Old.Serial != "" && m.Serial == op.Old.Serial || op.Old.WWN != "" && m.WWN == op.Old.WWN {
				old = &plan.Record.Members[i]
			}
		}
		if old == nil {
			return BundlePlan{}, refuse("changed", "the member "+op.Old.Disk+" is not in bundle "+op.Bundle)
		}
		if plan.Current != nil {
			for _, m := range plan.Current.Members {
				if m.Serial == old.Serial && m.WWN == old.WWN && m.State != "missing" {
					plan.Old = m.Disk
				}
			}
			if plan.Current.State == "syncing" {
				return BundlePlan{}, refuse("busy", "bundle "+op.Bundle+" is still copying; wait until it is done")
			}
		}
		d, err := unusedDisk(*op.New)
		if err != nil {
			return BundlePlan{}, err
		}
		if old.Size != 0 && d.Size < old.Size {
			return BundlePlan{}, refuse("too-small", d.Name+" is smaller than the member it replaces")
		}
		plan.Disks = []observability.BlockDisk{d}
	}
	return plan, nil
}

// fuseMembers checks a fuse bundle's partitions: mounted, not on the
// system disk nor on a bundle device, writable, with room for a reserve
// bundle; a mirror's copies numbered 1… on disks no other copy uses.
func fuseMembers(op control.NodeDiskOp, inventory observability.Devices, records []Record) ([]BundleMemberRecord, error) {
	out := []BundleMemberRecord{}
	copyDisks := map[uint8]map[string]bool{}
	for _, m := range op.Members {
		var disk observability.BlockDisk
		var part *observability.BlockPart
		for _, d := range inventory.Disks {
			if d.Name != m.Disk {
				continue
			}
			disk = d
			for i := range d.Parts {
				if d.Parts[i].Name == m.Part {
					part = &disk.Parts[i]
				}
			}
		}
		switch {
		case disk.Name == "" || part == nil:
			return nil, refuse("not-found", "no part "+m.Part)
		case disk.Class == "system":
			return nil, refuse("system-disk", "a part of the system disk cannot be a bundle member")
		case disk.Kind == "bundle" || disk.Class == "bundle-member":
			return nil, refuse("busy", m.Part+" is part of a bundle")
		case part.UUID != m.UUID:
			return nil, refuse("changed", "the filesystem on "+m.Part+" is not the one shown")
		case disk.ReadOnly || part.Swap:
			return nil, refuse("busy", m.Part+" is read-only or swap")
		case m.Bytes < fuseMinBytes:
			return nil, refuse("too-small", m.Part+": give at least 64 MiB")
		}
		mounts := part.Mounts
		mount := ""
		for _, r := range records {
			if r.UUID == part.UUID && slices.Contains(mounts, r.Path) {
				mount = r.Path // the one sfcd keeps mounted
			}
		}
		if mount == "" && len(mounts) > 0 {
			mount = mounts[0]
		}
		if mount == "" {
			return nil, refuse("not-mounted", m.Part+" is not mounted; mount it first")
		}
		if part.Space != nil {
			need := m.Bytes
			if op.Allocation == "grow" {
				need = 0
			}
			if part.Space.Available < need+16<<20 || m.Bytes > part.Space.Total {
				return nil, refuse("too-small", m.Part+" has "+strconv.FormatUint(part.Space.Available>>20, 10)+" MiB free")
			}
		}
		if copyDisks[m.Copy] == nil {
			copyDisks[m.Copy] = map[string]bool{}
		}
		copyDisks[m.Copy][disk.Name] = true
		out = append(out, BundleMemberRecord{Disk: disk.Name, Serial: disk.Serial, WWN: disk.WWN, Size: disk.Size, Part: part.Name, UUID: part.UUID, Bytes: m.Bytes, Copy: m.Copy, Dir: FuseDir(mount, op.Bundle)})
	}
	if op.Mode == "mirror" {
		for n := uint8(1); int(n) <= len(copyDisks); n++ {
			if copyDisks[n] == nil {
				return nil, refuse("members", "mirror copies are numbered 1, 2, …")
			}
			for k := n + 1; int(k) <= len(copyDisks); k++ {
				for disk := range copyDisks[n] {
					if copyDisks[k][disk] {
						return nil, refuse("members", "mirror copies "+strconv.Itoa(int(n))+" and "+strconv.Itoa(int(k))+" share disk "+disk)
					}
				}
			}
		}
		if len(copyDisks) < 2 {
			return nil, refuse("members", "a mirror needs two copies")
		}
	}
	return out, nil
}

// FuseMemberBusy refuses changing a partition that holds a fuse bundle's
// chunks: unmount, format (of it or its whole disk) and forget.
func FuseMemberBusy(op control.NodeDiskOp, plan Plan, bundles []BundleRecord) error {
	if op.Action != "unmount" && op.Action != "format" && op.Action != "forget" && !(op.Action == "prepare-storage" && op.Format) {
		return nil
	}
	for _, b := range bundles {
		if b.Backend != "fuse" {
			continue
		}
		for _, m := range b.Members {
			if m.UUID == "" {
				continue
			}
			if plan.Part.UUID == m.UUID || op.UUID == m.UUID {
				return refuse("busy", op.Part+" holds bundle "+b.Name+"; unbundle it first")
			}
			if plan.Whole || op.Part == op.Disk {
				for _, p := range plan.Disk.Parts {
					if p.UUID == m.UUID {
						return refuse("busy", p.Name+" holds bundle "+b.Name+"; unbundle it first")
					}
				}
			}
		}
	}
	return nil
}
