// SPDX-License-Identifier: Apache-2.0

// Package nodedisks formats and mounts a server's additional disks for sfcd
// (devel/proposals/node-disk-management.md). It never touches the system
// disk, never edits /etc/fstab, and checks every change against a fresh
// device inventory right before it acts.
package nodedisks

import (
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
)

// Record is one mount sfcd made. sfcd mounts it again at start, before
// storage roots, volumes and containers.
type Record struct {
	Schema          uint8
	UUID, Path      string
	Disk, Part      string
	Serial, WWN     string `json:",omitempty"`
	Operation, User string
	At              int64
}

func (r Record) Valid() bool {
	return r.Schema == 1 && r.UUID != "" && len(r.UUID) <= 64 && control.ValidDiskMountPath(r.Path) && r.Disk != "" && strings.HasPrefix(r.Part, r.Disk) && len(r.Part) <= 64 && len(r.Serial) <= 128 && len(r.WWN) <= 128 && r.Operation != "" && r.At > 0
}

// Refusal is a fixed reason (control.NodeDiskCodes) with a short detail.
type Refusal struct{ Code, Detail string }

func (r Refusal) Error() string { return r.Code + ": " + r.Detail }

func refuse(code, detail string) error { return Refusal{Code: code, Detail: detail} }

// Plan is what one checked operation will touch.
type Plan struct {
	Disk observability.BlockDisk
	// Part is the target part. For a whole-disk format of a disk with a
	// table it is the zero part; Whole is set.
	Part  observability.BlockPart
	Whole bool
	// Path is the mount point (mount) or the recorded one (unmount).
	Path string
	// Record is the existing mount record (mount again, unmount).
	Record *Record
	// Mounted: unmount of a recorded filesystem that is still mounted.
	Mounted bool
}

func under(path, base string) bool {
	return path == base || base == "/" || strings.HasPrefix(path, base+"/")
}

// Check decides whether op may run now. inventory is read right before;
// roots are the server's open storage root paths (control.NodeDiskRead);
// records are this server's mount records; dockerRoot is Docker's data
// root ("" when there is no engine).
func Check(op control.NodeDiskOp, inventory observability.Devices, roots []string, records []Record, dockerRoot string) (Plan, error) {
	var plan Plan
	if op.Action == "forget" {
		return checkForget(op, inventory, roots, records)
	}
	found := false
	for _, d := range inventory.Disks {
		if d.Name == op.Disk {
			plan.Disk, found = d, true
		}
	}
	if !found {
		return Plan{}, refuse("not-found", "no disk "+op.Disk)
	}
	d := plan.Disk
	if d.Class == "system" {
		return Plan{}, refuse("system-disk", "the system disk is changed by hand on the server only")
	}
	if op.Serial != "" && op.Serial != d.Serial || op.WWN != "" && op.WWN != d.WWN || op.Size != 0 && op.Size != d.Size || op.TableID != "" && op.TableID != d.TableID {
		return Plan{}, refuse("changed", "disk "+d.Name+" is not the one shown")
	}
	plan.Whole = op.Part == op.Disk
	partFound := false
	for _, p := range d.Parts {
		if p.Name == op.Part {
			plan.Part, partFound = p, true
		}
	}
	if !partFound && !(op.Action == "format" && plan.Whole) {
		return Plan{}, refuse("not-found", "no part "+op.Part)
	}
	if op.UUID != "" && plan.Part.UUID != op.UUID {
		return Plan{}, refuse("changed", "the filesystem on "+op.Part+" is not the one shown")
	}
	recorded := func(p observability.BlockPart) *Record {
		for i := range records {
			if p.UUID != "" && records[i].UUID == p.UUID {
				return &records[i]
			}
		}
		return nil
	}
	switch op.Action {
	case "format":
		if d.ReadOnly {
			return Plan{}, refuse("busy", "disk is read-only")
		}
		targets := []observability.BlockPart{plan.Part}
		if plan.Whole {
			targets = d.Parts
		}
		for _, p := range targets {
			if p.Busy() {
				return Plan{}, refuse("busy", p.Name+" is mounted, swap or used by another device")
			}
			if r := recorded(p); r != nil {
				for _, root := range roots {
					if under(root, r.Path) {
						return Plan{}, refuse("storage-root", "storage root "+root+" is on "+p.Name)
					}
				}
				return Plan{}, refuse("busy", p.Name+" is set to be mounted at "+r.Path+"; unmount it first")
			}
		}
	case "mount":
		p := plan.Part
		if p.Filesystem != "ext4" {
			return Plan{}, refuse("not-ext4", p.Name+" has no ext4 filesystem")
		}
		if p.Busy() || d.ReadOnly {
			return Plan{}, refuse("busy", p.Name+" is mounted, swap, read-only or used by another device")
		}
		plan.Path = op.MountPath
		if plan.Path == "" {
			plan.Path = control.DefaultDiskMountPath(p.Name)
		}
		if !control.ValidDiskMountPath(plan.Path) {
			return Plan{}, refuse("mount-path", plan.Path+" is a system path")
		}
		if dockerRoot != "" && (under(dockerRoot, plan.Path) || under(plan.Path, dockerRoot) && dockerRoot != "/") {
			return Plan{}, refuse("mount-path", plan.Path+" overlaps the Docker data root")
		}
		// The mount point must sit on the system disk, never inside
		// another disk's mount.
		best, class := "", ""
		for _, disk := range inventory.Disks {
			for _, part := range disk.Parts {
				for _, m := range part.Mounted() {
					if under(plan.Path, m) && len(m) > len(best) {
						best, class = m, disk.Class
					}
				}
			}
		}
		if best == "" || best == plan.Path || class != "system" {
			return Plan{}, refuse("mount-path", plan.Path+" is inside another disk's mount")
		}
		for _, root := range roots {
			if under(root, plan.Path) || under(plan.Path, root) {
				return Plan{}, refuse("mount-path", plan.Path+" overlaps storage root "+root)
			}
		}
		for i := range records {
			if records[i].Path == plan.Path && records[i].UUID != p.UUID {
				return Plan{}, refuse("mount-path", plan.Path+" is recorded for another disk")
			}
		}
		plan.Record = recorded(p)
	case "unmount":
		p := plan.Part
		plan.Record = recorded(p)
		if plan.Record == nil {
			return Plan{}, refuse("not-managed", p.Name+" was not mounted by Seafield Cluster; unmount it by hand")
		}
		plan.Path = plan.Record.Path
		for _, root := range roots {
			if under(root, plan.Path) {
				return Plan{}, refuse("storage-root", "storage root "+root+" is on "+p.Name+"; drain and remove it first")
			}
		}
		if dockerRoot != "" && under(dockerRoot, plan.Path) {
			return Plan{}, refuse("busy", "the Docker data root is on "+p.Name)
		}
		for _, m := range p.Mounts {
			if m == plan.Path {
				plan.Mounted = true
			} else if !under(m, plan.Path) {
				return Plan{}, refuse("busy", p.Name+" is also mounted at "+m)
			}
		}
		for _, disk := range inventory.Disks {
			for _, part := range disk.Parts {
				for _, m := range part.Mounted() {
					if m != plan.Path && under(m, plan.Path) && plan.Path != "/" {
						return Plan{}, refuse("busy", m+" is mounted inside "+plan.Path)
					}
				}
			}
		}
	}
	return plan, nil
}

// checkForget allows dropping a record only while its disk is absent; a
// present disk is unmounted instead.
func checkForget(op control.NodeDiskOp, inventory observability.Devices, roots []string, records []Record) (Plan, error) {
	var plan Plan
	for i := range records {
		if records[i].UUID == op.UUID && records[i].Part == op.Part && records[i].Disk == op.Disk {
			plan.Record = &records[i]
		}
	}
	if plan.Record == nil {
		return Plan{}, refuse("not-managed", "no mount record for "+op.Part)
	}
	plan.Path = plan.Record.Path
	for _, d := range inventory.Disks {
		for _, p := range d.Parts {
			if p.UUID == op.UUID {
				return Plan{}, refuse("busy", "the disk is present as "+p.Name+"; unmount it instead")
			}
		}
	}
	for _, root := range roots {
		if under(root, plan.Path) {
			return Plan{}, refuse("storage-root", "storage root "+root+" is on it; remove the storage root first")
		}
	}
	return plan, nil
}
