// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"log"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/diskfs"
	"github.com/jay94ks/seafield/internal/nodedisks"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/schema"
	"golang.org/x/sys/unix"
)

// Disk bundles (devel/design/node-disk-bundles.md §2): the
// bundle record bundle/<name> sits next to the mount records in
// <state_dir>/disks/mounts.db. The filesystem on a bundle has an ordinary
// mount record with Bundle set.

func (d *nodeDiskRuntime) bundles() ([]nodedisks.BundleRecord, error) {
	rows, err := d.db.Scan("bundle/")
	if err != nil {
		return nil, err
	}
	out := []nodedisks.BundleRecord{}
	for _, raw := range rows {
		rec, e := schema.Decode[nodedisks.BundleRecord](raw)
		if e == nil && rec.Valid() {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// bundleStates reads the state of every recorded bundle for the device
// report and for a check.
func (d *nodeDiskRuntime) bundleStates(ctx context.Context, inventory observability.Devices) []observability.BlockBundle {
	records, err := d.bundles()
	if err != nil || len(records) == 0 {
		return nil
	}
	return mergeBundles(d.lvm.Bundles(ctx, records, inventory), fuseBundles(records, inventory))
}

func mergeBundles(lvm, fuse []observability.BlockBundle) []observability.BlockBundle {
	out := append(lvm, fuse...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// runNodeDiskBundle runs bundle, unbundle or replace-member; the caller
// holds d.mu and records the outcome.
func (r *Runtime) runNodeDiskBundle(ctx context.Context, d *nodeDiskRuntime, j *nodeDiskJournal, op control.NodeDiskOp, roots []string, step func(string, map[string][]byte) error) error {
	inventory, err := r.diskInventory(ctx)
	if err != nil {
		return nodedisks.Refusal{Code: "io", Detail: "device inventory: " + err.Error()}
	}
	records, err := d.records()
	if err != nil {
		return err
	}
	bundles, err := d.bundles()
	if err != nil {
		return err
	}
	current := mergeBundles(d.lvm.Bundles(ctx, bundles, inventory), fuseBundles(bundles, inventory))
	plan, err := nodedisks.CheckBundle(op, inventory, current, roots, records, bundles, r.dockerRoot(ctx))
	if err != nil {
		return err
	}
	key := "bundle/" + op.Bundle
	switch op.Action {
	case "bundle":
		rec := nodedisks.BundleRecord{Schema: 1, Name: op.Bundle, Backend: op.Backend, Mode: op.Mode, Operation: op.Operation, User: j.Result.User, At: time.Now().Unix()}
		device := ""
		if op.Backend == "fuse" {
			id, err := newFuseID()
			if err != nil {
				return err
			}
			rec.ID, rec.Allocation, rec.Members = id, op.Allocation, plan.Fuse
			if err := step("members", nil); err != nil {
				return err
			}
			if err := step("create", map[string][]byte{key: diskJSON(rec)}); err != nil {
				return err
			}
			spec, err := fuseSpec(rec)
			if err != nil {
				return err
			}
			if err := diskfs.Create(spec, op.Allocation == "grow"); err != nil {
				code := "io"
				if errors.Is(err, unix.ENOSPC) {
					code = "too-small"
				}
				return nodedisks.Refusal{Code: code, Detail: err.Error()}
			}
			if device, err = d.startFuse(ctx, rec); err != nil {
				return err
			}
		} else {
			devs := []string{}
			for _, disk := range plan.Disks {
				rec.Members = append(rec.Members, nodedisks.BundleMemberRecord{Disk: disk.Name, Serial: disk.Serial, WWN: disk.WWN, Size: disk.Size})
				devs = append(devs, "/dev/"+disk.Name)
			}
			if err := step("members", nil); err != nil {
				return err
			}
			for _, disk := range plan.Disks {
				if err := d.host.WipePart(disk.Name); err != nil {
					return err
				}
			}
			// The record goes first, so a bundle half made is still shown and
			// can be unbundled.
			if err := step("create", map[string][]byte{key: diskJSON(rec)}); err != nil {
				return err
			}
			if err := d.lvm.Create(ctx, op.Bundle, op.Mode, devs); err != nil {
				return err
			}
			if pvs, err := d.lvm.PVUUIDs(ctx, op.Bundle); err == nil {
				for i := range rec.Members {
					rec.Members[i].PVUUID = pvs["/dev/"+rec.Members[i].Disk]
				}
			}
			device = nodedisks.LVMDevice(op.Bundle)
		}
		uuid, _, err := nodedisks.NewUUID()
		if err != nil {
			return err
		}
		j.FormatUUID = uuid
		if err := step("format", map[string][]byte{key: diskJSON(rec)}); err != nil {
			return err
		}
		if err := d.host.MakeExt4(ctx, device, uuid, op.Label); err != nil {
			return err
		}
		if inventory, err = r.diskInventory(ctx); err != nil {
			return nodedisks.Refusal{Code: "io", Detail: "device inventory: " + err.Error()}
		}
		var made observability.BlockDisk
		for _, disk := range inventory.Disks {
			if disk.Kind == "bundle" && disk.Bundle == op.Bundle {
				made = disk
			}
		}
		if made.Name == "" || len(made.Parts) != 1 || made.Parts[0].UUID != uuid {
			return nodedisks.Refusal{Code: "io", Detail: "the new bundle device did not appear"}
		}
		part := made.Parts[0]
		mrec := nodedisks.Record{Schema: 1, UUID: uuid, Path: plan.Path, Disk: made.Name, Part: part.Name, Operation: op.Operation, User: j.Result.User, At: time.Now().Unix(), Bundle: op.Bundle}
		if err := nodedisks.PreparePoint(plan.Path); err != nil {
			return err
		}
		if err := step("mount", map[string][]byte{"mount/" + uuid: diskJSON(mrec)}); err != nil {
			return err
		}
		if err := d.host.Mount(part.Name, plan.Path); err != nil {
			return err
		}
		j.Result.UUID, j.Result.Device, j.Result.MountPath = uuid, "/dev/"+part.Name, plan.Path
	case "unbundle":
		if plan.Mount != nil {
			if err := step("unmount", nil); err != nil {
				return err
			}
			if plan.Mounted {
				if err := nodedisks.Unmount(plan.Path); err != nil {
					return err
				}
			}
			if err := step("record", map[string][]byte{"mount/" + plan.Mount.UUID: nil}); err != nil {
				return err
			}
		}
		if plan.Record.Backend == "fuse" {
			if err := step("remove", nil); err != nil {
				return err
			}
			if err := d.stopFuse(*plan.Record, true); err != nil {
				return err
			}
			if err := step("done", map[string][]byte{key: nil}); err != nil {
				return err
			}
			if plan.Mount != nil {
				j.Result.UUID, j.Result.MountPath = plan.Mount.UUID, plan.Path
			}
			return nil
		}
		devs, disks, missing := []string{}, []string{}, false
		if plan.Current != nil {
			for _, m := range plan.Current.Members {
				if m.State != "missing" {
					devs, disks = append(devs, "/dev/"+m.Disk), append(disks, m.Disk)
				} else {
					missing = true
				}
			}
		}
		if err := step("remove", nil); err != nil {
			return err
		}
		if err := d.lvm.Remove(ctx, op.Bundle, devs, missing); err != nil {
			return err
		}
		for _, disk := range disks {
			if err := d.host.WipePart(disk); err != nil {
				return err
			}
		}
		if err := step("done", map[string][]byte{key: nil}); err != nil {
			return err
		}
		if plan.Mount != nil {
			j.Result.UUID, j.Result.MountPath = plan.Mount.UUID, plan.Path
		}
	case "replace-member":
		rec := *plan.Record
		rec.Members = slices.Clone(rec.Members)
		newDisk := plan.Disks[0]
		if err := step("members", nil); err != nil {
			return err
		}
		if err := d.host.WipePart(newDisk.Name); err != nil {
			return err
		}
		old := ""
		if plan.Old != "" {
			old = "/dev/" + plan.Old
		}
		if err := step("replace", nil); err != nil {
			return err
		}
		if err := d.lvm.Replace(ctx, op.Bundle, old, "/dev/"+newDisk.Name); err != nil {
			return err
		}
		m := nodedisks.BundleMemberRecord{Disk: newDisk.Name, Serial: newDisk.Serial, WWN: newDisk.WWN, Size: newDisk.Size, Syncing: true}
		if pvs, err := d.lvm.PVUUIDs(ctx, op.Bundle); err == nil {
			m.PVUUID = pvs["/dev/"+newDisk.Name]
		}
		rec.Members = slices.DeleteFunc(rec.Members, func(x nodedisks.BundleMemberRecord) bool {
			return op.Old.Serial != "" && x.Serial == op.Old.Serial || op.Old.WWN != "" && x.WWN == op.Old.WWN
		})
		rec.Members = append(rec.Members, m)
		if err := step("record", map[string][]byte{key: diskJSON(rec)}); err != nil {
			return err
		}
		j.Result.Disk = newDisk.Name
	}
	return nil
}

// activateBundles turns on every recorded lvm bundle whose device is not
// there; reconcileNodeDisks then mounts it like any other record. It
// returns true when it turned one on.
func (r *Runtime) activateBundles(ctx context.Context, d *nodeDiskRuntime, inventory observability.Devices) bool {
	bundles, err := d.bundles()
	if err != nil {
		return false
	}
	changed := false
	records, _ := d.records()
	names := []string{}
	for _, disk := range inventory.Disks {
		names = append(names, disk.Name+"/"+disk.Serial)
	}
	d.wmu.Lock()
	d.diskSet = strings.Join(names, ",")
	if d.retries == nil {
		d.retries = map[string]activationRetry{}
	}
	d.wmu.Unlock()
	for _, b := range bundles {
		if b.Backend == "fuse" {
			loop := nodedisks.LoopFor(d.host.Sys, diskfs.DiskFile(b.Name))
			if diskfs.Running(b.Name, 0) && loop != "" {
				d.retry(b.Name, nil)
				continue
			}
			if !d.retryDue(b.Name) {
				continue // starting waits up to 15 s; do not do it every cycle
			}
			if loop != "" {
				// The server died: the ext4 on its loop device only gives
				// I/O errors now. Let go of it and start again.
				for _, rec := range records {
					if rec.Bundle == b.Name {
						detachMount(rec.Path)
					}
				}
				log.Printf("node disk bundle restarting: bundle=%s reason=server-gone", b.Name)
			}
			if _, err := d.startFuse(ctx, b); err != nil {
				d.retry(b.Name, err)
				d.warn(nodedisks.Record{UUID: "bundle/" + b.Name, Path: b.Name}, "bundle-not-active")
				continue
			}
			changed = true
			continue
		}
		if b.Backend != "lvm" {
			continue
		}
		active := slices.ContainsFunc(inventory.Disks, func(disk observability.BlockDisk) bool { return disk.Kind == "bundle" && disk.Bundle == b.Name })
		if active {
			d.retry(b.Name, nil)
			continue
		}
		if !d.retryDue(b.Name) {
			continue // a linear bundle with a member gone fails every time
		}
		if err := d.lvm.Activate(ctx, b.Name); err != nil {
			d.retry(b.Name, err)
			d.warn(nodedisks.Record{UUID: "bundle/" + b.Name, Path: b.Name}, "bundle-not-active")
			continue
		}
		d.retry(b.Name, nil)
		changed = true
	}
	return changed
}

// activationRetry spaces failed bundle activations: 1 minute, doubling to
// 30, and at once when the set of disks changes.
type activationRetry struct {
	next  time.Time
	wait  time.Duration
	disks string
}

func (d *nodeDiskRuntime) retryDue(name string) bool {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	r, ok := d.retries[name]
	return !ok || time.Now().After(r.next) || r.disks != d.diskSet
}

func (d *nodeDiskRuntime) retry(name string, err error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	if err == nil {
		delete(d.retries, name)
		return
	}
	r := d.retries[name]
	r.wait = min(max(2*r.wait, time.Minute), 30*time.Minute)
	r.next, r.disks = time.Now().Add(r.wait), d.diskSet
	d.retries[name] = r
}
