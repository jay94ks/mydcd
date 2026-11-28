// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/jay94ks/seafield/internal/diskfs"
	"github.com/jay94ks/seafield/internal/nodedisks"
	"github.com/jay94ks/seafield/internal/observability"
	"golang.org/x/sys/unix"
)

// Fuse disk bundles (devel/design/node-disk-bundles.md §2-5):
// chunk files on mounted partitions, served by `sfcd diskfs serve` as one
// FUSE file, attached to a loop device that carries the ext4.

func newFuseID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// fuseSpec rebuilds the diskfs spec from the record: the chunk layout is
// fixed by the members' order and bytes.
func fuseSpec(rec nodedisks.BundleRecord) (diskfs.Spec, error) {
	spec := diskfs.Spec{Schema: 1, Bundle: rec.Name, Mode: rec.Mode}
	id, err := hex.DecodeString(rec.ID)
	if err != nil || len(id) != len(spec.ID) {
		return diskfs.Spec{}, errors.New("bundle " + rec.Name + " has no valid ID")
	}
	copy(spec.ID[:], id)
	copies := []uint8{}
	for _, m := range rec.Members {
		if !slices.Contains(copies, m.Copy) {
			copies = append(copies, m.Copy)
		}
	}
	slices.Sort(copies)
	for _, c := range copies {
		members := []diskfs.Member{}
		for _, m := range rec.Members {
			if m.Copy == c {
				members = append(members, diskfs.Member{Dir: m.Dir, Bytes: m.Bytes, Disk: m.Disk, Part: m.Part})
			}
		}
		spec.Copies = append(spec.Copies, diskfs.Layout(members))
	}
	if !spec.Valid() {
		return diskfs.Spec{}, errors.New("bundle " + rec.Name + " has no valid layout")
	}
	return spec, nil
}

func (d *nodeDiskRuntime) fuseSpecPath(name string) string {
	return filepath.Join(d.dir, "fuse", name+".json")
}

// startFuse makes sure rec's disk is served and on a loop device, and
// returns the loop device. A server that died under a loop device leaves
// that device unusable: the loop goes and both start again (the caller
// unmounted the ext4 first).
func (d *nodeDiskRuntime) startFuse(ctx context.Context, rec nodedisks.BundleRecord) (string, error) {
	spec, err := fuseSpec(rec)
	if err != nil {
		return "", err
	}
	loop := nodedisks.LoopFor(d.host.Sys, diskfs.DiskFile(rec.Name))
	if diskfs.Running(rec.Name, 0) && loop != "" {
		return loop, nil
	}
	if loop != "" && !diskfs.Running(rec.Name, 0) {
		if err := nodedisks.DetachLoop(loop); err != nil {
			return "", err
		}
		loop = ""
	}
	raw, _ := json.Marshal(spec)
	path := d.fuseSpecPath(rec.Name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return "", err
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if err := diskfs.Start(ctx, rec.Name, path, exe); err != nil {
		return "", nodedisks.Refusal{Code: "io", Detail: err.Error()}
	}
	return nodedisks.AttachLoop(diskfs.DiskFile(rec.Name))
}

// stopFuse detaches the loop device, stops the server and, when remove is
// set, deletes the chunk files and the spec.
func (d *nodeDiskRuntime) stopFuse(rec nodedisks.BundleRecord, remove bool) error {
	if loop := nodedisks.LoopFor(d.host.Sys, diskfs.DiskFile(rec.Name)); loop != "" {
		if err := nodedisks.DetachLoop(loop); err != nil {
			return err
		}
	}
	if err := diskfs.Stop(rec.Name); err != nil {
		return nodedisks.Refusal{Code: "in-use", Detail: err.Error()}
	}
	if !remove {
		return nil
	}
	if spec, err := fuseSpec(rec); err == nil {
		if err := diskfs.Remove(spec); err != nil {
			return nodedisks.Refusal{Code: "io", Detail: err.Error()}
		}
	}
	_ = os.Remove(d.fuseSpecPath(rec.Name))
	_ = os.Remove(diskfs.StatusFile(rec.Name))
	_ = os.Remove(diskfs.MountDir(rec.Name))
	_ = os.Remove(filepath.Dir(diskfs.MountDir(rec.Name)))
	return nil
}

// fuseBundles reads the state of the recorded fuse bundles from each
// server's status.json and the inventory.
func fuseBundles(records []nodedisks.BundleRecord, devices observability.Devices) []observability.BlockBundle {
	out := []observability.BlockBundle{}
	for _, r := range records {
		if r.Backend != "fuse" {
			continue
		}
		b := observability.BlockBundle{Name: r.Name, Backend: r.Backend, Mode: r.Mode, State: "missing"}
		for _, disk := range devices.Disks {
			if disk.Kind == "bundle" && disk.Bundle == r.Name {
				b.Device, b.Size = disk.Name, disk.Size
			}
		}
		status, ok := diskfs.ReadStatus(r.Name)
		running := ok && diskfs.Running(r.Name, 0)
		if running {
			b.State, b.SyncPercent = status.State, status.SyncPercent
			if b.Size == 0 {
				b.Size = status.Size
			}
		}
		if !slices.Contains(observability.BundleStates, b.State) {
			b.State = "missing"
		}
		for _, m := range r.Members {
			member := observability.BundleMember{Disk: m.Disk, Part: m.Part, Serial: m.Serial, WWN: m.WWN, Size: m.Bytes, State: "missing"}
			if running {
				n := int(m.Copy)
				if n == 0 {
					n = 1
				}
				for _, c := range status.Copies {
					if c.Copy == n && slices.Contains(observability.BundleMemberStates, c.State) {
						member.State = c.State
					}
				}
			}
			if st, err := os.Stat(m.Dir); err != nil || !st.IsDir() {
				member.State = "missing"
			}
			b.Members = append(b.Members, member)
		}
		out = append(out, b)
	}
	return out
}

// detachMount lazily unmounts a broken mount (its fuse server died).
func detachMount(path string) { _ = unix.Unmount(path, unix.MNT_DETACH) }
