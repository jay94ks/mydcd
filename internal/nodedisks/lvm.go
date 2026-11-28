// SPDX-License-Identifier: Apache-2.0

package nodedisks

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/observability"
)

// LVM runs the lvm2 tool for lvm disk bundles. A bundle is the volume group
// "sfc-<name>" tagged sfc-managed with one logical volume "data" (linear,
// or raid1 with one copy per member). Run is replaced in tests.
type LVM struct {
	Run func(ctx context.Context, args ...string) ([]byte, error)
}

// LVMTag marks a volume group sfcd made. sfcd changes only a group that has
// this tag and a local bundle record.
const LVMTag = "sfc-managed"

var RealLVM = LVM{Run: runLVM}

func runLVM(ctx context.Context, args ...string) ([]byte, error) {
	tool, err := exec.LookPath("lvm")
	if err != nil {
		return nil, refuse("tool", "lvm is not installed (lvm2)")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Env = []string{"LVM_SUPPRESS_FD_WARNINGS=1", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(errOut.String())
		if len(detail) > 300 {
			detail = detail[:300]
		}
		return nil, refuse("tool", "lvm "+args[0]+": "+err.Error()+" "+detail)
	}
	return out.Bytes(), nil
}

// LVMDevice is the bundle's device path under /dev.
func LVMDevice(bundle string) string {
	return "mapper/" + strings.ReplaceAll(observability.LVMBundleVG(bundle), "-", "--") + "-" + observability.LVMBundleLV
}

func lvmLV(bundle string) string {
	return observability.LVMBundleVG(bundle) + "/" + observability.LVMBundleLV
}

// Create makes the bundle on devs (paths like /dev/sdb). The caller wiped
// them and formats the result.
func (l LVM) Create(ctx context.Context, bundle, mode string, devs []string) error {
	vg := observability.LVMBundleVG(bundle)
	for _, dev := range devs {
		if _, err := l.Run(ctx, "pvcreate", "-ff", "-y", dev); err != nil {
			return err
		}
	}
	if _, err := l.Run(ctx, append([]string{"vgcreate", "-y", "--addtag", LVMTag, vg}, devs...)...); err != nil {
		return err
	}
	args := []string{"lvcreate", "-y", "-W", "y", "-Z", "y", "-n", observability.LVMBundleLV, "-l", "100%FREE"}
	if mode == "mirror" {
		args = append(args, "--type", "raid1", "-m", strconv.Itoa(len(devs)-1))
	} else {
		args = append(args, "--type", "linear")
	}
	_, err := l.Run(ctx, append(args, vg)...)
	return err
}

// Remove deletes the logical volume, the group and the member labels. The
// filesystem on it is unmounted first by the caller.
func (l LVM) Remove(ctx context.Context, bundle string, devs []string, missing bool) error {
	vg := observability.LVMBundleVG(bundle)
	if missing {
		// A volume group with a member gone refuses lvremove and vgremove
		// until the missing physical volume is dropped from it.
		if _, err := l.Run(ctx, "vgreduce", "--removemissing", "--force", vg); err != nil {
			return err
		}
	}
	lvs, err := l.report(ctx, "lvs", "vg_name,lv_name")
	present := err != nil // unreadable: try the removal anyway
	for _, lv := range lvs {
		present = present || lv["vg_name"] == vg && lv["lv_name"] == observability.LVMBundleLV
	}
	if present {
		if _, err := l.Run(ctx, "lvremove", "-y", "-f", lvmLV(bundle)); err != nil {
			return err
		}
	}
	if _, err := l.Run(ctx, "vgremove", "-y", vg); err != nil {
		return err
	}
	for _, dev := range devs {
		if _, err := l.Run(ctx, "pvremove", "-y", "-ff", dev); err != nil {
			return err
		}
	}
	return nil
}

// Replace swaps a mirror member. old is "" when that member is gone; the
// copy to the new member then starts from the remaining ones.
func (l LVM) Replace(ctx context.Context, bundle, old, new string) error {
	vg := observability.LVMBundleVG(bundle)
	if _, err := l.Run(ctx, "pvcreate", "-ff", "-y", new); err != nil {
		return err
	}
	if _, err := l.Run(ctx, "vgextend", vg, new); err != nil {
		return err
	}
	if old == "" {
		if _, err := l.Run(ctx, "lvconvert", "-y", "--repair", lvmLV(bundle), new); err != nil {
			return err
		}
		_, err := l.Run(ctx, "vgreduce", "--removemissing", "--force", vg)
		return err
	}
	if _, err := l.Run(ctx, "lvconvert", "-y", "--replace", old, lvmLV(bundle), new); err != nil {
		return err
	}
	if _, err := l.Run(ctx, "vgreduce", vg, old); err != nil {
		return err
	}
	_, err := l.Run(ctx, "pvremove", "-y", old)
	return err
}

// Activate turns the bundle on at start. A mirror with a member gone comes
// up degraded; a linear bundle with a member gone does not come up.
func (l LVM) Activate(ctx context.Context, bundle string) error {
	_, err := l.Run(ctx, "vgchange", "-ay", "--activationmode", "degraded", observability.LVMBundleVG(bundle))
	return err
}

type lvmReport struct {
	Report []struct {
		VG []map[string]string `json:"vg"`
		LV []map[string]string `json:"lv"`
		PV []map[string]string `json:"pv"`
	} `json:"report"`
}

func (l LVM) report(ctx context.Context, cmd string, fields string) ([]map[string]string, error) {
	raw, err := l.Run(ctx, cmd, "--reportformat", "json", "--units", "b", "--nosuffix", "-a", "-o", fields)
	if err != nil {
		return nil, err
	}
	var r lvmReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, refuse("tool", "lvm "+cmd+" report: "+err.Error())
	}
	var rows []map[string]string
	for _, part := range r.Report {
		rows = append(rows, part.VG...)
		rows = append(rows, part.LV...)
		rows = append(rows, part.PV...)
	}
	return rows, nil
}

// BundleRecord is one bundle sfcd made, kept in the local disk journal. It
// names the members, so a member that is gone is still shown by its disk.
type BundleRecord struct {
	Schema              uint8
	Name, Backend, Mode string
	// fuse: the bundle ID in every chunk header (hex) and the allocation.
	ID              string `json:",omitempty"`
	Allocation      string `json:",omitempty"`
	Members         []BundleMemberRecord
	Operation, User string
	At              int64
}

type BundleMemberRecord struct {
	Disk        string
	Serial, WWN string `json:",omitempty"`
	Size        uint64 `json:",omitempty"`
	// PVUUID is the lvm physical volume UUID, which finds the member when
	// its kernel name changed.
	PVUUID string `json:",omitempty"`
	// Syncing: the member was put in by a replace and the copy to it may
	// still run.
	Syncing bool `json:",omitempty"`
	// fuse: the member partition (by its filesystem UUID), the bytes it
	// gives, its mirror copy number and the chunk directory on it.
	Part  string `json:",omitempty"`
	UUID  string `json:",omitempty"`
	Bytes uint64 `json:",omitempty"`
	Copy  uint8  `json:",omitempty"`
	Dir   string `json:",omitempty"`
}

func (r BundleRecord) Valid() bool {
	ok := r.Schema == 1 && observability.ValidBundleName(r.Name) && slices.Contains(observability.BundleBackends, r.Backend) && slices.Contains(observability.BundleModes, r.Mode) && len(r.Members) >= 2 && len(r.Members) <= 32 && r.Operation != "" && r.At > 0
	for _, m := range r.Members {
		ok = ok && m.Disk != "" && len(m.Disk) <= 64 && len(m.Serial) <= 128 && len(m.WWN) <= 128 && len(m.PVUUID) <= 64 && len(m.Part) <= 64 && len(m.UUID) <= 64 && len(m.Dir) <= 4096 && m.Copy <= 8
		ok = ok && (r.Backend == "lvm") == (m.UUID == "") && (r.Backend == "lvm" || m.Dir != "" && m.Bytes > 0)
	}
	return ok && (r.Backend == "lvm") == (r.ID == "" && r.Allocation == "")
}

// Bundles reads the state of the recorded lvm bundles. devices is the
// inventory, whose Bundle-marked devices say which bundle is active.
func (l LVM) Bundles(ctx context.Context, records []BundleRecord, devices observability.Devices) []observability.BlockBundle {
	out := []observability.BlockBundle{}
	want := false
	for _, r := range records {
		want = want || r.Backend == "lvm"
	}
	var lvs, pvs []map[string]string
	if want {
		lvs, _ = l.report(ctx, "lvs", "vg_name,lv_name,lv_size,sync_percent,vg_tags,lv_attr")
		pvs, _ = l.report(ctx, "pvs", "pv_name,vg_name,pv_uuid,dev_size,pv_missing")
	}
	for _, r := range records {
		if r.Backend != "lvm" {
			continue
		}
		vg := observability.LVMBundleVG(r.Name)
		b := observability.BlockBundle{Name: r.Name, Backend: r.Backend, Mode: r.Mode, State: "ok"}
		for _, d := range devices.Disks {
			if d.Kind == "bundle" && d.Bundle == r.Name {
				b.Device, b.Size = d.Name, d.Size
			}
		}
		sync := 100.0
		for _, lv := range lvs {
			if lv["vg_name"] == vg && lv["lv_name"] == observability.LVMBundleLV && strings.Contains(lv["vg_tags"], LVMTag) {
				if n, err := strconv.ParseUint(lv["lv_size"], 10, 64); err == nil && b.Size == 0 {
					b.Size = n
				}
				if v, err := strconv.ParseFloat(strings.TrimSpace(lv["sync_percent"]), 64); err == nil {
					sync = v
				}
			}
		}
		missing := 0
		for _, m := range r.Members {
			member := observability.BundleMember{Disk: m.Disk, Serial: m.Serial, WWN: m.WWN, Size: m.Size, State: "missing"}
			for _, pv := range pvs {
				// The PV UUID finds a member whose kernel name moved; without
				// one (it could not be read after create) the name is used.
				same := m.PVUUID != "" && pv["pv_uuid"] == m.PVUUID || m.PVUUID == "" && pv["pv_name"] == "/dev/"+m.Disk
				if pv["vg_name"] == vg && same && pv["pv_missing"] == "" {
					member.State = "ok"
					if name, found := strings.CutPrefix(pv["pv_name"], "/dev/"); found && !strings.Contains(name, "/") {
						member.Disk = name
					}
				}
			}
			if member.State == "missing" {
				missing++
			} else if m.Syncing && sync < 100 {
				member.State = "syncing"
			}
			b.Members = append(b.Members, member)
		}
		switch {
		case missing > 0 && (r.Mode == "linear" || missing == len(r.Members)):
			b.State = "missing"
		case missing > 0:
			b.State = "degraded"
		case sync < 100:
			b.State, b.SyncPercent = "syncing", uint8(sync)
		}
		if b.Device == "" && b.State != "missing" && len(lvs) == 0 {
			b.State = "missing" // lvm could not be read and the device is not active
		}
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b observability.BlockBundle) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// PVUUIDs maps each device path to its physical volume UUID.
func (l LVM) PVUUIDs(ctx context.Context, bundle string) (map[string]string, error) {
	pvs, err := l.report(ctx, "pvs", "pv_name,vg_name,pv_uuid")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, pv := range pvs {
		if pv["vg_name"] == observability.LVMBundleVG(bundle) {
			out[pv["pv_name"]] = pv["pv_uuid"]
		}
	}
	return out, nil
}
