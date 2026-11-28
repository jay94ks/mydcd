// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/observability"
)

// nodeDevices joins the server's latest device inventory with what the
// cluster put on it: "/" (system), the Docker data root and every open
// storage root of that server. The join is by mount point at read time;
// the inventory itself stays a measurement.
func (p Policy) nodeDevices(s state.State, node string, reports map[string]observability.Report, now uint64) (*NodeDevicesView, error) {
	view := &NodeDevicesView{Node: node, Disks: []NodeBlockDiskView{}, Recorded: []observability.RecordedMount{}, Bundles: []observability.BlockBundle{}, Stale: true, ObservationMaxAge: observability.MaxAge}
	report, known := reports["devices"]
	if !known || report.Devices == nil {
		return view, nil
	}
	view.ObservedAt, view.Stale, view.Truncated = report.At, !observability.Fresh(report.At, now), report.Devices.Truncated
	view.Recorded = append(view.Recorded, report.Devices.Recorded...)
	view.Bundles = append(view.Bundles, report.Devices.Bundles...)
	for _, d := range report.Devices.Disks {
		disk := NodeBlockDiskView{BlockDisk: d, Parts: []NodeBlockPartView{}, Purposes: []string{}}
		disk.BlockDisk.Parts = nil
		for _, part := range d.Parts {
			row := NodeBlockPartView{BlockPart: part, Purposes: []string{}, StorageRoots: []string{}}
			swap := part.Swap
			for _, h := range part.Holders {
				swap = swap || h.Swap
			}
			if swap {
				row.Purposes = append(row.Purposes, "swap")
			}
			disk.Parts = append(disk.Parts, row)
		}
		view.Disks = append(view.Disks, disk)
	}
	type place struct{ purpose, root, path string }
	places := []place{{purpose: "system", path: "/"}}
	if r, ok := reports["disk/container-runtime"]; ok && r.Disk != nil {
		places = append(places, place{purpose: "container-runtime", path: r.Disk.Mount})
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return nil, err
	}
	for _, root := range roots.Roots() {
		if root.Definition.Node != node || root.Closed != nil {
			continue
		}
		path := root.Definition.Path
		// The root's own report resolved symlinks to its real mount.
		if r, ok := reports["disk/root/"+root.Definition.ID]; ok && r.Disk != nil && r.Disk.RootGeneration == root.Generation {
			path = r.Disk.Mount
		}
		places = append(places, place{purpose: "storage-root", root: root.Definition.ID, path: path})
	}
	for _, pl := range places {
		di, pi, best := -1, -1, -1
		for i, disk := range view.Disks {
			for j, part := range disk.Parts {
				for _, m := range part.Mounted() {
					if (m == "/" || pl.path == m || strings.HasPrefix(pl.path, m+"/")) && len(m) > best {
						di, pi, best = i, j, len(m)
					}
				}
			}
		}
		if di < 0 {
			continue
		}
		part := &view.Disks[di].Parts[pi]
		part.Purposes = append(part.Purposes, pl.purpose)
		if pl.root != "" {
			part.StorageRoots = append(part.StorageRoots, pl.root)
		}
	}
	for i := range view.Disks {
		disk := &view.Disks[i]
		for j := range disk.Parts {
			part := &disk.Parts[j]
			slices.Sort(part.Purposes)
			part.Purposes = slices.Compact(part.Purposes)
			slices.Sort(part.StorageRoots)
			part.StorageRoots = slices.Compact(part.StorageRoots)
			disk.Purposes = append(disk.Purposes, part.Purposes...)
		}
		slices.Sort(disk.Purposes)
		disk.Purposes = slices.Compact(disk.Purposes)
	}
	for len(view.Disks) > 0 {
		raw, _ := json.Marshal(view)
		if len(raw) <= NodeDevicesBudget {
			break
		}
		view.Disks, view.Truncated = view.Disks[:len(view.Disks)-1], true
	}
	return view, nil
}

// linkBlockDevices names, on each filesystem row, the disk it is on.
func linkBlockDevices(rows []NodeDiskView, devices *NodeDevicesView) {
	for i := range rows {
		if rows[i].Mount == "" || rows[i].ID == "" {
			continue
		}
		for _, disk := range devices.Disks {
			for _, part := range disk.Parts {
				if slices.Contains(part.Mounted(), rows[i].Mount) {
					rows[i].BlockDevice, rows[i].BlockClass = disk.Name, disk.Class
				}
			}
		}
	}
}
