// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

// NodeDisk: the fake answers like a server's journal. It refuses the
// system disk (sda / vda) as sfcd does, finishes every other operation at
// once, and replays the original result for a reused operation ID. It does
// not change the fake inventory.
func (c *fakeConn) NodeDisk(ctx context.Context, op control.NodeDiskOp) (control.NodeDiskResult, error) {
	const m = "node-disk"
	if !op.Valid() {
		return control.NodeDiskResult{}, fail(m, CodeInvalid, "")
	}
	if err := c.adminRead(ctx, m, op.Node); err != nil {
		return control.NodeDiskResult{}, err
	}
	defer c.unlock()
	w := c.f.w
	if w.diskOps == nil {
		w.diskOps = map[string]control.NodeDiskResult{}
	}
	key := op.Node + "/" + op.Operation
	if old, ok := w.diskOps[key]; ok {
		return old, nil
	}
	if op.Action == "status" {
		return control.NodeDiskResult{}, fail(m, CodeMissing, "")
	}
	now := c.f.now().Unix()
	r := control.NodeDiskResult{Schema: 1, Operation: op.Operation, Node: op.Node, Action: op.Action, User: "admin", Disk: op.Disk, Part: op.Part, Bundle: op.Bundle, State: "done", Step: op.Action, StartedAt: now, FinishedAt: now, Label: op.Label}
	switch {
	case op.Disk == "sda" || op.Disk == "vda":
		r.State, r.Step, r.Code, r.Error = "failed", "check", "system-disk", "the system disk is changed by hand on the server only"
	case op.Action == "format":
		if op.Part == op.Disk {
			r.Part = op.Disk + "1"
			if last := op.Disk[len(op.Disk)-1]; last >= '0' && last <= '9' {
				r.Part = op.Disk + "p1"
			}
		}
		r.UUID, r.Device = "00000000-0000-4000-8000-"+strings.Repeat("0", 12-len(r.Part))+r.Part, "/dev/"+r.Part
	case op.Action == "mount":
		r.UUID, r.Device, r.MountPath = op.UUID, "/dev/"+op.Part, op.MountPath
		if r.MountPath == "" {
			r.MountPath = control.DefaultDiskMountPath(op.Part)
		}
	case op.Action == "prepare-storage":
		r.Step = "directory"
		r.UUID = op.UUID
		if op.Format {
			r.Part = op.Disk + "1"
			if last := op.Disk[len(op.Disk)-1]; last >= '0' && last <= '9' {
				r.Part = op.Disk + "p1"
			}
			r.UUID = "00000000-0000-4000-8000-" + strings.Repeat("0", 12-len(r.Part)) + r.Part
		}
		r.Device, r.MountPath = "/dev/"+r.Part, op.MountPath
		if r.MountPath == "" {
			r.MountPath = control.DefaultDiskMountPath(r.Part)
		}
		r.RootPath = r.MountPath
		if op.SubPath != "" {
			r.RootPath += "/" + op.SubPath
		}
	case op.Action == "bundle":
		r.Step, r.UUID, r.Device = "mount", "00000000-0000-4000-8000-00000000b00d", "/dev/dm-8"
		if op.Backend == "fuse" {
			r.Device = "/dev/loop7"
		}
		r.MountPath = op.MountPath
		if r.MountPath == "" {
			r.MountPath = control.DefaultDiskMountPath(op.Bundle)
		}
	case op.Action == "replace-member":
		r.Step, r.Disk = "record", op.New.Disk
	case op.Action == "unbundle":
		r.Step = "done"
	case op.Action == "unmount":
		r.UUID, r.Device = op.UUID, "/dev/"+op.Part
	}
	w.diskOps[key] = r
	return r, nil
}
