// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// diskOpView is a server's journal row for one disk operation. state is
// running / done / failed; code a fixed reason (control.NodeDiskCodes).
// Times are Unix seconds.
type diskOpView struct {
	Operation  string `json:"operation"`
	Node       string `json:"node"`
	Action     string `json:"action"`
	User       string `json:"user"`
	Disk       string `json:"disk,omitempty"`
	Part       string `json:"part,omitempty"`
	Bundle     string `json:"bundle,omitempty"`
	State      string `json:"state"`
	Step       string `json:"step"`
	Code       string `json:"code,omitempty"`
	Error      string `json:"error,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	Device     string `json:"device,omitempty"`
	MountPath  string `json:"mountPath,omitempty"`
	Label      string `json:"label,omitempty"`
	RootPath   string `json:"rootPath,omitempty"`
	StartedAt  int64  `json:"startedAt,omitempty"`
	FinishedAt int64  `json:"finishedAt,omitempty"`
}

func newDiskOpView(r control.NodeDiskResult) diskOpView {
	return diskOpView{Operation: r.Operation, Node: r.Node, Action: r.Action, User: r.User, Disk: r.Disk, Part: r.Part, Bundle: r.Bundle, State: r.State, Step: r.Step, Code: r.Code, Error: r.Error, UUID: r.UUID, Device: r.Device, MountPath: r.MountPath, Label: r.Label, RootPath: r.RootPath, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt}
}

// POST /nodes/{node}/disks/{disk}/{action} (format / mount / unmount /
// forget / prepare-storage) {opId, part, serial?, wwn?, size?, tableId?,
// uuid?, mountPath?, label?, format?, subPath?} → node-disk. The fence fields are what the screen showed; the
// server refuses (state failed, code changed) when the disk differs now.
// A system disk is always refused (code system-disk). No Raft: the reply
// is the server's journal row; a running format is read back with
// GET /nodes/{node}/disk-operations/{opId}. Reusing an opId returns the
// original result and never runs twice. prepare-storage formats an unused
// disk first when format is set, mounts the part unless sfcd already has,
// and makes subPath (0700) under the mount; the web then registers the
// result's rootPath with the existing POST /nodes/{node}/storage. A retry
// after a failure past the format step sends format false with the uuid
// the failed result names.
func (s *Server) handleNodeDiskOp(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string `json:"opId"`
		Part      string `json:"part"`
		Serial    string `json:"serial,omitempty"`
		WWN       string `json:"wwn,omitempty"`
		Size      uint64 `json:"size,omitempty"`
		TableID   string `json:"tableId,omitempty"`
		UUID      string `json:"uuid,omitempty"`
		MountPath string `json:"mountPath,omitempty"`
		Label     string `json:"label,omitempty"`
		Format    bool   `json:"format,omitempty"`
		SubPath   string `json:"subPath,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	op := control.NodeDiskOp{Operation: req.OpID, Node: r.PathValue("node"), Action: r.PathValue("action"), Disk: r.PathValue("disk"), Part: req.Part, Serial: req.Serial, WWN: req.WWN, Size: req.Size, TableID: req.TableID, UUID: req.UUID, MountPath: req.MountPath, Label: req.Label, Format: req.Format, SubPath: req.SubPath}
	if op.Action == "status" || !op.Valid() {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "opId, part and the fields the action needs (format: serial or wwn and size; mount: uuid, mountPath a non-system absolute path; forget: uuid; prepare-storage: format with serial or wwn and size on the whole disk, or uuid; subPath a relative path of plain names)")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (diskOpView, error) {
		res, err := c.NodeDisk(ctx, op)
		if err != nil {
			return diskOpView{}, err
		}
		return newDiskOpView(res), nil
	})
}

// GET /nodes/{node}/disk-operations/{operation} → node-disk status. An
// unknown operation is 404.
func (s *Server) handleNodeDiskStatus(w http.ResponseWriter, r *http.Request, ws *webSession) {
	op := control.NodeDiskOp{Operation: r.PathValue("operation"), Node: r.PathValue("node"), Action: "status"}
	if !op.Valid() {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "operation")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (diskOpView, error) {
		res, err := c.NodeDisk(ctx, op)
		if isSfcCode(err, sfc.CodeMissing) {
			return diskOpView{}, &httpErr{http.StatusNotFound, "not-found", "no such disk operation"}
		}
		if err != nil {
			return diskOpView{}, err
		}
		return newDiskOpView(res), nil
	})
}

// diskMemberReq is one bundle member as the screen showed it: lvm takes an
// unused disk {disk, serial|wwn, size}; fuse a mounted partition {disk,
// part, uuid, bytes, copy}.
type diskMemberReq struct {
	Disk   string `json:"disk"`
	Part   string `json:"part,omitempty"`
	Serial string `json:"serial,omitempty"`
	WWN    string `json:"wwn,omitempty"`
	Size   uint64 `json:"size,omitempty"`
	UUID   string `json:"uuid,omitempty"`
	Bytes  uint64 `json:"bytes,omitempty"`
	Copy   uint8  `json:"copy,omitempty"`
}

func (m diskMemberReq) member() control.NodeDiskMember {
	return control.NodeDiskMember{Disk: m.Disk, Part: m.Part, Serial: m.Serial, WWN: m.WWN, Size: m.Size, UUID: m.UUID, Bytes: m.Bytes, Copy: m.Copy}
}

func (s *Server) runNodeDiskOp(w http.ResponseWriter, r *http.Request, ws *webSession, op control.NodeDiskOp, hint string) {
	if !op.Valid() {
		writeError(w, http.StatusUnprocessableEntity, "invalid", hint)
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (diskOpView, error) {
		res, err := c.NodeDisk(ctx, op)
		if err != nil {
			return diskOpView{}, err
		}
		return newDiskOpView(res), nil
	})
}

// POST /nodes/{node}/disk-bundles {opId, name, backend (lvm|fuse), mode
// (linear|mirror), members[], mountPath?, label?, allocation? (fuse:
// reserve|grow)} → node-disk bundle. lvm wipes the member disks, makes the
// bundle, formats it ext4 and mounts it (default /var/lib/sfc-disks/<name>).
// fuse leaves its member partitions as they are and puts chunk files in
// <member mount>/.sfc-disks/<name>; the ext4 goes on the joined disk.
func (s *Server) handleNodeDiskBundle(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID       string          `json:"opId"`
		Name       string          `json:"name"`
		Backend    string          `json:"backend"`
		Mode       string          `json:"mode"`
		Members    []diskMemberReq `json:"members"`
		MountPath  string          `json:"mountPath,omitempty"`
		Label      string          `json:"label,omitempty"`
		Allocation string          `json:"allocation,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	op := control.NodeDiskOp{Operation: req.OpID, Node: r.PathValue("node"), Action: "bundle", Bundle: req.Name, Backend: req.Backend, Mode: req.Mode, MountPath: req.MountPath, Label: req.Label, Allocation: req.Allocation}
	for _, m := range req.Members {
		op.Members = append(op.Members, m.member())
	}
	s.runNodeDiskOp(w, r, ws, op, "opId, name (lowercase letters, digits and -), backend lvm or fuse, mode linear or mirror, 2–32 members (lvm: disk with serial or wwn and size; fuse: disk, part, uuid, bytes, copy for a mirror; allocation reserve or grow)")
}

// POST /nodes/{node}/disk-bundles/{name}/{action} (unbundle |
// replace-member) {opId, old?, new?} → node-disk. unbundle needs no storage
// root on the bundle; its members become blank unused disks. replace-member
// (lvm mirror only; fuse answers not-supported) takes old {disk, serial|wwn} and new {disk, serial|wwn,
// size}; the copy runs on and shows as syncing in devices.bundles.
func (s *Server) handleNodeDiskBundleOp(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string         `json:"opId"`
		Old  *diskMemberReq `json:"old,omitempty"`
		New  *diskMemberReq `json:"new,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	op := control.NodeDiskOp{Operation: req.OpID, Node: r.PathValue("node"), Action: r.PathValue("action"), Bundle: r.PathValue("name")}
	if op.Action != "unbundle" && op.Action != "replace-member" {
		writeError(w, http.StatusNotFound, "not-found", "action: unbundle or replace-member")
		return
	}
	if req.Old != nil {
		m := req.Old.member()
		op.Old = &m
	}
	if req.New != nil {
		m := req.New.member()
		op.New = &m
	}
	s.runNodeDiskOp(w, r, ws, op, "opId; replace-member: old {disk, serial or wwn} and new {disk, serial or wwn, size}")
}
