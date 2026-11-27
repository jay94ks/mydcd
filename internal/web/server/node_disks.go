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
	State      string `json:"state"`
	Step       string `json:"step"`
	Code       string `json:"code,omitempty"`
	Error      string `json:"error,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	Device     string `json:"device,omitempty"`
	MountPath  string `json:"mountPath,omitempty"`
	Label      string `json:"label,omitempty"`
	StartedAt  int64  `json:"startedAt,omitempty"`
	FinishedAt int64  `json:"finishedAt,omitempty"`
}

func newDiskOpView(r control.NodeDiskResult) diskOpView {
	return diskOpView{Operation: r.Operation, Node: r.Node, Action: r.Action, User: r.User, Disk: r.Disk, Part: r.Part, State: r.State, Step: r.Step, Code: r.Code, Error: r.Error, UUID: r.UUID, Device: r.Device, MountPath: r.MountPath, Label: r.Label, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt}
}

// POST /nodes/{node}/disks/{disk}/{action} (format / mount / unmount /
// forget) {opId, part, serial?, wwn?, size?, tableId?, uuid?, mountPath?,
// label?} → node-disk. The fence fields are what the screen showed; the
// server refuses (state failed, code changed) when the disk differs now.
// A system disk is always refused (code system-disk). No Raft: the reply
// is the server's journal row; a running format is read back with
// GET /nodes/{node}/disk-operations/{opId}. Reusing an opId returns the
// original result and never runs twice. Registering a storage root on a
// new mount is the existing POST /nodes/{node}/storage with its mountPath.
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
	}
	if !readJSON(w, r, &req) {
		return
	}
	op := control.NodeDiskOp{Operation: req.OpID, Node: r.PathValue("node"), Action: r.PathValue("action"), Disk: r.PathValue("disk"), Part: req.Part, Serial: req.Serial, WWN: req.WWN, Size: req.Size, TableID: req.TableID, UUID: req.UUID, MountPath: req.MountPath, Label: req.Label}
	if op.Action == "status" || !op.Valid() {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "opId, part and the fields the action needs (format: serial or wwn and size; mount: uuid, mountPath a non-system absolute path; forget: uuid)")
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
