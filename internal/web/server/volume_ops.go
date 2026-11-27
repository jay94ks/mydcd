// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"maps"
	"net/http"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Data store backups, restores, capacity and delete (UI-60 row menu, UI-62
// backups, UI-63 restore). The daemon builds the payloads from the sfcd
// rows (volume scope and native binding, the backup record, the backup
// source); sfcd decides. Move (UI-64) is in volume_move.go: it is an app
// operation (app-plan-stream with a move request, artifact upload, approvals).

// findVolume reads a tenant volume by name (and app when given).
func findVolume(ctx context.Context, c sfc.Conn, tenant, name, app string) (volumeView, error) {
	var found []volumeView
	after := ""
	for {
		p, err := volumePage(ctx, c, tenant, after)
		if err != nil {
			return volumeView{}, err
		}
		for _, v := range p.Items {
			if v.Tenant == tenant && v.Name == name && (app == "" || v.App == app) {
				found = append(found, v)
			}
		}
		if p.Next == "" {
			break
		}
		after = p.Next
	}
	switch len(found) {
	case 0:
		return volumeView{}, &httpErr{http.StatusNotFound, "not-found", "no such data store"}
	case 1:
		return found[0], nil
	}
	return volumeView{}, &httpErr{http.StatusConflict, "ambiguous", "several apps have a data store of this name; give app"}
}

func volumeBackups(ctx context.Context, c sfc.Conn, v volumeView) ([]sfc.VolumeBackupView, error) {
	var out []sfc.VolumeBackupView
	after := ""
	for {
		p, err := c.VolumeBackups(ctx, v.Tenant, after)
		if err != nil {
			return nil, err
		}
		for _, b := range p.Items {
			if b.Source.Scope == v.Scope {
				out = append(out, b)
			}
		}
		if p.Next == "" {
			return out, nil
		}
		after = p.Next
	}
}

func volumeRestores(ctx context.Context, c sfc.Conn, v volumeView) ([]sfc.VolumeRestoreView, error) {
	var out []sfc.VolumeRestoreView
	after := ""
	for {
		p, err := c.VolumeRestores(ctx, v.Tenant, after)
		if err != nil {
			return nil, err
		}
		for _, r := range p.Items {
			if r.Source.Backup.Scope == v.Scope {
				out = append(out, r)
			}
		}
		if p.Next == "" {
			return out, nil
		}
		after = p.Next
	}
}

func findBackup(ctx context.Context, c sfc.Conn, v volumeView, id string) (sfc.VolumeBackupView, error) {
	bs, err := volumeBackups(ctx, c, v)
	if err != nil {
		return sfc.VolumeBackupView{}, err
	}
	for _, b := range bs {
		if b.ID == id {
			return b, nil
		}
	}
	return sfc.VolumeBackupView{}, &httpErr{http.StatusNotFound, "not-found", "no such backup"}
}

type volumeDetail struct {
	Volume   volumeView              `json:"volume"`
	Backups  []sfc.VolumeBackupView  `json:"backups"`
	Restores []sfc.VolumeRestoreView `json:"restores"`
}

// GET /t/{t}/volumes/{name}?app=
func (s *Server) handleVolumeDetail(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (volumeDetail, error) {
		v, err := findVolume(ctx, c, r.PathValue("t"), r.PathValue("name"), r.URL.Query().Get("app"))
		if err != nil {
			return volumeDetail{}, err
		}
		rows := []volumeView{v}
		fillWriters(ctx, c, rows)
		d := volumeDetail{Volume: rows[0], Backups: []sfc.VolumeBackupView{}, Restores: []sfc.VolumeRestoreView{}}
		if d.Backups, err = volumeBackups(ctx, c, v); err != nil {
			return d, err
		}
		if d.Restores, err = volumeRestores(ctx, c, v); err != nil {
			return d, err
		}
		return d, nil
	})
}

// volumeStep is a data store endpoint: build gets the volume row.
func (s *Server) volumeStep(w http.ResponseWriter, r *http.Request, ws *webSession, opID, app string, body any,
	build func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error)) {
	tenant, name := r.PathValue("t"), r.PathValue("name")
	s.sharedCreate(w, r, ws, opID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		v, err := findVolume(ctx, c, tenant, name, app)
		if err != nil {
			return "", nil, 0, "", err
		}
		action, payload, expected, err := build(ctx, c, v)
		return action, payload, expected, "volume/" + name, err
	})
}

// POST /t/{t}/volumes/{name}/backups {opId, app?, id?, maxBytes?, maxEntries?}
// → begin-volume-backup (app data stores only). id defaults to "b-" + opId;
// maxBytes (staging reservation) to the capacity, else twice the used
// bytes, at least 1 GiB, at most 1 TiB.
func (s *Server) handleVolumeBackup(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID       string `json:"opId"`
		App        string `json:"app,omitempty"`
		ID         string `json:"id,omitempty"`
		MaxBytes   uint64 `json:"maxBytes,omitempty"`
		MaxEntries uint32 `json:"maxEntries,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.volumeStep(w, r, ws, req.OpID, req.App, req, func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error) {
		if v.App == "" {
			return "", nil, 0, &httpErr{http.StatusConflict, "no-app", "sfcd backs up only data stores that belong to an app"}
		}
		id := req.ID
		if id == "" {
			id = "b-" + req.OpID
		}
		if !storageIDRE.MatchString(id) || len(id) > 61 {
			return "", nil, 0, invalid("id: lowercase letters, digits and -, starting with a letter (at most 61)")
		}
		maxBytes := req.MaxBytes
		if maxBytes == 0 {
			maxBytes = sizeHint(v)
		}
		if maxBytes < 1024 || maxBytes > 1<<40 {
			return "", nil, 0, invalid("maxBytes: 1024 .. 1 TiB")
		}
		entries := req.MaxEntries
		if entries == 0 {
			entries = 100000
		}
		if entries > 100000 {
			return "", nil, 0, invalid("maxEntries: 1 .. 100000")
		}
		src, err := c.VolumeBackupSource(ctx, v.Tenant, control.VolumeSelector{App: v.App, ID: v.Name})
		if err != nil {
			return "", nil, 0, err
		}
		q := control.VolumeBackupBegin{Scope: src.Source.Scope, ID: id, MaxBytes: maxBytes, MaxEntries: entries, Compatibility: src.Source.Compatibility}
		return sfc.ActionBeginVolumeBackup, q, src.VolumeRevision, nil
	})
}

// POST /t/{t}/volumes/{name}/backups/{id}/cancel {opId, app?} → cancel-volume-backup
// DELETE /t/{t}/volumes/{name}/backups/{id} {opId, app?} → delete-volume-backup
func (s *Server) handleVolumeBackupSelection(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID string `json:"opId"`
			App  string `json:"app,omitempty"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		body := struct {
			Action string
			Req    any
		}{action, req}
		id := r.PathValue("id")
		s.volumeStep(w, r, ws, req.OpID, req.App, body, func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error) {
			b, err := findBackup(ctx, c, v, id)
			if err != nil {
				return "", nil, 0, err
			}
			return action, control.VolumeBackupSelection{Scope: b.Source.Scope, ID: b.ID}, b.Revision, nil
		})
	}
}

// POST /t/{t}/volumes/{name}/restore {opId, app?, backup, target:{name, app?},
// capacityBytes?} → begin-volume-restore into a new data store on the
// backup's server (sfcd restores only into a new volume). The restore ID
// is "r-" + the first 8 characters of opId. MaxBytes is sfcd's lower
// bound, DataBytes + 8 KiB × Entries of the backup's receipt.
func (s *Server) handleVolumeRestore(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID   string `json:"opId"`
		App    string `json:"app,omitempty"`
		Backup string `json:"backup"`
		Target struct {
			Name     string `json:"name"`
			App      string `json:"app,omitempty"`
			Existing bool   `json:"existing,omitempty"`
		} `json:"target"`
		CapacityBytes uint64 `json:"capacityBytes,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.volumeStep(w, r, ws, req.OpID, req.App, req, func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error) {
		if req.Target.Existing {
			return "", nil, 0, &httpErr{http.StatusUnprocessableEntity, "restore-new-only", "sfcd restores only into a new data store"}
		}
		if !storageIDRE.MatchString(req.Target.Name) {
			return "", nil, 0, invalid("target.name: a new data store name")
		}
		b, err := findBackup(ctx, c, v, req.Backup)
		if err != nil {
			return "", nil, 0, err
		}
		if b.Source.Phase != "Ready" || b.Source.Receipt == nil {
			return "", nil, 0, &httpErr{http.StatusConflict, "backup-not-ready", "only a finished backup can be restored"}
		}
		app := req.Target.App
		if app == "" {
			app = b.Source.Scope.App
		}
		id := "r-" + req.OpID[:8]
		scope := volumes.Scope{Cluster: b.Source.Scope.Cluster, Tenant: v.Tenant, App: app, ID: req.Target.Name, Generation: 1}
		spec := volumes.NativeSpec{Schema: 1, Scope: scope, Node: b.Source.Node, NodeKey: b.Source.Owner, Materialization: "r-" + id,
			UID: b.Source.UID, GID: b.Source.GID, Mode: b.Source.Mode, Retain: true}
		if spec.Validate() != nil {
			return "", nil, 0, invalid("target: not a valid data store for this backup")
		}
		// sfcd's restoreNeed: the data plus 8 KiB for each archive entry
		maxBytes := max(b.Source.Receipt.DataBytes+uint64(b.Source.Receipt.Entries)*8192, 1024)
		if maxBytes > 1<<40 {
			return "", nil, 0, &httpErr{http.StatusUnprocessableEntity, "restore-too-large", "this backup needs more than 1 TiB to restore"}
		}
		if req.CapacityBytes != 0 && (req.CapacityBytes < maxBytes || req.CapacityBytes > 1<<40) {
			return "", nil, 0, invalid("capacityBytes: from the backup's restore size up to 1 TiB")
		}
		q := control.VolumeRestoreBegin{Backup: control.VolumeBackupSelection{Scope: b.Source.Scope, ID: b.ID}, ID: id, Target: spec, MaxBytes: maxBytes, CapacityBytes: req.CapacityBytes}
		return sfc.ActionBeginVolumeRestore, q, b.Revision, nil
	})
}

// POST /t/{t}/volumes/{name}/restores/{id}/cancel {opId, app?} → cancel-volume-restore
func (s *Server) handleVolumeRestoreCancel(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		App  string `json:"app,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	s.volumeStep(w, r, ws, req.OpID, req.App, req, func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error) {
		rs, err := volumeRestores(ctx, c, v)
		if err != nil {
			return "", nil, 0, err
		}
		for _, x := range rs {
			if x.ID == id {
				return sfc.ActionCancelVolumeRestore, control.VolumeRestoreSelection{Backup: x.Source.Backup, ID: x.ID}, x.Revision, nil
			}
		}
		return "", nil, 0, &httpErr{http.StatusNotFound, "not-found", "no such restore"}
	})
}

// PUT /t/{t}/volumes/{name}/capacity {opId, app?, bytes} → set-volume-capacity
// (system administrator; only grows).
func (s *Server) handleVolumeCapacity(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID  string `json:"opId"`
		App   string `json:"app,omitempty"`
		Bytes uint64 `json:"bytes"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.volumeStep(w, r, ws, req.OpID, req.App, req, func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error) {
		if req.Bytes == 0 || req.Bytes > 1<<40 {
			return "", nil, 0, invalid("bytes: up to 1 TiB")
		}
		if req.Bytes <= v.CapacityBytes {
			return "", nil, 0, &httpErr{http.StatusUnprocessableEntity, "capacity-grow-only", "capacity can only grow"}
		}
		return sfc.ActionSetVolumeCapacity, control.VolumeCapacity{Scope: v.Scope, Native: v.NativeBinding, Bytes: req.Bytes}, v.Revision, nil
	})
}

// DELETE /t/{t}/volumes/{name} {opId, app?} → delete-volume, or
// unregister-fixed-volume for a fixed data store (its data stays on disk).
func (s *Server) handleVolumeDelete(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		App  string `json:"app,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.volumeStep(w, r, ws, req.OpID, req.App, req, func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error) {
		action := sfc.ActionDeleteVolume
		if v.Kind == "fixed" {
			action = sfc.ActionUnregisterFixed
		}
		return action, v.Scope, v.Revision, nil
	})
}

type backupUsageView struct {
	Count        uint32 `json:"count"`
	Bytes        uint64 `json:"bytes"`
	StagingCount uint32 `json:"stagingCount"`
	StagingBytes uint64 `json:"stagingBytes"`
}

type backupLimitView struct {
	Node   string `json:"node"`
	Scope  string `json:"scope"`  // server (every workspace on the node) / workspace
	Hidden bool   `json:"hidden"` // server row without values (not a system administrator)
	backupUsageView
	Revision uint64          `json:"revision"`
	Used     backupUsageView `json:"used"`
}

func backupLimitOf(l control.PublicBackupLimit) backupLimitView {
	bv := backupLimitView{Node: l.Node, Scope: "workspace", Revision: l.Revision,
		backupUsageView: backupUsageView{l.Count, l.Bytes, l.StagingCount, l.StagingBytes},
		Used:            backupUsageView{l.UsedCount, l.UsedBytes, l.UsedStagingCount, l.UsedStagingBytes}}
	if l.Tenant == "" {
		bv.Scope = "server"
	}
	return bv
}

// GET /t/{t}/backup-limits?node= → {items}: the workspace's rows (PublicRead
// volume-backup-limits) and the server-wide rows. A system administrator
// gets the server-wide values (a second read with no tenant); anyone else
// only learns that one exists (hidden). sfcd admits a backup only when
// both rows of its node exist.
func (s *Server) handleBackupLimits(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, node := r.PathValue("t"), r.URL.Query().Get("node")
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string][]backupLimitView, error) {
		rows, err := readBackupLimits(ctx, c, tenant, node)
		if err != nil {
			return nil, err
		}
		out := []backupLimitView{}
		global := map[string]bool{}
		for _, l := range rows {
			out = append(out, backupLimitOf(l))
			if l.GlobalPresent {
				global[l.Node] = true
			}
		}
		server, err := readBackupLimits(ctx, c, "", node)
		switch {
		case err == nil:
			for _, l := range server {
				out = append(out, backupLimitOf(l))
				delete(global, l.Node)
			}
		case !isSfcCode(err, sfc.CodeDenied):
			return nil, err
		}
		for _, n := range slices.Sorted(maps.Keys(global)) {
			out = append(out, backupLimitView{Node: n, Scope: "server", Hidden: true})
		}
		return map[string][]backupLimitView{"items": out}, nil
	})
}

// PUT /t/{t}/backup-limits/{node} {opId, scope?(workspace|server), count,
// bytes, stagingCount?, stagingBytes?, expected?} → set-volume-backup-limit
// (system administrator). Expected defaults to the current row revision (0
// for a new row); a row's Original (move budget) is sent back as it is.
func (s *Server) handleBackupLimit(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID         string `json:"opId"`
		Scope        string `json:"scope,omitempty"`
		Count        uint32 `json:"count"`
		Bytes        uint64 `json:"bytes"`
		StagingCount uint32 `json:"stagingCount,omitempty"`
		StagingBytes uint64 `json:"stagingBytes,omitempty"`
		Expected     uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, node := r.PathValue("t"), r.PathValue("node")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		rowTenant := tenant
		switch req.Scope {
		case "", "workspace":
		case "server":
			rowTenant = ""
		default:
			return "", nil, 0, "", invalid("scope: workspace or server")
		}
		if req.Bytes > 1<<50 || req.StagingBytes > 1<<50 || req.StagingCount > 256 {
			return "", nil, 0, "", invalid("bytes, stagingBytes: up to 1 PiB; stagingCount: up to 256")
		}
		rows, err := readBackupLimits(ctx, c, rowTenant, node)
		if err != nil {
			return "", nil, 0, "", err
		}
		l := sfc.VolumeBackupLimit{Tenant: rowTenant, Node: node, Count: req.Count, Bytes: req.Bytes, StagingCount: req.StagingCount, StagingBytes: req.StagingBytes}
		// The row's Original (the move budget) goes back as it is: sfcd
		// refuses a change that drops it (ConditionFailed). REQ-66: the
		// PublicRead row carries it.
		expected := uint64(0)
		for _, row := range rows {
			if row.Tenant == rowTenant && row.Node == node {
				expected = row.Revision
				if row.Original != nil {
					o := *row.Original
					l.Original = &o
				}
			}
		}
		if req.Expected != 0 {
			expected = req.Expected
		}
		return sfc.ActionSetVolumeBackupLimit, l, expected, "backup-limit/" + node, nil
	})
}

// GET /t/{t}/volumes/{name}/users?app= → volume-users.
func (s *Server) handleVolumeUsers(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (resourceUsersView, error) {
		v, err := findVolume(ctx, c, r.PathValue("t"), r.PathValue("name"), r.URL.Query().Get("app"))
		if err != nil {
			return resourceUsersView{}, err
		}
		return readResourceUsers(ctx, c, "volume-users", v.Tenant, v.Name, v.App)
	})
}

// GET /t/{t}/networks/{name}/users → network-users.
func (s *Server) handleNetworkUsers(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (resourceUsersView, error) {
		return readResourceUsers(ctx, c, "network-users", r.PathValue("t"), r.PathValue("name"), "")
	})
}
