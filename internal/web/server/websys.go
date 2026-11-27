// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/jay94ks/seafield/internal/web/seal"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Web app settings (UI-C1), the web settings change log (UI-A3) and the
// web data backup. Everything here is the web app's own data: none of it
// changes the cluster.

const (
	defaultAuditDays  = 365
	defaultNotifyDays = 90
	defaultHookDays   = 30
	defaultMCPDays    = 90
	maxRestore        = 512 << 20
	// RestoreFile is the staged restore in the data folder. The daemon
	// swaps it in on its next start (see store.ApplyRestore).
	RestoreFile = "web.db.restore"
)

// settings returns the effective web settings (defaults filled in).
func (s *Server) settings() store.Settings {
	var v store.Settings
	if p := s.cur.Load(); p != nil {
		v = *p
	}
	if v.OpRetentionDays == 0 {
		v.OpRetentionDays = int(s.opt.OpRetention / (24 * time.Hour))
		if v.OpRetentionDays == 0 {
			v.OpRetentionDays = 1
		}
	}
	if v.AuditRetentionDays == 0 {
		v.AuditRetentionDays = defaultAuditDays
	}
	if v.NotificationRetentionDays == 0 {
		v.NotificationRetentionDays = defaultNotifyDays
	}
	if v.AllowKeyLogin == nil {
		yes := true
		v.AllowKeyLogin = &yes
	}
	if v.WebhookDeliveryRetentionDays == 0 {
		v.WebhookDeliveryRetentionDays = defaultHookDays
	}
	if v.MCPCallRetentionDays == 0 {
		v.MCPCallRetentionDays = defaultMCPDays
	}
	if v.TrashRetentionDays == 0 {
		v.TrashRetentionDays = defaultTrashDays
	}
	return v
}

func (s *Server) keyLoginAllowed() bool { return *s.settings().AllowKeyLogin }

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func (s *Server) loadSettings() {
	v, err := s.opt.Store.GetSettings()
	if err != nil {
		s.log.Error("load web settings", "err", err)
		return
	}
	if v != nil {
		s.cur.Store(v)
	}
}

func (s *Server) sessionLimits() (time.Duration, time.Duration) {
	v := s.settings()
	return time.Duration(v.SessionMaxHours) * time.Hour, time.Duration(v.SessionIdleMinutes) * time.Minute
}

// prune runs hourly: settled ops, ended session rows, audit entries and
// notifications past their retention.
func (s *Server) prune() {
	v := s.settings()
	now := s.now()
	if n, err := s.opt.Store.PruneOps(now.Add(-days(v.OpRetentionDays))); err != nil {
		s.log.Error("prune ops", "err", err)
	} else if n > 0 {
		s.log.Info("pruned settled ops", "count", n)
	}
	_ = s.opt.Store.PruneSessions(now.Add(-days(v.OpRetentionDays)))
	if _, err := s.opt.Store.PruneAudit(now.Add(-days(v.AuditRetentionDays))); err != nil {
		s.log.Error("prune audit", "err", err)
	}
	if _, err := s.opt.Store.PruneNotifications(now.Add(-days(v.NotificationRetentionDays))); err != nil {
		s.log.Error("prune notifications", "err", err)
	}
	if _, err := s.opt.Store.PruneTrash(now); err != nil {
		s.log.Error("prune deleted", "err", err)
	}
}

// requireAdmin asks sfcd whether the user is a system administrator now
// (not only at login).
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request, ws *webSession) bool {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var who sfc.Whoami
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		who, err = c.Whoami(ctx)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return false
	}
	if !who.User.SystemAdmin {
		writeError(w, http.StatusForbidden, "denied", "system administrators only")
		return false
	}
	return true
}

// audit records a web settings change. before/after are JSON values with
// secrets already removed (callers record only that a secret changed).
func (s *Server) audit(ws *webSession, tenant, area, action, target string, before, after any) {
	e := &store.AuditEntry{ID: randomID(12), At: s.now(), User: ws.user.ID, Username: ws.user.Username, Tenant: tenant, Area: area, Action: action, Target: target}
	if before != nil {
		e.Before, _ = json.Marshal(before)
	}
	if after != nil {
		e.After, _ = json.Marshal(after)
	}
	if err := s.opt.Store.AppendAudit(e); err != nil {
		s.log.Error("audit", "err", err, "area", area, "action", action)
	}
}

type sealKind struct {
	Kind     string `json:"kind"`
	Count    int    `json:"count"`
	Modified string `json:"modified"`
}

func (s *Server) sealSummary() map[string]any {
	st, reason := s.opt.Seal.Status()
	out := map[string]any{"state": st, "ready": st == seal.StateReady, "reason": reason, "keySource": s.opt.SealKeySource}
	if k := s.opt.Seal.Keys(); k.Dir != "" {
		out["dir"] = k.Dir
		if k.Key != "" {
			out["fingerprint"] = k.Key
		}
		if k.Next != "" {
			out["next"] = map[string]any{"fingerprint": k.Next}
		}
	}
	if es, err := s.opt.Seal.Entries(); err == nil {
		by := map[string]*sealKind{}
		for _, e := range es {
			k := by[e.Kind]
			if k == nil {
				k = &sealKind{Kind: e.Kind}
				by[e.Kind] = k
			}
			k.Count++
			if m := rfc3339(e.Modified); m > k.Modified {
				k.Modified = m
			}
		}
		kinds := make([]sealKind, 0, len(by))
		for _, k := range by {
			kinds = append(kinds, *k)
		}
		sort.Slice(kinds, func(i, j int) bool { return kinds[i].Kind < kinds[j].Kind })
		out["kinds"] = kinds
		out["files"] = len(es)
	}
	return out
}

// GET /system/settings
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	v := s.settings()
	_, restoreErr := os.Stat(filepath.Join(s.opt.DataDir, RestoreFile))
	connected, ver := s.backendVersion(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": v,
		"defaults": map[string]any{"sessionMaxHours": 0, "sessionIdleMinutes": 0, "opRetentionDays": int(s.opt.OpRetention / (24 * time.Hour)), "auditRetentionDays": defaultAuditDays, "notificationRetentionDays": defaultNotifyDays,
			"allowKeyLogin": true, "maxSessionsPerUser": 0, "webhookDeliveryRetentionDays": defaultHookDays, "mcpCallRetentionDays": defaultMCPDays, "trashRetentionDays": defaultTrashDays},
		"info": map[string]any{
			"version":        s.opt.Version,
			"schema":         store.SchemaVersion,
			"dbBytes":        s.opt.Store.Size(),
			"dbPath":         s.opt.DBPath,
			"socket":         s.opt.Socket,
			"connected":      connected,
			"sfcdVersion":    ver,
			"restorePending": s.opt.DataDir != "" && restoreErr == nil,
		},
		"seal": s.sealSummary(),
	})
}

type sfcdVersionView struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildTime string `json:"buildTime,omitempty"`
	Protocol  string `json:"protocol"`
	Node      string `json:"node,omitempty"`
}

// backendVersion: whether a new sfcd connection opens now and, if so, the
// server-version it answers (REQ-48; read before login, then closed).
func (s *Server) backendVersion(ctx context.Context) (bool, *sfcdVersionView) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	c, err := s.opt.Client.Dial(ctx)
	if err != nil {
		return false, nil
	}
	defer c.Close()
	v, err := c.ServerVersion(ctx)
	if err != nil {
		return true, nil
	}
	// sfcd's own answer: Protocol is the SFCP number, BuildTime
	// its vcs.time (RFC 3339) when known; it names no node.
	return true, &sfcdVersionView{Version: v.Version, Commit: v.Commit, Protocol: strconv.Itoa(int(v.Protocol)), BuildTime: v.BuildTime}
}

func checkRange(name string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s must be between %d and %d", name, lo, hi)
	}
	return nil
}

// PUT /system/settings {settings}
func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Settings store.Settings `json:"settings"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	n := req.Settings
	for _, err := range []error{
		checkRange("sessionMaxHours", n.SessionMaxHours, 0, 24*30),
		checkRange("sessionIdleMinutes", n.SessionIdleMinutes, 0, 24*60),
		checkRange("opRetentionDays", n.OpRetentionDays, 1, 3650),
		checkRange("auditRetentionDays", n.AuditRetentionDays, 30, 3650),
		checkRange("notificationRetentionDays", n.NotificationRetentionDays, 1, 3650),
		checkRange("maxSessionsPerUser", n.MaxSessionsPerUser, 0, 50),
		checkRange("webhookDeliveryRetentionDays", n.WebhookDeliveryRetentionDays, 0, 3650),
		checkRange("mcpCallRetentionDays", n.MCPCallRetentionDays, 0, 3650),
		checkRange("trashRetentionDays", n.TrashRetentionDays, 0, 30),
	} {
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
			return
		}
	}
	before := s.settings()
	n.UpdatedBy, n.UpdatedAt = ws.user.Username, s.now()
	if err := s.opt.Store.PutSettings(&n); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.cur.Store(&n)
	before.UpdatedBy, before.UpdatedAt = "", time.Time{}
	after := n
	after.UpdatedBy, after.UpdatedAt = "", time.Time{}
	s.audit(ws, "", "web-settings", "update", "", before, after)
	if n.MaxSessionsPerUser > 0 {
		s.sessions.capAll(n.MaxSessionsPerUser)
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": s.settings()})
}

// POST /system/seal/reset {confirm:"reset"}: drop every sealed secret and
// start over with the current key (the old key was lost).
func (s *Server) handleSealReset(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	if req.Confirm != "reset" {
		writeError(w, http.StatusBadRequest, "confirm-mismatch", `type "reset" to confirm`)
		return
	}
	before, _ := s.opt.Seal.Status()
	if err := s.opt.Seal.Reset(); err != nil {
		if errors.Is(err, seal.ErrUnavailable) {
			writeError(w, http.StatusConflict, "no-key", "start the daemon with SFC_WEB_SEAL_KEY first")
			return
		}
		if errors.Is(err, seal.ErrReady) {
			writeError(w, http.StatusConflict, "seal-ready", "sealed storage works; reset is only for a lost key")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "seal", "reset", "", map[string]any{"state": before}, map[string]any{"state": seal.StateReady})
	writeJSON(w, http.StatusOK, s.sealSummary())
}

// GET /system/backup: the whole web DB as one file. Sealed files are a
// separate folder and are never included.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	name := "sfc-web-" + s.now().UTC().Format("20060102-150405") + ".db"
	// Size and content come from the same read transaction, so a write
	// committed meanwhile cannot make the length disagree with the body.
	_, err := s.opt.Store.Backup(func(size int64) io.Writer {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		return w
	})
	if err != nil {
		s.log.Error("backup", "err", err)
		return
	}
	s.audit(ws, "", "web-backup", "download", name, nil, nil)
}

// POST /system/restore (body: a backup file). The file is checked and
// staged; it replaces the web DB on the next start. Live data is not
// touched now.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	if s.opt.DataDir == "" {
		writeError(w, http.StatusNotImplemented, "unsupported", "no data folder")
		return
	}
	n, err := s.stageRestore(http.MaxBytesReader(w, r.Body, maxRestore))
	if err != nil {
		var he *httpErr
		if errors.As(err, &he) {
			writeError(w, he.status, he.code, he.msg)
		} else {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
		}
		return
	}
	s.audit(ws, "", "web-backup", "restore-staged", "", nil, map[string]any{"bytes": n})
	writeJSON(w, http.StatusAccepted, map[string]any{"restorePending": true, "bytes": n})
}

// DELETE /system/restore: cancel a staged restore.
func (s *Server) handleCancelRestore(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	err := os.Remove(filepath.Join(s.opt.DataDir, RestoreFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err == nil {
		s.audit(ws, "", "web-backup", "restore-cancelled", "", nil, nil)
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /audit?tenant=&before=&limit= — system administrators see every
// entry; others see entries of workspaces they belong to.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "bad-request", "limit must be 1..1000")
			return
		}
		limit = n
	}
	var before time.Time
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad-request", "before must be RFC 3339")
			return
		}
		before = t
	}
	ctx, cancel := s.callCtx(r)
	var who sfc.Whoami
	var tenants []sfc.TenantView
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		if who, err = c.Whoami(ctx); err != nil {
			return err
		}
		tenants, err = c.Tenants(ctx)
		return err
	})
	cancel()
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	mine := map[string]bool{}
	for _, t := range tenants {
		mine[t.ID] = true
	}
	want := q.Get("tenant")
	items, err := s.opt.Store.ListAudit(before, limit, func(e *store.AuditEntry) bool {
		if want != "" && e.Tenant != want {
			return false
		}
		return who.User.SystemAdmin || (e.Tenant != "" && mine[e.Tenant])
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if items == nil {
		items = []*store.AuditEntry{}
	}
	var next string
	if len(items) == limit {
		next = items[len(items)-1].At.Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next": next})
}
