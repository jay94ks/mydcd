// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Web data auto-backup (UI-C1 자동 백업): a gzip copy of the web DB, sealed
// with the web's seal key, written as a file into a fixed tenant volume
// under mydc-web-backups/, the oldest
// copies beyond keep removed, and a restore staged straight from such a
// file. The schedule and the copies are web-own work; the files are REQ-28
// volume files (volume_file_jobs.go), so every list/get/put/delete is a
// signed volume-file op and mydcd judges who may touch the volume. The copy holds every workspace's
// web data, so it is sealed: whoever can read the volume sees ciphertext
// only, and only a web with the same seal key restores it.
//
// A run needs a mydcd session to sign with. "Run now" uses the
// administrator's own session. Scheduled runs log in as the web's
// automation account (automation.go, REQ-9 mock); mydcd decides whether that
// account may write the folder. Without one, or when its login fails, the
// due run is recorded (automation-account-missing / automation-login-failed)
// and the administrator who set it up is told; nothing is written.

const (
	autoBackupPrefix = "mydc-web-backups/"
	backupPurpose    = "web-backup"
	NotifyWebBackup  = "web-backup"
)

var (
	backupAtRE   = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	backupFileRE = regexp.MustCompile(`^web-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{4}Z\.db\.gz\.sealed$`)
)

type autoBackupState struct {
	mu      sync.Mutex // the stored row
	running atomic.Bool
}

func (s *Server) autoBackupRow() store.AutoBackup {
	v, err := s.opt.Store.GetAutoBackup()
	if err != nil {
		s.log.Error("load auto-backup", "err", err)
	}
	if v == nil {
		return store.AutoBackup{At: "03:00", Keep: 7}
	}
	return *v
}

// nextSlot is the first schedule time after now (server local time).
func nextSlot(now time.Time, at string) time.Time {
	var h, m int
	fmt.Sscanf(at, "%d:%d", &h, &m)
	l := now.Local()
	t := time.Date(l.Year(), l.Month(), l.Day(), h, m, 0, 0, l.Location())
	if !t.After(now) {
		t = t.AddDate(0, 0, 1)
	}
	return t
}

type autoBackupView struct {
	Enabled bool   `json:"enabled"`
	At      string `json:"at"`
	Keep    int    `json:"keep"`
	Tenant  string `json:"tenant,omitempty"`
	Volume  string `json:"volume,omitempty"`
	Prefix  string `json:"prefix"`
	Running bool   `json:"running"`
	// Sealed: copies are sealed with the seal key; SealReady false means
	// run and restore-from answer 503 seal-unavailable.
	Sealed    bool                 `json:"sealed"`
	SealReady bool                 `json:"sealReady"`
	Last      *store.AutoBackupRun `json:"last,omitempty"`
	Next      string               `json:"next,omitempty"`
	// Account: the automation account scheduled runs sign with ("" when
	// none is set up).
	Account string `json:"account,omitempty"`
	// AccountID: its user ID, known after its first successful login
	// (POST /system/automation/check), for file-grants.
	AccountID string `json:"accountId,omitempty"`
	// Granted: whether the automation account holds an active file grant on
	// prefix of the volume (REQ-49 volume-file-grants, read with the
	// caller's session). Left out when there is no account or mydcd does
	// not tell the caller.
	Granted   *bool  `json:"granted,omitempty"`
	UpdatedBy string `json:"updatedBy,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

func (s *Server) viewAutoBackup(v store.AutoBackup) autoBackupView {
	out := autoBackupView{Enabled: v.Enabled, At: v.At, Keep: v.Keep, Tenant: v.Tenant, Volume: v.Volume, Prefix: autoBackupPrefix,
		Running: s.backup.running.Load(), Sealed: true, SealReady: s.opt.Seal.Ready(), Last: v.Last, UpdatedBy: v.UpdatedBy}
	if v.Enabled {
		out.Next = rfc3339(nextSlot(s.now(), v.At))
	}
	if a := s.automationRow(); a != nil {
		out.Account, out.AccountID = a.Username, a.UserID
	}
	if !v.UpdatedAt.IsZero() {
		out.UpdatedAt = rfc3339(v.UpdatedAt)
	}
	return out
}

// GET /system/auto-backup (system admin) → {enabled, at, keep, tenant?,
// volume?, prefix, running, last?:{at, ok, bytes?, path?, error?, by?},
// next?, updatedBy?, updatedAt?}.
func (s *Server) handleGetAutoBackup(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	v := s.viewAutoBackup(s.autoBackupRow())
	s.addGranted(r, ws, &v)
	writeJSON(w, http.StatusOK, v)
}

// PUT /system/auto-backup {enabled, at("HH:MM", server time), keep(1..365),
// tenant, volume} → the same shape. The volume must be a fixed volume no
// app owns (checked with the caller's session). Delegating the folder to
// the automation account (file-grants) is a separate op.
func (s *Server) handlePutAutoBackup(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Enabled bool   `json:"enabled"`
		At      string `json:"at"`
		Keep    int    `json:"keep"`
		Tenant  string `json:"tenant"`
		Volume  string `json:"volume"`
	}
	if !readJSON(w, r, &req) || !s.requireAdmin(w, r, ws) {
		return
	}
	switch {
	case !backupAtRE.MatchString(req.At):
		writeError(w, http.StatusUnprocessableEntity, "invalid", "at: HH:MM (server time)")
		return
	case req.Keep < 1 || req.Keep > 365:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "keep: 1..365")
		return
	case req.Enabled && (req.Tenant == "" || req.Volume == ""):
		writeError(w, http.StatusUnprocessableEntity, "invalid", "tenant and volume are required to turn it on")
		return
	}
	if req.Tenant != "" || req.Volume != "" {
		ctx, cancel := s.callCtx(r)
		err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error { return backupVolume(ctx, c, req.Tenant, req.Volume) })
		cancel()
		if err != nil {
			s.writeOpOutcome(w, ws, nil, 0, err)
			return
		}
	}
	s.backup.mu.Lock()
	cur := s.autoBackupRow()
	before := s.viewAutoBackup(cur)
	cur.Enabled, cur.At, cur.Keep, cur.Tenant, cur.Volume = req.Enabled, req.At, req.Keep, req.Tenant, req.Volume
	cur.UpdatedByID, cur.UpdatedBy, cur.UpdatedAt = ws.user.ID, ws.user.Username, s.now()
	// slots before this change are not due
	cur.Slot = s.now()
	err := s.opt.Store.PutAutoBackup(&cur)
	s.backup.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	after := s.viewAutoBackup(cur)
	s.audit(ws, "", "web-backup", "auto-backup", "", before, after)
	s.addGranted(r, ws, &after)
	writeJSON(w, http.StatusOK, after)
}

// backupVolume: a fixed volume of the tenant that no app owns.
func backupVolume(ctx context.Context, c mydc.Conn, tenant, volume string) error {
	after := ""
	for {
		p, err := volumePage(ctx, c, tenant, after)
		if err != nil {
			return err
		}
		for _, v := range p.Items {
			if v.Name != volume {
				continue
			}
			if v.Kind != "fixed" || v.App != "" {
				return invalid("volume: a fixed volume no app owns")
			}
			return nil
		}
		if p.Next == "" {
			return &httpErr{http.StatusNotFound, "not-found", "no such volume in the workspace"}
		}
		after = p.Next
	}
}

// POST /system/auto-backup/run → 202 {running: true}: one backup now with
// the administrator's session (409 running while one runs). last changes
// when it ends.
func (s *Server) handleRunAutoBackup(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	cfg := s.autoBackupRow()
	if cfg.Tenant == "" || cfg.Volume == "" {
		writeError(w, http.StatusConflict, "not-configured", "choose the workspace and volume first")
		return
	}
	if !s.opt.Seal.Ready() {
		writeError(w, http.StatusServiceUnavailable, "seal-unavailable", "backups are sealed with the web's seal key, which is not ready")
		return
	}
	if !s.backup.running.CompareAndSwap(false, true) {
		writeError(w, http.StatusConflict, "running", "a backup is already running")
		return
	}
	go func() {
		defer s.backup.running.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		run := s.backupNow(ctx, ws, cfg)
		s.backup.mu.Lock()
		cur := s.autoBackupRow()
		cur.Last = &run
		_ = s.opt.Store.PutAutoBackup(&cur)
		s.backup.mu.Unlock()
		s.log.Info("web auto-backup", "user", ws.user.Username, "ok", run.OK, "path", run.Path, "err", run.Error)
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"running": true})
}

// backupNow writes one copy and removes the oldest beyond keep.
func (s *Server) backupNow(ctx context.Context, ws *webSession, cfg store.AutoBackup) store.AutoBackupRun {
	now := s.now()
	run := store.AutoBackupRun{At: now, By: ws.user.Username}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := s.opt.Store.Backup(func(int64) io.Writer { return zw }); err != nil {
		run.Error = "read web data: " + err.Error()
		return run
	}
	if err := zw.Close(); err != nil {
		run.Error = err.Error()
		return run
	}
	sealed, err := s.opt.Seal.SealBlob(backupPurpose, buf.Bytes())
	buf.Reset()
	if err != nil {
		run.Error = "seal: " + err.Error()
		return run
	}
	if len(sealed) > mydc.MaxVolumeFileBytes {
		run.Error = fmt.Sprintf("the sealed web data (%d bytes) is larger than a volume file may be", len(sealed))
		return run
	}
	name := autoBackupPrefix + "web-" + now.UTC().Format("2006-01-02T1504") + "Z.db.gz.sealed"
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		q := control.VolumeFileQuery{Volume: cfg.Volume, Path: name, Method: mydc.ActionPutVolumeFile, Size: int64(len(sealed)),
			MaxBytes: mydc.MaxVolumeFileBytes, Digest: sha256.Sum256(sealed), Overwrite: true}
		res, err := s.runVolumeFile(ctx, c, ws, vfJob{tenant: cfg.Tenant, q: q, body: sealed, o: newVolumeFileOp(ws, "", cfg.Tenant, q, backupReason)})
		if err != nil {
			return err
		}
		if res.reply.Code != "ok" {
			return fmt.Errorf("volume-file-put: %s", res.reply.Code)
		}
		return s.pruneBackups(ctx, c, ws, cfg)
	})
	run.Path, run.Bytes = name, int64(len(sealed))
	clear(sealed)
	if err != nil {
		run.Error = err.Error()
		return run
	}
	run.OK = true
	return run
}

var backupReason = &store.OpReason{Reason: "web-backup"}

// pruneBackups removes the oldest web-*.db.gz.sealed copies beyond keep.
func (s *Server) pruneBackups(ctx context.Context, c mydc.Conn, ws *webSession, cfg store.AutoBackup) error {
	entries, _, err := s.volumeFileList(ctx, c, ws, cfg.Tenant, cfg.Volume, autoBackupPrefix, backupReason, incidentMaxPages)
	if err != nil {
		return err
	}
	var names []string
	for _, f := range entries {
		if rest, ok := strings.CutPrefix(f.Path, autoBackupPrefix); ok && backupFileRE.MatchString(rest) {
			names = append(names, f.Path)
		}
	}
	slices.Sort(names) // the names sort by time
	for len(names) > cfg.Keep {
		q := control.VolumeFileQuery{Volume: cfg.Volume, Path: names[0], Method: mydc.ActionDeleteVolumeFile}
		res, err := s.runVolumeFile(ctx, c, ws, vfJob{tenant: cfg.Tenant, q: q, o: newVolumeFileOp(ws, "", cfg.Tenant, q, backupReason)})
		if err == nil && res.reply.Code != "ok" && res.reply.Code != "not-found" {
			err = errors.New(res.reply.Code)
		}
		if err != nil {
			return fmt.Errorf("remove old copy %s: %w", names[0], err)
		}
		names = names[1:]
	}
	return nil
}

// autoBackupTick handles a due schedule slot: the run logs in as the
// automation account. When there is none, the login fails or a run is
// already going, the slot is recorded with the reason and the person who set
// it up is told once.
func (s *Server) autoBackupTick() {
	s.backup.mu.Lock()
	defer s.backup.mu.Unlock()
	cfg := s.autoBackupRow()
	if !cfg.Enabled {
		return
	}
	now := s.now()
	due := nextSlot(now, cfg.At).AddDate(0, 0, -1)
	if !due.After(cfg.Slot) {
		return
	}
	cfg.Slot = due
	fail := func(code string) {
		cfg.Last = &store.AutoBackupRun{At: now, Error: code}
		if err := s.opt.Store.PutAutoBackup(&cfg); err != nil {
			s.log.Error("auto-backup slot", "err", err)
		}
		s.backupFailed(cfg, code)
	}
	switch {
	case s.automationRow() == nil:
		fail(ErrAutomationMissing)
		return
	case !s.opt.Seal.Ready():
		fail("seal-unavailable")
		return
	case !s.backup.running.CompareAndSwap(false, true):
		fail("running")
		return
	}
	if err := s.opt.Store.PutAutoBackup(&cfg); err != nil {
		s.backup.running.Store(false)
		s.log.Error("auto-backup slot", "err", err)
		return
	}
	go func() {
		defer s.backup.running.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		var run store.AutoBackupRun
		as, err := s.automationLogin(ctx, backupPurpose)
		if err != nil {
			run = store.AutoBackupRun{At: s.now(), Error: ErrAutomationLogin + ": " + automationErrorCode(err)}
		} else {
			run = s.backupNow(ctx, as, cfg)
			as.conn.Close()
		}
		s.backup.mu.Lock()
		cur := s.autoBackupRow()
		cur.Last = &run
		_ = s.opt.Store.PutAutoBackup(&cur)
		s.backup.mu.Unlock()
		s.log.Info("web auto-backup (scheduled)", "ok", run.OK, "path", run.Path, "err", run.Error)
		if !run.OK {
			s.backupFailed(cur, run.Error)
		}
	}()
}

func (s *Server) backupFailed(cfg store.AutoBackup, code string) {
	if cfg.UpdatedByID == "" {
		return
	}
	body := "예약된 백업을 쓰지 못했습니다(" + code + "). 설정 화면에서 '지금 백업'을 누르거나 자동 작업 계정을 확인해 주세요."
	if code == ErrAutomationMissing {
		body = "자동 작업 계정이 없어 예약된 백업을 쓰지 못했습니다. 설정 화면에서 자동 작업 계정을 만들거나 '지금 백업'을 눌러 주세요."
	}
	s.notify(&store.Notification{User: cfg.UpdatedByID, Kind: NotifyWebBackup, Severity: "warning", Action: true,
		Title: "웹 데이터 자동 백업을 하지 못했습니다", Body: body, Link: "/settings"})
}

// POST /system/restore-from {tenant, volume, path} → 202 {restorePending,
// bytes}, as POST /system/restore: the daemon reads a sealed backup file
// from the volume with the administrator's session, opens it with the seal
// key, checks it and stages it for the next start. A file sealed with
// another key is 422 seal-key.
func (s *Server) handleRestoreFrom(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Tenant string `json:"tenant"`
		Volume string `json:"volume"`
		Path   string `json:"path"`
	}
	if !readJSON(w, r, &req) || !s.requireAdmin(w, r, ws) {
		return
	}
	if rest, ok := strings.CutPrefix(req.Path, autoBackupPrefix); !ok || rest == "" || path.Clean(req.Path) != req.Path || strings.Contains(rest, "/") {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "path: a file directly under "+autoBackupPrefix)
		return
	}
	if s.opt.DataDir == "" {
		writeError(w, http.StatusNotImplemented, "unsupported", "no data folder")
		return
	}
	if !s.opt.Seal.Ready() {
		writeError(w, http.StatusServiceUnavailable, "seal-unavailable", "backups open with the web's seal key, which is not ready")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var data []byte
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		res, err := s.volumeFileGet(ctx, c, ws, req.Tenant, req.Volume, req.Path, mydc.MaxVolumeFileBytes, backupReason)
		if err != nil {
			return volumeFileErr(err)
		}
		if err := replyErr(res.reply); err != nil {
			return err
		}
		data = res.data
		return nil
	})
	if err != nil {
		s.writeVolumeFileError(w, ws, err)
		return
	}
	plain, err := s.opt.Seal.OpenBlob(backupPurpose, data)
	clear(data)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "seal-key", "the file does not open with this web's seal key: "+err.Error())
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "the backup is not a readable gzip")
		return
	}
	n, err := s.stageRestore(io.LimitReader(zr, maxRestore+1))
	if err != nil {
		var he *httpErr
		if errors.As(err, &he) {
			writeError(w, he.status, he.code, he.msg)
		} else {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
		}
		return
	}
	s.audit(ws, "", "web-backup", "restore-staged", req.Tenant+"/"+req.Volume+"/"+req.Path, nil, map[string]any{"bytes": n})
	writeJSON(w, http.StatusAccepted, map[string]any{"restorePending": true, "bytes": n})
}

// stageRestore checks a web DB file and stages it as RestoreFile.
func (s *Server) stageRestore(src io.Reader) (int64, error) {
	tmp, err := os.CreateTemp(s.opt.DataDir, ".restore-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	_ = tmp.Chmod(0o600)
	n, err := io.Copy(tmp, src)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return 0, &httpErr{http.StatusBadRequest, "bad-request", err.Error()}
	case n > maxRestore:
		return 0, &httpErr{http.StatusRequestEntityTooLarge, "too-large", "the web data file is larger than 512 MiB"}
	}
	if err := store.Check(tmp.Name()); err != nil {
		return 0, &httpErr{http.StatusUnprocessableEntity, "invalid", err.Error()}
	}
	if err := os.Rename(tmp.Name(), filepath.Join(s.opt.DataDir, RestoreFile)); err != nil {
		return 0, err
	}
	return n, nil
}

// newOpID is a lowercase UUID v4 for an op the daemon starts itself.
func newOpID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// addGranted fills v.Granted from mydcd's grant list for the volume.
func (s *Server) addGranted(r *http.Request, ws *webSession, v *autoBackupView) {
	a := s.automationRow()
	if a == nil || a.UserID == "" || v.Tenant == "" || v.Volume == "" {
		return // the account's user ID is known after its first login
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var rows []control.PublicFileGrant
	if err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		rows, err = readFileGrants(ctx, c, v.Tenant, v.Volume, "")
		return err
	}); err != nil {
		return
	}
	ok := false
	for _, g := range rows {
		if g.Volume == v.Volume && strings.HasPrefix(autoBackupPrefix, g.Prefix) && g.AccountEnabled && g.VolumePresent && g.User == a.UserID {
			ok = true
		}
	}
	v.Granted = &ok
}
