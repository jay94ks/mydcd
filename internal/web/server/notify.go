// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"github.com/jay94ks/seafield/internal/web/store"
)

// Notifications (UI-C0) are per-user copies of events. The event's
// authority stays with sfcd or the web feature that raised it; deleting a
// notification changes nothing else.

// Notification kinds.
const (
	NotifyOpFailed         = "op-failed"
	NotifyOpUnknown        = "op-unknown" // the user must settle it with result/resume
	NotifyDeployDone       = "deploy-done"
	NotifyMoveStarted      = "volume-move-started" // accepted and approved; the nodes copy now
	NotifyCertificate      = "certificate"         // issue/renewal failures, expiry warnings
	NotifyIncidentApproval = "incident-approval"   // an incident action waits for approval
	NotifyWebhookOff       = "webhook-off"         // a webhook turned off after failures
	NotifyMCPToolsChanged  = "mcp-tools-changed"   // an MCP server's tool catalog changed
	NotifyVPSDNS           = "vps-dns"             // DNS taken out for a stopped VPS server, or not put back
)

var notifyKinds = []string{NotifyOpFailed, NotifyOpUnknown, NotifyDeployDone, NotifyMoveStarted, NotifyCertificate, NotifyWebBackup, NotifyIncidentApproval, NotifyWebhookOff, NotifyMCPToolsChanged, NotifyVPSDNS}

// notify stores n for its user unless the user muted its kind or
// workspace.
func (s *Server) notify(n *store.Notification) {
	p, err := s.opt.Store.GetNotifyPrefs(n.User)
	if err == nil && (slices.Contains(p.MutedKinds, n.Kind) || (n.Tenant != "" && slices.Contains(p.MutedTenants, n.Tenant))) {
		return
	}
	n.ID = randomID(12)
	n.CreatedAt = s.now()
	if n.Severity == "" {
		n.Severity = "info"
	}
	if err := s.opt.Store.PutNotification(n); err != nil {
		s.log.Error("notify", "err", err, "kind", n.Kind)
	}
}

// saveOp stores an op and raises a notification when a top-level op
// settles badly (failed, unknown) or a deploy job finishes.
func (s *Server) saveOp(o *store.Op) error {
	prev := ""
	if old, err := s.opt.Store.GetOp(o.User, o.ID); err == nil {
		prev = old.State
	}
	if err := s.opt.Store.UpdateOp(o); err != nil {
		return err
	}
	if o.State != prev {
		s.standaloneOriginSettled(o)
	}
	if o.Parent != "" || o.State == prev {
		return nil
	}
	what := o.Action
	if o.Target != "" {
		what += " " + o.Target
	}
	link := "/ops/" + o.ID
	switch {
	case o.State == store.OpFailed || (o.State == store.OpRejected && (o.Action == "deploy" || o.Action == "volume-move")):
		s.notify(&store.Notification{User: o.User, Kind: NotifyOpFailed, Severity: "error", Tenant: o.Tenant,
			Title: fmt.Sprintf("작업 실패: %s", what), Body: o.ErrorCode, Link: link})
	case o.State == store.OpUnknown:
		s.notify(&store.Notification{User: o.User, Kind: NotifyOpUnknown, Severity: "warning", Tenant: o.Tenant, Action: true,
			Title: fmt.Sprintf("결과 확인 필요: %s", what), Body: "결과를 알 수 없습니다. 같은 작업으로 결과를 확인하세요.", Link: link})
	case o.State == store.OpApplied && o.Action == "deploy":
		s.notify(&store.Notification{User: o.User, Kind: NotifyDeployDone, Tenant: o.Tenant,
			Title: fmt.Sprintf("배포 완료: %s", o.Target), Link: link})
	case o.State == store.OpApplied && o.Action == "volume-move":
		s.notify(&store.Notification{User: o.User, Kind: NotifyMoveStarted, Tenant: o.Tenant,
			Title: fmt.Sprintf("저장소 옮기기 시작: %s", o.Target), Body: "서버들이 자료를 복사하고 있습니다. 진행 상태는 저장소 화면에서 볼 수 있습니다.", Link: link})
	}
	return nil
}

// GET /notifications?unread=1&limit=
func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request, ws *webSession) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "bad-request", "limit must be 1..500")
			return
		}
		limit = n
	}
	items, unread, err := s.opt.Store.ListNotifications(ws.user.ID, r.URL.Query().Get("unread") == "1", limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if items == nil {
		items = []*store.Notification{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "unread": unread})
}

// POST /notifications/{id}/read and POST /notifications/read-all
func (s *Server) handleNotificationRead(w http.ResponseWriter, r *http.Request, ws *webSession) {
	err := s.opt.Store.MarkNotificationsRead(ws.user.ID, r.PathValue("id"), s.now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "missing", "no such notification")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleNotificationReadAll(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if err := s.opt.Store.MarkNotificationsRead(ws.user.ID, "", s.now()); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET/PUT /notify-prefs
func (s *Server) handleGetNotifyPrefs(w http.ResponseWriter, r *http.Request, ws *webSession) {
	p, err := s.opt.Store.GetNotifyPrefs(ws.user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"prefs": nonNilPrefs(p), "kinds": notifyKinds})
}

func (s *Server) handlePutNotifyPrefs(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Prefs store.NotifyPrefs `json:"prefs"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	for _, k := range req.Prefs.MutedKinds {
		if !slices.Contains(notifyKinds, k) {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "unknown notification kind "+k)
			return
		}
	}
	if len(req.Prefs.MutedTenants) > 1000 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "too many workspaces")
		return
	}
	if err := s.opt.Store.PutNotifyPrefs(ws.user.ID, &req.Prefs); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"prefs": nonNilPrefs(&req.Prefs)})
}

func nonNilPrefs(p *store.NotifyPrefs) *store.NotifyPrefs {
	if p.MutedKinds == nil {
		p.MutedKinds = []string{}
	}
	if p.MutedTenants == nil {
		p.MutedTenants = []string{}
	}
	return p
}
