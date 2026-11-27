// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/web/provlog"
)

// Provider diagnostic log (docs/reference/web-api/…-provider-log.md). Off by
// default. A system administrator turns it on from 웹 앱 설정; that makes a
// bearer token, shown once, for the debugging tool (`sfc-web provider-log`).
// Collection and the token end after an idle hour (provlog.IdleLimit).

func (s *Server) providerLog() *provlog.Log { return s.opt.ProviderLog }

// GET /api/v1/diag/provider-log/state
func (s *Server) handleProviderLogState(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	if s.providerLog() == nil {
		writeError(w, http.StatusConflict, "not-supported", "the provider log is not available")
		return
	}
	writeJSON(w, http.StatusOK, s.providerLog().State())
}

// POST /api/v1/diag/provider-log/enable → {token, state}. The token is
// shown only in this response.
func (s *Server) handleProviderLogEnable(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	l := s.providerLog()
	if l == nil {
		writeError(w, http.StatusConflict, "not-supported", "the provider log is not available")
		return
	}
	tok, st, err := l.Enable(ws.user.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "diag", "enable-provider-log", "provider-log", nil, map[string]any{"token": "issued"})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "state": st})
}

// POST /api/v1/diag/provider-log/disable
func (s *Server) handleProviderLogDisable(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	l := s.providerLog()
	if l == nil {
		writeError(w, http.StatusConflict, "not-supported", "the provider log is not available")
		return
	}
	st := l.Disable(ws.user.Username)
	s.audit(ws, "", "diag", "disable-provider-log", "provider-log", nil, nil)
	writeJSON(w, http.StatusOK, st)
}

// providerLogReader lets a request read the log: a live bearer token
// (counts as activity) or a system administrator's web session.
func (s *Server) providerLogReader(w http.ResponseWriter, r *http.Request) (tokenAuth, ok bool) {
	l := s.providerLog()
	if l == nil {
		writeError(w, http.StatusConflict, "not-supported", "the provider log is not available")
		return false, false
	}
	if h := r.Header.Get("Authorization"); h != "" {
		tok, found := strings.CutPrefix(h, "Bearer ")
		if !found || !l.Authorize(strings.TrimSpace(tok)) {
			writeError(w, http.StatusUnauthorized, "token-expired", "the provider log token is wrong or expired; turn the log on again in 웹 앱 설정")
			return false, false
		}
		return true, true
	}
	allowed := false
	s.authed(func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		allowed = s.requireAdmin(w, r, ws)
	})(w, r)
	return false, allowed
}

func providerLogFilter(r *http.Request) (provlog.Filter, error) {
	q := r.URL.Query()
	f := provlog.Filter{Provider: q.Get("provider"), Conn: q.Get("conn"), Op: q.Get("op"), Level: q.Get("level"), Text: q.Get("q")}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, fmt.Errorf("since: %w", err)
		}
		f.Since = t
	}
	switch f.Level {
	case "", provlog.Info, provlog.Warn, provlog.Error:
	default:
		return f, fmt.Errorf("level must be info, warn or error")
	}
	return f, nil
}

func uintParam(r *http.Request, name string) (uint64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, nil
	}
	return strconv.ParseUint(v, 10, 64)
}

// GET /api/v1/diag/provider-log?after=&limit=&provider=&conn=&op=&level=&since=&q=
// (or tail=n for the newest n). Entries are oldest first.
func (s *Server) handleProviderLogList(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.providerLogReader(w, r); !ok {
		return
	}
	f, err := providerLogFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	after, err := uintParam(r, "after")
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad-request", "after: "+err.Error())
		return
	}
	limit, err := uintParam(r, "limit")
	if err != nil || limit > 5000 {
		writeError(w, http.StatusBadRequest, "bad-request", "limit must be 0..5000")
		return
	}
	var p provlog.Page
	if tail, err := uintParam(r, "tail"); err != nil || tail > 5000 {
		writeError(w, http.StatusBadRequest, "bad-request", "tail must be 0..5000")
		return
	} else if tail > 0 {
		p = s.providerLog().Tail(f, int(tail))
	} else {
		p = s.providerLog().List(f, after, int(limit))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"page": p, "state": s.providerLog().State()})
}

// GET /api/v1/diag/provider-log/download: every stored entry as JSON lines.
func (s *Server) handleProviderLogDownload(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.providerLogReader(w, r); !ok {
		return
	}
	f, err := providerLogFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/x-ndjson")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sfc-provider-log-%s.jsonl"`, s.now().UTC().Format("20060102-150405")))
	if err := s.providerLog().Export(w, f); err != nil {
		s.log.Error("provider log export", "err", err)
	}
}

// providerLogPing is how often an idle stream sends a comment line.
var providerLogPing = 20 * time.Second

// GET /api/v1/diag/provider-log/stream?after=&…filter: SSE. Each entry is
// an "entry" event whose id is its seq, so a reconnect with Last-Event-ID
// (or after=) continues without gaps. Entries older than after are sent
// first. A token stream ends with an "expired" event when collection
// turns off; an administrator's stream stays open.
func (s *Server) handleProviderLogStream(w http.ResponseWriter, r *http.Request) {
	tokenAuth, ok := s.providerLogReader(w, r)
	if !ok {
		return
	}
	f, err := providerLogFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	after, err := uintParam(r, "after")
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad-request", "after: "+err.Error())
		return
	}
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			after = n
		}
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "streaming not supported")
		return
	}
	l := s.providerLog()
	sub, cancel := l.Subscribe()
	defer cancel()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	sendEvent(w, "state", l.State())
	send := func(e provlog.Entry) {
		if e.Seq <= after {
			return
		}
		after = e.Seq
		if f.Match(e) {
			fmt.Fprintf(w, "id: %d\n", e.Seq)
			sendEvent(w, "entry", e)
		}
	}
	// backlog, then live entries (a seq already sent is skipped)
	for {
		p := l.List(provlog.Filter{}, after, 1000)
		for _, e := range p.Entries {
			send(e)
		}
		if !p.More {
			break
		}
	}
	fl.Flush()
	ping := time.NewTicker(providerLogPing)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, open := <-sub:
			if !open {
				return
			}
			if e.Seq > after+1 {
				// missed entries (slow reader): fetch them
				for _, m := range l.List(provlog.Filter{}, after, int(e.Seq-after)).Entries {
					send(m)
				}
			}
			send(e)
			fl.Flush()
		case <-ping.C:
			if tokenAuth && !l.Enabled() {
				sendEvent(w, "expired", l.State())
				fl.Flush()
				return
			}
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}
