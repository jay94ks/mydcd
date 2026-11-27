// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

type credentialChallengeReq struct {
	Username   string `json:"username"`
	Method     string `json:"method"` // password or token
	Credential string `json:"credential,omitempty"`
}

type keyChallengeReq struct {
	Username  string `json:"username"`
	PublicKey string `json:"publicKey"` // hex, 32 bytes
}

type credentialLoginReq struct {
	TicketID string `json:"ticketId"`
	Secret   string `json:"secret"`
}

type keyLoginReq struct {
	TicketID  string `json:"ticketId"`
	Signature string `json:"signature"` // hex, 64 bytes Ed25519
}

// POST /api/v1/auth/credential/challenge
func (s *Server) handleCredentialChallenge(w http.ResponseWriter, r *http.Request) {
	var req credentialChallengeReq
	if !readJSON(w, r, &req) {
		return
	}
	var method sfc.AuthMethod
	switch req.Method {
	case "password":
		method = sfc.MethodPassword
	case "token":
		method = sfc.MethodToken
	}
	if req.Username == "" || method == "" {
		writeError(w, http.StatusBadRequest, "bad-request", "username and method (password or token) are required")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	conn, err := s.opt.Client.Dial(ctx)
	if err != nil {
		s.writeBackendError(w, nil, err)
		return
	}
	t, err := conn.CredentialChallenge(ctx, req.Username, method, req.Credential)
	if err != nil {
		conn.Close()
		s.writeBackendError(w, nil, err)
		return
	}
	p := &pendingLogin{method: req.Method, username: req.Username, ticket: t, conn: conn}
	s.sessions.addPending(p)
	writeJSON(w, http.StatusOK, map[string]any{"ticketId": p.id, "deadline": rfc3339(p.deadline)})
}

// POST /api/v1/auth/credential/login
func (s *Server) handleCredentialLogin(w http.ResponseWriter, r *http.Request) {
	var req credentialLoginReq
	if !readJSON(w, r, &req) {
		return
	}
	secret := []byte(req.Secret)
	req.Secret = ""
	defer clear(secret)
	p := s.sessions.takePending(req.TicketID)
	if p == nil || p.method != "password" && p.method != "token" {
		if p != nil {
			p.conn.Close()
		}
		writeError(w, http.StatusUnauthorized, "ticket-expired", "login ticket is missing or expired; start again")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	sess, err := p.conn.CredentialLogin(s.loginContext(ctx, r), p.ticket, secret)
	if err != nil {
		p.conn.Close()
		s.writeBackendError(w, nil, err)
		return
	}
	s.finishLogin(w, r, p, sess)
}

// POST /api/v1/auth/key/challenge: the server dials, gets a Ticket bound to
// a session key the Conn generated, and returns the exact bytes the browser
// signs. The user's private key never leaves the browser.
func (s *Server) handleKeyChallenge(w http.ResponseWriter, r *http.Request) {
	var req keyChallengeReq
	if !readJSON(w, r, &req) {
		return
	}
	if !s.keyLoginAllowed() {
		writeKeyLoginOff(w)
		return
	}
	raw, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(raw) != 32 || req.Username == "" {
		writeError(w, http.StatusBadRequest, "bad-request", "username and a 32-byte hex publicKey are required")
		return
	}
	var key [32]byte
	copy(key[:], raw)
	ctx, cancel := s.callCtx(r)
	defer cancel()
	conn, err := s.opt.Client.Dial(ctx)
	if err != nil {
		s.writeBackendError(w, nil, err)
		return
	}
	t, err := conn.Challenge(ctx, req.Username, key)
	if err != nil {
		conn.Close()
		s.writeBackendError(w, nil, err)
		return
	}
	proof := sfc.NewKeyProof(t)
	p := &pendingLogin{method: "key", username: req.Username, ticket: t, proof: proof, conn: conn}
	s.sessions.addPending(p)
	writeJSON(w, http.StatusOK, map[string]any{
		"ticketId": p.id,
		"ticket":   camel{t},
		// The browser may verify ticket.signature with ticket.issuer over
		// ticketBytes before signing proof.
		"ticketBytes": base64.StdEncoding.EncodeToString(sfc.TicketSigningBytes(t)),
		"proof":       base64.StdEncoding.EncodeToString(sfc.KeyProofSigningBytes(proof)),
		"deadline":    rfc3339(p.deadline),
	})
}

func writeKeyLoginOff(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "key-login-disabled", "browser key login is turned off in the web app settings")
}

// GET /api/v1/auth/methods (no session): which login methods the web
// offers, for the login page.
func (s *Server) handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"credential": true, "key": s.keyLoginAllowed()})
}

// POST /api/v1/auth/key/login
func (s *Server) handleKeyLogin(w http.ResponseWriter, r *http.Request) {
	var req keyLoginReq
	if !readJSON(w, r, &req) {
		return
	}
	if !s.keyLoginAllowed() {
		writeKeyLoginOff(w)
		return
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil || len(sig) != 64 {
		writeError(w, http.StatusBadRequest, "bad-request", "signature must be 64 bytes hex")
		return
	}
	p := s.sessions.takePending(req.TicketID)
	if p == nil || p.method != "key" || p.approve {
		if p != nil {
			p.conn.Close()
		}
		writeError(w, http.StatusUnauthorized, "ticket-expired", "login ticket is missing or expired; start again")
		return
	}
	proof := p.proof
	proof.Signature = sig
	ctx, cancel := s.callCtx(r)
	defer cancel()
	sess, err := p.conn.Login(s.loginContext(ctx, r), p.ticket, proof)
	if err != nil {
		p.conn.Close()
		s.writeBackendError(w, nil, err)
		return
	}
	// R02: the issued session still needs the user key's approval. The
	// daemon keeps the session and the connection; the browser only signs.
	a := sfc.NewSessionApproval(sess, p.ticket.UserKey)
	next := &pendingLogin{method: "key", username: p.username, approve: true, session: sess, approval: a, conn: p.conn}
	s.sessions.addPending(next)
	writeJSON(w, http.StatusOK, map[string]any{
		"approve":       true,
		"ticketId":      next.id,
		"sessionDigest": hex.EncodeToString(a.Session[:]),
		"approval":      base64.StdEncoding.EncodeToString(sfc.SessionApprovalSigningBytes(a)),
		"deadline":      rfc3339(next.deadline),
	})
}

// POST /api/v1/auth/key/approve: the browser's signature of the approval
// bytes key/login returned. Attaches it to the session and starts the web
// session (cookie).
func (s *Server) handleKeyApprove(w http.ResponseWriter, r *http.Request) {
	var req keyLoginReq
	if !readJSON(w, r, &req) {
		return
	}
	if !s.keyLoginAllowed() {
		writeKeyLoginOff(w)
		return
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil || len(sig) != 64 {
		writeError(w, http.StatusBadRequest, "bad-request", "signature must be 64 bytes hex")
		return
	}
	p := s.sessions.takePending(req.TicketID)
	if p == nil || !p.approve {
		if p != nil {
			p.conn.Close()
		}
		writeError(w, http.StatusUnauthorized, "ticket-expired", "login ticket is missing or expired; start again")
		return
	}
	a := p.approval
	a.Signature = sig
	ctx, cancel := s.callCtx(r)
	defer cancel()
	sess, err := p.conn.ApproveSession(ctx, a)
	if err != nil {
		p.conn.Close()
		s.writeBackendError(w, nil, err)
		return
	}
	s.finishLogin(w, r, p, sess)
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, p *pendingLogin, sess sfc.Session) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	who, err := p.conn.Whoami(ctx)
	if err != nil {
		p.conn.Close()
		s.writeBackendError(w, nil, err)
		return
	}
	u := sessionUser{ID: who.User.ID, Username: who.User.Username, SystemAdmin: who.User.SystemAdmin}
	if u.ID == "" {
		u.ID = sess.User
	}
	id, ws, err := s.sessions.start(p, u, time.Unix(sess.ExpiresAt, 0))
	if err != nil {
		p.conn.Close()
		s.log.Error("store session", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		Expires:  ws.expiresAt,
		HttpOnly: true,
		Secure:   s.requestHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	s.log.Info("login", "user", u.Username, "method", p.method)
	s.writeSessionView(w, r, ws)
}

// POST /api/v1/auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		if ws := s.sessions.lookup(c.Value, true); ws != nil {
			s.sessions.end(ws, "logout")
		}
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.requestHTTPS(r), SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// authed wraps a handler that needs a live session.
func (s *Server) authed(h func(http.ResponseWriter, *http.Request, *webSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The coordinator's in-process call on the person's session
		// (dispatch); a context value cannot come from the network.
		if ws, ok := r.Context().Value(ctxSession{}).(*webSession); ok && ws != nil {
			h(w, r, ws)
			return
		}
		c, err := r.Cookie(cookieName)
		var ws *webSession
		if err == nil {
			// Automatic refreshes (polling, SSE reconnects) send
			// X-SFC-Background: 1 and do not count as activity for the
			// idle limit.
			ws = s.sessions.lookup(c.Value, r.Header.Get("X-SFC-Background") != "1")
		}
		if ws == nil {
			writeError(w, http.StatusUnauthorized, "session-expired", "log in again")
			return
		}
		h(w, r, ws)
	}
}

type sessionView struct {
	User      sfc.UserView     `json:"user"`
	Tenants   []sfc.TenantView `json:"tenants"`
	ExpiresAt string           `json:"expiresAt"`
	Method    string           `json:"method"`
	// RootRevision is the root CAS revision at this read. /ops fills a zero
	// rootRevision with the current value itself.
	RootRevision uint64 `json:"rootRevision"`
}

func (s *Server) writeSessionView(w http.ResponseWriter, r *http.Request, ws *webSession) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
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
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, http.StatusOK, camel{sessionView{User: who.User, Tenants: tenants, ExpiresAt: rfc3339(ws.expiresAt), Method: ws.method, RootRevision: who.RootRevision}})
}

// GET /api/v1/auth/session
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, ws *webSession) {
	s.writeSessionView(w, r, ws)
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }
