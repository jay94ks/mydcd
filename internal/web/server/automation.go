// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/jay94ks/seafield/internal/web/seal"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// The web's automation account. Scheduled work has no person
// to sign it, so the web logs in to an ordinary sfcd account with a key
// pair it made itself. The private key (an Ed25519 seed) is the sealed file
// automationKey and never leaves the daemon; bbolt holds the account name
// and the public key. Registering the public key on the account (put-user),
// its action scope (set-account-scope), key-only and memberships are the
// administrator's own signed ops: sfcd decides what the account may do,
// and the web gives it no authority of its own.

const (
	automationKey = "automation-key"
	// ErrAutomationMissing is the run error when no automation account is
	// set up.
	ErrAutomationMissing = "automation-account-missing"
	// ErrAutomationLogin is the run error when the account could not log in
	// (key not registered, revoked, scope, sfcd down).
	ErrAutomationLogin = "automation-login-failed"
)

var usernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type automationView struct {
	Configured  bool                   `json:"configured"`
	SealReady   bool                   `json:"sealReady"`
	Username    string                 `json:"username,omitempty"`
	UserID      string                 `json:"userId,omitempty"`
	PublicKey   string                 `json:"publicKey,omitempty"`
	Fingerprint string                 `json:"fingerprint,omitempty"`
	CreatedBy   string                 `json:"createdBy,omitempty"`
	CreatedAt   string                 `json:"createdAt,omitempty"`
	LastCheck   *store.AutomationCheck `json:"lastCheck,omitempty"`
}

func keyFingerprint(pubHex string) string {
	raw, _ := hex.DecodeString(pubHex)
	h := sha256.Sum256(raw)
	s := hex.EncodeToString(h[:])
	return "SHA256:" + s[:8] + "…" + s[len(s)-8:]
}

func (s *Server) automationRow() *store.Automation {
	a, err := s.opt.Store.GetAutomation()
	if err != nil {
		s.log.Error("automation row", "err", err)
		return nil
	}
	return a
}

func (s *Server) automationView() automationView {
	v := automationView{SealReady: s.opt.Seal.Ready()}
	if a := s.automationRow(); a != nil {
		v.UserID = a.UserID
		v.Configured, v.Username, v.PublicKey, v.Fingerprint = true, a.Username, a.PublicKey, keyFingerprint(a.PublicKey)
		v.CreatedBy, v.CreatedAt, v.LastCheck = a.CreatedBy, rfc3339(a.CreatedAt), a.LastCheck
	}
	return v
}

// GET /system/automation (system admin) → automationView.
func (s *Server) handleGetAutomation(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	writeJSON(w, http.StatusOK, s.automationView())
}

// PUT /system/automation {username, rotate?} (system admin): name the
// account and make its key pair. A new key is made the first time, when the
// name changes, or with rotate; otherwise the key stays. The answer carries
// the public key to register on the account with put-user. A replaced key
// stays registered in sfcd until the administrator removes it.
func (s *Server) handlePutAutomation(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Username string `json:"username"`
		Rotate   bool   `json:"rotate"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	if !usernameRE.MatchString(req.Username) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "username: lowercase letters, digits, . _ -, at most 64")
		return
	}
	if !s.opt.Seal.Ready() {
		writeError(w, http.StatusServiceUnavailable, "seal-unavailable", "the automation key is sealed with the web's seal key, which is not ready")
		return
	}
	before := s.automationRow()
	if before != nil && before.Username == req.Username && !req.Rotate {
		if _, err := s.opt.Seal.Get(automationKey); err == nil {
			writeJSON(w, http.StatusOK, s.automationView())
			return
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "key generation failed")
		return
	}
	seed := priv.Seed()
	err = s.opt.Seal.Put(automationKey, seed)
	clear(seed)
	clear(priv)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not seal the key")
		return
	}
	a := &store.Automation{Username: req.Username, PublicKey: hex.EncodeToString(pub), CreatedByID: ws.user.ID, CreatedBy: ws.user.Username, CreatedAt: s.now()}
	if err := s.opt.Store.PutAutomation(a); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	var prev any
	if before != nil {
		prev = map[string]any{"username": before.Username, "fingerprint": keyFingerprint(before.PublicKey)}
	}
	s.audit(ws, "", "automation", "key", req.Username, prev, map[string]any{"username": a.Username, "fingerprint": keyFingerprint(a.PublicKey)})
	writeJSON(w, http.StatusOK, s.automationView())
}

// DELETE /system/automation (system admin): forget the account and remove
// the sealed key → 204. Scheduled work stops; the public key stays
// registered in sfcd until the administrator removes it there.
func (s *Server) handleDeleteAutomation(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	before := s.automationRow()
	if before == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := s.opt.Seal.Delete(automationKey); err != nil && !errors.Is(err, seal.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "internal", "could not remove the sealed key")
		return
	}
	if err := s.opt.Store.PutAutomation(nil); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "automation", "delete", before.Username, map[string]any{"username": before.Username, "fingerprint": keyFingerprint(before.PublicKey)}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// POST /system/automation/check (system admin): log in as the account now
// and ask whoami → {ok, user?, username?, systemAdmin?, error?}. Also
// recorded as lastCheck.
func (s *Server) handleCheckAutomation(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	if s.automationRow() == nil {
		writeError(w, http.StatusConflict, "not-configured", "make the automation key first")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	as, err := s.automationLogin(ctx, "check")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": automationErrorCode(err)})
		return
	}
	defer as.conn.Close()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": as.user.ID, "username": as.user.Username, "systemAdmin": as.user.SystemAdmin})
}

// errAutomationMissing: no account set up, or its sealed key is gone.
var errAutomationMissing = errors.New(ErrAutomationMissing)

// automationErrorCode is the short code shown for a failed login: the
// sfcd code when there is one (denied, unauthenticated, …).
func automationErrorCode(err error) string {
	var me *sfc.Error
	switch {
	case errors.Is(err, errAutomationMissing):
		return ErrAutomationMissing
	case errors.Is(err, seal.ErrUnavailable):
		return "seal-unavailable"
	case errors.As(err, &me):
		return string(me.Code)
	}
	return ErrAutomationLogin
}

// automationLogin opens a new connection and logs in as the automation
// account with its sealed key (sfcd's key login: challenge, then the
// signed proof). The session is not a browser login: it has no cookie and
// the caller closes ws.conn when done. reason says what it is for and is
// kept with lastCheck.
func (s *Server) automationLogin(ctx context.Context, reason string) (*webSession, error) {
	ws, err := s.automationLoginOnce(ctx)
	check := &store.AutomationCheck{At: s.now(), OK: err == nil, Reason: reason}
	if err != nil {
		check.Error = automationErrorCode(err)
	} else {
		check.User = ws.user.ID
	}
	if a := s.automationRow(); a != nil {
		a.LastCheck = check
		if err == nil {
			a.UserID = ws.user.ID
		}
		if perr := s.opt.Store.PutAutomation(a); perr != nil {
			s.log.Error("automation check", "err", perr)
		}
	}
	if err != nil {
		s.log.Warn("automation login", "reason", reason, "err", check.Error)
	}
	return ws, err
}

func (s *Server) automationLoginOnce(ctx context.Context) (*webSession, error) {
	a := s.automationRow()
	if a == nil {
		return nil, errAutomationMissing
	}
	seed, err := s.opt.Seal.Get(automationKey)
	if errors.Is(err, seal.ErrNotFound) {
		return nil, errAutomationMissing
	}
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("automation key: wrong size")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	if hex.EncodeToString(pub[:]) != a.PublicKey {
		return nil, errors.New("automation key does not match the recorded public key")
	}
	conn, err := s.opt.Client.Dial(ctx)
	if err != nil {
		return nil, err
	}
	t, err := conn.Challenge(ctx, a.Username, pub)
	if err != nil {
		conn.Close()
		return nil, err
	}
	proof := sfc.NewKeyProof(t)
	proof.Signature = ed25519.Sign(priv, sfc.KeyProofSigningBytes(proof))
	sess, err := conn.Login(ctx, t, proof)
	if err != nil {
		conn.Close()
		return nil, err
	}
	who, err := conn.Whoami(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	u := sessionUser{ID: who.User.ID, Username: who.User.Username, SystemAdmin: who.User.SystemAdmin}
	if u.ID == "" {
		u.ID = sess.User
	}
	return &webSession{method: "automation", user: u, expiresAt: time.Unix(sess.ExpiresAt, 0), conn: conn}, nil
}
