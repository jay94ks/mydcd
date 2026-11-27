// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// An invitation is a single-use token on an account (credential ID
// sfc.InviteCredential(expiry)). Its code is shown once, in the link of
// the reply that issued it; the web keeps it nowhere. The recipient opens
// it (the code logs in as the account and is consumed), adds its own key
// with the token session, and then logs in with that key.

// inviteSessionTTL is how long an opened invitation's token session waits
// for the recipient's key.
const inviteSessionTTL = 10 * time.Minute

var inviteSeconds = map[string]int64{"1h": 3600, "24h": 86400, "7d": 7 * 86400}

type inviteIssueReq struct {
	OpID    string `json:"opId"`
	Expires string `json:"expires"` // 1h, 24h, 7d
}

// POST /api/v1/users/{u}/invites (system administrator): a new invitation.
// The reply's link holds the code; a replayed opId answers without it.
func (s *Server) handleIssueInvite(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req inviteIssueReq
	if !readJSON(w, r, &req) {
		return
	}
	seconds, ok := inviteSeconds[req.Expires]
	if !ok {
		writeError(w, http.StatusBadRequest, "bad-request", "expires must be 1h, 24h or 7d")
		return
	}
	username := r.PathValue("u")
	var issued sfc.InviteIssue
	defer func() { issued.Destroy() }()
	s.sharedCreateWith(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		issued.Destroy()
		var err error
		if issued, err = c.IssueInvite(ctx, username, seconds); err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionIssueInitialCredential, issued.Fact, issued.Expected, username, nil
	}, nil, func(o *store.Op) map[string]any {
		if o.State != store.OpApplied || len(issued.Token) == 0 {
			return nil
		}
		return map[string]any{
			"link":      "/login/invite?u=" + url.QueryEscape(username) + "#" + string(issued.Token),
			"expiresAt": rfc3339(time.Unix(issued.ExpiresAt, 0)),
		}
	})
}

type inviteRevokeReq struct {
	OpID     string `json:"opId"`
	Expected uint64 `json:"expected"`
}

// POST /api/v1/users/{u}/invites/revoke (system administrator): turns off
// the account's enabled invitation (disable-credential).
func (s *Server) handleRevokeInvite(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req inviteRevokeReq
	if !readJSON(w, r, &req) {
		return
	}
	username := r.PathValue("u")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		u, err := c.UserCredentials(ctx, username)
		if err != nil {
			return "", nil, 0, "", err
		}
		id := enabledInvite(u.Credentials)
		if id == "" {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "no-invite", "the account has no invitation turned on"}
		}
		return sfc.ActionDisableCredential, access.CredentialDisable{User: u.ID, Credential: id}, req.Expected, username, nil
	})
}

// enabledInvite is the ID of the account's enabled invitation, if any.
func enabledInvite[C access.Credential | access.PublicCredential](cs []C) string {
	for _, x := range cs {
		var id string
		var method access.Method
		var enabled, oneTime bool
		switch v := any(x).(type) {
		case access.Credential:
			id, method, enabled, oneTime = v.ID, v.Method, v.Enabled, v.OneTime
		case access.PublicCredential:
			id, method, enabled, oneTime = v.ID, v.Method, v.Enabled, v.OneTime
		}
		if _, ok := sfc.InviteExpiry(id); ok && enabled && oneTime && method == access.Token {
			return id
		}
	}
	return ""
}

// inviteState is the users list's invite field: an enabled invitation and
// whether its time is up. An opened one stays "active" until the recipient
// (or an administrator) turns it off.
type inviteState struct {
	State     string `json:"state"` // active, expired
	ExpiresAt string `json:"expiresAt"`
}

// userRow is a users-list row: the public user and its invitation.
type userRow struct {
	publicUserView
	Invite *inviteState `json:"invite,omitempty"`
}

func inviteOf(cs []access.PublicCredential, now time.Time) *inviteState {
	id := enabledInvite(cs)
	if id == "" {
		return nil
	}
	exp, _ := sfc.InviteExpiry(id)
	st := inviteState{State: "active", ExpiresAt: rfc3339(time.Unix(exp, 0))}
	if !now.Before(time.Unix(exp, 0)) {
		st.State = "expired"
	}
	return &st
}

type inviteOpenReq struct {
	Username string `json:"username"`
	Code     string `json:"code"`
}

// writeInviteInvalid answers an invitation that is used, expired, revoked
// or never existed: sfcd does not tell them apart.
func writeInviteInvalid(w http.ResponseWriter) {
	writeError(w, http.StatusGone, "invite-invalid", "this invitation link is used, expired or turned off; ask an administrator for a new one")
}

func deniedErr(err error) bool {
	var me *sfc.Error
	return errors.As(err, &me) && (me.Code == sfc.CodeDenied || me.Code == sfc.CodeMissing || me.Code == sfc.CodeExpired)
}

// POST /api/v1/login/invite/open (no session): logs in with the invitation's
// code, which consumes it, and keeps that token session for
// inviteSessionTTL. The browser must have its new key (and its passphrase
// confirmed) before calling this.
func (s *Server) handleInviteOpen(w http.ResponseWriter, r *http.Request) {
	var req inviteOpenReq
	if !readJSON(w, r, &req) {
		return
	}
	code := []byte(req.Code)
	req.Code = ""
	defer clear(code)
	if req.Username == "" || len(code) == 0 {
		writeError(w, http.StatusBadRequest, "bad-request", "username and code are required")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	conn, err := s.opt.Client.Dial(ctx)
	if err != nil {
		s.writeBackendError(w, nil, err)
		return
	}
	keep := false
	defer func() {
		if !keep {
			conn.Close()
		}
	}()
	t, err := conn.CredentialChallenge(ctx, req.Username, sfc.MethodToken, "")
	if err == nil {
		if _, ok := sfc.InviteExpiry(t.Credential); !ok {
			// a token that is not an invitation is not used here
			writeInviteInvalid(w)
			return
		}
		_, err = conn.CredentialLogin(s.loginContext(ctx, r), t, code)
	}
	if err != nil {
		if deniedErr(err) {
			writeInviteInvalid(w)
		} else {
			s.writeBackendError(w, nil, err)
		}
		return
	}
	who, err := conn.Whoami(ctx)
	if err != nil {
		s.writeBackendError(w, nil, err)
		return
	}
	u, err := conn.OwnCredentials(ctx)
	if err != nil {
		s.writeBackendError(w, nil, err)
		return
	}
	p := &pendingLogin{method: "invite", username: u.Username, conn: conn, accountRevision: u.Revision, user: u.ID}
	s.sessions.addPendingFor(p, inviteSessionTTL)
	keep = true
	s.log.Info("invite opened", "user", u.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"ticket":          p.id,
		"userId":          u.ID,
		"username":        u.Username,
		"accountRevision": u.Revision,
		"clusterId":       hex.EncodeToString(who.Session.Cluster[:]),
		"expiresAt":       rfc3339(p.deadline),
	})
}

type inviteFinishReq struct {
	Ticket     string `json:"ticket"`
	Credential struct {
		ID        string `json:"id"`
		PublicKey string `json:"publicKey"` // hex, 32 bytes
	} `json:"credential"`
	Label     string `json:"label,omitempty"`
	Challenge string `json:"challenge"` // hex, 32 bytes
	Proof     string `json:"proof"`     // base64, the new key's signature
}

// POST /api/v1/login/invite/finish (no session): the account's own
// add-credential with the opened invitation's token session; then that
// session ends and the browser logs in with the new key.
func (s *Server) handleInviteFinish(w http.ResponseWriter, r *http.Request) {
	var req inviteFinishReq
	if !readJSON(w, r, &req) {
		return
	}
	pub, err1 := hex.DecodeString(req.Credential.PublicKey)
	challenge, err2 := hex.DecodeString(req.Challenge)
	proof, err3 := base64.StdEncoding.DecodeString(req.Proof)
	if err1 != nil || err2 != nil || err3 != nil || len(pub) != 32 || len(challenge) != 32 || len(proof) != 64 || req.Credential.ID == "" || strings.HasPrefix(req.Credential.ID, sfc.InvitePrefix) {
		writeError(w, http.StatusBadRequest, "bad-request", "credential.id, a 32-byte hex credential.publicKey and challenge, and a 64-byte base64 proof are required")
		return
	}
	p := s.sessions.takePending(req.Ticket)
	if p == nil || p.method != "invite" {
		if p != nil {
			p.conn.Close()
		}
		writeError(w, http.StatusGone, "ticket-expired", "the opened invitation timed out; ask an administrator for a new link")
		return
	}
	defer p.conn.Close()
	add := access.CredentialAddition{User: p.user, Credential: access.CredentialKey{ID: req.Credential.ID, Method: access.PrivateKey, PublicKey: [32]byte(pub)}, Label: req.Label, Challenge: [32]byte(challenge), Proof: proof}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	raw, _ := json.Marshal(add)
	doc, _ := json.Marshal(control.ChangeDocument{Schema: 1, Action: sfc.ActionAddCredential, Expected: p.accountRevision, Payload: raw})
	ch, err := control.InputChange(doc, p.user)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "add-credential: the values do not make a valid request")
		return
	}
	who, err := p.conn.Whoami(ctx)
	if err != nil {
		s.writeBackendError(w, nil, err)
		return
	}
	op, err := p.conn.Prepare(ctx, ch, who.RootFor(sfc.ActionAddCredential))
	var res sfc.Result
	if err == nil {
		res, err = p.conn.Submit(ctx, op)
	}
	if err != nil {
		s.writeBackendError(w, nil, err)
		return
	}
	if res.Code != sfc.ResultApplied {
		writeJSON(w, http.StatusConflict, map[string]any{"error": apiError{Code: "not-applied", Message: "sfcd did not add the key; open a new invitation"}, "result": map[string]any{"code": int(res.Code)}})
		return
	}
	s.log.Info("invite finished", "user", p.username, "credential", req.Credential.ID)
	writeJSON(w, http.StatusOK, map[string]any{"credential": req.Credential.ID, "username": p.username})
}
