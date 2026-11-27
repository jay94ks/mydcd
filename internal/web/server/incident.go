// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Incident response (REQ-9 and REQ-11 mocks): the incident account's
// action scope, display-only op reasons, and the temporary actions that
// were missing (cordon a server, reconnect a tunnel link, prune a server's
// unused images). sfcd judges every permission; the scope is sfcd's too.

// opReasonOf reads the optional X-SFC-Reason and X-SFC-Incident headers
// (UTF-8, percent-encoded, one line; sfcd's limits: the reason at most 512
// characters, the incident at most 128 bytes). The reason is part of the
// op's digest and goes with the signed original; it is display metadata
// only.
func opReasonOf(r *http.Request) (*store.OpReason, error) {
	var out store.OpReason
	for _, h := range []struct {
		name string
		to   *string
		ok   func(string) bool
	}{{"X-SFC-Reason", &out.Reason, func(v string) bool { return utf8.RuneCountInString(v) <= 512 }},
		{"X-SFC-Incident", &out.Incident, func(v string) bool { return len(v) <= 128 }}} {
		raw := r.Header.Get(h.name)
		if raw == "" {
			continue
		}
		v, err := url.PathUnescape(raw)
		if err != nil || !utf8.ValidString(v) || !h.ok(v) || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return nil, errors.New(h.name + ": percent-encoded UTF-8 on one line, the reason at most 512 characters, the incident at most 128 bytes")
		}
		*h.to = v
	}
	if out == (store.OpReason{}) {
		return nil, nil
	}
	return &out, nil
}

type scopeView struct {
	User     string   `json:"user"`
	Actions  []string `json:"actions"`
	KeyOnly  bool     `json:"keyOnly"`
	Revision uint64   `json:"revision"`
}

func viewScope(s sfc.AccountScope) scopeView {
	v := scopeView{User: s.User, Actions: s.Actions, KeyOnly: s.KeyOnly, Revision: s.Revision}
	if v.Actions == nil {
		v.Actions = []string{}
	}
	return v
}

// GET /users/{u}/scope → {user, actions, keyOnly, revision}: the actions
// the account's ops may carry (empty = no limit) and whether it may log in
// with a private key only. Revision is the account revision. A system administrator,
// or the account itself.
func (s *Server) handleAccountScope(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (scopeView, error) {
		sc, err := c.AccountScope(ctx, r.PathValue("u"))
		return viewScope(sc), err
	})
}

// PATCH /users/{u}/scope {opId, expected, add?, remove?, unlimited?,
// keyOnly?} → set-account-scope {User, Add, Remove, Unlimited, KeyOnly}
// (system admin): a change to the account's action limit, not the whole
// list. add/remove are action names; adding to an account with no limit
// starts one, unlimited lifts it (alone, without add/remove), keyOnly turns
// key-only login on or off. expected is the scope revision it was read at:
// when the account changed since, 409 stale. Adding an action the limit has
// is 422 exists, removing one it lacks 422 no-such-action. Every session of
// the account ends.
func (s *Server) handleSetAccountScope(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string   `json:"opId"`
		Expected  uint64   `json:"expected"`
		Add       []string `json:"add"`
		Remove    []string `json:"remove"`
		Unlimited bool     `json:"unlimited"`
		KeyOnly   *bool    `json:"keyOnly"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	user := r.PathValue("u")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if len(req.Add)+len(req.Remove) == 0 && !req.Unlimited && req.KeyOnly == nil {
			return "", nil, 0, "", invalid("add, remove, unlimited or keyOnly: at least one change")
		}
		if req.Unlimited && len(req.Add)+len(req.Remove) > 0 {
			return "", nil, 0, "", invalid("unlimited goes without add and remove")
		}
		for _, list := range [][]string{req.Add, req.Remove} {
			if len(list) > 64 || len(list) > 0 && !access.ValidCredentialOperations(list) {
				return "", nil, 0, "", invalid("add, remove: at most 64 distinct action names such as restart-task")
			}
		}
		if req.Expected == 0 {
			return "", nil, 0, "", invalid("expected: the scope revision it was read at")
		}
		cur, err := c.AccountScope(ctx, user)
		if err != nil {
			return "", nil, 0, "", err
		}
		if cur.Revision != req.Expected {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "stale", "the account changed since it was read; read it again"}
		}
		for _, a := range req.Add {
			if slices.Contains(cur.Actions, a) {
				return "", nil, 0, "", invalidCode("exists", "the limit already allows "+a)
			}
		}
		for _, a := range req.Remove {
			if !slices.Contains(cur.Actions, a) {
				return "", nil, 0, "", invalidCode("no-such-action", "the limit has no "+a)
			}
		}
		q := sfc.AccountScopeChange{User: user, Add: req.Add, Remove: req.Remove, Unlimited: req.Unlimited, KeyOnly: req.KeyOnly}
		return sfc.ActionSetAccountScope, q, req.Expected, "user/" + user, nil
	})
}

type reasonView struct {
	Found      bool   `json:"found"`
	Reason     string `json:"reason,omitempty"`
	Incident   string `json:"incident,omitempty"`
	ApprovedBy string `json:"approvedBy,omitempty"`
}

// GET /ops/{id}/reason → {found, reason?, incident?, approvedBy?}: the
// reason signed inside one of the caller's web ops, read from the stored
// original (sfcd keeps the same bytes and has no other read for it).
func (s *Server) handleOpReason(w http.ResponseWriter, r *http.Request, ws *webSession) {
	o := s.loadOp(w, r, ws)
	if o == nil {
		return
	}
	if o.RequestID == "" || len(o.Signed) == 0 {
		writeError(w, http.StatusConflict, "job", "this op has no single original (a job); read its step ops")
		return
	}
	rs, ok, err := sfc.SignedReason(o.Signed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "stored original")
		return
	}
	writeJSON(w, http.StatusOK, reasonView{ok, rs.Reason, rs.Incident, rs.ApprovedBy})
}

// POST /nodes/{node}/cordon {opId, reason?, expected?} → cordon-node;
// POST /nodes/{node}/uncordon {opId, expected?} → uncordon-node (system
// admin). Expected defaults to the scheduling (cordon) revision. A cordoned server
// keeps its tasks; new placements there are refused (NODE_CORDONED).
func (s *Server) handleCordon(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID     string `json:"opId"`
			Reason   string `json:"reason,omitempty"`
			Expected uint64 `json:"expected,omitempty"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		node := r.PathValue("node")
		s.sharedCreate(w, r, ws, req.OpID, actionBody{action, req}, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
			if action == sfc.ActionUncordonNode && req.Reason != "" || !(sfc.NodeCordon{ID: node, Reason: req.Reason}).Valid() {
				return "", nil, 0, "", invalid("reason: one line of at most 256 characters, cordon only")
			}
			m, err := findMember(ctx, c, node)
			if err != nil {
				return "", nil, 0, "", err
			}
			if m == nil {
				return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such server"}
			}
			if req.Expected == 0 && m.Cordoned == (action == sfc.ActionCordonNode) {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "unchanged", "the server is already in that state"}
			}
			var payload any = sfc.NodeCordon{ID: node, Reason: req.Reason}
			if action == sfc.ActionUncordonNode {
				payload = control.NodeSelection{ID: node}
			}
			return action, payload, expectedOr(req.Expected, m.cordonRevision()), "node/" + node, nil
		})
	}
}
