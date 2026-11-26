// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Incident response (REQ-9 and REQ-11 mocks): the incident account's
// action scope, display-only op reasons, and the temporary actions that
// were missing (cordon a server, reconnect a tunnel link, prune a server's
// unused images). mydcd judges every permission; the scope is mydcd's too.

// opReasonOf reads the optional X-MyDC-Reason and X-MyDC-Incident headers
// (UTF-8, percent-encoded, one line; mydcd's limits: the reason at most 512
// characters, the incident at most 128 bytes). The reason is part of the
// op's digest and goes with the signed original; it is display metadata
// only.
func opReasonOf(r *http.Request) (*store.OpReason, error) {
	var out store.OpReason
	for _, h := range []struct {
		name string
		to   *string
		ok   func(string) bool
	}{{"X-MyDC-Reason", &out.Reason, func(v string) bool { return utf8.RuneCountInString(v) <= 512 }},
		{"X-MyDC-Incident", &out.Incident, func(v string) bool { return len(v) <= 128 }}} {
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

func viewScope(s mydc.AccountScope) scopeView {
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
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (scopeView, error) {
		sc, err := c.AccountScope(ctx, r.PathValue("u"))
		return viewScope(sc), err
	})
}

// PUT /users/{u}/scope {opId, actions, keyOnly, expected?} →
// set-account-scope {User, Operations, KeyOnly} (system admin). Empty
// actions with keyOnly false removes the scope. Expected defaults to the
// account revision; every session of the account ends.
func (s *Server) handleSetAccountScope(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string   `json:"opId"`
		Actions  []string `json:"actions"`
		KeyOnly  bool     `json:"keyOnly"`
		Expected uint64   `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	user := r.PathValue("u")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		if len(req.Actions) > 64 {
			return "", nil, 0, "", invalid("actions: at most 64")
		}
		for _, a := range req.Actions {
			if a == "" || len(a) > 64 {
				return "", nil, 0, "", invalid("actions: action names such as restart-task")
			}
		}
		cur, err := c.AccountScope(ctx, user)
		if err != nil {
			return "", nil, 0, "", err
		}
		q := mydc.AccountScopeChange{User: user, KeyOnly: req.KeyOnly}
		if len(req.Actions) > 0 {
			q.Operations = req.Actions
		}
		return mydc.ActionSetAccountScope, q, expectedOr(req.Expected, cur.Revision), "user/" + user, nil
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
// original (mydcd keeps the same bytes and has no other read for it).
func (s *Server) handleOpReason(w http.ResponseWriter, r *http.Request, ws *webSession) {
	o := s.loadOp(w, r, ws)
	if o == nil {
		return
	}
	if o.RequestID == "" || len(o.Signed) == 0 {
		writeError(w, http.StatusConflict, "job", "this op has no single original (a job); read its step ops")
		return
	}
	rs, ok, err := mydc.SignedReason(o.Signed)
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
		s.sharedCreate(w, r, ws, req.OpID, actionBody{action, req}, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
			if action == mydc.ActionUncordonNode && req.Reason != "" || !(mydc.NodeCordon{ID: node, Reason: req.Reason}).Valid() {
				return "", nil, 0, "", invalid("reason: one line of at most 256 characters, cordon only")
			}
			m, err := findMember(ctx, c, node)
			if err != nil {
				return "", nil, 0, "", err
			}
			if m == nil {
				return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such server"}
			}
			if req.Expected == 0 && m.Cordoned == (action == mydc.ActionCordonNode) {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "unchanged", "the server is already in that state"}
			}
			var payload any = mydc.NodeCordon{ID: node, Reason: req.Reason}
			if action == mydc.ActionUncordonNode {
				payload = control.NodeSelection{ID: node}
			}
			return action, payload, expectedOr(req.Expected, m.cordonRevision()), "node/" + node, nil
		})
	}
}
