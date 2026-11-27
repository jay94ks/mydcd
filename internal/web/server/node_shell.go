// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/websocket"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Server SSH shell. sfcd checks the user's right
// (system administrator or NodeShell on the server) and the policy, then
// opens a PTY as the server's dedicated Seafield Cluster account. The web relays the
// PTY to the browser and never stores keys or screen content; its op
// record holds only the signed open request (server, size). Settings,
// grants and the forced close are ordinary signed actions; sfcd judges
// every one of them.

type nodeShellNodeView struct {
	Node     string `json:"node"`
	Shell    string `json:"shell"` // inherit / on / off
	Sudo     bool   `json:"sudo"`
	Enabled  bool   `json:"enabled"` // effective
	Ready    bool   `json:"ready"`
	NotReady string `json:"notReady,omitempty"`
}

type nodeShellGrantView struct {
	User  string   `json:"user"`
	Nodes []string `json:"nodes"`
}

type nodeShellPolicyView struct {
	Enabled     bool                 `json:"enabled"`
	MaxSessions int                  `json:"maxSessions"`
	IdleSeconds int                  `json:"idleSeconds"`
	Account     string               `json:"account"`
	Nodes       []nodeShellNodeView  `json:"nodes"`
	Grants      []nodeShellGrantView `json:"grants"`
	Revision    uint64               `json:"revision"`
}

func nodeShellPolicyOf(p sfc.NodeShellPolicy) nodeShellPolicyView {
	v := nodeShellPolicyView{Enabled: p.Enabled, MaxSessions: p.MaxSessions, IdleSeconds: p.IdleSeconds, Account: p.Account, Revision: p.Revision,
		Nodes: []nodeShellNodeView{}, Grants: []nodeShellGrantView{}}
	for _, n := range p.Nodes {
		v.Nodes = append(v.Nodes, nodeShellNodeView{Node: n.Node, Shell: n.Shell, Sudo: n.Sudo, Enabled: n.Enabled, Ready: n.Ready, NotReady: n.NotReady})
	}
	for _, g := range p.Grants {
		v.Grants = append(v.Grants, nodeShellGrantView{User: g.User, Nodes: append([]string{}, g.Nodes...)})
	}
	return v
}

type nodeShellEndView struct {
	Code     int               `json:"code"`
	Reason   string            `json:"reason"`
	ClosedBy map[string]string `json:"closedBy,omitempty"`
}

type nodeShellSessionView struct {
	SessionID    string            `json:"sessionId"`
	User         string            `json:"user"`
	Username     string            `json:"username"`
	Node         string            `json:"node"`
	Account      string            `json:"account"`
	Sudo         bool              `json:"sudo"`
	State        string            `json:"state"`
	CreatedAt    string            `json:"createdAt"`
	OpenedAt     string            `json:"openedAt,omitempty"`
	LastActivity string            `json:"lastActivity,omitempty"`
	ClosedAt     string            `json:"closedAt,omitempty"`
	BytesIn      uint64            `json:"bytesIn"`
	BytesOut     uint64            `json:"bytesOut"`
	End          *nodeShellEndView `json:"end,omitempty"`
}

// unixTime: sfcd's Unix seconds as RFC 3339, "" for 0 (not yet).
func unixTime(sec int64) string {
	if sec == 0 {
		return ""
	}
	return rfc3339(time.Unix(sec, 0))
}

func nodeShellEndOf(e sfc.NodeShellEnd) *nodeShellEndView {
	v := &nodeShellEndView{Code: e.Code, Reason: e.Reason}
	if by := e.ClosedBy; by != nil {
		v.ClosedBy = map[string]string{"user": by.User, "username": by.Username}
	}
	return v
}

func nodeShellSessionOf(s sfc.NodeShellSession) nodeShellSessionView {
	v := nodeShellSessionView{SessionID: s.SessionID, User: s.User, Username: s.Username, Node: s.Node, Account: s.Account, Sudo: s.Sudo,
		State: s.State, CreatedAt: unixTime(s.CreatedAt), OpenedAt: unixTime(s.OpenedAt), LastActivity: unixTime(s.LastActivity),
		ClosedAt: unixTime(s.ClosedAt), BytesIn: s.BytesIn, BytesOut: s.BytesOut}
	if s.End != nil {
		v.End = nodeShellEndOf(*s.End)
	}
	return v
}

// GET /node-shell → {enabled, maxSessions, idleSeconds, account, nodes:[{node,
// shell, sudo, enabled, ready, notReady?}], grants:[{user, nodes}], revision}.
// A non-admin with NodeShell sees the granted servers and their own grant.
func (s *Server) handleNodeShellPolicy(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (nodeShellPolicyView, error) {
		p, err := c.NodeShellPolicy(ctx)
		return nodeShellPolicyOf(p), err
	})
}

// PUT /node-shell {opId, enabled?, maxSessions?, idleSeconds?, expected?} →
// set-node-shell-policy. Omitted fields keep the current values; Expected
// defaults to the policy revision.
func (s *Server) handleNodeShellPolicyPut(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID        string `json:"opId"`
		Enabled     *bool  `json:"enabled,omitempty"`
		MaxSessions *int   `json:"maxSessions,omitempty"`
		IdleSeconds *int   `json:"idleSeconds,omitempty"`
		Expected    uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		p, err := c.NodeShellPolicy(ctx)
		if err != nil {
			return "", nil, 0, "", err
		}
		q := sfc.SetNodeShellPolicy{Enabled: p.Enabled, MaxSessions: p.MaxSessions, IdleSeconds: p.IdleSeconds}
		if req.Enabled != nil {
			q.Enabled = *req.Enabled
		}
		if req.MaxSessions != nil {
			q.MaxSessions = *req.MaxSessions
		}
		if req.IdleSeconds != nil {
			q.IdleSeconds = *req.IdleSeconds
		}
		if q.MaxSessions < 1 || q.MaxSessions > 16 || q.IdleSeconds < 60 || q.IdleSeconds > 86400 {
			return "", nil, 0, "", invalid("maxSessions 1–16, idleSeconds 60–86400")
		}
		return sfc.ActionSetNodeShellPolicy, q, expectedOr(req.Expected, p.Revision), "node-shell", nil
	})
}

// PUT /node-shell/nodes/{node} {opId, shell(inherit/on/off), sudo,
// expected?} → set-node-shell-node. sfcd applies sudo to the account.
func (s *Server) handleNodeShellNodePut(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Shell    string `json:"shell"`
		Sudo     bool   `json:"sudo"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	node := r.PathValue("node")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		switch req.Shell {
		case sfc.NodeShellInherit, sfc.NodeShellOn, sfc.NodeShellOff:
		default:
			return "", nil, 0, "", invalid("shell: inherit, on or off")
		}
		p, err := c.NodeShellPolicy(ctx)
		if err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionSetNodeShellNode, sfc.SetNodeShellNode{Node: node, Shell: req.Shell, Sudo: req.Sudo}, expectedOr(req.Expected, p.Revision), "node-shell/" + node, nil
	})
}

// PUT /node-shell/grants/{user} {opId, nodes, expected?} →
// set-node-shell-grant (user ID; empty nodes revokes NodeShell).
func (s *Server) handleNodeShellGrantPut(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string   `json:"opId"`
		Nodes    []string `json:"nodes"`
		Expected uint64   `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	user := r.PathValue("user")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		p, err := c.NodeShellPolicy(ctx)
		if err != nil {
			return "", nil, 0, "", err
		}
		nodes := append([]string{}, req.Nodes...)
		return sfc.ActionSetNodeShellGrant, sfc.SetNodeShellGrant{User: user, Nodes: nodes}, expectedOr(req.Expected, p.Revision), "node-shell/grant/" + user, nil
	})
}

// GET /node-shell/sessions?after=&active=&state=&node= → {items, next,
// total}: sfcd's page of 8 by sessionId (system administrator: all;
// others: their own). active=1 is state=open (queued, opened, closing);
// state=closed the kept closed ones; node narrows to one server. Total and
// next follow the filter.
func (s *Server) handleNodeShellSessions(w http.ResponseWriter, r *http.Request, ws *webSession) {
	qs := r.URL.Query()
	q := sfc.NodeShellSessionsQuery{After: qs.Get("after"), State: qs.Get("state"), Node: qs.Get("node")}
	if qs.Get("active") == "1" {
		q.State = sfc.NodeShellStateOpen
	}
	if len(q.After) > 256 || q.State != "" && q.State != sfc.NodeShellStateOpen && q.State != sfc.NodeShellClosed || q.Node != "" && !safeParamRE.MatchString(q.Node) {
		writeError(w, http.StatusBadRequest, "bad-request", "after: a session id; state: open or closed; node: a name")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		p, err := c.QueryNodeShellSessions(ctx, q)
		if err != nil {
			return nil, err
		}
		items := []nodeShellSessionView{}
		for _, x := range p.Sessions {
			items = append(items, nodeShellSessionOf(x))
		}
		return map[string]any{"items": items, "next": p.Next, "total": p.Total, "asOf": rfc3339(s.now())}, nil
	})
}

// POST /node-shell/sessions/{id}/close {opId} → close-node-shell
// {SessionID} (Expected 0).
func (s *Server) handleNodeShellClose(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		return sfc.ActionCloseNodeShell, sfc.CloseNodeShell{SessionID: id}, 0, "node-shell/session/" + id, nil
	})
}

// shellMsg: a browser → daemon message on the shell socket.
type shellMsg struct {
	Type string `json:"type"` // stdin, resize, close
	Data []byte `json:"data,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
}

// nodeShellStream adapts a NodeShell to the session's held streams (a
// logout or session end closes it).
type nodeShellStream struct{ sfc.NodeShell }

// GET /nodes/{node}/shell?opId=&cols=&rows= (WebSocket): open-node-shell.
// The signed request is stored first (op "open-node-shell", no content),
// then opened. One opId opens one shell: a used opId is 409 shell-used.
// Refusals before the socket opens are HTTP errors with sfcd's code
// (403 forbidden, 409 node-shell-disabled / node-shell-not-ready / limit,
// 503 node-unreachable).
//
// Socket: daemon → browser {"type":"session", session}, {"type":"stdout",
// "data":base64}, {"type":"end", "code", "reason"(exit/idle/closed)},
// {"type":"error", "code"}; browser → daemon {"type":"stdin", "data"},
// {"type":"resize", rows, cols}, {"type":"close"}. The browser leaving
// closes the shell.
func (s *Server) handleNodeShellOpen(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	opID := q.Get("opId")
	if !uuidRE.MatchString(opID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	if r.Header.Get("Origin") == "" || !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "csrf", "cross-origin terminal")
		return
	}
	node := r.PathValue("node")
	cv, _ := strconv.ParseUint(q.Get("cols"), 10, 16)
	rv, _ := strconv.ParseUint(q.Get("rows"), 10, 16)
	cols, rows := uint16(cv), uint16(rv)
	if node == "" || cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
		s.refuseShell(w, r, ws, &httpErr{http.StatusBadRequest, "bad-request", "cols and rows: 1–1000"})
		return
	}
	if old, err := s.opt.Store.GetOp(ws.user.ID, opID); err == nil && old != nil {
		s.refuseShell(w, r, ws, &httpErr{http.StatusConflict, "shell-used", "this opId already opened a shell; use a new opId"})
		return
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.refuseShell(w, r, ws, &httpErr{http.StatusInternalServerError, "internal", err.Error()})
		return
	}
	payload := sfc.OpenNodeShell{Node: node, Cols: cols, Rows: rows}
	digestReq := opRequest{Action: sfc.ActionOpenNodeShell, Payload: mustJSON(map[string]any{"node": node})}
	dg := digestReq.digest()

	ctx, cancel := s.callCtx(r)
	var sh sfc.NodeShell
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		who, err := c.Whoami(ctx)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(payload)
		ch := sfc.Change{Schema: 1, Action: sfc.ActionOpenNodeShell, Principal: ws.user.ID, Expected: 0, Payload: raw}
		op, err := c.PrepareRequest(ctx, "shell-"+opID, ch, who.RootFor(sfc.ActionOpenNodeShell))
		if err != nil {
			return err
		}
		now := s.now()
		o := &store.Op{ID: opID, User: ws.user.ID, Username: ws.user.Username, RequestID: "shell-" + opID, Action: sfc.ActionOpenNodeShell,
			Target: "node/" + node, Digest: dg, Signed: op, State: store.OpRunning, SubmittedAt: now, UpdatedAt: now}
		if existing, err := s.opt.Store.CreateOp(o); err != nil {
			return err
		} else if existing != nil {
			return &httpErr{http.StatusConflict, "shell-used", "this opId already opened a shell; use a new opId"}
		}
		// sfcd accepts the open first (a queued session counted in the
		// limits), then the same original opens the PTY.
		res, serr := c.Submit(ctx, op)
		if serr != nil || res.Code != sfc.ResultApplied {
			settleSubmit(o, res, serr, s.now())
			code := ""
			if serr == nil {
				code = shellRefusal(res)
				if o.ErrorCode == "" {
					o.ErrorCode = code
				}
			}
			_ = s.saveOp(o)
			if serr != nil {
				return serr
			}
			return &httpErr{statusOf(code), code, "sfcd refused the shell: " + code}
		}
		sh, err = c.OpenNodeShell(ctx, op)
		if err != nil {
			s.finishShellOp(ws, opID, "", 0, err)
		}
		return err
	})
	cancel()
	if err != nil {
		s.refuseShell(w, r, ws, err)
		return
	}
	held := nodeShellStream{sh}
	release, ok := ws.hold(held)
	if !ok {
		s.finishShellOp(ws, opID, "closed", 130, nil)
		s.refuseShell(w, r, ws, errSessionEnded)
		return
	}
	defer release()
	defer sh.Close()

	wsrv := websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil }, // origin checked above
		Handler: func(conn *websocket.Conn) {
			defer conn.Close()
			s.pumpShell(r.Context(), conn, sh, opID, ws)
		},
	}
	wsrv.ServeHTTP(w, r)
}

// shellRefusal: the web error code of a refused open-node-shell submit
// (the sfcd rejection reason, forbidden, conflict for a stale CAS).
func shellRefusal(res sfc.Result) string {
	if c := sfc.ResultErrorCode(res.Code); c != "" {
		return c
	}
	switch res.Code {
	case sfc.ResultForbidden:
		return string(sfc.CodeForbidden)
	case sfc.ResultConditionFailed:
		return "conflict"
	}
	if res.Reason != "" && safeParamRE.MatchString(res.Reason) {
		return res.Reason
	}
	return "refused"
}

// refuseShell answers a refusal of a shell open. A WebSocket upgrade (a
// browser cannot read the status of a refused upgrade) gets the socket and
// one {"type":"error", "status", "code", "message"} before it closes; any
// other request gets the same HTTP error.
func (s *Server) refuseShell(w http.ResponseWriter, r *http.Request, ws *webSession, err error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		s.writeBackendError(w, ws, err)
		return
	}
	status, e := s.backendError(ws, err)
	wsrv := websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil }, // origin checked before
		Handler: func(conn *websocket.Conn) {
			defer conn.Close()
			_ = websocket.JSON.Send(conn, map[string]any{"type": "error", "status": status, "code": e.Code, "message": e.Message})
		},
	}
	wsrv.ServeHTTP(w, r)
}

func (s *Server) pumpShell(ctx context.Context, conn *websocket.Conn, sh sfc.NodeShell, opID string, ws *webSession) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	_ = websocket.JSON.Send(conn, map[string]any{"type": "session", "session": nodeShellSessionOf(sh.Session())})
	go func() {
		defer cancel()
		for {
			var m shellMsg
			if err := websocket.JSON.Receive(conn, &m); err != nil {
				// The browser left: the shell ends with it.
				_ = sh.Close()
				return
			}
			var err error
			switch m.Type {
			case "stdin":
				err = sh.Send(ctx, m.Data)
			case "resize":
				if m.Cols == 0 || m.Rows == 0 || m.Cols > 1000 || m.Rows > 1000 {
					continue
				}
				err = sh.Resize(ctx, m.Cols, m.Rows)
			case "close":
				err = sh.Close()
			}
			if err != nil {
				_ = websocket.JSON.Send(conn, map[string]string{"type": "error", "code": streamErrCode(err)})
			}
		}
	}()
	for {
		data, err := sh.Recv(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				end := sh.End()
				s.finishShellOp(ws, opID, end.Reason, end.Code, nil)
				msg := map[string]any{"type": "end", "code": end.Code, "reason": end.Reason}
				if by := end.ClosedBy; by != nil {
					msg["closedBy"] = map[string]string{"user": by.User, "username": by.Username}
				}
				_ = websocket.JSON.Send(conn, msg)
			} else if ctx.Err() == nil {
				s.finishShellOp(ws, opID, "", 0, err)
				_ = websocket.JSON.Send(conn, map[string]string{"type": "error", "code": streamErrCode(err)})
			} else {
				s.finishShellOp(ws, opID, "closed", 130, nil)
			}
			return
		}
		if err := websocket.JSON.Send(conn, map[string]any{"type": "stdout", "data": data}); err != nil {
			return
		}
	}
}

// finishShellOp settles the open-node-shell op: applied with the exit code
// and reason, or failed with sfcd's code.
func (s *Server) finishShellOp(ws *webSession, opID, reason string, code int, err error) {
	o, gerr := s.opt.Store.GetOp(ws.user.ID, opID)
	if gerr != nil || o.State != store.OpRunning {
		return
	}
	o.UpdatedAt = s.now()
	if err != nil {
		o.State, o.ErrorCode = store.OpFailed, streamErrCode(err)
	} else {
		o.State = store.OpApplied
		o.Result = &store.OpResult{Found: true, Code: code}
		o.ErrorCode = ""
		if reason != "" && reason != "exit" {
			o.ErrorCode = reason
		}
	}
	_ = s.saveOp(o)
}
