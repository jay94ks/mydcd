// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// GET /api/v1/me/credentials: the caller's own login methods (public data
// only), the account revision to use as expected for add/disable, and the
// cluster ID (hex) that the new key's add-credential proof binds
// (access.CredentialAdditionBytes).
func (s *Server) handleOwnCredentials(w http.ResponseWriter, r *http.Request, ws *webSession) {
	type ownView struct {
		publicUserView
		ClusterID string `json:"clusterId"`
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (ownView, error) {
		who, err := c.Whoami(ctx)
		if err != nil {
			return ownView{}, err
		}
		u, err := c.OwnCredentials(ctx)
		return ownView{publicUserRow(u), hex.EncodeToString(who.Session.Cluster[:])}, err
	})
}

// userView / publicUserView: sfcd's user rows plus accountRevision (=
// Revision, the Expected of credential changes) that screens read.
type userView struct {
	sfc.User
	AccountRevision uint64 `json:"accountRevision"`
}

type publicUserView struct {
	sfc.PublicUser
	AccountRevision uint64 `json:"accountRevision"`
}

func publicUserRow(u sfc.PublicUser) publicUserView {
	return publicUserView{PublicUser: u, AccountRevision: u.Revision}
}

// mapPage reshapes a page's rows for a screen and keeps its paging fields.
func mapPage[T, U any](p sfc.Page[T], f func(T) U) sfc.Page[U] {
	out := sfc.Page[U]{Items: make([]U, 0, len(p.Items)), Next: p.Next, Revision: p.Revision, Collection: p.Collection, ApprovalRevision: p.ApprovalRevision}
	for _, x := range p.Items {
		out.Items = append(out.Items, f(x))
	}
	return out
}

// GET /api/v1/me/logins?after=: the caller's own recent logins (sfcd keeps
// them per server and merges them). Failed attempts are included; a run of
// failures from one source is one row with count. budgetLeft/budgetMax are
// the answering server's remaining password/token attempts.
type loginRow struct {
	At         string `json:"at"`
	LastAt     string `json:"lastAt,omitempty"`
	Count      uint32 `json:"count"`
	OK         bool   `json:"ok"`
	Reason     string `json:"reason,omitempty"` // denied, throttled
	Method     string `json:"method"`
	Credential string `json:"credential,omitempty"`
	Session    string `json:"session,omitempty"`
	ExpiresAt  string `json:"expiresAt,omitempty"`
	Client     string `json:"client,omitempty"`
	Address    string `json:"address"`
	Source     string `json:"source,omitempty"`
	Node       string `json:"node"`
}

type loginsView struct {
	Items      []loginRow `json:"items"`
	Next       string     `json:"next,omitempty"`
	Missing    []string   `json:"missing"`
	BudgetLeft *int       `json:"budgetLeft,omitempty"`
	BudgetMax  *int       `json:"budgetMax,omitempty"`
}

func loginRowOf(r sfc.LoginRecord) loginRow {
	ms := func(v int64) string { return time.UnixMilli(v).UTC().Format(time.RFC3339Nano) }
	row := loginRow{At: ms(r.At), Count: r.Count, OK: r.OK, Reason: r.Reason, Method: string(r.Method), Credential: r.Credential, Session: r.Session, Client: r.Client.Client, Address: r.Client.Address, Source: r.Source, Node: r.Node}
	if r.LastAt != r.At {
		row.LastAt = ms(r.LastAt)
	}
	if r.ExpiresAt != 0 {
		row.ExpiresAt = time.Unix(r.ExpiresAt, 0).UTC().Format(time.RFC3339)
	}
	if row.Address == "" {
		// No browser report (a CLI login): the connection sfcd saw.
		row.Address = r.Source
	}
	return row
}

func (s *Server) handleOwnLogins(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (loginsView, error) {
		p, err := c.LoginRecords(ctx, r.URL.Query().Get("after"))
		if err != nil {
			return loginsView{}, err
		}
		out := loginsView{Items: make([]loginRow, 0, len(p.Items)), Next: p.Next, Missing: append([]string{}, p.Missing...)}
		for _, x := range p.Items {
			out.Items = append(out.Items, loginRowOf(x))
		}
		if p.Budget != nil {
			out.BudgetLeft, out.BudgetMax = &p.Budget.Left, &p.Budget.Max
		}
		return out, nil
	})
}

// loginContext carries the browser's user agent and address to sfcd's
// login record. The address is the connection's, or, from a trusted
// ingress, the last X-Forwarded-For hop that ingress added.
func (s *Server) loginContext(ctx context.Context, r *http.Request) context.Context {
	return sfc.WithLoginClient(ctx, r.UserAgent(), s.clientAddress(r))
}

func (s *Server) clientAddress(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	from := ap.Addr().Unmap()
	if r.Context().Value(directKey{}) == nil {
		for _, p := range s.opt.TrustedProxies {
			if !p.Contains(from) {
				continue
			}
			hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(hops[len(hops)-1])); err == nil {
				return a.Unmap().String()
			}
			break
		}
	}
	return from.String()
}

// GET /api/v1/me/sessions: the caller's sessions that may still be open,
// newest first. current marks the one this browser uses. sfcd lists them
// from its login records, so a server that did not answer is in missing.
type sessionRow struct {
	ID         string `json:"id"`
	Current    bool   `json:"current"`
	Method     string `json:"method"`
	Credential string `json:"credential,omitempty"`
	At         string `json:"at"`
	ExpiresAt  string `json:"expiresAt"`
	Client     string `json:"client,omitempty"`
	Address    string `json:"address"`
	Source     string `json:"source,omitempty"`
	Node       string `json:"node"`
}

type sessionsView struct {
	Items   []sessionRow `json:"items"`
	Missing []string     `json:"missing"`
}

func (s *Server) handleOwnSessions(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (sessionsView, error) {
		p, err := c.OwnSessions(ctx)
		if err != nil {
			return sessionsView{}, err
		}
		me, _ := c.Session()
		out := sessionsView{Items: make([]sessionRow, 0, len(p.Items)), Missing: append([]string{}, p.Missing...)}
		for _, x := range p.Items {
			l := loginRowOf(x)
			out.Items = append(out.Items, sessionRow{ID: x.Session, Current: x.Session == me.ID, Method: l.Method, Credential: l.Credential, At: l.At, ExpiresAt: l.ExpiresAt, Client: l.Client, Address: l.Address, Source: l.Source, Node: l.Node})
		}
		return out, nil
	})
}

// DELETE /api/v1/me/sessions/{id} {opId}: end one of the caller's own
// sessions (revoke-session). Ending the current one is a logout; use
// /auth/logout for that. To end every other session, call this for each.
func (s *Server) handleRevokeOwnSession(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	if id == "" || len(id) > 128 {
		writeError(w, http.StatusNotFound, "not-found", "no such session")
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, sess sfc.Session) (string, any, uint64, string, error) {
		if id == sess.ID {
			return "", nil, 0, "", &sfc.Error{Code: sfc.CodeInvalid, Method: sfc.ActionRevokeSession, Detail: "this is the current session; log out instead"}
		}
		return sfc.ActionRevokeSession, control.SessionRevocation{User: sess.User, Session: id}, sess.AccountRevision, "session/" + id, nil
	})
}
