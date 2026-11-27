// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/loginlog"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// A login's record is written only after its ticket's signature proves this
// node issued it for that account, so a forged or foreign ticket cannot add
// rows to someone's history. Unknown usernames never get that far.

// LoginBudget is how many more password or token attempts the answering
// server (the leader) admits for the caller's username now
// (credentials.Budget). Each server counts its own attempts.
type LoginBudget struct {
	Left, Max int
}

func (s Service) ownTicket(t *Ticket) bool {
	return t != nil && s.Self != nil && t.Schema == 1 && t.Cluster == s.Policy.Cluster && t.Issuer == s.Self.Public && t.User != "" && ed25519.Verify(ed25519.PublicKey(s.Self.Public[:]), ticketBytes(*t), t.Signature)
}

// recordLogin notes the outcome of a login whose ticket this node issued.
// An "unavailable" (or other non-judgment) reply is not an attempt result.
func (s Service) recordLogin(t *Ticket, hint *loginlog.Client, source string, reply Reply, reason string) {
	if s.LoginRecorder == nil || !s.ownTicket(t) {
		return
	}
	r := loginlog.Record{User: t.User, Username: t.Username, Method: t.AuthMethod, Credential: t.Credential, Source: source}
	if r.Method == "" {
		r.Method = access.PrivateKey
	}
	if hint != nil && hint.Valid() {
		r.Client = *hint
	}
	session, ok := replyData[access.Session](reply)
	switch {
	case reply.Code == "ok" && ok:
		r.OK, r.Session, r.ExpiresAt, r.AccountRevision = true, session.ID, session.ExpiresAt, session.AccountRevision
	case reply.Code == "denied":
		r.Reason = reason
	default:
		return
	}
	s.LoginRecorder(r)
}

func (s Service) loginRecordsQuery(ctx context.Context, view cluster.View, session access.Session, q loginlog.Query) Reply {
	if s.LoginRecords == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	q.User = session.User
	page, err := s.LoginRecords(ctx, view, session, q)
	if err != nil {
		if errors.Is(err, loginlog.ErrInvalid) {
			return Reply{Schema: 1, Code: "denied"}
		}
		return Reply{Schema: 1, Code: "unavailable"}
	}
	reply := Reply{Schema: 1, Code: "ok", LoginPage: &page}
	if s.Credentials != nil && s.Self != nil {
		catalog, err := s.Policy.Catalog(view.State)
		if u, ok := catalog.User(session.User); err == nil && ok {
			left, max := s.Credentials.AttemptsLeft(u.Username, time.Now())
			reply.LoginBudget = &LoginBudget{Left: left, Max: max}
		}
	}
	return reply
}

// validLoginFields: LoginQuery only (and exactly) on login-records. The
// query names no user: it is always the session's own. A login's client
// description is in its typed request (login_methods.go).
func (r Request) validLoginFields() bool {
	if (r.LoginQuery != nil) != (r.Method == "login-records") {
		return false
	}
	if r.Method == "own-sessions" {
		return reflect.DeepEqual(r, Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce})
	}
	if r.Method != "login-records" {
		return true
	}
	q := *r.LoginQuery
	if q.User != "" {
		return false
	}
	q.User = "-"
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, LoginQuery: r.LoginQuery}
	return q.Valid() && reflect.DeepEqual(r, want)
}

// LoginRecords reads the caller's own recent logins across the cluster,
// newest first.
func (c Client) LoginRecords(ctx context.Context, peer sfcp.Peer, session access.Session, after string, limit int) (loginlog.Page, *LoginBudget, error) {
	q := loginlog.Query{After: after, Limit: limit}
	if check := (loginlog.Query{User: "-", After: after, Limit: limit}); !check.Valid() {
		return loginlog.Page{}, nil, sfcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "login-records", LoginQuery: &q})
	if err != nil {
		return loginlog.Page{}, nil, err
	}
	if reply.LoginPage == nil || len(reply.LoginPage.Items) > limit {
		return loginlog.Page{}, nil, sfcp.ErrFrame
	}
	for _, r := range reply.LoginPage.Items {
		if !r.Valid() || r.User != session.User {
			return loginlog.Page{}, nil, sfcp.ErrFrame
		}
	}
	return *reply.LoginPage, reply.LoginBudget, nil
}

type loginClientKey struct{}

// WithLoginClient attaches the client's own description to the logins sent
// with ctx (CredentialLogin, KeyLogin). sfcd keeps it beside the record as
// a hint; it grants nothing.
func WithLoginClient(ctx context.Context, c loginlog.Client) context.Context {
	return context.WithValue(ctx, loginClientKey{}, c)
}

// LoginClientFrom is the hint WithLoginClient attached to ctx, if any.
func LoginClientFrom(ctx context.Context) *loginlog.Client {
	c, ok := ctx.Value(loginClientKey{}).(loginlog.Client)
	if !ok || c == (loginlog.Client{}) || !c.Valid() {
		return nil
	}
	return &c
}

// ownSessions lists the caller's sessions that may still be open: their
// successful logins of the last session lifetime that are not expired,
// revoked, or outdated by an account or credential change. A server that
// did not answer is in Missing, and its sessions may be absent.
func (s Service) ownSessions(ctx context.Context, view cluster.View, session access.Session) Reply {
	if s.LoginRecords == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	catalog, err := s.Policy.Catalog(view.State)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	now := time.Now()
	oldest := now.Add(-time.Duration(access.MaxSessionSeconds)*time.Second - time.Minute).UnixMilli()
	out := loginlog.Page{Items: []loginlog.Record{}}
	q := loginlog.Query{User: session.User, Limit: loginlog.MaxPage}
	for range 8 {
		page, err := s.LoginRecords(ctx, view, session, q)
		if err != nil {
			return Reply{Schema: 1, Code: "unavailable"}
		}
		out.Missing = append(out.Missing, page.Missing...)
		done := page.Next == ""
		for _, r := range page.Items {
			if r.At < oldest {
				done = true
				break
			}
			if r.OK && r.ExpiresAt > now.Unix() && catalog.SessionLive(r.User, r.Session, r.Credential, r.AccountRevision) {
				out.Items = append(out.Items, r)
			}
		}
		if done {
			break
		}
		q.After = page.Next
	}
	slices.Sort(out.Missing)
	out.Missing = slices.Compact(out.Missing)
	return Reply{Schema: 1, Code: "ok", OwnSessions: &out}
}

// OwnSessions reads the caller's sessions that may still be open, newest
// first (from login records; see Service.ownSessions).
func (c Client) OwnSessions(ctx context.Context, peer sfcp.Peer, session access.Session) (loginlog.Page, error) {
	reply, err := c.query(ctx, peer, session, Request{Method: "own-sessions"})
	if err != nil {
		return loginlog.Page{}, err
	}
	if reply.OwnSessions == nil || len(reply.OwnSessions.Items) > 8*loginlog.MaxPage {
		return loginlog.Page{}, sfcp.ErrFrame
	}
	for _, r := range reply.OwnSessions.Items {
		if !r.Valid() || !r.OK || r.User != session.User {
			return loginlog.Page{}, sfcp.ErrFrame
		}
	}
	return *reply.OwnSessions, nil
}
