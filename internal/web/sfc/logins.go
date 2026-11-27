// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/jay94ks/seafield/internal/loginlog"
	"github.com/jay94ks/seafield/internal/userauth"
)

// LoginRecord is one login sfcd judged (loginlog.Record): a success with
// its session, or a failed attempt (Count > 1 for a run from one source).
type LoginRecord = loginlog.Record

// LoginPage is the caller's own recent logins across the cluster, newest
// first. Missing names servers whose records could not be read. Budget is
// the answering server's remaining password/token attempts for the
// caller's username, when it has a credential provider.
type LoginPage struct {
	Items   []LoginRecord
	Next    string
	Missing []string
	Budget  *userauth.LoginBudget
}

// LoginRecordsPage is how many records one LoginRecords call returns.
const LoginRecordsPage = 50

// WithLoginClient attaches what the browser reported about itself to the
// logins sent with ctx; sfcd keeps it beside the record as a hint.
func WithLoginClient(ctx context.Context, client, address string) context.Context {
	c := loginlog.Client{Client: truncateUTF8(client, 256), Address: truncateUTF8(address, 64)}
	if !c.Valid() {
		return ctx
	}
	return userauth.WithLoginClient(ctx, c)
}

func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && s[max]&0xc0 == 0x80 {
		max--
	}
	return s[:max]
}

func loginClientOf(ctx context.Context) loginlog.Client {
	if c := userauth.LoginClientFrom(ctx); c != nil {
		return *c
	}
	return loginlog.Client{}
}

// --- real ---

func (c *realConn) LoginRecords(ctx context.Context, after string) (LoginPage, error) {
	const m = "login-records"
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return LoginPage{}, err
	}
	defer done()
	p, budget, err := c.c.LoginRecords(ctx, c.peer, s, after, LoginRecordsPage)
	if err != nil {
		return LoginPage{}, realError(m, err)
	}
	return LoginPage{Items: p.Items, Next: p.Next, Missing: p.Missing, Budget: budget}, nil
}

// --- fake ---

// noteLogin keeps a fake record for an attempt on a known account. The
// caller holds c.f.mu.
func (c *fakeConn) noteLogin(ctx context.Context, t Ticket, s *Session) {
	r := loginlog.Record{Schema: 1, ID: fakeRecordID(), Node: "node-a", User: t.User, Username: t.Username, Method: t.AuthMethod, Credential: t.Credential, Count: 1, Client: loginClientOf(ctx), Source: "unix-uid:0"}
	if r.Method == "" {
		r.Method = MethodPrivateKey
	}
	r.At = time.Now().UnixMilli()
	if len(c.f.w.logins) > 0 && r.At <= c.f.w.logins[0].At {
		r.At = c.f.w.logins[0].At + 1 // keep newest-first order within a millisecond
	}
	r.LastAt = r.At
	if s != nil {
		r.OK, r.Session, r.ExpiresAt, r.AccountRevision = true, s.ID, s.ExpiresAt, s.AccountRevision
	} else {
		r.Reason = "denied"
	}
	c.f.w.logins = append([]loginlog.Record{r}, c.f.w.logins...)
}

func (c *fakeConn) LoginRecords(ctx context.Context, after string) (LoginPage, error) {
	user, err := c.lockSession(ctx, "login-records")
	if err != nil {
		return LoginPage{}, err
	}
	defer c.unlock()
	cursor, has, err := loginlog.ParseCursor(after)
	if err != nil {
		return LoginPage{}, fail("login-records", CodeDenied, "")
	}
	var own []loginlog.Record
	for _, r := range c.f.w.logins {
		if r.User == user && (!has || loginlog.Before(loginlog.Of(r), cursor)) {
			own = append(own, r)
		}
	}
	return LoginPage{Items: []LoginRecord{}, Budget: &userauth.LoginBudget{Left: 5, Max: 5}}.fill(own), nil
}

func (p LoginPage) fill(rows []loginlog.Record) LoginPage {
	loginlog.Sort(rows)
	merged := loginlog.Merge([]loginlog.Page{{Items: rows}}, LoginRecordsPage)
	p.Items, p.Next = merged.Items, merged.Next
	return p
}

func fakeRecordID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// SessionsPage is the caller's sessions that may still be open (from
// successful login records; revoked, expired and outdated ones left out).
type SessionsPage struct {
	Items   []LoginRecord
	Missing []string
}

func (c *realConn) OwnSessions(ctx context.Context) (SessionsPage, error) {
	const m = "own-sessions"
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return SessionsPage{}, err
	}
	defer done()
	p, err := c.c.OwnSessions(ctx, c.peer, s)
	if err != nil {
		return SessionsPage{}, realError(m, err)
	}
	return SessionsPage{Items: p.Items, Missing: p.Missing}, nil
}

func (c *fakeConn) OwnSessions(ctx context.Context) (SessionsPage, error) {
	user, err := c.lockSession(ctx, "own-sessions")
	if err != nil {
		return SessionsPage{}, err
	}
	defer c.unlock()
	out := SessionsPage{Items: []LoginRecord{}}
	now := time.Now().Unix()
	for _, r := range c.f.w.logins {
		if r.User == user && r.OK && r.ExpiresAt > now && !c.f.w.revoked[r.User+"/"+r.Session] {
			out.Items = append(out.Items, r)
		}
	}
	return out, nil
}
