// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

const cookieName = "mydc_web_session"

// webSession is one browser login. It owns one mydc.Conn (session key,
// transport, userauth client). The Conn redials after mydcd closes an idle
// connection and serializes exchanges per connection itself, so calls of
// one login run concurrently (R03).
type webSession struct {
	hash      string
	method    string
	user      sessionUser
	expiresAt time.Time
	issuedAt  time.Time

	conn mydc.Conn
	seen atomic.Int64 // unix nanos of the last browser request (idle limit)

	// Open container streams (logs, top/stats, exec). They do not use conn
	// after opening, so end() must stop them itself: a logout or expiry
	// ends every stream of the login.
	smu     sync.Mutex
	streams map[heldStream]struct{} // guarded by smu
	ended   bool                    // guarded by smu
}

// hold registers an open stream with the session. release unregisters it.
// If the session has already ended, the stream is stopped at once and hold
// returns false.
func (ws *webSession) hold(st heldStream) (release func(), ok bool) {
	ws.smu.Lock()
	if ws.ended {
		ws.smu.Unlock()
		stopStream(st)
		return func() {}, false
	}
	if ws.streams == nil {
		ws.streams = make(map[heldStream]struct{})
	}
	ws.streams[st] = struct{}{}
	ws.smu.Unlock()
	return func() {
		ws.smu.Lock()
		delete(ws.streams, st)
		ws.smu.Unlock()
	}, true
}

// stopStreams stops every open stream and refuses new ones.
func (ws *webSession) stopStreams() {
	ws.smu.Lock()
	ws.ended = true
	all := ws.streams
	ws.streams = nil
	ws.smu.Unlock()
	for st := range all {
		stopStream(st)
	}
}

// stopStream ends a stream's I/O (Cancel is not a kill) and closes it.
// heldStream: an open stream of the session (a container stream, a
// server shell). Cancel, when it has one, ends the I/O before Close.
type heldStream interface{ Close() error }

func stopStream(st heldStream) {
	if c, ok := st.(interface{ Cancel(context.Context) error }); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = c.Cancel(ctx)
		cancel()
	}
	_ = st.Close()
}

// pendingLogin is a challenge issued on a fresh connection, waiting for the
// browser's secret or signature. Login must finish on the same connection.
type pendingLogin struct {
	id       string
	method   string // password, token, key
	username string
	ticket   mydc.Ticket
	proof    mydc.KeyProof // key login only: unsigned proof the browser signs
	// approve: a key login that mydcd accepted, waiting for the browser's
	// signature of approval (R02). session is the issued, unapproved session.
	approve  bool
	session  mydc.Session
	approval mydc.SessionApproval
	conn     mydc.Conn
	deadline time.Time
}

// sessions tracks pending logins and live sessions in memory. Only hashes and
// display data go to the store.
type sessions struct {
	store   *store.Store
	now     func() time.Time
	ttl     time.Duration // pending login lifetime
	mu      sync.Mutex
	pending map[string]*pendingLogin
	live    map[string]*webSession // by cookie hash
	// limits returns the web settings' login cap and idle limit (0: off).
	limits func() (maxAge, idle time.Duration)
	// perUser returns the web settings' cap on one user's live logins
	// (0: none).
	perUser func() int
}

func newSessions(st *store.Store, now func() time.Time, ttl time.Duration) *sessions {
	return &sessions{store: st, now: now, ttl: ttl, pending: map[string]*pendingLogin{}, live: map[string]*webSession{}}
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashID(id string) string {
	h := sha256.Sum256([]byte("mydc-web-session-1\x00" + id))
	return hex.EncodeToString(h[:])
}

func (s *sessions) addPending(p *pendingLogin) {
	p.id = randomID(24)
	deadline := s.now().Add(s.ttl)
	if p.ticket.Deadline > 0 {
		if td := time.Unix(p.ticket.Deadline, 0); td.Before(deadline) {
			deadline = td
		}
	}
	p.deadline = deadline
	s.mu.Lock()
	s.pending[p.id] = p
	s.mu.Unlock()
}

// takePending removes and returns a pending login. A ticket is single use:
// a failed attempt closes the connection and the browser starts over.
func (s *sessions) takePending(id string) *pendingLogin {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending[id]
	if p == nil {
		return nil
	}
	delete(s.pending, id)
	if !s.now().Before(p.deadline) {
		p.conn.Close()
		return nil
	}
	return p
}

// start turns a successful login into a web session and returns the cookie
// value.
func (s *sessions) start(p *pendingLogin, u sessionUser, expiresAt time.Time) (string, *webSession, error) {
	id := randomID(32)
	if s.limits != nil {
		if maxAge, _ := s.limits(); maxAge > 0 {
			if c := s.now().Add(maxAge); c.Before(expiresAt) {
				expiresAt = c
			}
		}
	}
	now := s.now()
	ws := &webSession{hash: hashID(id), method: p.method, user: u, expiresAt: expiresAt, issuedAt: now, conn: p.conn}
	row := &store.SessionRow{Hash: ws.hash, User: u.ID, Username: u.Username, Method: p.method, IssuedAt: now, ExpiresAt: expiresAt, LastActive: now}
	if err := s.store.PutSession(row); err != nil {
		return "", nil, err
	}
	ws.seen.Store(now.UnixNano())
	s.mu.Lock()
	s.live[ws.hash] = ws
	s.mu.Unlock()
	if s.perUser != nil {
		if n := s.perUser(); n > 0 {
			s.capUser(u.ID, n)
		}
	}
	return id, ws, nil
}

// capUser ends a user's oldest live logins beyond n.
func (s *sessions) capUser(user string, n int) {
	s.mu.Lock()
	var mine []*webSession
	for _, ws := range s.live {
		if ws.user.ID == user {
			mine = append(mine, ws)
		}
	}
	s.mu.Unlock()
	if len(mine) <= n {
		return
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].issuedAt.After(mine[j].issuedAt) })
	for _, ws := range mine[n:] {
		s.end(ws, "session-limit")
	}
}

// capAll applies capUser to every user (after the cap is lowered).
func (s *sessions) capAll(n int) {
	s.mu.Lock()
	users := map[string]bool{}
	for _, ws := range s.live {
		users[ws.user.ID] = true
	}
	s.mu.Unlock()
	for u := range users {
		s.capUser(u, n)
	}
}

// lookup returns the live session of a cookie value, or nil when it is
// missing or expired. touch records browser activity for the idle limit.
func (s *sessions) lookup(cookie string, touch bool) *webSession {
	if cookie == "" {
		return nil
	}
	h := hashID(cookie)
	s.mu.Lock()
	ws := s.live[h]
	s.mu.Unlock()
	if ws == nil {
		return nil
	}
	now := s.now()
	if !now.Before(ws.expiresAt) {
		s.end(ws, "expired")
		return nil
	}
	if s.idleOut(ws, now) {
		s.end(ws, "idle")
		return nil
	}
	if touch {
		ws.seen.Store(now.UnixNano())
	}
	return ws
}

func (s *sessions) idleOut(ws *webSession, now time.Time) bool {
	if s.limits == nil {
		return false
	}
	_, idle := s.limits()
	return idle > 0 && now.Sub(time.Unix(0, ws.seen.Load())) >= idle
}

// end closes a session's connection, stops its open streams and marks its
// row ended.
func (s *sessions) end(ws *webSession, reason string) {
	s.mu.Lock()
	_, ok := s.live[ws.hash]
	delete(s.live, ws.hash)
	s.mu.Unlock()
	if !ok {
		return
	}
	ws.conn.Close()
	ws.stopStreams()
	_ = s.store.EndSession(ws.hash, reason, s.now())
}

// sweep expires pending logins and sessions.
func (s *sessions) sweep() {
	now := s.now()
	var deadPending []*pendingLogin
	var deadLive []*webSession
	s.mu.Lock()
	for id, p := range s.pending {
		if !now.Before(p.deadline) {
			delete(s.pending, id)
			deadPending = append(deadPending, p)
		}
	}
	var idleLive []*webSession
	for _, ws := range s.live {
		if !now.Before(ws.expiresAt) {
			deadLive = append(deadLive, ws)
		} else if s.idleOut(ws, now) {
			idleLive = append(idleLive, ws)
		}
	}
	s.mu.Unlock()
	for _, p := range deadPending {
		p.conn.Close()
	}
	for _, ws := range deadLive {
		s.end(ws, "expired")
	}
	for _, ws := range idleLive {
		s.end(ws, "idle")
	}
}

// closeAll ends every session (shutdown).
func (s *sessions) closeAll() {
	s.mu.Lock()
	var all []*webSession
	for _, ws := range s.live {
		all = append(all, ws)
	}
	for id, p := range s.pending {
		delete(s.pending, id)
		p.conn.Close()
	}
	s.mu.Unlock()
	for _, ws := range all {
		s.end(ws, "shutdown")
	}
}

// do runs fn with the session's connection.
func (ws *webSession) do(ctx context.Context, fn func(context.Context, mydc.Conn) error) error {
	return fn(ctx, ws.conn)
}

// sessionUser is the logged-in account as reported by whoami at login.
type sessionUser struct {
	ID          string
	Username    string
	SystemAdmin bool
}
