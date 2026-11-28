// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Live updates (devel/design/web-live-updates.md): one sfcd change watch
// per login, fanned out to that login's browser sockets on
// GET /api/v1/live. A frame names the records that changed (never their
// content); the browser reads only those records through their usual
// endpoints. Nothing here reads sfcd on a timer.

const (
	liveRing     = 1024 // batches a reconnecting socket can resume over
	liveQueue    = 64   // frames buffered for a slow socket before they are merged
	liveMerged   = 512  // refs one merged frame names before it becomes a resync
	liveRetryMin = time.Second
	liveRetryMax = 30 * time.Second
)

// liveRef is one changed record as the browser sees it.
//
// A report notice (kinds "node-observation", "node-report", "diagnostic")
// names the server in Name and, for an observation, its Source and the
// tenant/app it belongs to.
type liveRef struct {
	Kind    string `json:"kind"`
	Tenant  string `json:"tenant,omitempty"`
	Name    string `json:"name"`
	Deleted bool   `json:"deleted,omitempty"`
	Source  string `json:"source,omitempty"`
	App     string `json:"app,omitempty"`
	// An engine notice ("engine.container", "engine.node") of this server
	// names the container and, comma-separated, what to read again
	// (start, stop, die, oom, pressure, health; boot, lag, build).
	Container string `json:"container,omitempty"`
	Reasons   string `json:"reasons,omitempty"`
}

// liveFrame is one socket message.
//
//	{"type":"changes","index":N,"refs":[...]}         records changed up to N
//	{"type":"changes","index":N,"resync":true}        read again, then go on from N
//	{"type":"state","state":"live"|"reconnecting"}    the watch behind the socket
//	{"type":"error","code":...}                       before the socket closes
type liveFrame struct {
	Type   string    `json:"type"`
	Index  uint64    `json:"index,omitempty"`
	Resync bool      `json:"resync,omitempty"`
	Refs   []liveRef `json:"refs,omitempty"`
	State  string    `json:"state,omitempty"`
	Code   string    `json:"code,omitempty"`
}

type liveBatch struct {
	index uint64
	refs  []liveRef
}

// liveWatch is the change watch of one login.
type liveWatch struct {
	ws     *webSession
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	sockets map[*liveSocket]struct{}
	waiting map[*liveSocket]uint64 // joined before the first sfcd frame
	ring    []liveBatch            // oldest first
	floor   uint64                 // nothing at or before floor can be replayed
	// seq numbers the batches the tabs see (sfcd's and the web's own).
	// It starts from the clock so a restarted daemon never reuses a tab's
	// number for other changes.
	seq     uint64
	watched uint64 // last sfcd index received (0: not yet)
	live    bool
	// gap: the sfcd watch broke, so report notices of the break are lost
	// (only numbered changes resume). Told to the tabs when it is back.
	gap bool

	// Tenant roles of the login, for deciding who hears of a tenant
	// incident: read once and shared, forgotten when a tenant record
	// changes or after liveRolesTTL.
	rmu      sync.Mutex
	roles    map[string]sfc.Role
	rolesAt  time.Time
	rolesGet chan struct{} // closed when the read in flight ends
	rolesGen uint64        // bumped by forgetRoles: a read begun before is not kept
}

// liveRolesTTL bounds how long a removed membership can still hear of its
// old tenant's incidents (by reference only: reading the incident checks
// again).
const liveRolesTTL = time.Minute

// tenantRoles returns the login's tenant roles, reading sfcd at most once
// for every caller that asks while a read is in flight.
func (w *liveWatch) tenantRoles(ctx context.Context, read func(context.Context) (map[string]sfc.Role, error)) (map[string]sfc.Role, error) {
	for {
		w.rmu.Lock()
		if w.roles != nil && time.Since(w.rolesAt) < liveRolesTTL {
			r := w.roles
			w.rmu.Unlock()
			return r, nil
		}
		if wait := w.rolesGet; wait != nil {
			w.rmu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		w.rolesGet = done
		gen := w.rolesGen
		w.rmu.Unlock()
		roles, err := read(ctx)
		w.rmu.Lock()
		if err == nil && gen == w.rolesGen {
			w.roles, w.rolesAt = roles, time.Now()
		}
		w.rolesGet = nil
		close(done)
		w.rmu.Unlock()
		if err != nil {
			return nil, err
		}
		return roles, nil
	}
}

func (w *liveWatch) forgetRoles() {
	w.rmu.Lock()
	w.roles = nil
	w.rolesGen++
	w.rmu.Unlock()
}

// Close ends the watch (the session ended).
func (w *liveWatch) Close() error {
	w.cancel()
	<-w.done
	return nil
}

type liveSocket struct {
	out  chan liveFrame
	stop chan struct{}
	once sync.Once
	// A burst the browser does not take in time is merged here instead of
	// queued: one changes frame (each record named once, or a resync when
	// too many), the last state, an error. The writer sends it once out is
	// empty. Guarded by the watch's mu.
	over *liveOver
	kick chan struct{}
}

type liveOver struct {
	changes *liveFrame
	state   string
	err     string
}

func (c *liveSocket) drop() { c.once.Do(func() { close(c.stop) }) }

// send queues f. A socket that does not keep up gets its next frames
// merged into one, so a burst costs the browser at most one more read and
// never grows the queue. w.mu is held.
func (w *liveWatch) send(c *liveSocket, f liveFrame) {
	if c.over == nil {
		select {
		case c.out <- f:
			return
		default:
			c.over = &liveOver{}
		}
	}
	o := c.over
	switch f.Type {
	case "state":
		o.state = f.State
	case "error":
		o.err = f.Code
	case "changes":
		if o.changes == nil {
			o.changes = &liveFrame{Type: "changes"}
		}
		m := o.changes
		m.Index = f.Index
		if f.Resync || m.Resync {
			m.Resync, m.Refs = true, nil
			break
		}
		for _, r := range f.Refs {
			if !slices.Contains(m.Refs, r) {
				m.Refs = append(m.Refs, r)
			}
		}
		if len(m.Refs) > liveMerged {
			m.Resync, m.Refs = true, nil
		}
	}
	if c.kick != nil {
		select {
		case c.kick <- struct{}{}:
		default:
		}
	}
}

// takeOver returns the merged frames once the queue is empty.
func (w *liveWatch) takeOver(c *liveSocket) []liveFrame {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c.over == nil || len(c.out) != 0 {
		return nil
	}
	o := c.over
	c.over = nil
	var out []liveFrame
	if o.changes != nil {
		out = append(out, *o.changes)
	}
	if o.state != "" {
		out = append(out, liveFrame{Type: "state", State: o.state})
	}
	if o.err != "" {
		out = append(out, liveFrame{Type: "error", Code: o.err})
	}
	return out
}

func (w *liveWatch) broadcast(f liveFrame) {
	for c := range w.sockets {
		w.send(c, f)
	}
}

func liveRefs(b sfc.ChangeBatch) []liveRef {
	out := make([]liveRef, 0, len(b.Refs))
	for _, r := range b.Refs {
		out = append(out, liveRef{Kind: r.Kind, Tenant: r.Tenant, Name: r.Name, Deleted: r.Deleted})
	}
	for _, e := range b.Events {
		out = append(out, liveRef{Kind: e.Kind, Tenant: e.Tenant, Name: e.Node, Source: e.Source, App: e.App, Container: e.Container, Reasons: strings.Join(e.Reasons, ",")})
	}
	return out
}

// receive takes one sfcd frame.
func (w *liveWatch) receive(b sfc.ChangeBatch) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.live {
		w.live = true
		w.broadcast(liveFrame{Type: "state", State: "live"})
	}
	first := w.watched == 0
	if !first && !b.Resync && (b.EventsLost || w.gap) {
		// Report notices are not resumed: the tabs read again, and a tab
		// that comes back from before this point reads again too.
		w.seq++
		w.ring, w.floor = nil, w.seq
		w.broadcast(liveFrame{Type: "changes", Index: w.seq, Resync: true})
	}
	w.gap = false
	if !first && len(b.Events) > 0 && b.Index == w.watched && !b.Resync {
		w.push(liveRefs(sfc.ChangeBatch{Events: b.Events}))
		return
	}
	if b.Index <= w.watched && !b.Resync {
		return
	}
	w.watched = b.Index
	switch {
	case first:
		// The watch starts here: what the tabs read before may be older.
		w.seq++
		w.ring, w.floor = nil, w.seq
	case b.Resync:
		w.seq++
		w.ring, w.floor = nil, w.seq
		w.broadcast(liveFrame{Type: "changes", Index: w.seq, Resync: true})
	default:
		for _, r := range b.Refs {
			if r.Kind == "tenant" {
				w.forgetRoles()
				break
			}
		}
		w.push(liveRefs(b))
	}
	for c, from := range w.waiting {
		if _, still := w.sockets[c]; still {
			w.start(c, from)
		}
	}
	w.waiting = nil
}

// push sends refs to every socket as the next batch. w.mu is held.
func (w *liveWatch) push(refs []liveRef) {
	if len(refs) == 0 {
		return
	}
	w.seq++
	w.ring = append(w.ring, liveBatch{w.seq, refs})
	if over := len(w.ring) - liveRing; over > 0 {
		w.floor = w.ring[over-1].index
		w.ring = append([]liveBatch(nil), w.ring[over:]...)
	}
	w.broadcast(liveFrame{Type: "changes", Index: w.seq, Refs: refs})
}

// local takes refs of the web daemon's own data (store.Change).
func (w *liveWatch) local(refs []liveRef) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.watched == 0 {
		return // not started: the tabs read again when it starts
	}
	w.push(refs)
}

func (w *liveWatch) lost() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gap = true
	if w.live {
		w.live = false
		w.broadcast(liveFrame{Type: "state", State: "reconnecting"})
	}
}

// join adds a socket that already saw changes up to from (0: none) and
// sends it what it missed, or a resync when that is no longer known.
func (w *liveWatch) join(c *liveSocket, from uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sockets[c] = struct{}{}
	state := "reconnecting"
	if w.live {
		state = "live"
	}
	w.send(c, liveFrame{Type: "state", State: state})
	if w.watched == 0 {
		// The first sfcd frame starts it.
		if w.waiting == nil {
			w.waiting = map[*liveSocket]uint64{}
		}
		w.waiting[c] = from
		return
	}
	w.start(c, from)
}

// start tells c where it stands. w.mu is held.
func (w *liveWatch) start(c *liveSocket, from uint64) {
	if from == 0 || from < w.floor || from > w.seq {
		w.send(c, liveFrame{Type: "changes", Index: w.seq, Resync: from != 0})
		return
	}
	var refs []liveRef
	for _, b := range w.ring {
		if b.index > from {
			refs = append(refs, b.refs...)
		}
	}
	w.send(c, liveFrame{Type: "changes", Index: w.seq, Refs: refs})
}

func (w *liveWatch) leave(c *liveSocket) {
	w.mu.Lock()
	delete(w.sockets, c)
	w.mu.Unlock()
}

// run keeps the login's sfcd watch open, resuming from the last index
// after a break. It ends with ctx (the login ended) or when sfcd refuses
// the session.
func (w *liveWatch) run(ctx context.Context) {
	defer close(w.done)
	retry := liveRetryMin
	for ctx.Err() == nil {
		var from uint64
		w.mu.Lock()
		from = w.watched
		w.mu.Unlock()
		started := time.Now()
		err := w.ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
			_, err := c.WatchChanges(ctx, from, func(b sfc.ChangeBatch) error {
				w.receive(b)
				return nil
			})
			return err
		})
		if ctx.Err() != nil {
			return
		}
		w.lost()
		var e *sfc.Error
		if errors.As(err, &e) && (e.Code == sfc.CodeClosed || e.Code == sfc.CodeExpired || e.Code == sfc.CodeDenied) {
			w.mu.Lock()
			w.broadcast(liveFrame{Type: "error", Code: "session-expired"})
			for s := range w.sockets {
				s.drop()
			}
			w.mu.Unlock()
			return
		}
		if time.Since(started) > liveRetryMax {
			retry = liveRetryMin
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry = min(retry*2, liveRetryMax)
	}
}

// liveState holds the watches by login.
type liveState struct {
	mu      sync.Mutex
	watches map[*webSession]*liveWatch
}

// attach joins c to ws's watch, starting the watch on first use.
func (s *Server) attachLive(ws *webSession, c *liveSocket, from uint64) (*liveWatch, bool) {
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	if w, ok := s.live.watches[ws]; ok {
		select {
		case <-w.done:
		default:
			w.join(c, from)
			return w, true
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &liveWatch{ws: ws, cancel: cancel, done: make(chan struct{}), sockets: map[*liveSocket]struct{}{}, seq: uint64(time.Now().UnixMicro())}
	release, ok := ws.hold(w)
	if !ok {
		cancel()
		return nil, false
	}
	if s.live.watches == nil {
		s.live.watches = map[*webSession]*liveWatch{}
	}
	s.live.watches[ws] = w
	w.join(c, from)
	go func() {
		w.run(ctx)
		release()
		s.live.mu.Lock()
		if s.live.watches[ws] == w {
			delete(s.live.watches, ws)
		}
		s.live.mu.Unlock()
	}()
	return w, true
}

// storeChanged hands a committed web store write to the watches that may
// see it: a user's own record (op, notification, AI conversation) to that
// user's logins; any other to system administrators and, when it belongs
// to a tenant (incident, webhook, guide), to logins with a role there.
// It must not block the writer, so the tenant check runs apart; the browser reads the record again whatever order refs arrive in.
func (s *Server) storeChanged(c store.Change) {
	ref := liveRef{Kind: c.Kind, Tenant: c.Tenant, Name: c.ID, Deleted: c.Deleted}
	s.live.mu.Lock()
	var check []*liveWatch
	for ws, w := range s.live.watches {
		switch {
		case c.User != "":
			// A user's own record (op, notification, AI conversation).
			if ws.user.ID == c.User {
				w.local([]liveRef{ref})
			}
		case ws.user.SystemAdmin:
			w.local([]liveRef{ref})
		case c.Tenant != "":
			// A tenant's record (incident, webhook, guide): its members too.
			check = append(check, w)
		}
	}
	s.live.mu.Unlock()
	for _, w := range check {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), s.opt.CallTimeout)
			defer cancel()
			roles, err := w.tenantRoles(ctx, func(ctx context.Context) (map[string]sfc.Role, error) {
				acc, err := s.incidentAccessCtx(ctx, w.ws)
				return acc.roles, err
			})
			if err == nil && roles[c.Tenant] != "" {
				w.local([]liveRef{ref})
			}
		}()
	}
}

// handleLive: GET /api/v1/live?from=N (WebSocket). from is the last index
// this tab applied; it resumes from there when the login's watch still
// knows it.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		writeError(w, http.StatusBadRequest, "bad-request", "WebSocket only")
		return
	}
	if r.Header.Get("Origin") == "" || !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "csrf", "cross-origin live socket")
		return
	}
	var from uint64
	if v := r.URL.Query().Get("from"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad-request", "from must be an index")
			return
		}
		from = n
	}
	c := &liveSocket{out: make(chan liveFrame, liveQueue), stop: make(chan struct{}), kick: make(chan struct{}, 1)}
	watch, ok := s.attachLive(ws, c, from)
	if !ok {
		writeError(w, http.StatusUnauthorized, "session-expired", "log in again")
		return
	}
	defer watch.leave(c)
	wsrv := websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil }, // origin checked above
		Handler: func(conn *websocket.Conn) {
			defer conn.Close()
			// The browser sends nothing; a read error is the socket closing.
			go func() {
				var discard []byte
				for websocket.Message.Receive(conn, &discard) == nil {
				}
				c.drop()
			}()
			write := func(f liveFrame) bool {
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				return websocket.JSON.Send(conn, f) == nil && f.Type != "error"
			}
			for {
				select {
				case f := <-c.out:
					if !write(f) {
						return
					}
				case <-c.kick:
				case <-c.stop:
					return
				case <-watch.done:
					// Flush what is queued (an error frame), then close.
					for {
						select {
						case f := <-c.out:
							_ = websocket.JSON.Send(conn, f)
						default:
							for _, f := range watch.takeOver(c) {
								_ = websocket.JSON.Send(conn, f)
							}
							return
						}
					}
				}
				for _, f := range watch.takeOver(c) {
					if !write(f) {
						return
					}
				}
			}
		},
	}
	wsrv.ServeHTTP(w, r)
}
