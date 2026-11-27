// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"golang.org/x/net/websocket"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// streamRecordView is one container stream record for the browser.
type streamRecordView struct {
	Type     string               `json:"type"`
	Sequence uint64               `json:"sequence,omitempty"`
	Data     []byte               `json:"data,omitempty"` // base64
	Text     string               `json:"text,omitempty"` // Data when it is valid UTF-8
	Sample   *sfc.ContainerSample `json:"sample,omitempty"`
	Receipt  *sfc.ExecReceipt     `json:"receipt,omitempty"`
	Code     string               `json:"code,omitempty"`
}

func viewRecord(r sfc.StreamRecord) streamRecordView {
	v := streamRecordView{Type: r.Kind, Sequence: r.Sequence, Data: r.Data, Sample: r.Sample, Receipt: r.Receipt, Code: r.Code}
	if len(r.Data) > 0 && utf8.Valid(r.Data) {
		v.Text = string(r.Data)
	}
	return v
}

// openStream resolves the container, signs the intent and opens the stream
// on the session's connection. The stream itself is independent of the
// connection afterwards. store, when set, runs between signing and opening
// (exec intents are stored before they are sent).
func (s *Server) openStream(ctx context.Context, ws *webSession, tenant string, sel sfc.ContainerSelection, spec sfc.StreamSpec, requestID string, store func(sfc.StreamTarget, sfc.SignedIntent) error) (sfc.Stream, error) {
	var st sfc.Stream
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		target, err := c.ResolveStream(ctx, tenant, sel, spec)
		if err != nil {
			return err
		}
		intent, err := c.PrepareStream(ctx, target, spec, requestID)
		if err != nil {
			return err
		}
		if store != nil {
			if err := store(target, intent); err != nil {
				return err
			}
		}
		st, err = c.OpenStream(ctx, tenant, intent)
		return err
	})
	return st, err
}

// errSessionEnded is returned when the login ended while a stream opened.
var errSessionEnded = &sfc.Error{Code: sfc.CodeSessionExpired, Detail: "the login ended"}

// selectionOf reads the container from the path: an app task
// (/apps/{app}?service=&instance=) or a standalone container
// (/standalone/{name}, REQ-29 mock).
func selectionOf(r *http.Request) sfc.ContainerSelection {
	if name := r.PathValue("name"); name != "" {
		return sfc.ContainerSelection{Standalone: name}
	}
	q := r.URL.Query()
	return sfc.ContainerSelection{App: r.PathValue("app"), Service: q.Get("service"), Instance: q.Get("instance")}
}

func boolParam(r *http.Request, name string, def bool) bool {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

// GET /api/v1/t/{t}/apps/{app}/stream?kind=logs|top|stats&service=&instance=
// &tail=&stdout=&stderr=&interval=: a Server-Sent Events stream of one
// container's log follow or top/stats watch. Events are named after the
// record type (stdout, stderr, sample, output-eof) plus "end" and "error";
// data is the JSON record. Server pings become SSE comments.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	sel := selectionOf(r)
	if sel.Service == "" && sel.Standalone == "" {
		writeError(w, http.StatusBadRequest, "bad-request", "service is required")
		return
	}
	var spec sfc.StreamSpec
	switch kind := q.Get("kind"); kind {
	case "", "logs":
		tail, _ := strconv.Atoi(q.Get("tail"))
		if tail < 0 || tail > 10000 {
			writeError(w, http.StatusBadRequest, "bad-request", "tail must be 0..10000")
			return
		}
		spec = sfc.LogsFollowSpec(sel, tail, boolParam(r, "stdout", true), boolParam(r, "stderr", true))
	case "top", "stats":
		iv := 5 * time.Second
		if v := q.Get("interval"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d < time.Second || d > time.Minute {
				writeError(w, http.StatusBadRequest, "bad-request", "interval must be 1s..1m")
				return
			}
			iv = d
		}
		spec = sfc.WatchSpec(kind, sel, iv)
	default:
		writeError(w, http.StatusBadRequest, "bad-request", "kind must be logs, top or stats")
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "streaming not supported")
		return
	}
	ctx, cancel := s.callCtx(r)
	st, err := s.openStream(ctx, ws, r.PathValue("t"), sel, spec, "", nil)
	cancel()
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	release, ok := ws.hold(st)
	if !ok {
		s.writeBackendError(w, ws, errSessionEnded)
		return
	}
	defer release()
	defer st.Close()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	sendEvent(w, "target", camel{st.Target()})
	fl.Flush()

	rctx := r.Context()
	go func() {
		<-rctx.Done()
		// The browser went away: end the I/O. Logs/top/stats have no
		// effect to keep.
		cctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		_ = st.Cancel(cctx)
		c()
		st.Close()
	}()
	for {
		rec, err := st.Recv(rctx)
		if err != nil {
			if rctx.Err() != nil {
				return
			}
			if errors.Is(err, io.EOF) {
				sendEvent(w, "end", map[string]string{"type": "end"})
			} else {
				sendEvent(w, "error", map[string]string{"type": "error", "code": streamErrCode(err)})
			}
			fl.Flush()
			return
		}
		if rec.Kind == sfc.RecordPing {
			fmt.Fprint(w, ": ping\n\n")
		} else {
			sendEvent(w, rec.Kind, camel{viewRecord(rec)})
		}
		fl.Flush()
	}
}

func streamErrCode(err error) string {
	var me *sfc.Error
	if errors.As(err, &me) {
		return string(me.Code)
	}
	return "disconnected"
}

func sendEvent(w io.Writer, name string, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, raw)
}

// execMsg is a browser → server terminal message.
type execMsg struct {
	Type string `json:"type"` // stdin, close-stdin, resize, cancel
	Data []byte `json:"data,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
}

// GET /api/v1/t/{t}/apps/{app}/exec?opId=&service=&instance=&cmd=..&cmd=..
// &tty=1&stdin=1&rows=&cols= (WebSocket): interactive exec. The signed exec
// intent is stored as op <opId> (action "exec") before it is opened, so a
// lost connection is settled with /ops/{opId}/result (exec status), never by
// running the command again. Reconnecting with the same opId reopens the same
// intent: the server sends its receipt and ends without a second run.
func (s *Server) handleExec(w http.ResponseWriter, r *http.Request, ws *webSession) {
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
	tenant := r.PathValue("t")
	sel := selectionOf(r)
	argv := q["cmd"]
	tty, stdin := boolParam(r, "tty", false), boolParam(r, "stdin", false)
	var rows, cols uint16
	if tty {
		rv, _ := strconv.ParseUint(q.Get("rows"), 10, 16)
		cv, _ := strconv.ParseUint(q.Get("cols"), 10, 16)
		rows, cols = uint16(rv), uint16(cv)
	}
	if sel.Service == "" && sel.Standalone == "" || len(argv) == 0 || (tty && (rows == 0 || cols == 0)) {
		writeError(w, http.StatusBadRequest, "bad-request", "service, cmd and (for tty) rows/cols are required")
		return
	}
	spec := sfc.ExecStreamSpec(argv, stdin, tty, rows, cols)
	digestReq := opRequest{Action: "exec", Payload: mustJSON(map[string]any{"sel": sel, "argv": argv, "tty": tty, "stdin": stdin})}
	dg := digestReq.digest()

	old, err := s.opt.Store.GetOp(ws.user.ID, opID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if old != nil && (old.Action != "exec" || old.Digest != dg) {
		writeError(w, http.StatusConflict, "op-conflict", "this opId was already used for a different change")
		return
	}

	ctx, cancel := s.callCtx(r)
	var st sfc.Stream
	if old != nil {
		// Same original intent: the server answers with its receipt only.
		err = ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
			var err error
			st, err = c.OpenStream(ctx, tenant, sfc.SignedIntent(old.Signed))
			return err
		})
	} else {
		// The exec operation ID must follow the sfcd ID grammar
		// (starts with a letter), so it is "exec-<opId>".
		st, err = s.openStream(ctx, ws, tenant, sel, spec, "exec-"+opID, func(t sfc.StreamTarget, in sfc.SignedIntent) error {
			now := s.now()
			o := &store.Op{ID: opID, User: ws.user.ID, Username: ws.user.Username, RequestID: "exec-" + opID, Action: "exec", Tenant: tenant,
				Target: execTarget(sel, t), Digest: dg, Signed: in, State: store.OpRunning, SubmittedAt: now, UpdatedAt: now}
			existing, err := s.opt.Store.CreateOp(o)
			if err == nil && existing != nil {
				err = &httpErr{http.StatusConflict, "op-conflict", "concurrent use of this opId"}
			}
			return err
		})
	}
	cancel()
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	release, ok := ws.hold(st)
	if !ok {
		s.writeBackendError(w, ws, errSessionEnded)
		return
	}
	defer release()
	defer st.Close()

	wsrv := websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil }, // origin checked above
		Handler: func(conn *websocket.Conn) {
			defer conn.Close()
			s.pumpExec(r.Context(), conn, st, opID, ws)
		},
	}
	wsrv.ServeHTTP(w, r)
}

func (s *Server) pumpExec(ctx context.Context, conn *websocket.Conn, st sfc.Stream, opID string, ws *webSession) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer cancel()
		for {
			var m execMsg
			if err := websocket.JSON.Receive(conn, &m); err != nil {
				// Browser gone: end the I/O only; the process keeps running.
				cctx, c := context.WithTimeout(context.Background(), 5*time.Second)
				_ = st.Cancel(cctx)
				c()
				return
			}
			var err error
			switch m.Type {
			case "stdin":
				err = st.Stdin(ctx, m.Data)
			case "close-stdin":
				err = st.CloseStdin(ctx)
			case "resize":
				err = st.Resize(ctx, m.Rows, m.Cols)
			case "cancel":
				err = st.Cancel(ctx)
			}
			if err != nil {
				_ = websocket.JSON.Send(conn, map[string]string{"type": "error", "code": streamErrCode(err)})
			}
		}
	}()
	for {
		rec, err := st.Recv(ctx)
		if err != nil {
			if ctx.Err() == nil {
				t := map[string]string{"type": "end"}
				if !errors.Is(err, io.EOF) {
					t = map[string]string{"type": "error", "code": streamErrCode(err)}
				}
				_ = websocket.JSON.Send(conn, t)
			}
			return
		}
		if rec.Kind == sfc.RecordPing {
			continue
		}
		if rec.Kind == sfc.RecordReceipt && rec.Receipt != nil {
			s.noteReceipt(ws, opID, *rec.Receipt)
		}
		raw, err := camelJSON(viewRecord(rec))
		if err != nil {
			return
		}
		if err := websocket.Message.Send(conn, string(raw)); err != nil {
			return
		}
	}
}

// noteReceipt records a finished exec's exit in its op.
func (s *Server) noteReceipt(ws *webSession, opID string, rc sfc.ExecReceipt) {
	o, err := s.opt.Store.GetOp(ws.user.ID, opID)
	if err != nil {
		return
	}
	applyExecReceipt(o, rc, s.now())
	_ = s.saveOp(o)
}

func applyExecReceipt(o *store.Op, rc sfc.ExecReceipt, now time.Time) {
	o.UpdatedAt = now
	if rc.Phase == sfc.ExecFinished {
		code := 0
		if rc.ExitCode != nil {
			code = *rc.ExitCode
		}
		o.Result = &store.OpResult{Found: true, Code: code}
		o.State = store.OpApplied
		o.ErrorCode = ""
		if code != 0 {
			o.ErrorCode = fmt.Sprintf("exit-%d", code)
		}
	}
}

// execStatus settles a stored exec op with `status`.
func (s *Server) execStatus(w http.ResponseWriter, r *http.Request, ws *webSession, o *store.Op) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var es sfc.ExecStatus
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		es, err = c.ExecStatus(ctx, o.Tenant, sfc.SignedIntent(o.Signed))
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	applyExecReceipt(o, es.Receipt, s.now())
	if err := s.saveOp(o); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, opStatus(o), map[string]any{"op": viewOp(o), "exec": camel{es}})
}

func mustJSON(v any) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}

// execTarget names the container of an exec op for the operation list.
func execTarget(sel sfc.ContainerSelection, t sfc.StreamTarget) string {
	if sel.Standalone != "" {
		return "standalone/" + sel.Standalone
	}
	return fmt.Sprintf("%s/%s/%s", t.App, t.Service, t.Instance)
}
