// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/containerops"
)

// Fake container streams. Record order and kinds are checked with the real
// containerops.SessionFlow in both directions.
//
// Fake exec behaves like `cat`: stdin is echoed to stdout. Without stdin it
// prints one line naming argv and exits 0; argv[0] "false" exits 1. A logs
// follow stream sends the tail, then one synthetic line per stream tick
// (SetStreamTick, default 2 s; 0 = only EmitLog lines).

type execRecord struct {
	user    string
	digest  [32]byte
	target  StreamTarget
	receipt ExecReceipt
	running bool
}

// SetStreamTick sets the synthetic log line interval of follow streams.
func (f *Fake) SetStreamTick(d time.Duration) { f.mu.Lock(); f.streamTick = d; f.mu.Unlock() }

// EmitLog pushes one log line to every open follow stream of that service.
// For a standalone container use EmitStandaloneLog.
func (f *Fake) EmitLog(tenant, app, service, stream, text string) {
	f.mu.Lock()
	var targets []*fakeStream
	for s := range f.streams {
		standalone := app == standaloneApp && s.target.Standalone == service
		if s.spec.Kind == "logs" && s.target.Tenant == tenant && (standalone || s.target.Standalone == "" && s.target.App == app && s.target.Service == service) {
			targets = append(targets, s)
		}
	}
	f.mu.Unlock()
	for _, s := range targets {
		s.logLine(stream, text)
	}
}

// EmitStandaloneLog pushes one log line to follow streams of a standalone container.
func (f *Fake) EmitStandaloneLog(tenant, name, stream, text string) {
	f.EmitLog(tenant, standaloneApp, name, stream, text)
}

// BreakStreams drops every open stream as a lost connection (Recv returns
// CodeClosed). Exec processes keep running, as on a real disconnection.
func (f *Fake) BreakStreams() {
	f.mu.Lock()
	var all []*fakeStream
	for s := range f.streams {
		all = append(all, s)
	}
	f.mu.Unlock()
	for _, s := range all {
		s.shutdown(false)
	}
}

func (w *world) streamTarget(tenant string, t Task, appRev uint64) StreamTarget {
	var nodeKey string
	for _, m := range w.members {
		if m.ID == t.Node {
			nodeKey = m.Key
		}
	}
	target := StreamTarget{
		Cluster: w.cluster, Owner: digestOf([]byte(nodeKey)),
		Binding: digestOf([]byte(tenant + "/" + t.App + "/" + t.Service + "/" + t.Instance + fmt.Sprint(t.Generation))),
		Tenant:  tenant, App: t.App, Service: t.Service, Node: t.Node, Instance: t.Instance,
		Generation: t.Generation, Revision: max(t.Generation, appRev),
		NativeID:  nativeIDOf(t),
		StartedAt: time.Unix(t.StartedAt, 0).UTC().Format(time.RFC3339Nano),
	}
	// sfcd's standalone target: the public name in Standalone and the
	// immutable internal scope as App.
	if sel := selectionOf(t.App, t.Service, t.Instance); sel.Standalone != "" {
		target.Standalone = sel.Standalone
		if e := w.standalones[tenant+"/"+sel.Standalone]; e != nil && e.scope != "" {
			target.App = e.scope
		}
	}
	return target
}

// targetSelection: the selection that resolves a stream target again.
func targetSelection(t StreamTarget) ContainerSelection {
	if t.Standalone != "" {
		return ContainerSelection{Standalone: t.Standalone}
	}
	return ContainerSelection{App: t.App, Service: t.Service, Instance: t.Instance}
}

func (w *world) currentTarget(tenant string, sel ContainerSelection) (StreamTarget, bool) {
	if sel.Standalone == "" {
		sel = selectionOf(sel.App, sel.Service, sel.Instance)
	}
	if sel.Standalone != "" {
		e := w.standalones[tenant+"/"+sel.Standalone]
		if e == nil || e.view.State != "running" {
			return StreamTarget{}, false
		}
		return w.streamTarget(tenant, e.task(), e.view.Revision), true
	}
	a := w.apps[tenant+"/"+sel.App]
	if a == nil || a.view.Retiring {
		return StreamTarget{}, false
	}
	for _, t := range a.tasks {
		if t.Service == sel.Service && (sel.Instance == "" || sel.Instance == t.Instance) {
			return w.streamTarget(tenant, t, a.view.Revision), true
		}
	}
	return StreamTarget{}, false
}

func (c *fakeConn) ResolveStream(ctx context.Context, tenant string, sel ContainerSelection, spec StreamSpec) (StreamTarget, error) {
	const m = "container-resolve"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return StreamTarget{}, err
	}
	defer c.unlock()
	w := c.f.w
	ops := sel.Ops()
	if spec.Validate() != nil || spec.Query != nil && (spec.Query.Selection.App != ops.App || spec.Query.Selection.Service != ops.Service || spec.Query.Selection.Standalone != ops.Standalone) {
		return StreamTarget{}, fail(m, CodeInvalid, "spec")
	}
	if !w.canRead(user, tenant) || spec.Kind == "exec" && !w.canManage(user, tenant) {
		return StreamTarget{}, fail(m, CodeDenied, "")
	}
	if sel.Standalone != "" {
		t, _, err := w.standaloneTarget(user, tenant, sel.Standalone, c.f.now().Unix())
		switch {
		case errors.Is(err, errForbidden):
			return StreamTarget{}, fail(m, CodeDenied, "")
		case err != nil:
			return StreamTarget{}, fail(m, CodeUnavailable, "standalone container is not running")
		}
		return t, nil
	}
	t, ok := w.currentTarget(tenant, sel)
	if !ok {
		return StreamTarget{}, fail(m, CodeUnavailable, "no running task")
	}
	return t, nil
}

func (c *fakeConn) PrepareStream(ctx context.Context, target StreamTarget, spec StreamSpec, requestID string) (SignedIntent, error) {
	const m = "container-prepare"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fail(m, CodeTransport, err.Error())
	}
	if c.closed {
		return nil, fail(m, CodeClosed, "")
	}
	if c.session == nil || c.key == nil {
		return nil, fail(m, CodeNotLoggedIn, "")
	}
	if requestID == "" {
		id := make([]byte, 12)
		if _, err := rand.Read(id); err != nil {
			return nil, fail(m, CodeTransport, err.Error())
		}
		requestID = "observe-" + hex.EncodeToString(id)
		if spec.Kind == "exec" {
			requestID = "exec-" + hex.EncodeToString(id)
		}
	}
	q := SessionIntent{Schema: 1, Request: requestID, User: c.session.User, Session: access.ExactSessionDigest(*c.session),
		At: c.f.now().Unix(), Target: target, Spec: spec}
	q.Signature = ed25519.Sign(c.key, containerops.SessionIntentBytes(q))
	if q.Verify(c.session.Key) != nil {
		return nil, fail(m, CodeInvalid, "intent")
	}
	b, err := json.Marshal(q)
	if err != nil {
		return nil, fail(m, CodeInvalid, err.Error())
	}
	return b, nil
}

func decodeIntent(m string, b SignedIntent) (SessionIntent, error) {
	var q SessionIntent
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		return q, fail(m, CodeInvalid, "intent")
	}
	if canon, _ := json.Marshal(q); !bytes.Equal(canon, b) || q.Validate() != nil {
		return q, fail(m, CodeInvalid, "intent")
	}
	return q, nil
}

func (c *fakeConn) OpenStream(ctx context.Context, tenant string, raw SignedIntent) (Stream, error) {
	const m = "container-open"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return nil, err
	}
	defer c.unlock()
	f, w := c.f, c.f.w
	q, err := decodeIntent(m, raw)
	if err != nil {
		return nil, err
	}
	if q.Verify(c.session.Key) != nil || q.Session != access.ExactSessionDigest(*c.session) || q.User != user || q.Target.Tenant != tenant {
		return nil, fail(m, CodeDenied, "intent")
	}
	now := f.now().Unix()
	if q.At > now || now-q.At > 30 {
		return nil, fail(m, CodeExpired, "intent At")
	}
	if !w.canRead(user, tenant) || q.Spec.Kind == "exec" && !w.canManage(user, tenant) {
		return nil, fail(m, CodeDenied, "")
	}
	digest := q.Digest()
	s := &fakeStream{f: f, spec: q.Spec, target: q.Target, out: make(chan StreamRecord, 512), stop: make(chan struct{})}
	s.inFlow.Intent, s.outFlow.Intent = digest, digest
	if q.Spec.Kind == "exec" {
		key := user + "/" + q.Request
		if e := w.execs[key]; e != nil {
			// Original ID: report its receipt and end; never run again.
			if e.digest != digest {
				return nil, fail(m, CodeConflict, "operation ID reused with another intent")
			}
			s.emitLocked(StreamRecord{Kind: RecordReceipt, Receipt: cloneReceipt(e.receipt)})
			s.emitLocked(StreamRecord{Kind: "end"})
			return s, nil
		}
	}
	if sa := w.standaloneOf(q.Target); sa != nil && !w.standaloneVisible(user, sa) {
		return nil, fail(m, CodeDenied, "")
	}
	w.expireStandalones(now)
	cur, ok := w.currentTarget(tenant, targetSelection(q.Target))
	if !ok || !cur.Matches(q.Target) {
		return nil, fail(m, CodeTargetChanged, "")
	}
	w.standaloneAttach(q.Target)
	if f.streams == nil {
		f.streams = map[*fakeStream]bool{}
	}
	f.streams[s] = true
	switch q.Spec.Kind {
	case "logs":
		s.emitLocked(StreamRecord{Kind: RecordSample, Sample: &ContainerSample{Schema: 1, Kind: "logs", Target: q.Target, ObservedAt: f.now(), LogDriver: "local"}})
		n := min(q.Spec.Query.Tail, 20)
		for i := 0; i < n; i++ {
			s.lineLocked("stdout", fmt.Sprintf("[%s] log line %d", q.Target.Service, i+1))
		}
		if f.streamTick > 0 {
			go s.tick(f.streamTick, func(i int) { s.logLine("stdout", fmt.Sprintf("[%s] follow line %d", q.Target.Service, i)) })
		}
	case "top", "stats":
		s.emitLocked(StreamRecord{Kind: RecordSample, Sample: s.sample()})
		go s.tick(q.Spec.Interval, func(int) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.emitLocked(StreamRecord{Kind: RecordSample, Sample: s.sample()})
		})
	case "exec":
		e := &execRecord{user: user, digest: digest, target: q.Target, running: true,
			receipt: ExecReceipt{Schema: 1, Intent: digest, ExecID: "exec-" + hex.EncodeToString(digest[:8]), Phase: ExecStarted}}
		w.execs[user+"/"+q.Request] = e
		s.exec = e
		s.emitLocked(StreamRecord{Kind: RecordReceipt, Receipt: cloneReceipt(e.receipt)})
		if !q.Spec.Exec.Stdin {
			s.lineLocked("stdout", "fake exec: "+strings.Join(q.Spec.Exec.Argv, " "))
			s.finishExecLocked(false)
		}
	}
	return s, nil
}

func (c *fakeConn) ExecStatus(ctx context.Context, tenant string, raw SignedIntent) (ExecStatus, error) {
	const m = "container-status"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return ExecStatus{}, err
	}
	defer c.unlock()
	w := c.f.w
	q, err := decodeIntent(m, raw)
	if err != nil {
		return ExecStatus{}, err
	}
	if q.Spec.Kind != "exec" || q.User != user || q.Target.Tenant != tenant {
		return ExecStatus{}, fail(m, CodeDenied, "")
	}
	if !w.canRead(user, tenant) || !w.canManage(user, tenant) {
		return ExecStatus{}, fail(m, CodeDenied, "")
	}
	e := w.execs[user+"/"+q.Request]
	if e == nil {
		return ExecStatus{}, fail(m, CodeMissing, "")
	}
	if e.digest != q.Digest() {
		return ExecStatus{}, fail(m, CodeConflict, "")
	}
	st := ExecStatus{Schema: 1, Request: q.Request, Target: e.target, Receipt: *cloneReceipt(e.receipt), ObservedAt: c.f.now().UTC()}
	if e.receipt.Phase != ExecFinished {
		running := e.running
		st.Running = &running
	}
	return st, nil
}

func cloneReceipt(r ExecReceipt) *ExecReceipt {
	if r.ExitCode != nil {
		v := *r.ExitCode
		r.ExitCode = &v
	}
	return &r
}

type fakeStream struct {
	f      *Fake
	spec   StreamSpec
	target StreamTarget
	exec   *execRecord

	mu      sync.Mutex
	inFlow  containerops.SessionFlow
	outFlow containerops.SessionFlow
	out     chan StreamRecord
	stop    chan struct{}
	done    bool // no more server records
	gone    bool // closed or broken
	ended   bool // Recv delivered end/error
	ticks   int

	overflow  bool
	outClosed bool
}

func (s *fakeStream) closeOut() {
	if !s.outClosed {
		s.outClosed = true
		close(s.out)
	}
}

func (s *fakeStream) Target() StreamTarget { return s.target }

// emitLocked validates and queues one server record. s.mu (or f.mu during
// open) is held.
func (s *fakeStream) emitLocked(r StreamRecord) {
	if s.done {
		return
	}
	r.Schema, r.Sequence = 1, s.outFlow.Sequence+1
	next, err := s.outFlow.Accept(s.spec, s.target, r, false)
	if err != nil {
		panic("sfcli fake stream emitted an invalid record: " + r.Kind + ": " + err.Error())
	}
	s.outFlow = next
	select {
	case s.out <- r:
	default:
		// Slow reader: bounded buffer, then the stream errors (as sfcd does).
		s.done, s.overflow = true, true
		s.closeOut()
		return
	}
	if next.Ended {
		s.done = true
	}
}

func (s *fakeStream) lineLocked(stream, text string) {
	if s.outFlow.OutputEOF {
		return
	}
	if stream == "stderr" && s.spec.Kind == "logs" && !s.spec.Query.Stderr || stream == "stdout" && s.spec.Kind == "logs" && !s.spec.Query.Stdout {
		return
	}
	if s.spec.Exec != nil && s.spec.Exec.TTY {
		stream = "stdout"
	}
	line := []byte(text + "\n")
	if s.spec.Kind == "logs" {
		line = []byte(s.f.now().UTC().Format(time.RFC3339Nano) + " " + text + "\n")
	}
	s.emitLocked(StreamRecord{Kind: stream, Data: line})
}

func (s *fakeStream) logLine(stream, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lineLocked(stream, text)
}

func (s *fakeStream) sample() *ContainerSample {
	r := &ContainerSample{Schema: 1, Kind: s.spec.Kind, Target: s.target, ObservedAt: s.f.now().UTC(), LogDriver: "local"}
	if s.spec.Kind == "top" {
		r.Titles = []string{"PID", "USER", "CMD"}
		r.Processes = [][]string{{"1", "root", s.target.Service}, {"27", "app", s.target.Service + " worker"}}
	} else {
		cpu, mem, lim, pids := 3.2+float64(s.ticks%5), 210*mib, 1*gib, uint64(7)
		r.Stats = &containerops.Stats{SampleAt: r.ObservedAt, CPUPercent: &cpu, CPUStatus: "ok", MemoryBytes: &mem, MemoryLimitBytes: &lim, PIDs: &pids}
	}
	s.ticks++
	return r
}

func (s *fakeStream) tick(d time.Duration, fn func(i int)) {
	t := time.NewTicker(d)
	defer t.Stop()
	for i := 1; ; i++ {
		select {
		case <-s.stop:
			return
		case <-t.C:
			fn(i)
		}
	}
}

// finishExecLocked ends a fake exec; lockF is false when f.mu is already held.
func (s *fakeStream) finishExecLocked(lockF bool) {
	code := 0
	if s.spec.Exec.Argv[0] == "false" {
		code = 1
	}
	s.emitLocked(StreamRecord{Kind: RecordOutputEOF})
	if lockF {
		s.f.mu.Lock()
	}
	s.exec.receipt.Phase, s.exec.receipt.ExitCode, s.exec.receipt.OutputEnded = ExecFinished, &code, true
	s.exec.receipt.StdinClosed = s.exec.receipt.StdinClosed || s.spec.Exec.Stdin
	s.exec.running = false
	r := cloneReceipt(s.exec.receipt)
	if lockF {
		s.f.mu.Unlock()
	}
	s.emitLocked(StreamRecord{Kind: RecordReceipt, Receipt: r})
	s.emitLocked(StreamRecord{Kind: "end"})
}

func (s *fakeStream) Recv(ctx context.Context) (StreamRecord, error) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return StreamRecord{}, io.EOF
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return StreamRecord{}, fail("container-stream", CodeTransport, ctx.Err().Error())
	case r, ok := <-s.out:
		if !ok {
			s.mu.Lock()
			s.ended = true
			overflow := s.overflow
			s.mu.Unlock()
			if overflow {
				return StreamRecord{}, fail("container-stream", CodeStreamError, "slow reader")
			}
			return StreamRecord{}, fail("container-stream", CodeClosed, "stream connection lost")
		}
		switch r.Kind {
		case "end":
			s.finish()
			return StreamRecord{}, io.EOF
		case "error":
			s.finish()
			return StreamRecord{}, fail("container-stream", Code(r.Code), "")
		}
		return r, nil
	}
}

func (s *fakeStream) finish() {
	s.mu.Lock()
	s.ended = true
	s.mu.Unlock()
	s.shutdown(true)
}

// send validates a client record; s.mu is held.
func (s *fakeStream) send(ctx context.Context, r StreamRecord) error {
	if err := ctx.Err(); err != nil {
		return fail("container-stream", CodeTransport, err.Error())
	}
	if s.gone || s.done {
		return fail("container-stream", CodeClosed, "")
	}
	r.Schema, r.Sequence = 1, s.inFlow.Sequence+1
	next, err := s.inFlow.Accept(s.spec, s.target, r, true)
	if err != nil {
		return fail("container-stream", CodeInvalid, r.Kind)
	}
	s.inFlow = next
	return nil
}

func (s *fakeStream) Stdin(ctx context.Context, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(data) > 0 {
		n := min(len(data), StreamChunkBytes)
		if err := s.send(ctx, StreamRecord{Kind: "stdin", Data: data[:n]}); err != nil {
			return err
		}
		s.emitLocked(StreamRecord{Kind: RecordStdout, Data: bytes.Clone(data[:n])})
		data = data[n:]
	}
	return nil
}

func (s *fakeStream) CloseStdin(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.send(ctx, StreamRecord{Kind: "stdin-eof"}); err != nil {
		return err
	}
	s.f.mu.Lock()
	s.exec.receipt.StdinClosed = true
	s.f.mu.Unlock()
	s.finishExecLocked(true)
	return nil
}

func (s *fakeStream) Resize(ctx context.Context, rows, cols uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.send(ctx, StreamRecord{Kind: "resize", Rows: rows, Cols: cols})
}

func (s *fakeStream) Cancel(ctx context.Context) error {
	s.mu.Lock()
	if err := s.send(ctx, StreamRecord{Kind: "cancel"}); err != nil {
		s.mu.Unlock()
		return err
	}
	if s.exec != nil {
		s.f.mu.Lock()
		s.exec.receipt.Detached = true
		r := cloneReceipt(s.exec.receipt)
		s.f.mu.Unlock()
		s.emitLocked(StreamRecord{Kind: RecordReceipt, Receipt: r})
	}
	s.emitLocked(StreamRecord{Kind: "end"})
	s.mu.Unlock()
	return nil
}

func (s *fakeStream) Close() error {
	s.shutdown(true)
	return nil
}

// shutdown stops producers. graceful=false simulates a lost connection: the
// reader sees CodeClosed after draining. Exec processes are not stopped.
func (s *fakeStream) shutdown(graceful bool) {
	s.mu.Lock()
	if s.gone {
		s.mu.Unlock()
		return
	}
	s.gone = true
	close(s.stop)
	if !graceful {
		s.done = true
		s.closeOut()
	}
	if s.exec != nil && s.exec.receipt.Phase != ExecFinished {
		s.f.mu.Lock()
		s.exec.receipt.Detached = true
		s.f.mu.Unlock()
	}
	s.mu.Unlock()
	s.f.mu.Lock()
	if s.f.streams[s] {
		s.f.w.standaloneDetach(s.target, s.f.now().Unix())
	}
	delete(s.f.streams, s)
	s.f.mu.Unlock()
}
