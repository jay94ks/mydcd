// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/pkg/sfcp/enginemux"
)

func engineFrame(p Purpose, kind uint8, v any) Frame {
	raw, _ := json.Marshal(v)
	return Frame{Purpose: p, Kind: kind, Fields: []Field{{Tag: 1, Required: true, Value: raw}}}
}

// sfed's side, as the engine would run it: dial, then serve 32–34 and call
// 35–37 on one session.
func TestEngineSocketBothDirections(t *testing.T) {
	self, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewTransport(self, [32]byte{3}, func(Identity) (Peer, bool) { return Peer{}, false })
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sfcdp.sock")
	tr.engine.check = func(*net.UnixConn) error { return nil }
	connected := make(chan *EngineSession, 1)
	tr.OnEngine(func(e *EngineSession) { connected <- e })
	if err = tr.HandleEngine(EngineVolume, "get", func(ctx context.Context, e *EngineSession, st EngineStream, first Frame, req EngineRequest) error {
		return st.WriteFrame(engineFrame(EngineVolume, 2, EngineReply{Schema: 1, OpID: req.OpID, Result: EngineApplied}))
	}); err != nil {
		t.Fatal(err)
	}
	if tr.HandleEngine(EngineLog, "bulk", nil) == nil || tr.HandleEngine(EngineVolume, "get", func(context.Context, *EngineSession, EngineStream, Frame, EngineRequest) error { return nil }) == nil {
		t.Fatal("sfed purpose or duplicate op registered")
	}
	if err = tr.ListenEngine(path); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("socket mode", err)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	engine := enginemux.Client(c)
	defer engine.Close()
	go func() { // sfed serves 34
		for {
			st, err := engine.Accept()
			if err != nil {
				return
			}
			s := EngineStream{st}
			f, err := s.ReadFrame(MaxBody)
			if err != nil {
				return
			}
			var q EngineRequest
			_ = json.Unmarshal(f.Fields[0].Value, &q)
			_ = s.WriteFrame(engineFrame(f.Purpose, 2, EngineReply{Schema: 1, OpID: q.OpID, Result: EngineApplied, Reason: q.Op}))
			_ = s.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// sfed → sfcd: a registered op, then an unknown one.
	ask := func(op string) EngineReply {
		st, err := engine.Open()
		if err != nil {
			t.Fatal(err)
		}
		s := EngineStream{st}
		if err = s.WriteFrame(engineFrame(EngineVolume, 1, EngineRequest{Schema: 1, Op: op, OpID: "op9"})); err != nil {
			t.Fatal(err)
		}
		_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
		f, err := s.ReadFrame(MaxBody)
		if err != nil {
			t.Fatal(err)
		}
		var r EngineReply
		_ = json.Unmarshal(f.Fields[0].Value, &r)
		return r
	}
	if r := ask("get"); r.Result != EngineApplied || r.OpID != "op9" {
		t.Fatal("registered op", r)
	}
	if r := ask("nope"); r.Result != EngineNotApplied || r.Reason != "unknown-op" {
		t.Fatal("unknown op", r)
	}

	// sfcd → sfed over the same session.
	var e *EngineSession
	select {
	case e = <-connected:
	case <-ctx.Done():
		t.Fatal("OnEngine not called")
	}
	if got, ok := tr.Engine(); !ok || got != e {
		t.Fatal("current engine session")
	}
	f, err := e.Call(ctx, engineFrame(EngineLogAck, 1, EngineRequest{Schema: 1, Op: "ack", OpID: "op1"}), CallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var r EngineReply
	if json.Unmarshal(f.Fields[0].Value, &r) != nil || r.Result != EngineApplied || r.Reason != "ack" {
		t.Fatal("call to sfed", r)
	}
	if _, err = e.Call(ctx, engineFrame(EngineVolume, 1, EngineRequest{Schema: 1, Op: "get"}), CallOptions{Admit: true}); !errors.Is(CallCause(err), ErrAdmission) || EngineResult(err) != EngineNotApplied {
		t.Fatal("sfcd called its own purpose", err)
	}

	// The engine purposes never pass the mesh/management codec.
	mesh := engineFrame(EngineVolume, 1, EngineRequest{Schema: 1, Op: "get"})
	mesh.Request = 1
	if _, err := Encode(mesh); err == nil {
		t.Fatal("engine purpose encodable on the mesh")
	}

	// A refused peer never gets a session.
	tr.engine.mu.Lock()
	tr.engine.check = func(*net.UnixConn) error { return enginemux.ErrPeer }
	tr.engine.mu.Unlock()
	bad, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = bad.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = bad.Read(make([]byte, 1)); err == nil {
		t.Fatal("refused peer kept its connection")
	}
	_ = bad.Close()
	if got, _ := tr.Engine(); got != e {
		t.Fatal("refused peer replaced the engine session")
	}
}
