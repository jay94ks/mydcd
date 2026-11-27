// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/pkg/sfcp/enginemux"
)

// fds sent with an answer survive the end of the served stream: the engine
// may take them after reading the answer, not before the stream ends.
func TestEngineAnswerFDsOutliveTheStream(t *testing.T) {
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
	path := filepath.Join(dir, "sfcd.sock")
	tr.engine.check = func(*net.UnixConn) error { return nil }
	if err = tr.HandleEngine(EngineVolume, "mount", func(ctx context.Context, e *EngineSession, st EngineStream, first Frame, req EngineRequest) error {
		fd, err := syscall.Dup(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		if err = st.Attach(fd); err != nil {
			return err
		}
		return st.WriteFrame(engineFrame(EngineVolume, 2, EngineReply{Schema: 1, OpID: req.OpID, Result: EngineApplied}))
	}); err != nil {
		t.Fatal(err)
	}
	if err = tr.ListenEngine(path); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	engine := enginemux.Client(c)
	defer engine.Close()
	for range 20 {
		st, err := engine.Open()
		if err != nil {
			t.Fatal(err)
		}
		s := EngineStream{st}
		if err = s.WriteFrame(engineFrame(EngineVolume, 1, EngineRequest{Schema: 1, Op: "mount"})); err != nil {
			t.Fatal(err)
		}
		_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err = s.ReadFrame(MaxBody); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond) // the stream's end arrives first
		fds := s.TakeFDs()
		if len(fds) != 1 {
			t.Fatal("answer fd lost", fds)
		}
		_ = syscall.Close(fds[0])
		_ = s.Close()
	}
}
