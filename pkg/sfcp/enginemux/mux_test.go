// SPDX-License-Identifier: Apache-2.0

package enginemux

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/pkg/sfcp/wire"
)

var rules = wire.Rules(func(p wire.Purpose, kind uint8) (wire.Rule, bool) {
	if p == 32 && (kind == 1 || kind == 2) {
		return wire.Rule{Fields: []int{-1}, Budget: wire.MaxBody}, true
	}
	return wire.Rule{}, false
})

func pair(t *testing.T) (*Session, *Session) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) net.Conn {
		f := os.NewFile(uintptr(fd), "mux")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	server, client := Server(conn(fds[0])), Client(conn(fds[1]))
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	return server, client
}

func frame(id uint64, kind uint8, body []byte) wire.Frame {
	return wire.Frame{Purpose: 32, Kind: kind, Request: id, Fields: []wire.Field{{Tag: 1, Required: true, Value: body}}}
}

func TestCallsBothWays(t *testing.T) {
	server, client := pair(t)
	serve := func(s *Session) {
		for {
			st, err := s.Accept()
			if err != nil {
				return
			}
			go func() {
				f, err := rules.ReadFrame(st, wire.MaxBody)
				if err != nil {
					return
				}
				_ = rules.WriteFrame(st, frame(st.ID(), 2, append([]byte("re:"), f.Fields[0].Value...)))
				_ = st.Close()
			}()
		}
	}
	go serve(server)
	go serve(client)
	call := func(s *Session, msg string) {
		st, err := s.Open()
		if err != nil {
			t.Fatal(err)
		}
		if err = rules.WriteFrame(st, frame(st.ID(), 1, []byte(msg))); err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		f, err := rules.ReadFrame(st, wire.MaxBody)
		if err != nil || f.Request != st.ID() || string(f.Fields[0].Value) != "re:"+msg {
			t.Fatal(f, err)
		}
		if _, err = st.Read(make([]byte, 1)); err != io.EOF {
			t.Fatal("no EOF after reply", err)
		}
	}
	for range 3 {
		call(client, "from dialer")
		call(server, "from listener")
	}
	a, _ := client.Open()
	b, _ := server.Open()
	if a.ID()%2 != 0 || b.ID()%2 != 1 {
		t.Fatal("stream ID parity", a.ID(), b.ID())
	}
}

// Large frames pass one window at a time and stay in order; another stream
// is not blocked by an unread one.
func TestWindowAndIndependentStreams(t *testing.T) {
	server, client := pair(t)
	slow, _ := client.Open()
	payload := bytes.Repeat([]byte{7}, wire.MaxBody-8)
	done := make(chan error, 1)
	go func() {
		for i := range 4 {
			payload[0] = byte(i)
			if err := rules.WriteFrame(slow, frame(slow.ID(), 1, payload)); err != nil {
				done <- err
				return
			}
		}
		done <- slow.Close()
	}()
	in, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	fast, _ := client.Open()
	if err = rules.WriteFrame(fast, frame(fast.ID(), 1, []byte("quick"))); err != nil {
		t.Fatal(err)
	}
	other, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if f, err := rules.ReadFrame(other, wire.MaxBody); err != nil || string(f.Fields[0].Value) != "quick" {
		t.Fatal("second stream blocked", err)
	}
	for i := range 4 {
		f, err := rules.ReadFrame(in, wire.MaxBody)
		if err != nil || f.Fields[0].Value[0] != byte(i) || len(f.Fields[0].Value) != len(payload) {
			t.Fatal(i, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDescriptorsResetAndChecks(t *testing.T) {
	server, client := pair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	st, _ := client.Open()
	dup, _ := syscall.Dup(int(w.Fd()))
	_ = w.Close()
	if err = st.Attach(dup); err != nil {
		t.Fatal(err)
	}
	if err = rules.WriteFrame(st, frame(st.ID(), 1, []byte("fd"))); err != nil {
		t.Fatal(err)
	}
	in, _ := server.Accept()
	if _, err = rules.ReadFrame(in, wire.MaxBody); err != nil {
		t.Fatal(err)
	}
	fds := in.TakeFDs()
	if len(fds) != 1 {
		t.Fatal("fds", fds)
	}
	got := os.NewFile(uintptr(fds[0]), "w")
	_, _ = got.Write([]byte("ok"))
	_ = got.Close()
	buf := make([]byte, 2)
	if _, err = io.ReadFull(r, buf); err != nil || string(buf) != "ok" {
		t.Fatal("descriptor not usable", err)
	}

	// A reset reaches the other side.
	in.CancelRead(0)
	_ = st.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = st.Read(make([]byte, 1)); !errors.Is(err, ErrReset) {
		t.Fatal("reset not seen", err)
	}

	// A frame must carry its stream's request ID; deadlines apply.
	wrong, _ := client.Open()
	if err = rules.WriteFrame(wrong, frame(wrong.ID()+2, 1, []byte("x"))); !errors.Is(err, ErrProto) {
		t.Fatal("foreign request ID accepted", err)
	}
	_ = wrong.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err = wrong.Read(make([]byte, 1)); !errors.Is(err, ErrTimeout) {
		t.Fatal("deadline", err)
	}
	var many []int
	for range 5 {
		fd, _ := syscall.Dup(int(r.Fd()))
		many = append(many, fd)
	}
	if err = wrong.Attach(many...); err == nil {
		t.Fatal("too many descriptors accepted")
	}
	// Attach closed the refused descriptors itself.
}

func TestPeerCloseEndsStreams(t *testing.T) {
	server, client := pair(t)
	st, _ := client.Open()
	_ = rules.WriteFrame(st, frame(st.ID(), 1, []byte("x")))
	if _, err := server.Accept(); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	_ = st.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := st.Read(make([]byte, 1)); err == nil || errors.Is(err, ErrTimeout) {
		t.Fatal("stream outlived its session", err)
	}
	select {
	case <-client.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("client session not ended")
	}
}

func TestInstalled(t *testing.T) {
	if !Installed("/usr/lib/sfc/bin/sfed", "sfed") || !Installed("/usr/local/bin/sfcd", "sfcd") {
		t.Fatal("installed path refused")
	}
	for _, exe := range []string{"/tmp/sfed", "/usr/lib/sfc/bin/sfed (deleted)", "/usr/lib/sfc/bin/sub/sfed"} {
		if Installed(exe, "sfed") {
			t.Fatal("accepted", exe)
		}
	}
	if Installed("/usr/local/bin/x", "../x") {
		t.Fatal("name with a path accepted")
	}
}

// The check runs against a real peer: this test process is not an installed
// sfed, so it is refused whether or not the kernel offers SO_PEERPIDFD.
func TestCheckPeerRefusesUninstalledBinary(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[0]), "a")
	c, err := net.FileConn(f)
	_ = f.Close()
	defer syscall.Close(fds[1])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := CheckPeer(c.(*net.UnixConn), "sfed"); !errors.Is(err, ErrPeer) {
		t.Fatal("uninstalled peer admitted", err)
	}
}
