// SPDX-License-Identifier: Apache-2.0

// Package enginemux carries many SFCP streams over one local unix
// connection between sfcd and the Seafield engine (/run/sfe/sfcd.sock).
// QUIC gives every other SFCP session its streams; here this package does.
//
// There is no second framing layer. Every byte on the connection is a SFCP
// frame (pkg/sfcp/wire), and a frame belongs to the stream whose ID is its
// request ID. Streams the listener opens have odd IDs, streams the dialer
// opens have even IDs. Two header bytes that are reserved (zero) on every
// other connection are used here:
//
//	byte 8: number of file descriptors sent with this frame (0..MaxFDs),
//	        passed as SCM_RIGHTS on the sendmsg that carries its first byte
//	byte 9: flags; FlagFIN ends the sender's direction, FlagRST resets
//	        the stream
//
// Purpose 47 is this package's own: kind 1 returns receive window (field 1,
// u32 little endian), kind 2 is an empty frame that carries only flags.
// Readers of a Stream see the frames with bytes 8 and 9 zeroed, so the usual
// wire.Rules checks apply unchanged; purpose 47 frames are never delivered.
//
// Flow control: each direction of each stream may have Window frame bytes
// (headers included) unread; the reader returns window as its consumer reads.
//
// The package imports the standard library, this module's wire package and,
// for the peer check only, golang.org/x/sys/unix (vendored by Moby too), so
// the engine can keep a byte-identical copy.
package enginemux

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/jay94ks/seafield/pkg/sfcp/wire"
)

const (
	// Control is the purpose of this package's own frames.
	Control wire.Purpose = 47
	// Window is the per-stream, per-direction budget of unread frame bytes
	// (headers included): one largest frame.
	Window = wire.HeaderSize + wire.MaxBody
	// MaxFDs is the most descriptors one frame may carry.
	MaxFDs  = 4
	FlagFIN = 1
	FlagRST = 2

	kindWindow = 1
	kindFlags  = 2
	maxStreams = 256
)

var (
	ErrClosed  = errors.New("engine mux closed")
	ErrReset   = errors.New("engine mux stream reset")
	ErrTimeout = os.ErrDeadlineExceeded
	ErrProto   = errors.New("engine mux protocol violation")
)

type outgoing struct {
	b   []byte
	fds []int
}

// Session is one multiplexed connection.
type Session struct {
	conn     net.Conn
	unixConn *net.UnixConn
	listener bool

	mu      sync.Mutex
	streams map[uint64]*Stream
	next    uint64
	accept  chan *Stream
	err     error
	done    chan struct{}

	out      chan outgoing
	pending  []int // received descriptors not yet matched to a frame
	closeOne sync.Once
}

// Server wraps the connection a listener accepted; Client wraps a dialed one.
func Server(c net.Conn) *Session { return newSession(c, true) }
func Client(c net.Conn) *Session { return newSession(c, false) }

func newSession(c net.Conn, listener bool) *Session {
	s := &Session{conn: c, listener: listener, streams: map[uint64]*Stream{}, accept: make(chan *Stream, 16), done: make(chan struct{}), out: make(chan outgoing, 64)}
	s.unixConn, _ = c.(*net.UnixConn)
	s.next = 2
	if listener {
		s.next = 1
	}
	go s.readLoop()
	go s.writeLoop()
	return s
}

// Done is closed when the session ends; Err then says why.
func (s *Session) Done() <-chan struct{} { return s.done }

func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close ends the session and every stream.
func (s *Session) Close() error {
	s.fail(ErrClosed)
	return nil
}

func (s *Session) fail(err error) {
	s.closeOne.Do(func() {
		s.mu.Lock()
		s.err = err
		streams := s.streams
		s.streams = map[uint64]*Stream{}
		pending := s.pending
		s.pending = nil
		s.mu.Unlock()
		close(s.done)
		_ = s.conn.Close()
		for _, st := range streams {
			st.broken(err)
		}
		closeFDs(pending)
	})
}

// Open starts a stream; its ID is the request ID every frame on it carries.
func (s *Session) Open() (*Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if len(s.streams) >= maxStreams {
		return nil, ErrProto
	}
	id := s.next
	s.next += 2
	st := newStream(s, id)
	s.streams[id] = st
	return st, nil
}

// Accept returns the next stream the peer opened.
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.done:
		return nil, s.Err()
	}
}

func (s *Session) ours(id uint64) bool { return id%2 == 1 == s.listener }

func (s *Session) send(o outgoing) error {
	select {
	case s.out <- o:
		return nil
	case <-s.done:
		closeFDs(o.fds)
		return s.Err()
	}
}

func (s *Session) writeLoop() {
	for {
		select {
		case o := <-s.out:
			if err := s.write(o); err != nil {
				s.fail(err)
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *Session) write(o outgoing) error {
	b := o.b
	if len(o.fds) > 0 {
		if s.unixConn == nil {
			return ErrProto
		}
		n, _, err := s.unixConn.WriteMsgUnix(b, syscall.UnixRights(o.fds...), nil)
		closeFDs(o.fds) // the kernel holds its own references now
		if err != nil {
			return err
		}
		b = b[n:]
	}
	for len(b) > 0 {
		n, err := s.conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func control(id uint64, kind uint8, flags byte, value []byte) []byte {
	b := make([]byte, wire.HeaderSize, wire.HeaderSize+8+len(value))
	copy(b, "MDG1")
	binary.LittleEndian.PutUint16(b[4:], 1)
	b[6], b[7], b[9] = byte(Control), kind, flags
	binary.LittleEndian.PutUint64(b[12:], id)
	if value != nil {
		b = binary.LittleEndian.AppendUint16(b, 1)
		b = binary.LittleEndian.AppendUint16(b, 1)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(value)))
		b = append(b, value...)
	}
	binary.LittleEndian.PutUint32(b[20:], uint32(len(b)-wire.HeaderSize))
	return b
}

// reader collects bytes and, on a unix connection, the descriptors that
// arrive with them, in order.
type reader struct {
	s   *Session
	buf []byte
	oob []byte
}

func (r *reader) fill(need int) error {
	for len(r.buf) < need {
		chunk := make([]byte, max(need-len(r.buf), 64<<10))
		var n int
		var err error
		if r.s.unixConn != nil {
			var oobn int
			n, oobn, _, _, err = r.s.unixConn.ReadMsgUnix(chunk, r.oob)
			if oobn > 0 {
				if e := r.s.takeRights(r.oob[:oobn]); e != nil {
					return e
				}
			}
		} else {
			n, err = r.s.conn.Read(chunk)
		}
		r.buf = append(r.buf, chunk[:max(n, 0)]...)
		if err != nil {
			if err == io.EOF && len(r.buf) >= need {
				return nil
			}
			return err
		}
	}
	return nil
}

func (s *Session) takeRights(oob []byte) error {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.pending = append(s.pending, fds...)
		over := len(s.pending) > 4*MaxFDs
		s.mu.Unlock()
		if over {
			return ErrProto
		}
	}
	return nil
}

func (s *Session) readLoop() {
	r := &reader{s: s, oob: make([]byte, syscall.CmsgSpace(4*MaxFDs*4))}
	for {
		if err := r.fill(wire.HeaderSize); err != nil {
			s.fail(err)
			return
		}
		h := r.buf[:wire.HeaderSize]
		n := int(binary.LittleEndian.Uint32(h[20:24]))
		if string(h[:4]) != "MDG1" || binary.LittleEndian.Uint16(h[4:6]) != 1 || h[8] > MaxFDs || h[9]&^(FlagFIN|FlagRST) != 0 || h[10] != 0 || h[11] != 0 || n > wire.MaxBody {
			s.fail(ErrProto)
			return
		}
		if err := r.fill(wire.HeaderSize + n); err != nil {
			s.fail(err)
			return
		}
		frame := r.buf[: wire.HeaderSize+n : wire.HeaderSize+n]
		r.buf = append([]byte(nil), r.buf[wire.HeaderSize+n:]...)
		if err := s.dispatch(frame); err != nil {
			s.fail(err)
			return
		}
	}
}

func (s *Session) dispatch(frame []byte) error {
	id := binary.LittleEndian.Uint64(frame[12:20])
	count, flags := int(frame[8]), frame[9]
	frame[8], frame[9] = 0, 0
	s.mu.Lock()
	if count > len(s.pending) {
		s.mu.Unlock()
		return ErrProto
	}
	fds := append([]int(nil), s.pending[:count]...)
	s.pending = s.pending[count:]
	st := s.streams[id]
	if st == nil && id != 0 && !s.ours(id) && wire.Purpose(frame[6]) != Control {
		if len(s.streams) >= maxStreams {
			s.mu.Unlock()
			closeFDs(fds)
			return ErrProto
		}
		st = newStream(s, id)
		s.streams[id] = st
		s.mu.Unlock()
		select {
		case s.accept <- st:
		case <-s.done:
			closeFDs(fds)
			return ErrClosed
		}
	} else {
		s.mu.Unlock()
	}
	if st == nil {
		closeFDs(fds) // late frames of a finished stream
		return nil
	}
	if wire.Purpose(frame[6]) == Control {
		closeFDs(fds)
		switch frame[7] {
		case kindWindow:
			if len(frame) != wire.HeaderSize+12 || binary.LittleEndian.Uint16(frame[24:]) != 1 || binary.LittleEndian.Uint32(frame[28:]) != 4 {
				return ErrProto
			}
			st.credit(int(binary.LittleEndian.Uint32(frame[32:])))
		case kindFlags:
			if len(frame) != wire.HeaderSize {
				return ErrProto
			}
		default:
			return ErrProto
		}
		st.flags(flags)
		return nil
	}
	if err := st.deliver(frame, fds); err != nil {
		return err
	}
	st.flags(flags)
	return nil
}

func (s *Session) forget(st *Stream) {
	s.mu.Lock()
	if s.streams[st.id] == st {
		delete(s.streams, st.id)
	}
	s.mu.Unlock()
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}

// Stream is one SFCP stream. It is used like a QUIC stream: whole frames
// are written with wire's WriteFrame and read with ReadFrame.
type Stream struct {
	s  *Session
	id uint64

	mu        sync.Mutex
	cond      *sync.Cond
	in        []byte // whole frames, flags zeroed
	inFDs     []int
	unacked   int // body bytes read but not yet returned as window
	peerFIN   bool
	sentFIN   bool
	err       error // reset or session failure
	sendRoom  int   // frame bytes the peer still accepts
	partial   []byte
	attach    []int
	rDeadline time.Time
	wDeadline time.Time
	timer     *time.Timer
}

func newStream(s *Session, id uint64) *Stream {
	st := &Stream{s: s, id: id, sendRoom: Window}
	st.cond = sync.NewCond(&st.mu)
	return st
}

// ID is the request ID every frame on this stream must carry.
func (st *Stream) ID() uint64 { return st.id }

func (st *Stream) broken(err error) {
	st.mu.Lock()
	if st.err == nil {
		st.err = err
	}
	closeFDs(st.inFDs)
	closeFDs(st.attach)
	st.inFDs, st.attach = nil, nil
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) credit(n int) {
	st.mu.Lock()
	st.sendRoom += n
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) flags(f byte) {
	if f&FlagRST != 0 {
		st.broken(ErrReset)
		st.s.forget(st)
		return
	}
	if f&FlagFIN != 0 {
		st.mu.Lock()
		st.peerFIN = true
		done := st.sentFIN
		st.cond.Broadcast()
		st.mu.Unlock()
		if done {
			st.s.forget(st)
		}
	}
}

func (st *Stream) deliver(frame []byte, fds []int) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.peerFIN || len(st.in)+len(frame) > Window {
		closeFDs(fds)
		return ErrProto
	}
	if st.err != nil {
		closeFDs(fds)
		return nil
	}
	st.in = append(st.in, frame...)
	st.inFDs = append(st.inFDs, fds...)
	st.cond.Broadcast()
	return nil
}

func (st *Stream) wait(deadline time.Time) {
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return
		}
		t := time.AfterFunc(d, func() { st.mu.Lock(); st.cond.Broadcast(); st.mu.Unlock() })
		defer t.Stop()
	}
	st.cond.Wait()
}

func expired(t time.Time) bool { return !t.IsZero() && !time.Now().Before(t) }

// Read returns frame bytes in order; io.EOF after the peer's FIN.
func (st *Stream) Read(p []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for len(st.in) == 0 {
		switch {
		case st.err != nil:
			return 0, st.err
		case st.peerFIN:
			return 0, io.EOF
		case expired(st.rDeadline):
			return 0, ErrTimeout
		}
		st.wait(st.rDeadline)
	}
	n := copy(p, st.in)
	st.in = st.in[n:]
	st.unacked += n
	if st.unacked >= Window/4 || len(st.in) == 0 {
		var v [4]byte
		binary.LittleEndian.PutUint32(v[:], uint32(st.unacked))
		st.unacked = 0
		go func() { _ = st.s.send(outgoing{b: control(st.id, kindWindow, 0, v[:])}) }()
	}
	return n, nil
}

// TakeFDs returns, in arrival order, the descriptors that came with frames
// read so far or queued; the caller owns them.
func (st *Stream) TakeFDs() []int {
	st.mu.Lock()
	defer st.mu.Unlock()
	fds := st.inFDs
	st.inFDs = nil
	return fds
}

// Attach queues descriptors for the next frame written; the stream owns them
// from now on and closes them after sending or on failure.
func (st *Stream) Attach(fds ...int) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.attach)+len(fds) > MaxFDs || st.s.unixConn == nil {
		closeFDs(fds)
		return ErrProto
	}
	st.attach = append(st.attach, fds...)
	return nil
}

// Write takes whole frames (partial frames are held until complete); each
// frame's request ID must be this stream's ID.
func (st *Stream) Write(p []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sentFIN {
		return 0, ErrClosed
	}
	st.partial = append(st.partial, p...)
	for len(st.partial) >= wire.HeaderSize {
		h := st.partial[:wire.HeaderSize]
		n := int(binary.LittleEndian.Uint32(h[20:24]))
		if string(h[:4]) != "MDG1" || n > wire.MaxBody || binary.LittleEndian.Uint64(h[12:20]) != st.id || wire.Purpose(h[6]) == Control || h[8] != 0 || h[9] != 0 {
			st.partial = nil
			return 0, ErrProto
		}
		if len(st.partial) < wire.HeaderSize+n {
			break
		}
		size := wire.HeaderSize + n
		for st.sendRoom < size {
			switch {
			case st.err != nil:
				return 0, st.err
			case expired(st.wDeadline):
				return 0, ErrTimeout
			}
			st.wait(st.wDeadline)
		}
		if st.err != nil {
			return 0, st.err
		}
		frame := append([]byte(nil), st.partial[:size]...)
		st.partial = st.partial[size:]
		frame[8] = byte(len(st.attach))
		fds := st.attach
		st.attach = nil
		st.sendRoom -= size
		st.mu.Unlock()
		err := st.s.send(outgoing{b: frame, fds: fds})
		st.mu.Lock()
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Close ends this side's direction (FIN). Reading continues until the peer's.
func (st *Stream) Close() error {
	st.mu.Lock()
	if st.sentFIN || st.err != nil {
		st.mu.Unlock()
		return nil
	}
	st.sentFIN = true
	done := st.peerFIN
	st.mu.Unlock()
	err := st.s.send(outgoing{b: control(st.id, kindFlags, FlagFIN, nil)})
	if done {
		st.s.forget(st)
	}
	return err
}

// CancelRead and CancelWrite reset the whole stream (RST); the code is not
// carried.
func (st *Stream) CancelRead(uint64)  { st.reset() }
func (st *Stream) CancelWrite(uint64) { st.reset() }

func (st *Stream) reset() {
	st.mu.Lock()
	if st.err != nil {
		st.mu.Unlock()
		return
	}
	st.mu.Unlock()
	st.broken(ErrReset)
	st.s.forget(st)
	_ = st.s.send(outgoing{b: control(st.id, kindFlags, FlagRST, nil)})
}

func (st *Stream) SetDeadline(t time.Time) error {
	st.mu.Lock()
	st.rDeadline, st.wDeadline = t, t
	st.cond.Broadcast()
	st.mu.Unlock()
	return nil
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	st.rDeadline = t
	st.cond.Broadcast()
	st.mu.Unlock()
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.mu.Lock()
	st.wDeadline = t
	st.cond.Broadcast()
	st.mu.Unlock()
	return nil
}
