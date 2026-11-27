// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
)

// Unix management record1: uint32 big-endian length, then <=64KiB bytes;
// zero length ends this exchange's direction. It is carried inside the pinned
// TLS connection after the ordinary SFCP handshake. SFCP frames, purpose,
// authentication and operation semantics remain unchanged. One exchange at a
// time avoids a second multiplexing/reassembly algorithm and bounds memory.
const localRecordMax = 64 << 10

type localStream struct {
	connection  *localConnection
	remaining   uint32
	readStarted bool // diagnostic only: any received record header byte
	readEOF     atomic.Bool
	writeEOF    atomic.Bool
	writeMu     sync.Mutex
	disposable  bool // a dedicated conversation owns this connection; never cache after EOF
	release     func()
	once        sync.Once
}

func (s *localStream) completed() {
	if s.readEOF.Load() && s.writeEOF.Load() {
		s.once.Do(func() {
			if s.disposable {
				_ = s.connection.finish()
			}
			if s.release != nil {
				s.release()
			}
		})
	}
}

func (s *localStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.readEOF.Load() {
		return 0, io.EOF
	}
	if s.remaining == 0 {
		var header [4]byte
		n, err := io.ReadFull(s.connection.conn, header[:])
		s.readStarted = s.readStarted || n > 0
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		s.remaining = binary.BigEndian.Uint32(header[:])
		if s.remaining > localRecordMax {
			return 0, ErrBudget
		}
		if s.remaining == 0 {
			s.readEOF.Store(true)
			s.completed()
			return 0, io.EOF
		}
	}
	n, err := s.connection.conn.Read(p[:min(len(p), int(s.remaining))])
	s.remaining -= uint32(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (s *localStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeEOF.Load() {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		size := min(len(p), localRecordMax)
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(size))
		if _, err := s.writeFull(header[:]); err != nil {
			return total, err
		}
		n, err := s.writeFull(p[:size])
		total += n
		if err != nil {
			return total, err
		}
		p = p[size:]
	}
	return total, nil
}

func (s *localStream) writeFull(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := s.connection.conn.Write(p)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
		p = p[n:]
	}
	return total, nil
}

func (s *localStream) Close() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeEOF.Load() {
		return nil
	}
	var eof [4]byte
	if _, err := s.writeFull(eof[:]); err != nil {
		return err
	}
	s.writeEOF.Store(true)
	s.completed()
	return nil
}

func (s *localStream) SetDeadline(deadline time.Time) error {
	return s.connection.conn.SetDeadline(deadline)
}

func (s *localStream) SetReadDeadline(deadline time.Time) error {
	return s.connection.conn.SetReadDeadline(deadline)
}
func (s *localStream) SetWriteDeadline(deadline time.Time) error {
	return s.connection.conn.SetWriteDeadline(deadline)
}

func (s *localStream) cancel() {
	if !s.readEOF.Load() || !s.writeEOF.Load() {
		_ = s.connection.finish()
	}
	s.once.Do(func() {
		if s.release != nil {
			s.release()
		}
	})
}
func (s *localStream) CancelRead(quic.StreamErrorCode)  { s.cancel() }
func (s *localStream) CancelWrite(quic.StreamErrorCode) { s.cancel() }
