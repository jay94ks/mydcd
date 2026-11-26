// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/quic-go/quic-go"
)

// OnReport ACKs only after the owning handler returns success. The receipt
// means local handler acceptance, never a Raft commit or service application.
func (t *Transport) OnReport(handler func(context.Context, *Session, []byte) error) error {
	if handler == nil {
		return errors.New("nil report handler")
	}
	return t.On(Observation, func(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
		if f.Kind != 1 {
			return ErrFrame
		}
		if err := handler(ctx, s, f.Fields[0].Value); err != nil {
			return err
		}
		digest := sha256.Sum256(f.Fields[0].Value)
		return WriteFrame(stream, Frame{Purpose: Observation, Kind: 2, Request: f.Request, Fields: []Field{{1, true, digest[:]}}})
	})
}
func (s *Session) Report(ctx context.Context, payload []byte) error {
	id := s.transport.NextRequest()
	f := Frame{Purpose: Observation, Kind: 1, Request: id, Fields: []Field{{1, true, payload}}}
	if _, err := Encode(f); err != nil {
		return err
	}
	stream, err := s.Open(ctx)
	if err != nil {
		return err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = WriteFrame(stream, f); err != nil {
		return err
	}
	ack, err := ReadFrame(stream, 128)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if ack.Purpose != Observation || ack.Kind != 2 || ack.Request != id || !bytes.Equal(ack.Fields[0].Value, digest[:]) || s.Admit(ack, Observation, false) != nil {
		return ErrAdmission
	}
	return nil
}
func (t *Transport) OnPacket(handler func(*Session, Frame) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || handler == nil || t.packetHandler != nil {
		return ErrAdmission
	}
	t.packetHandler = handler
	return nil
}
func (s *Session) SendPacket(ctx context.Context, frame Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if frame.Purpose != Packet || frame.Kind != 1 && frame.Kind != 2 || frame.Request != 0 {
		return ErrFrame
	}
	b, err := Encode(frame)
	if err != nil {
		return err
	}
	if !bytes.Equal(frame.Fields[0].Value, s.transport.self.Public[:]) {
		return ErrAdmission
	}
	budget, err := s.PacketBudget()
	if err != nil {
		return err
	}
	if len(b) > budget.FrameBytes {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(budget.FrameBytes)}
	}
	// quic-go enforces its current DATAGRAM/path limit. Never split or retry an
	// oversized IP packet in the transport adapter.
	return s.conn.SendDatagram(b)
}
func (t *Transport) receivePackets(s *Session) {
	for {
		b, err := s.conn.ReceiveDatagram(s.conn.Context())
		if err != nil {
			return
		}
		source := bytes.NewReader(b)
		f, err := ReadFrame(source, 65535+128)
		if err != nil || source.Len() != 0 || f.Purpose != Packet {
			t.dropPacket(0)
			continue
		}
		if s.Admit(f, Packet, true) != nil || !bytes.Equal(f.Fields[0].Value, s.peer.Key[:]) {
			t.dropPacket(1)
			continue
		}
		t.mu.Lock()
		handler := t.packetHandler
		t.mu.Unlock()
		if handler == nil {
			t.dropPacket(2)
		} else if err = handler(s, f); err != nil {
			switch {
			case errors.Is(err, ErrBudget):
				t.dropPacket(3)
			case errors.Is(err, ErrAdmission):
				t.dropPacket(4)
			default:
				t.dropPacket(5)
			}
		} else {
			t.packetsDelivered.Add(1)
		}
	}
}

// Diagnostic counters only: the handler's original result still determines
// admission and packet lifetime. No packet bytes or peer identities are kept.
type PacketDropStats struct {
	Frame, Admission, NoHandler, HandlerBudget, HandlerAdmission, HandlerOther uint64
}

func (t *Transport) dropPacket(reason int) {
	t.packetDropReasons[reason].Add(1)
	t.packetsDropped.Add(1)
}

func (t *Transport) PacketDropCounts() PacketDropStats {
	return PacketDropStats{t.packetDropReasons[0].Load(), t.packetDropReasons[1].Load(), t.packetDropReasons[2].Load(), t.packetDropReasons[3].Load(), t.packetDropReasons[4].Load(), t.packetDropReasons[5].Load()}
}

func (t *Transport) PacketCounts() (delivered, dropped uint64) {
	return t.packetsDelivered.Load(), t.packetsDropped.Load()
}
