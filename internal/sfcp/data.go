// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/quic-go/quic-go"
)

// A report frame carries one or more items of its kind: each is
// u32 LE length | bytes. The receipt is the frame digest plus, when some item
// was refused, optional field 128: a bitmap of the refused items (bit i of
// byte i/8). A refused item is dropped alone (design O2).
const reportItemsBudget = 64<<10 - 8

// OnReport calls handler once per item and ACKs the frame after every item
// was handled. The receipt means local handler acceptance, never a Raft
// commit or service application. kind is one of the report kinds
// (KindWorkloadReport ...).
func (t *Transport) OnReport(handler func(ctx context.Context, s *Session, kind uint8, payload []byte) error) error {
	if handler == nil {
		return errors.New("nil report handler")
	}
	return t.On(Observation, func(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
		items, ok := splitReportItems(f.Fields[0].Value)
		if !ReportKind(f.Kind) || !ok {
			return ErrFrame
		}
		var refused []byte
		for i, item := range items {
			if err := handler(ctx, s, f.Kind, item); err != nil {
				if refused == nil {
					refused = make([]byte, (len(items)+7)/8)
				}
				refused[i/8] |= 1 << (i % 8)
			}
		}
		digest := sha256.Sum256(f.Fields[0].Value)
		fields := []Field{{Tag: 1, Required: true, Value: digest[:]}}
		if refused != nil {
			fields = append(fields, Field{Tag: 128, Value: refused})
		}
		return WriteFrame(stream, Frame{Purpose: Observation, Kind: KindResponse, Request: f.Request, Fields: fields})
	})
}

func splitReportItems(b []byte) ([][]byte, bool) {
	var items [][]byte
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, false
		}
		n := int(binary.LittleEndian.Uint32(b))
		if n == 0 || n > len(b)-4 {
			return nil, false
		}
		items, b = append(items, b[4:4+n]), b[4+n:]
	}
	return items, len(items) > 0
}

// ErrReportRefused: the peer handled the report and refused it.
var ErrReportRefused = errors.New("report refused")

// Report sends one report of kind and waits for its receipt.
func (s *Session) Report(ctx context.Context, kind uint8, payload []byte) error {
	accepted, err := s.ReportBatch(ctx, kind, [][]byte{payload})
	if err == nil && !accepted[0] {
		err = ErrReportRefused
	}
	return err
}

// ReportBatch sends items of kind in as few frames as fit and reports which
// ones the peer accepted. An error means a frame was not answered; items of
// unanswered frames count as not accepted. An item too large for one frame
// is not sent.
func (s *Session) ReportBatch(ctx context.Context, kind uint8, items [][]byte) ([]bool, error) {
	if !ReportKind(kind) {
		return nil, ErrFrame
	}
	if !s.Supports(Observation, kind) {
		return nil, ErrUnsupported
	}
	accepted := make([]bool, len(items))
	var errs []error
	for start := 0; start < len(items); {
		var body []byte
		end := start
		for end < len(items) && len(body)+4+len(items[end]) <= reportItemsBudget {
			if len(items[end]) == 0 {
				return accepted, ErrFrame
			}
			body = binary.LittleEndian.AppendUint32(body, uint32(len(items[end])))
			body = append(body, items[end]...)
			end++
		}
		if end == start { // one item over the budget
			errs = append(errs, ErrBudget)
			start++
			continue
		}
		digest := sha256.Sum256(body)
		f := Frame{Purpose: Observation, Kind: kind, Request: s.transport.NextRequest(), Fields: []Field{{Tag: 1, Required: true, Value: body}}}
		reply, err := s.Call(ctx, f, CallOptions{Echo: digest[:], EchoTag: 1})
		if err != nil {
			return accepted, CallCause(err)
		}
		var refused []byte
		for _, field := range reply.Fields {
			if field.Tag == 128 {
				refused = field.Value
			}
		}
		for i := start; i < end; i++ {
			j := i - start
			accepted[i] = j/8 >= len(refused) || refused[j/8]&(1<<(j%8)) == 0
		}
		start = end
	}
	return accepted, errors.Join(errs...)
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
	if !s.Supports(Packet, frame.Kind) {
		return ErrUnsupported
	}
	b, err := encodePacket(frame)
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
		f, err := decodePacket(b, s.peer.Key)
		if err != nil {
			t.dropPacket(0)
			continue
		}
		if s.Admit(f, Packet, true) != nil {
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
