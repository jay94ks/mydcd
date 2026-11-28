// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// TUNUnderlayMTU is the smallest underlay (server network) MTU that carries a
// managed TUN network of tunMTU over IPv6, the larger header: the outer
// IP/UDP header, the packet frame and the QUIC short header and tag. It is
// the same budget the node checks before opening the TUN.
func TUNUnderlayMTU(tunMTU int) int { return tunMTU + 48 + PacketFrameOverhead + 37 }

// v0.65.0 SendDatagram's payload estimate subtracts 1+20+16 bytes.
// We additionally enforce the complete short-header/PN/tag/frame overhead for
// the actual peer CID length. Neither calculation can grant the larger budget.
const nativePayloadOverhead = 1 + 20 + 16

// PacketBudget is an outbound observation of ONE authenticated connection.
// It is neither a signed network admission nor evidence of peer service health.
type PacketBudget struct {
	Connection [32]byte
	Generation uint64
	UDPBytes   int
	CIDBytes   int
	FrameBytes int
	IPBytes    int
	ObservedAt time.Time
	Done       bool
}

type pathContextKey struct{}
type connectionPath struct {
	mu         sync.Mutex
	mtu        int
	remote     int
	cidBytes   int
	done       bool
	generation uint64
	observed   time.Time
	changed    chan struct{}
	route      nativeRoute
	// contact is the peer's liveness record once the connection is
	// authenticated; every received packet touches it.
	contact atomic.Pointer[peerContact]
}

func newConnectionPath() *connectionPath {
	// RFC 9000's 1200-byte floor is conservative even when the library's
	// default Initial size is larger or falls back after EMSGSIZE.
	return &connectionPath{mtu: 1200, cidBytes: 20, generation: 1, changed: make(chan struct{})}
}
func acceptPath(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	p := newConnectionPath()
	if err := p.bindRoute(info.RemoteAddr); err != nil {
		return nil, err
	}
	return context.WithValue(ctx, pathContextKey{}, p), nil
}
func pathTrace(ctx context.Context, _ bool, _ quic.ConnectionID) qlogwriter.Trace {
	p, _ := ctx.Value(pathContextKey{}).(*connectionPath)
	if p == nil {
		return nil
	}
	return p
}
func (p *connectionPath) AddProducer() qlogwriter.Recorder { return p }
func (p *connectionPath) Close() error                     { return nil }
func (p *connectionPath) RecordEvent(event qlogwriter.Event) {
	if _, ok := event.(qlog.PacketReceived); ok {
		if c := p.contact.Load(); c != nil {
			c.touch()
		}
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch e := event.(type) {
	case qlog.MTUUpdated:
		if e.Value < 1200 || e.Value > 65535 {
			return
		}
		p.mtu, p.observed, p.done = e.Value, time.Now(), e.Done
	case qlog.TupleAssigned:
		if e.TupleID != "" {
			return // An inactive or probing tuple is not the active send path.
		}
		p.generation++
		p.mtu, p.observed, p.done = 1200, time.Time{}, false
	case qlog.ParametersSet:
		if e.Initiator != qlog.InitiatorRemote {
			return
		}
		// Two-byte DATAGRAM lengths suffice for this conservative cap. Native
		// transport parameters may further restrict the payload independently.
		p.remote = int(min(e.MaxDatagramFrameSize, 16383))
		p.cidBytes = e.InitialSourceConnectionID.Len()
	case qlog.PacketSent:
		if e.Header.PacketType != qlog.PacketType1RTT || e.Tuple != "" || e.Header.DestConnectionID.Len() <= p.cidBytes {
			return
		}
		// Retain the largest observed CID if a peer rotates to a longer one.
		p.cidBytes = e.Header.DestConnectionID.Len()
	default:
		return
	}
	close(p.changed)
	p.changed = make(chan struct{})
}
func (p *connectionPath) budget() (PacketBudget, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	overhead := max(nativePayloadOverhead, 1+p.cidBytes+4+16+1+2)
	frame := max(0, min(p.mtu-overhead, p.remote-3))
	return PacketBudget{Generation: p.generation, UDPBytes: p.mtu, CIDBytes: p.cidBytes, FrameBytes: frame, IPBytes: max(0, frame-PacketFrameOverhead), ObservedAt: p.observed, Done: p.done}, p.changed
}

func (s *Session) PacketBudget() (PacketBudget, error) {
	if s.conn == nil {
		return PacketBudget{}, ErrAdmission
	}
	if err := s.conn.Context().Err(); err != nil {
		return PacketBudget{}, net.ErrClosed
	}
	if _, ok := s.transport.lookup(s.peer.Key); !ok || s.path == nil {
		return PacketBudget{}, ErrAdmission
	}
	b, _ := s.path.budget()
	b.Connection = s.gate.challenge
	return b, nil
}

// WaitPacketBudget waits for native path discovery; it does not send an
// application probe, retry a packet, or change the Initial packet-size floor.
func (s *Session) WaitPacketBudget(ctx context.Context, ipBytes int) (PacketBudget, error) {
	if ipBytes <= 0 || ipBytes > 65535 {
		return PacketBudget{}, ErrBudget
	}
	for {
		if err := ctx.Err(); err != nil {
			return PacketBudget{}, err
		}
		if _, err := s.PacketBudget(); err != nil {
			return PacketBudget{}, err
		}
		b, changed := s.path.budget()
		b.Connection = s.gate.challenge
		if b.IPBytes >= ipBytes {
			return b, nil
		}
		if b.Done {
			return PacketBudget{}, ErrBudget
		}
		select {
		case <-ctx.Done():
			return PacketBudget{}, ctx.Err()
		case <-s.conn.Context().Done():
			return PacketBudget{}, net.ErrClosed
		case <-changed:
		}
	}
}
