// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/quic-go/quic-go"
)

// PathSample is a signed sample of a current native connection budget. At is
// sampling time; Budget.ObservedAt is the original native ACK observation.
type PathSample struct {
	Schema    uint8
	Cluster   [32]byte
	From, To  Identity
	Scope     []byte
	Request   [32]byte
	MTU       int
	At        int64
	Budget    PacketBudget
	Signature []byte
}
type PathPair struct{ local, remote PathSample }

func (p PathPair) MTU() int {
	if p.local.MTU != p.remote.MTU {
		return 0
	}
	return p.local.MTU
}

func (p PathPair) Samples() (PathSample, PathSample) {
	clone := func(s PathSample) PathSample {
		s.Scope = bytes.Clone(s.Scope)
		s.Signature = bytes.Clone(s.Signature)
		return s
	}
	return clone(p.local), clone(p.remote)
}

func pathBytes(p PathSample) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("mydc-path-sample-1\x00"), b...)
}
func pathDigest(p PathSample) [32]byte {
	b, _ := json.Marshal(p)
	return sha256.Sum256(b)
}
func validSample(p PathSample, cluster [32]byte, from, to Identity, scope []byte, mtu int, request [32]byte) bool {
	return sampleProblem(p, cluster, from, to, scope, mtu, request) == ""
}

// pathClockSkew is how far ahead of this server's clock a peer's sample may
// be stamped. NTP-synced servers still differ by tens of milliseconds, which
// is more than a LAN round trip, so a strict "not after now" refused every
// sample from a server whose clock ran slightly ahead.
const pathClockSkew = 2_000

// sampleProblem names the first check a path sample fails, as a fixed string
// for the server failure log; "" means the sample is valid.
func sampleProblem(p PathSample, cluster [32]byte, from, to Identity, scope []byte, mtu int, request [32]byte) string {
	now := time.Now().UnixMilli()
	switch {
	case len(scope) == 0 || len(scope) > 1024 || p.Schema != 1 || p.Cluster != cluster || !bytes.Equal(p.Scope, scope) || p.Request != request:
		return "scope"
	case p.From != from || p.To != to:
		return "keys"
	case p.MTU != mtu || mtu < 1280 || mtu > 65535:
		return "mtu"
	case p.At <= 0:
		return "time"
	case p.At > now+pathClockSkew:
		return "future" // the sender's clock is ahead of this server's
	case now-p.At > 30_000:
		return "old"
	case p.Budget.Connection == [32]byte{} || p.Budget.Generation == 0 || p.Budget.ObservedAt.IsZero() || p.Budget.ObservedAt.UnixMilli() > p.At:
		return "budget-time"
	case p.Budget.IPBytes < mtu || p.Budget.FrameBytes-p.Budget.IPBytes != PacketFrameOverhead:
		return "budget-size"
	case !ed25519.Verify(ed25519.PublicKey(from[:]), pathBytes(p), p.Signature):
		return "signature"
	}
	return ""
}
func pathFrame(kind uint8, request uint64, sample PathSample) Frame {
	b, _ := json.Marshal(sample)
	h := sha256.Sum256(b)
	return Frame{Purpose: PathControl, Kind: kind, Request: request, Fields: []Field{{1, true, b}, {2, true, h[:]}}}
}
func readPathSample(f Frame) (PathSample, error) {
	if f.Purpose != PathControl || len(f.Fields) != 2 {
		return PathSample{}, ErrFrame
	}
	h := sha256.Sum256(f.Fields[0].Value)
	if !bytes.Equal(h[:], f.Fields[1].Value) {
		return PathSample{}, ErrFrame
	}
	return schema.Decode[PathSample](f.Fields[0].Value)
}
func (s *Session) samplePath(ctx context.Context, scope []byte, mtu int, request [32]byte) (PathSample, error) {
	if len(scope) == 0 || len(scope) > 1024 || mtu < 1280 || mtu > 65535 {
		return PathSample{}, ErrBudget
	}
	b, err := s.WaitPacketBudget(ctx, mtu)
	if err != nil {
		return PathSample{}, err
	}
	p := PathSample{Schema: 1, Cluster: s.transport.cluster, From: s.transport.LocalKey(), To: s.peer.Key, Scope: bytes.Clone(scope), Request: request, MTU: mtu, At: time.Now().UnixMilli(), Budget: b}
	p.Signature = ed25519.Sign(s.transport.self.Private, pathBytes(p))
	return p, nil
}

// OnPath authorizes the exact committed scope both before waiting for native
// discovery and before replying. A receipt is runtime evidence, not a commit.
func (t *Transport) OnPath(authorize func(context.Context, *Session, []byte, int) error, accept func(*Session, PathPair) error) error {
	if authorize == nil {
		return ErrAdmission
	}
	return t.On(PathControl, func(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
		p, err := readPathSample(f)
		if err != nil || f.Kind != 1 {
			return pathStep("frame", ErrAdmission)
		}
		if problem := sampleProblem(p, t.cluster, s.peer.Key, t.LocalKey(), p.Scope, p.MTU, [32]byte{}); problem != "" {
			return pathStep("peer-sample-"+problem, ErrAdmission)
		}
		if err = authorize(ctx, s, p.Scope, p.MTU); err != nil {
			return pathStep("authorize", err)
		}
		reply, err := s.samplePath(ctx, p.Scope, p.MTU, pathDigest(p))
		if err != nil {
			return pathStep("local-sample", err)
		}
		if err = authorize(ctx, s, p.Scope, p.MTU); err != nil {
			return pathStep("reauthorize", err)
		}
		if err = s.Admit(f, PathControl, false); err != nil {
			return pathStep("admit", err)
		}
		pair := PathPair{local: reply, remote: p}
		if !s.PathCurrent(pair) {
			return pathStep("path-current", ErrAdmission)
		}
		if accept != nil {
			if err = accept(s, pair); err != nil {
				return pathStep("accept", err)
			}
		}
		return WriteFrame(stream, pathFrame(2, f.Request, reply))
	})
}

// pathStepError names the fixed OnPath step that failed, for the server
// failure log. It wraps the original error, so Is/As still see the cause.
type pathStepError struct {
	step string
	err  error
}

func pathStep(step string, err error) error { return pathStepError{step, err} }
func (e pathStepError) Error() string       { return "path " + e.step + ": " + e.err.Error() }
func (e pathStepError) Unwrap() error       { return e.err }

func (s *Session) ObservePath(ctx context.Context, scope []byte, mtu int) (PathPair, error) {
	p, err := s.samplePath(ctx, scope, mtu, [32]byte{})
	if err != nil {
		return PathPair{}, err
	}
	f := pathFrame(1, s.transport.NextRequest(), p)
	if _, err = Encode(f); err != nil {
		return PathPair{}, err
	}
	// The remote must currently have the same member/tunnel permission; the
	// receiving endpoint independently checks the caller's current grant.
	if err = s.Admit(f, PathControl, false); err != nil {
		return PathPair{}, err
	}
	stream, err := s.Open(ctx)
	if err != nil {
		return PathPair{}, err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	if err = ctx.Err(); err != nil {
		return PathPair{}, err
	}
	if err = WriteFrame(stream, f); err != nil {
		return PathPair{}, err
	}
	ack, err := ReadFrame(stream, 4096)
	if err != nil {
		return PathPair{}, err
	}
	reply, err := readPathSample(ack)
	if err != nil || ack.Kind != 2 || ack.Request != f.Request || s.Admit(ack, PathControl, false) != nil || !validSample(reply, s.transport.cluster, s.peer.Key, s.transport.LocalKey(), scope, mtu, pathDigest(p)) {
		return PathPair{}, ErrAdmission
	}
	pair := PathPair{local: p, remote: reply}
	if !s.PathCurrent(pair) {
		return PathPair{}, ErrAdmission
	}
	return pair, nil
}

// PathCurrent fails after close, permission loss, migration or budget shrink.
// Remote changes are checked by that endpoint on its own send/admission path.
func (s *Session) PathCurrent(p PathPair) bool {
	b, err := s.PacketBudget()
	return err == nil && s.Admit(Frame{Purpose: PathControl, Kind: 1}, PathControl, false) == nil && p.local.From == s.transport.LocalKey() && p.local.To == s.peer.Key && b.Connection == p.local.Budget.Connection && b.Generation == p.local.Budget.Generation && b.IPBytes >= p.local.MTU
}
