// SPDX-License-Identifier: Apache-2.0

package enginefake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"time"

	"github.com/moby/moby/api/types/events"

	"github.com/jay94ks/seafield/internal/engineevents"
	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/logstore"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/pkg/sfcp/enginemux"
	"github.com/jay94ks/seafield/pkg/sfcp/wire"
)

// The engine session as sfed holds it (seafield/docs/sfcd-socket.md): the
// fake dials sfcd's engine socket and serves purpose 32 (numbered event
// feed, pushed batches), 33 (log queue bulk) and 34 (log ack). Every event
// the fake emits is in the feed; Log queues a line and emits seafield.logs.

// engineCodec frames engine purposes from the engine's side of the socket.
var engineCodec = wire.Rules(func(_ wire.Purpose, kind uint8) (wire.Rule, bool) {
	if kind == 4 {
		return wire.Rule{Fields: []int{8, -1, 32}, Budget: 8 + 32 + sfcp.ChunkSize + 64}, true
	}
	return wire.Rule{Fields: []int{-1}, Budget: 8 + 128<<10}, true
})

// ConnectSFCD keeps a session to sfcd's engine socket until Close: it dials,
// serves sfcd's streams and dials again when the session ends.
func (e *Engine) ConnectSFCD(socket string) {
	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.stopSFCD = append(e.stopSFCD, cancel)
	e.mu.Unlock()
	go func() {
		for ctx.Err() == nil {
			c, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
			if err != nil {
				select {
				case <-ctx.Done():
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}
			s := enginemux.Client(c)
			stop := context.AfterFunc(ctx, func() { _ = s.Close() })
			for {
				st, err := s.Accept()
				if err != nil {
					break
				}
				go e.serveSFCD(ctx, st)
			}
			stop()
			_ = s.Close()
		}
	}()
}

func (e *Engine) serveSFCD(ctx context.Context, st *enginemux.Stream) {
	defer st.Close()
	f, err := engineCodec.ReadFrame(st, 8+64<<10)
	if err != nil || f.Kind != 1 || len(f.Fields) != 1 {
		st.CancelRead(0)
		return
	}
	body := f.Fields[0].Value
	var req engineops.Request
	if json.Unmarshal(body, &req) != nil {
		return
	}
	switch f.Purpose {
	case sfcp.EngineEvents:
		var q engineevents.Subscribe
		if json.Unmarshal(body, &q) != nil || q.Op != "subscribe" {
			e.refuse(st, f.Purpose, req.OpID)
			return
		}
		e.serveEvents(ctx, st, q)
	case sfcp.EngineLog:
		var q struct {
			engineops.Request
			Container string
			After     uint64
			MaxBytes  int
		}
		if json.Unmarshal(body, &q) != nil || q.Op != "bulk" {
			e.refuse(st, f.Purpose, req.OpID)
			return
		}
		e.serveBulk(st, body, q.OpID, q.Container, q.After, q.MaxBytes)
	case sfcp.EngineLogAck:
		var q struct {
			engineops.Request
			Container string
			Upto      uint64
		}
		if json.Unmarshal(body, &q) != nil || q.Op != "ack" {
			e.refuse(st, f.Purpose, req.OpID)
			return
		}
		e.mu.Lock()
		c := e.lookupContainer(q.Container)
		if c != nil && q.Upto > c.logAcked {
			c.logAcked = min(q.Upto, c.logSeq)
		}
		e.mu.Unlock()
		if c == nil {
			e.answer(st, f.Purpose, engineops.Reply{OpID: q.OpID, Result: engineops.NotApplied, Reason: engineops.NotFound})
			return
		}
		e.answer(st, f.Purpose, engineops.Reply{OpID: q.OpID, Result: engineops.Applied})
	case sfcp.EngineExec:
		var q struct {
			engineops.Request
			ExecID string
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if req.Op != "kill" || dec.Decode(&q) != nil || q.ExecID == "" {
			e.refuse(st, f.Purpose, req.OpID)
			return
		}
		result, reason := e.killExec(q.ExecID)
		if result != engineops.Applied {
			e.answer(st, f.Purpose, engineops.Reply{OpID: q.OpID, Result: result, Reason: reason})
			return
		}
		e.answer(st, f.Purpose, struct {
			engineops.Reply
			Tree string `json:",omitempty"`
		}{engineops.Reply{OpID: q.OpID, Result: engineops.Applied}, "ended"})
	default:
		e.refuse(st, f.Purpose, req.OpID)
	}
}

func (e *Engine) answer(st *enginemux.Stream, p wire.Purpose, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = engineCodec.WriteFrame(st, wire.Frame{Purpose: p, Kind: 2, Request: st.ID(), Fields: []wire.Field{{Tag: 1, Required: true, Value: raw}}})
}

func (e *Engine) refuse(st *enginemux.Stream, p wire.Purpose, opID string) {
	e.answer(st, p, engineops.Reply{Schema: 1, OpID: opID, Result: engineops.NotApplied, Reason: engineops.Invalid})
}

// serveEvents answers a subscription and pushes the feed after q.After, and
// every event emitted later, until the stream or the fake ends.
func (e *Engine) serveEvents(ctx context.Context, st *enginemux.Stream, q engineevents.Subscribe) {
	e.mu.Lock()
	boot, last := e.boot, uint64(len(e.feed))
	e.mu.Unlock()
	e.answer(st, sfcp.EngineEvents, engineevents.Subscribed{Reply: engineops.Reply{Schema: 1, OpID: q.OpID, Result: engineops.Applied}, Boot: boot, Last: last})
	after := min(q.After, last)
	for ctx.Err() == nil {
		e.mu.Lock()
		pending, wake := e.feed[after:], e.feedWake
		e.mu.Unlock()
		if len(pending) == 0 {
			select {
			case <-wake:
			case <-ctx.Done():
				return
			}
			continue
		}
		pending = pending[:min(len(pending), 200)]
		b := engineevents.Batch{Boot: boot}
		for i, ev := range pending {
			b.Records = append(b.Records, engineevents.Record{Seq: after + uint64(i) + 1, Boot: boot, Event: ev})
		}
		raw, err := json.Marshal(b)
		if err != nil {
			return
		}
		if engineCodec.WriteFrame(st, wire.Frame{Purpose: sfcp.EngineEvents, Kind: 16, Request: st.ID(), Fields: []wire.Field{{Tag: 1, Required: true, Value: raw}}}) != nil {
			return
		}
		after += uint64(len(pending))
	}
}

// serveBulk answers one bulk of queued lines after `after` (at least one,
// up to maxBytes), then streams them as kind 4 chunks and ends the stream.
func (e *Engine) serveBulk(st *enginemux.Stream, request []byte, opID, ref string, after uint64, maxBytes int) {
	e.mu.Lock()
	c := e.lookupContainer(ref)
	if c == nil {
		e.mu.Unlock()
		e.answer(st, sfcp.EngineLog, engineops.Reply{Schema: 1, OpID: opID, Result: engineops.NotApplied, Reason: engineops.NotFound})
		return
	}
	var body []byte
	count, first, last := 0, uint64(0), uint64(0)
	for _, l := range c.Logs {
		if l.seq <= after || l.seq <= c.logAcked {
			continue
		}
		rec := logstore.Record{Seq: l.seq, Time: l.Time, Stderr: l.Stderr, Data: []byte(l.Text + "\n")}
		next := logstore.Encode(nil, rec)
		if count > 0 && len(body)+len(next) > maxBytes {
			break
		}
		if count == 0 {
			first = l.seq
		}
		body, last, count = append(body, next...), l.seq, count+1
	}
	live := c.State.Running
	e.mu.Unlock()
	type reply struct {
		engineops.Reply
		Count       int
		First, Last uint64
		Gap         *engineevents.Range
		Live        bool
		Size        int
	}
	e.answer(st, sfcp.EngineLog, reply{Reply: engineops.Reply{Schema: 1, OpID: opID, Result: engineops.Applied}, Count: count, First: first, Last: last, Live: live, Size: len(body)})
	header := sha256.Sum256(request)
	var off uint64
	for r := bytes.NewReader(body); r.Len() > 0; {
		chunk := make([]byte, min(r.Len(), sfcp.ChunkSize))
		_, _ = r.Read(chunk)
		var o [8]byte
		binary.LittleEndian.PutUint64(o[:], off)
		if engineCodec.WriteFrame(st, wire.Frame{Purpose: sfcp.EngineLog, Kind: 4, Request: st.ID(), Fields: []wire.Field{{Tag: 1, Required: true, Value: o[:]}, {Tag: 2, Required: true, Value: chunk}, {Tag: 3, Required: true, Value: header[:]}}}) != nil {
			return
		}
		off += uint64(len(chunk))
	}
}

// record adds ev to the numbered feed. The caller holds e.mu.
func (e *Engine) record(ev event) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return
	}
	var m events.Message
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	e.feed = append(e.feed, m)
	close(e.feedWake)
	e.feedWake = make(chan struct{})
}

func newBoot() string {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
	return hex.EncodeToString(b[:])
}
