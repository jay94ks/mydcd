// SPDX-License-Identifier: Apache-2.0

// Package engineops is the sfcd (sfcd) side table of requests the engine
// asks over its engine-only SFCP session: purpose 35 volume, 36 network and
// 37 image (seafield/docs/sfcd-socket.md, "프레임과 본문"). A feature writes
// one function per op that takes its request struct and returns its answer
// struct; the table decodes, checks the envelope, maps errors to a Result and
// encodes. Transport, local engine mode and fd passing are the SFCP side.
// See devel/refactor/18-sfcd-structure.md 5.3.
package engineops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jay94ks/seafield/internal/schema"
)

// Purpose is an engine-only SFCP purpose answered by sfcd.
type Purpose uint8

const (
	Volume  Purpose = 35
	Network Purpose = 36
	Image   Purpose = 37
)

func (p Purpose) valid() bool { return p == Volume || p == Network || p == Image }

// Result is the outcome every answer carries.
const (
	Applied    = "applied"
	NotApplied = "not-applied"
	Unknown    = "unknown"
)

// Reasons a not-applied answer carries.
const (
	Invalid  = "invalid"
	NotFound = "not-found"
	Conflict = "conflict"
	NotOwner = "not-owner"
	NotReady = "not-ready"
	Refused  = "refused"
)

// Size limits of one request body and one answer body.
const (
	MaxRequest = 64 << 10
	MaxAnswer  = 128 << 10
	MaxFds     = 4
	MaxOpID    = 128 // bytes of OpID and of BootID
)

// Request is the envelope every op request embeds as its first field, so the
// op's own values sit beside it in one JSON object.
// Its fields match sfcp.EngineRequest, the head the engine socket decodes.
type Request struct {
	Schema uint8
	Op     string
	OpID   string
	BootID string
}

func (r Request) envelope() Request { return r }

// Reply is the envelope every op answer embeds as its first field. Fds
// indexes the descriptors sent with the answer frame, in order.
type Reply struct {
	Schema uint8
	OpID   string
	Result string
	Reason string `json:",omitempty"`
	Fds    []int  `json:",omitempty"`
}

func (r *Reply) reply() *Reply { return r }

// Refusal makes an op answer not-applied with Reason: the op had no effect.
// Any other error answers unknown, because the effect may have happened.
type Refusal struct {
	Reason string
	Err    error
}

func (e *Refusal) Error() string {
	if e.Err == nil {
		return e.Reason
	}
	return e.Reason + ": " + e.Err.Error()
}
func (e *Refusal) Unwrap() error { return e.Err }

// Refuse returns a Refusal with reason; err may be nil.
func Refuse(reason string, err error) error { return &Refusal{Reason: reason, Err: err} }

type requester interface{ envelope() Request }

// Answer is what Serve hands the engine session: the kind 2 field 1 body,
// the descriptors sent with that frame, and for a streaming op the bytes sent
// after it as kind 4 chunks on the same stream. The session closes Stream.
type Answer struct {
	Body   []byte
	Files  []*os.File
	Stream io.ReadCloser
}

// Entry is one registered op.
type Entry struct {
	purpose Purpose
	op      string
	serve   func(ctx context.Context, body []byte, envelope Request) Answer
}

// Op registers fn as the answer to op on purpose. Q and A embed Request and
// Reply first. Q is decoded strictly (schema.Decode). fn's files are sent with
// the answer and indexed in Reply.Fds; the table closes them on any refusal.
func Op[Q requester, A any, PA interface {
	*A
	reply() *Reply
}](purpose Purpose, op string, fn func(ctx context.Context, q Q) (A, []*os.File, error)) Entry {
	return entry[Q, A, PA](purpose, op, func(ctx context.Context, q Q) (A, []*os.File, io.ReadCloser, error) {
		a, files, err := fn(ctx, q)
		return a, files, nil, err
	})
}

// StreamOp is Op for an answer followed by kind 4 chunks (image blob, log
// bulk): fn returns the answer and the body to stream after it. The table
// closes the stream on any refusal; otherwise the session sends and closes it.
func StreamOp[Q requester, A any, PA interface {
	*A
	reply() *Reply
}](purpose Purpose, op string, fn func(ctx context.Context, q Q) (A, io.ReadCloser, error)) Entry {
	return entry[Q, A, PA](purpose, op, func(ctx context.Context, q Q) (A, []*os.File, io.ReadCloser, error) {
		a, stream, err := fn(ctx, q)
		return a, nil, stream, err
	})
}

func entry[Q requester, A any, PA interface {
	*A
	reply() *Reply
}](purpose Purpose, op string, fn func(ctx context.Context, q Q) (A, []*os.File, io.ReadCloser, error)) Entry {
	return Entry{purpose: purpose, op: op, serve: func(ctx context.Context, body []byte, envelope Request) Answer {
		var answer A
		q, err := schema.Decode[Q](body)
		var files []*os.File
		var stream io.ReadCloser
		if err != nil || q.envelope() != envelope {
			err = Refuse(Invalid, err)
		} else {
			answer, files, stream, err = fn(ctx, q)
			if err == nil && len(files) > MaxFds {
				err = fmt.Errorf("engineops: %d descriptors, at most %d", len(files), MaxFds)
			}
		}
		if err != nil {
			closeAll(files)
			files = nil
			if stream != nil {
				_ = stream.Close()
				stream = nil
			}
			var zero A
			answer = zero
		}
		r := PA(&answer).reply()
		*r = Reply{Schema: 1, OpID: envelope.OpID, Result: Applied}
		for i := range files {
			r.Fds = append(r.Fds, i)
		}
		var refusal *Refusal
		switch {
		case errors.As(err, &refusal) && validReason(refusal.Reason):
			r.Result, r.Reason = NotApplied, refusal.Reason
		case err != nil:
			r.Result = Unknown
		}
		raw, merr := json.Marshal(answer)
		if merr != nil || len(raw) > MaxAnswer {
			closeAll(files)
			if stream != nil {
				_ = stream.Close()
			}
			var zero A
			*PA(&zero).reply() = Reply{Schema: 1, OpID: envelope.OpID, Result: Unknown}
			raw, _ = json.Marshal(zero)
			return Answer{Body: raw}
		}
		return Answer{Body: raw, Files: files, Stream: stream}
	}}
}

func validReason(r string) bool {
	switch r {
	case Invalid, NotFound, Conflict, NotOwner, NotReady, Refused:
		return true
	}
	return false
}

func closeAll(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

// Table answers engine requests by purpose and op name.
type Table struct {
	ops map[Purpose]map[string]Entry
}

// NewTable refuses an unknown purpose, an empty op name or an op registered twice.
func NewTable(entries ...Entry) (*Table, error) {
	t := &Table{ops: map[Purpose]map[string]Entry{}}
	for _, e := range entries {
		if !e.purpose.valid() || e.op == "" || len(e.op) > 64 || e.serve == nil {
			return nil, fmt.Errorf("engineops: bad entry %d/%q", e.purpose, e.op)
		}
		if t.ops[e.purpose] == nil {
			t.ops[e.purpose] = map[string]Entry{}
		}
		if _, dup := t.ops[e.purpose][e.op]; dup {
			return nil, fmt.Errorf("engineops: op %d/%q registered twice", e.purpose, e.op)
		}
		t.ops[e.purpose][e.op] = e
	}
	return t, nil
}

// Each calls f for every registered op, so the engine session can route
// each one here (sfcp.Transport.HandleEngine).
func (t *Table) Each(f func(purpose Purpose, op string)) {
	for p, ops := range t.ops {
		for op := range ops {
			f(p, op)
		}
	}
}

// Serve answers one request body (kind 1 field 1) with an answer body (kind 2
// field 1), its descriptors and any stream. It always answers; a request it
// cannot read or route is not-applied invalid with only the envelope fields.
func (t *Table) Serve(ctx context.Context, purpose Purpose, body []byte) Answer {
	var envelope Request
	if len(body) <= MaxRequest {
		_ = json.Unmarshal(body, &envelope)
	}
	// The op is unknown here, so this answer is the bare envelope.
	refuse := func(reason string) Answer {
		raw, _ := json.Marshal(Reply{Schema: 1, OpID: envelope.OpID, Result: NotApplied, Reason: reason})
		return Answer{Body: raw}
	}
	if len(body) > MaxRequest || envelope.Schema != 1 || envelope.OpID == "" || len(envelope.OpID) > MaxOpID || envelope.BootID == "" || len(envelope.BootID) > MaxOpID {
		return refuse(Invalid)
	}
	e, ok := t.ops[purpose][envelope.Op]
	if !ok {
		return refuse(Invalid)
	}
	return e.serve(ctx, body, envelope)
}
