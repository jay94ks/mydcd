// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/schema"
)

const NodeShellChunkBytes = 24 << 10

type NodeShellActor struct{ User, Username string }
type NodeShellEnd struct {
	Code     int
	Reason   string
	ClosedBy *NodeShellActor `json:",omitempty"`
}
type NodeShellRecord struct {
	Schema     uint8
	Sequence   uint64
	Kind       string
	Data       []byte        `json:",omitempty"`
	Cols, Rows uint16        `json:",omitempty"`
	End        *NodeShellEnd `json:",omitempty"`
}

func (e NodeShellEnd) Valid() bool {
	if e.Code < 0 || e.Code > 255 || !slices.Contains([]string{"exit", "idle", "closed", "policy"}, e.Reason) {
		return false
	}
	if e.Reason == "closed" || e.Reason == "policy" {
		return e.ClosedBy != nil && shellActorText(e.ClosedBy.User) && shellActorText(e.ClosedBy.Username)
	}
	return e.ClosedBy == nil
}
func shellActorText(s string) bool {
	return s != "" && len(s) <= 256 && utf8.ValidString(s) && !bytes.ContainsFunc([]byte(s), unicode.IsControl)
}

// NodeShellFlow validates one direction independently. Heartbeats never count
// as activity; the Runtime owns byte counters and idle policy. End is terminal.
type NodeShellFlow struct {
	Sequence          uint64
	HalfClosed, Ended bool
}

func (f NodeShellFlow) Accept(r NodeShellRecord, fromClient bool) (NodeShellFlow, error) {
	if f.Ended || f.Sequence == ^uint64(0) || r.Schema != 1 || r.Sequence != f.Sequence+1 || len(r.Data) > NodeShellChunkBytes {
		return f, ErrFrame
	}
	valid := false
	switch r.Kind {
	case "stdin":
		valid = fromClient && !f.HalfClosed && len(r.Data) > 0 && r.Cols == 0 && r.Rows == 0 && r.End == nil
	case "stdout":
		valid = !fromClient && len(r.Data) > 0 && r.Cols == 0 && r.Rows == 0 && r.End == nil
	case "resize":
		valid = fromClient && len(r.Data) == 0 && r.Cols >= 1 && r.Cols <= 1000 && r.Rows >= 1 && r.Rows <= 1000 && r.End == nil
	case "half-close":
		valid = fromClient && !f.HalfClosed && len(r.Data) == 0 && r.Cols == 0 && r.Rows == 0 && r.End == nil
	case "ping":
		valid = len(r.Data) == 0 && r.Cols == 0 && r.Rows == 0 && r.End == nil
	case "end":
		valid = !fromClient && len(r.Data) == 0 && r.Cols == 0 && r.Rows == 0 && r.End != nil && r.End.Valid()
	}
	if !valid {
		return f, ErrFrame
	}
	f.Sequence = r.Sequence
	f.HalfClosed = f.HalfClosed || r.Kind == "half-close"
	f.Ended = r.Kind == "end"
	return f, nil
}
func WriteNodeShellRecord(w io.Writer, request uint64, binding [32]byte, r NodeShellRecord) error {
	if request == 0 || binding == ([32]byte{}) || r.Schema != 1 || r.Sequence == 0 || len(r.Data) > NodeShellChunkBytes {
		return ErrFrame
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	defer clear(raw)
	return WriteFrame(w, Frame{Purpose: NodeShell, Kind: 5, Request: request, Fields: []Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: binding[:]}}})
}
func ReadNodeShellRecord(reader io.Reader, request uint64, binding [32]byte) (NodeShellRecord, error) {
	var r NodeShellRecord
	f, err := ReadFrame(reader, 128<<10)
	if err != nil {
		return r, err
	}
	if f.Purpose != NodeShell || f.Kind != 5 || f.Request != request || request == 0 || binding == ([32]byte{}) || !bytes.Equal(f.Fields[1].Value, binding[:]) {
		return r, ErrFrame
	}
	defer clear(f.Fields[0].Value)
	r, err = schema.Decode[NodeShellRecord](f.Fields[0].Value)
	if err != nil || r.Schema != 1 || r.Sequence == 0 || len(r.Data) > NodeShellChunkBytes {
		return NodeShellRecord{}, ErrFrame
	}
	return r, nil
}
func (s *Session) OpenNodeShellStream(ctx context.Context) (Stream, error) {
	return s.openDedicatedStream(ctx)
}
