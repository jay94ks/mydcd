// SPDX-License-Identifier: Apache-2.0

package containerops

import "math"

const SessionChunkBytes = 16 << 10

// SessionRecord is carried by the container-session purpose only. The SFCP
// request and signed intent digest remain fixed outside this ordered record.
// A distinct stdin-eof keeps the reverse output direction open on Unix/QUIC.
type SessionRecord struct {
	Schema   uint8
	Sequence uint64
	Kind     string
	Data     []byte       `json:",omitempty"`
	Rows     uint16       `json:",omitempty"`
	Cols     uint16       `json:",omitempty"`
	Sample   *Result      `json:",omitempty"`
	Receipt  *ExecReceipt `json:",omitempty"`
	Code     string       `json:",omitempty"`
}

// SessionFlow is a single direction's parser state, not a process supervisor.
// The caller mutates it only after the complete bounded record is decoded.
type SessionFlow struct {
	Intent       [32]byte
	Sequence     uint64
	InputEOF     bool
	OutputEOF    bool
	Ended        bool
	MetadataSeen bool
}

func (f SessionFlow) Accept(q SessionSpec, target Target, r SessionRecord, fromClient bool) (SessionFlow, error) {
	if q.Validate() != nil || !target.Valid() || r.Schema != 1 || f.Ended || f.Sequence == math.MaxUint64 || r.Sequence != f.Sequence+1 {
		return f, ErrSession
	}
	data, resize, sample, receipt, code := false, false, false, false, false
	next := f
	if fromClient {
		switch r.Kind {
		case "stdin":
			if q.Exec == nil || !q.Exec.Stdin || f.InputEOF {
				return f, ErrSession
			}
			data = true
		case "stdin-eof":
			if q.Exec == nil || !q.Exec.Stdin || f.InputEOF {
				return f, ErrSession
			}
			next.InputEOF = true
		case "resize":
			if q.Exec == nil || !q.Exec.TTY {
				return f, ErrSession
			}
			resize = true
		case "ping":
		case "cancel":
			next.Ended = true
		default:
			return f, ErrSession
		}
	} else {
		switch r.Kind {
		case "stdout", "stderr":
			if q.Kind != "exec" && q.Kind != "attach" && q.Kind != "logs" || f.OutputEOF || r.Kind == "stderr" && q.Exec != nil && q.Exec.TTY {
				return f, ErrSession
			}
			if q.Kind == "logs" && !f.MetadataSeen {
				return f, ErrSession
			}
			data = true
		case "sample":
			if q.Query == nil || q.Kind == "logs" && f.MetadataSeen {
				return f, ErrSession
			}
			sample = true
			next.MetadataSeen = true
		case "receipt":
			if q.Kind != "exec" {
				return f, ErrSession
			}
			receipt = true
		case "output-eof":
			if q.Kind != "exec" && q.Kind != "attach" && q.Kind != "logs" || f.OutputEOF {
				return f, ErrSession
			}
			next.OutputEOF = true
		case "ping":
		case "end":
			next.Ended = true
		case "error":
			code, next.Ended = true, true
		default:
			return f, ErrSession
		}
	}
	if data != (len(r.Data) > 0) || len(r.Data) > SessionChunkBytes || resize != (r.Rows != 0 && r.Cols != 0) || !resize && (r.Rows != 0 || r.Cols != 0) || sample != (r.Sample != nil) || receipt != (r.Receipt != nil) || code != (r.Code != "") {
		return f, ErrSession
	}
	if sample && r.Sample.Validate(*q.Query, target) != nil || receipt && (r.Receipt.Validate() != nil || f.Intent == ([32]byte{}) || r.Receipt.Intent != f.Intent) {
		return f, ErrSession
	}
	if code && r.Code != "denied" && r.Code != "unavailable" && r.Code != "target-changed" && r.Code != "timeout" && r.Code != "stream-error" && r.Code != "conflict" && r.Code != "unsupported" {
		return f, ErrSession
	}
	next.Sequence = r.Sequence
	return next, nil
}
