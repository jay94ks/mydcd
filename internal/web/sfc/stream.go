// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
)

// Container stream types (purpose15 ContainerSession). Aliases of the real
// containerops types so signed intents are byte-compatible with sfcd.
type (
	StreamSpec      = containerops.SessionSpec
	ExecSpec        = containerops.ExecSpec
	LogQuery        = containerops.Query
	StreamTarget    = containerops.Target
	SessionIntent   = containerops.SessionIntent
	StreamRecord    = containerops.SessionRecord
	ExecReceipt     = containerops.ExecReceipt
	ExecPhase       = containerops.ExecPhase
	ExecStatus      = containerops.ExecStatus
	ContainerSample = containerops.Result
)

const (
	ExecCreating  = containerops.ExecCreating
	ExecCreated   = containerops.ExecCreated
	ExecStartSent = containerops.ExecStartSent
	ExecStarted   = containerops.ExecStarted
	ExecFinished  = containerops.ExecFinished

	// StreamChunkBytes is the largest Data of one stream record.
	StreamChunkBytes = containerops.SessionChunkBytes
	// SampleMaxBytes is the largest output of one container-observe sample.
	SampleMaxBytes = containerops.MaxOutput
)

// Stream record kinds received from the server.
const (
	RecordStdout    = "stdout"
	RecordStderr    = "stderr"
	RecordSample    = "sample"
	RecordReceipt   = "receipt"
	RecordOutputEOF = "output-eof"
	RecordPing      = "ping"
	// "end" and "error" are not returned by Recv: end → io.EOF, error → *Error.
)

// CodeTargetChanged: the container was replaced between resolve and open
// (stream error code target-changed). Resolve again.
const CodeTargetChanged Code = "target-changed"

// Stream error record codes map onto Code; these are the extra ones.
const (
	CodeTimeout     Code = "timeout"
	CodeStreamError Code = "stream-error"
	CodeConflict    Code = "conflict"
)

// SignedIntent is the canonical JSON of the signed SessionIntent. For exec it
// is the durable original: store it before OpenStream and use it for
// ExecStatus after a disconnection. Opening the same exec intent again never
// re-runs the command; the server returns its receipt and ends.
type SignedIntent []byte

// DecodeIntent parses a signed intent for display.
func DecodeIntent(b SignedIntent) (SessionIntent, error) {
	var q SessionIntent
	if err := json.Unmarshal(b, &q); err != nil {
		return SessionIntent{}, err
	}
	return q, nil
}

// IntentID returns the intent's Request ID (the exec operation ID).
func IntentID(b SignedIntent) (string, error) {
	q, err := DecodeIntent(b)
	if err != nil || q.Request == "" {
		return "", errors.New("sfc: malformed signed intent")
	}
	return q.Request, nil
}

// LogsFollowSpec builds a logs-follow spec (tail lines, then new output).
func LogsFollowSpec(sel ContainerSelection, tail int, stdout, stderr bool) StreamSpec {
	return StreamSpec{Kind: "logs", Query: &LogQuery{
		Schema: 1, Selection: sel.Ops(), Kind: "logs", Tail: tail,
		Stdout: stdout, Stderr: stderr, Timestamps: true, MaxBytes: SampleMaxBytes,
	}}
}

// WatchSpec builds a top or stats watch sampled every interval (1s–1m).
func WatchSpec(kind string, sel ContainerSelection, interval time.Duration) StreamSpec {
	return StreamSpec{Kind: kind, Interval: interval, Query: &LogQuery{
		Schema: 1, Selection: sel.Ops(), Kind: kind, MaxBytes: SampleMaxBytes,
	}}
}

// ExecStreamSpec builds an exec spec. rows/cols must be >0 for TTY and 0 otherwise.
func ExecStreamSpec(argv []string, stdin, tty bool, rows, cols uint16) StreamSpec {
	return StreamSpec{Kind: "exec", Exec: &ExecSpec{Argv: argv, Stdin: stdin, TTY: tty, Rows: rows, Cols: cols}}
}

// Stream is one open container session (logs follow, top/stats watch or
// exec). In the real adapter it owns its own TLS/SFCP connection, so it
// outlives neither its Close nor the daemon, but is independent of the Conn
// that opened it. Closing or losing a stream never kills an exec process.
type Stream interface {
	Target() StreamTarget
	// Recv returns the next server record: stdout/stderr (Data), sample
	// (Sample), receipt (Receipt), output-eof, ping. After the server's end it
	// returns io.EOF; after an error record it returns *Error with that code.
	// A lost connection is CodeClosed: for exec, check ExecStatus.
	Recv(ctx context.Context) (StreamRecord, error)
	// Stdin sends input (exec with Stdin=true); data is split into
	// StreamChunkBytes records.
	Stdin(ctx context.Context, data []byte) error
	// CloseStdin half-closes input; output continues.
	CloseStdin(ctx context.Context) error
	// Resize changes the TTY size (exec with TTY=true).
	Resize(ctx context.Context, rows, cols uint16) error
	// Cancel ends the I/O. It is not a kill: the process keeps running.
	Cancel(ctx context.Context) error
	Close() error
}
