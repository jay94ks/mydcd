// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
)

var ErrSession = errors.New("invalid container session")

// ExecSpec uses the container's configured user and security settings. It has
// no privileged/user/host-shell override. Empty arguments after argv[0] matter.
type ExecSpec struct {
	Argv       []string
	Stdin, TTY bool
	Rows, Cols uint16
}

func (q ExecSpec) Validate() error {
	if len(q.Argv) < 1 || len(q.Argv) > 128 || q.Argv[0] == "" || q.TTY && (q.Rows == 0 || q.Cols == 0) || !q.TTY && (q.Rows != 0 || q.Cols != 0) {
		return ErrSession
	}
	var size int
	for _, arg := range q.Argv {
		size += len(arg)
		if len(arg) > 4096 || !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) || size > 16<<10 {
			return ErrSession
		}
	}
	return nil
}

// SessionSpec describes one fixed-generation connection. Query.MaxBytes is a
// per-sample bound for watches; a follow stream still uses bounded I/O chunks.
type SessionSpec struct {
	Kind     string
	Exec     *ExecSpec `json:",omitempty"`
	Query    *Query    `json:",omitempty"`
	Interval time.Duration
}

func (q SessionSpec) Validate() error {
	if q.Kind == "attach" {
		if q.Exec == nil || q.Query != nil || q.Interval != 0 || len(q.Exec.Argv) != 0 {
			return ErrSession
		}
		x := *q.Exec
		x.Argv = []string{"attach"}
		return x.Validate()
	}
	if q.Kind == "exec" {
		if q.Exec == nil || q.Query != nil || q.Interval != 0 {
			return ErrSession
		}
		return q.Exec.Validate()
	}
	if q.Exec != nil || q.Query == nil || q.Query.Validate() != nil || q.Kind != q.Query.Kind {
		return ErrSession
	}
	switch q.Kind {
	case "logs":
		if q.Interval != 0 || q.Query.Until != "" || q.Query.Cursor != "" {
			return ErrSession
		}
	case "top", "stats":
		if q.Interval < time.Second || q.Interval > time.Minute {
			return ErrSession
		}
	default:
		return ErrSession
	}
	return nil
}

// SessionIntent is independently signed by the session proof key after target
// resolution. A member forwarding a session cannot substitute argv, target or
// a new operation ID merely by knowing the public login/approval grant.
type SessionIntent struct {
	Schema    uint8
	Request   string
	User      string
	Session   [32]byte
	At        int64
	Target    Target
	Spec      SessionSpec
	Signature []byte
}

func SessionIntentBytes(q SessionIntent) []byte {
	q.Signature = nil
	raw, _ := json.Marshal(q)
	return append([]byte("mydc-container-session-intent-1\x00"), raw...)
}

func (q SessionIntent) Validate() error {
	stamp, err := time.Parse(time.RFC3339Nano, q.Target.StartedAt)
	if q.Schema != 1 || !lifecycle.ValidID(q.Request) || !lifecycle.ValidID(q.User) || q.Session == ([32]byte{}) || q.At <= 0 || !q.Target.Valid() || q.Target.NativeID == "" || err != nil || stamp.IsZero() || q.Spec.Validate() != nil || q.Spec.Kind == "attach" && q.Target.Standalone == "" {
		return ErrSession
	}
	if q.Spec.Query != nil {
		s := q.Spec.Query.Selection
		if (s.Standalone == "" && (q.Target.Standalone != "" || s.App != q.Target.App) || s.Standalone != "" && (s.App != "" || s.Standalone != q.Target.Standalone)) || s.Service != "" && s.Service != q.Target.Service || s.Instance != "" && s.Instance != q.Target.Instance {
			return ErrSession
		}
	}
	return nil
}

// Current catalog/quorum authorization remains an adapter obligation. Only a
// NEW connection applies the short admission window; retained status lookup
// verifies the immutable proof without pretending it is a new start permit.
func (q SessionIntent) Verify(key [32]byte) error {
	if q.Validate() != nil || key == ([32]byte{}) || !ed25519.Verify(ed25519.PublicKey(key[:]), SessionIntentBytes(q), q.Signature) {
		return ErrSession
	}
	return nil
}

func (q SessionIntent) Digest() [32]byte {
	raw, _ := json.Marshal(q)
	return sha256.Sum256(append([]byte("mydc-container-session-record-1\x00"), raw...))
}

type ExecPhase string

const (
	ExecCreating  ExecPhase = "creating"
	ExecCreated   ExecPhase = "created"
	ExecStartSent ExecPhase = "start-sent"
	ExecStarted   ExecPhase = "started"
	ExecFinished  ExecPhase = "finished"
)

// ExecReceipt stores metadata in the owner's existing private store. Started
// means positive start evidence, not a claim that the process is still alive.
// Stream EOF/disconnection and process completion are independent facts.
type ExecReceipt struct {
	Schema                             uint8
	Intent                             [32]byte
	ExecID                             string
	Phase                              ExecPhase
	StdinClosed, OutputEnded, Detached bool
	ExitCode                           *int `json:",omitempty"`
}

func (r ExecReceipt) Validate() error {
	if r.Schema != 1 || r.Intent == ([32]byte{}) || len(r.ExecID) > 256 || strings.ContainsAny(r.ExecID, "\x00\r\n/") {
		return ErrSession
	}
	if r.Phase == ExecCreating {
		if r.ExecID != "" || r.ExitCode != nil {
			return ErrSession
		}
		return nil
	}
	if r.ExecID == "" {
		return ErrSession
	}
	switch r.Phase {
	case ExecCreated, ExecStartSent, ExecStarted:
		if r.ExitCode != nil {
			return ErrSession
		}
	case ExecFinished:
		if r.ExitCode == nil || *r.ExitCode < 0 || *r.ExitCode > 255 {
			return ErrSession
		}
	default:
		return ErrSession
	}
	return nil
}

func (r ExecReceipt) CanFollow(old ExecReceipt) bool {
	if r.Validate() != nil || old.Validate() != nil || r.Schema != old.Schema || r.Intent != old.Intent || old.ExecID != "" && r.ExecID != old.ExecID || old.StdinClosed && !r.StdinClosed || old.OutputEnded && !r.OutputEnded || old.Detached && !r.Detached {
		return false
	}
	if old.ExitCode != nil && (r.ExitCode == nil || *r.ExitCode != *old.ExitCode) {
		return false
	}
	if r.Phase == old.Phase {
		return r.ExecID == old.ExecID
	}
	switch old.Phase {
	case ExecCreating:
		return r.Phase == ExecCreated
	case ExecCreated:
		return r.Phase == ExecStartSent
	case ExecStartSent:
		return r.Phase == ExecStarted
	case ExecStarted:
		return r.Phase == ExecFinished
	}
	return false
}

// Observe never interprets Inspect{Running:false,ExitCode:0} immediately after
// a lost Attach response as successful execution: Docker can return the same
// facts for a configured exec that has never started. Attach acceptance or a
// positive Running observation must first establish ExecStarted.
func (r ExecReceipt) Observe(running bool, exit int) (ExecReceipt, error) {
	if r.Validate() != nil {
		return r, ErrSession
	}
	if (r.Phase == ExecCreating || r.Phase == ExecCreated || r.Phase == ExecFinished) && running || r.Phase == ExecFinished && exit >= 0 && exit != *r.ExitCode {
		return r, ErrSession
	}
	if r.Phase == ExecStartSent && running {
		r.Phase = ExecStarted
	} else if r.Phase == ExecStarted && !running && exit >= 0 && exit <= 255 {
		r.Phase, r.ExitCode = ExecFinished, &exit
	}
	return r, nil
}
