// SPDX-License-Identifier: Apache-2.0

// Package sfev serves sfev.sock: the per-container Unix socket through which
// an app receives the secrets approved for it, over HTTP/2 without TLS
// (h2c, prior knowledge; design:
// devel/proposals/sfev-sock.md).
//
// One Endpoint serves one container. It holds at most one connection at a
// time; the first connection whose process proves to be in that container
// takes the slot and a later one is refused with 409 while the slot is held.
// Nothing here polls: values are read only when a client asks or when the
// caller publishes an event, and every read goes through the caller's Fetch,
// which owns the approval and quorum checks. Values are kept in memory only
// for the one response that carries them.
package sfev

import (
	"context"
	"errors"
	"time"
)

// Limits from the design.
const (
	// MaxValues bounds one response (all merged values of a container).
	MaxValues = 64 << 10
	// MaxRequestHeader bounds one request's header list.
	MaxRequestHeader = 8 << 10
	// MaxVerifying bounds connections still being identified.
	MaxVerifying = 4
	// VerifyTimeout bounds identifying one connection and reading its HTTP/2
	// connection preface.
	VerifyTimeout = 2 * time.Second
	// ContainerDir is where the socket's directory is mounted in the container.
	ContainerDir = "/run/sfc"
	// SocketName is the socket's file name.
	SocketName = "sfev.sock"
	// EnvName is the environment variable that names the socket in the container.
	EnvName = "SFC_SECRET_SOCKET"
)

// Snapshot is the merged key/value set approved for one container at one
// revision. Revision names the set: equal revisions mean equal values.
type Snapshot struct {
	Revision string
	Values   map[string]string
}

// Fetch reads the current approved values. It must check the container's
// approval and the current quorum permit before returning any value; its
// error decides the reply: ErrDenied → 403, ErrTooLarge → 413, anything
// else → 503.
type Fetch func(context.Context) (Snapshot, error)

var (
	// ErrDenied: the approval does not (or no longer) allow these values.
	ErrDenied = errors.New("sfev: not permitted")
	// ErrTooLarge: the merged values exceed MaxValues.
	ErrTooLarge = errors.New("sfev: values exceed the container limit")
	// ErrClosed: the endpoint was closed.
	ErrClosed = errors.New("sfev: endpoint closed")
)

// EventKind is what the caller tells an Endpoint.
type EventKind int

const (
	// Changed: a source of this container may have a new revision. The
	// endpoint fetches again only if a watch is open.
	Changed EventKind = iota + 1
	// Revoked: the approval no longer holds. The open connection gets a
	// revoked event and is closed; no value is fetched.
	Revoked
)

// Event is one notice to an Endpoint.
type Event struct {
	Kind   EventKind
	Reason string // short, value-free; sent with revoked
}
