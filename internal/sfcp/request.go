// SPDX-License-Identifier: Apache-2.0

// Package sfcp contains the reusable wire, admission and request-lifetime core.
// Actual QUIC/TLS and current membership are supplied by adapters.
package sfcp

import "errors"

var ErrRequest = errors.New("invalid request identity or transition")

type Phase uint8

const (
	Prepared Phase = iota + 1
	InFlight
	Completed
	NotSent
	Unknown
)

type Request struct {
	id     string
	digest [32]byte
	phase  Phase
}

func NewRequest(id string, digest [32]byte) (Request, error) {
	if id == "" {
		return Request{}, ErrRequest
	}
	return Request{id: id, digest: digest, phase: Prepared}, nil
}

func (r Request) Phase() Phase      { return r.phase }
func (r Request) SafeToRetry() bool { return r.phase == NotSent }

// BeginSend is recorded before the first write: even a partial frame makes the
// remote outcome uncertain without explicit non-execution evidence.
func (r Request) BeginSend() (Request, error) {
	if r.phase != Prepared {
		return r, ErrRequest
	}
	r.phase = InFlight
	return r, nil
}

func (r Request) Reply(id string, digest [32]byte) (Request, error) {
	if r.phase != InFlight || id != r.id || digest != r.digest {
		return r, ErrRequest
	}
	r.phase = Completed
	return r, nil
}

// Abandon handles local cancel, timeout, or transport loss. It does not cancel
// an already accepted remote operation or prove that no commit occurred.
func (r Request) Abandon() Request {
	switch r.phase {
	case Prepared:
		r.phase = NotSent
	case InFlight:
		r.phase = Unknown
	}
	return r
}
