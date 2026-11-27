// SPDX-License-Identifier: Apache-2.0

package sfc

import "fmt"

// Code is the sfcd Reply.Code (or a local client classification) that ended a
// call without the requested reply.
type Code string

const (
	CodeDenied           Code = "denied"
	CodeInvalid          Code = "invalid"
	CodeUnsupported      Code = "unsupported"
	CodeMissing          Code = "missing"
	CodeNotLeader        Code = "not-leader"
	CodeUnavailable      Code = "unavailable"
	CodeUnknown          Code = "unknown"
	CodeExpired          Code = "expired"
	CodeLedgerFull       Code = "ledger-full"
	CodeNotSessionIssuer Code = "not-session-issuer"
	// CodeCursorExpired: REQ-10 events cursor older than retention.
	CodeCursorExpired Code = "cursor-expired"

	// Local classifications (not server Reply codes).

	// CodeClosed: the Conn was closed (Close) or an open stream lost its
	// connection. An idle disconnection is not CodeClosed: the Conn dials
	// again and keeps its Session (R03).
	CodeClosed Code = "closed"
	// CodeNotLoggedIn: a session-only method was called before Login.
	CodeNotLoggedIn Code = "not-logged-in"
	// CodeSessionExpired: the Session passed ExpiresAt.
	CodeSessionExpired Code = "session-expired"
	// CodeTransport: the exchange failed locally before it was sent.
	CodeTransport Code = "transport"
)

// Error carries the reply classification. InputCode is the plan input error
// class for CodeInvalid; Leader is the hint for CodeNotLeader.
type Error struct {
	Code      Code
	Method    string
	InputCode string
	Leader    string
	Detail    string
}

func (e *Error) Error() string {
	s := fmt.Sprintf("sfc %s: %s", e.Method, e.Code)
	if e.InputCode != "" {
		s += " (" + e.InputCode + ")"
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Is matches by Code so callers can write errors.Is(err, sfc.ErrUnknown).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Method == "" && t.Code == e.Code
}

var (
	ErrDenied           = &Error{Code: CodeDenied}
	ErrInvalid          = &Error{Code: CodeInvalid}
	ErrUnsupported      = &Error{Code: CodeUnsupported}
	ErrMissing          = &Error{Code: CodeMissing}
	ErrNotLeader        = &Error{Code: CodeNotLeader}
	ErrUnavailable      = &Error{Code: CodeUnavailable}
	ErrUnknown          = &Error{Code: CodeUnknown}
	ErrExpired          = &Error{Code: CodeExpired}
	ErrLedgerFull       = &Error{Code: CodeLedgerFull}
	ErrNotSessionIssuer = &Error{Code: CodeNotSessionIssuer}
	ErrCursorExpired    = &Error{Code: CodeCursorExpired}
	ErrClosed           = &Error{Code: CodeClosed}
	ErrNotLoggedIn      = &Error{Code: CodeNotLoggedIn}
	ErrSessionExpired   = &Error{Code: CodeSessionExpired}
)

func fail(method string, code Code, detail string) error {
	return &Error{Code: code, Method: method, Detail: detail}
}
