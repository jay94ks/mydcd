// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Real product types. Aliases keep signing bytes and stored originals
// byte-compatible with mydcd.
type (
	Ticket           = userauth.Ticket
	KeyProof         = access.KeyProof
	Session          = access.Session
	Scope            = access.Scope
	Role             = access.Role
	AuthMethod       = access.Method
	Credential       = access.Credential
	User             = access.User
	Change           = control.Change
	UserOperation    = control.UserOperation
	Result           = state.Result
	ResultCode       = state.Code
	UserView         = userauth.UserView
	TenantView       = userauth.TenantView
	NodeCLIPolicy    = access.NodeCLIPolicy
	SessionApproval  = access.SessionApproval
	PublicUser       = access.PublicUser
	PublicCredential = access.PublicCredential
	TenantMember     = access.TenantMember
	// TenantRetirement: `tenant-retirement` (Reply.TenantRetirement).
	TenantRetirement = control.TenantRetirementStatus
	NodeDisksPage    = control.NodeDisksPage
	NodeDiskView     = control.NodeDiskView
	MeshLinksPage    = control.MeshLinksPage
	MeshLinkView     = control.MeshLinkView
	MeshLinkEnd      = control.MeshLinkEnd
	// RaftStatus: `raft-status` (Reply.RaftStatus), system admin.
	RaftStatus     = userauth.RaftStatus
	RaftNodeStatus = userauth.RaftNodeStatus
	StorageRoot    = nodestorage.Root
	// EventsPage: `events` (Reply.Events).
	EventsPage = eventlog.Page
	EventItem  = eventlog.Item
	EventQuery = eventlog.Query
	// NodeSummaryPage: `node-summary` (Reply.NodeSummary).
	NodeSummaryPage = control.NodeSummaryPage
	NodeSummaryView = control.NodeSummaryView
	NodeAdminView   = control.NodeAdminView
	NodeUsageView   = control.NodeUsageView
)

const (
	RoleManager = access.Manager
	RoleViewer  = access.Viewer

	MethodPassword   = access.Password
	MethodToken      = access.Token
	MethodPrivateKey = access.PrivateKey

	ResultApplied         = state.Applied
	ResultConditionFailed = state.ConditionFailed
	ResultInvalid         = state.Invalid
	ResultRequestConflict = state.RequestConflict
	ResultForbidden       = state.Forbidden
	ResultExpired         = state.Expired
	ResultLedgerFull      = state.LedgerFull
)

// SignedOp is the canonical JSON of the original signed UserOperation. The
// daemon stores it before sending and passes the same bytes to Submit, Result
// and Resume. It must never be rewritten.
type SignedOp []byte

// OperationID returns the durable RequestID of a signed original operation.
func OperationID(op SignedOp) (string, error) {
	var v struct{ RequestID string }
	if err := json.Unmarshal(op, &v); err != nil || v.RequestID == "" {
		return "", errors.New("mydc: malformed signed operation")
	}
	return v.RequestID, nil
}

// DecodeOperation parses a signed original operation for display.
func DecodeOperation(op SignedOp) (UserOperation, error) {
	var v UserOperation
	if err := json.Unmarshal(op, &v); err != nil {
		return UserOperation{}, err
	}
	return v, nil
}

// SignedReason: the display reason signed inside an original
// (PrepareReason), read back from the stored original; mydcd keeps the same
// bytes and has no other read for it.
func SignedReason(op SignedOp) (OperationReason, bool, error) {
	v, err := DecodeOperation(op)
	if err != nil || v.Reason == nil {
		return OperationReason{}, false, err
	}
	return OperationReason{Reason: v.Reason.Text, Incident: v.Reason.IncidentID, ApprovedBy: v.Reason.ApprovedBy}, true, nil
}

func opReason(r OperationReason) *control.OperationReason {
	if r == (OperationReason{}) {
		return nil
	}
	return &control.OperationReason{Text: r.Reason, IncidentID: r.Incident, ApprovedBy: r.ApprovedBy}
}

// KeyProofSigningBytes is the exact byte string the browser signs with the
// user's private key for a private-key login (domain mydc-user-key-proof-1).
func KeyProofSigningBytes(p KeyProof) []byte { return access.KeyProofBytes(p) }

// NewKeyProof builds the unsigned proof for a Ticket returned by Challenge.
// The browser signs KeyProofSigningBytes(proof) and the daemon sets Signature.
func NewKeyProof(t Ticket) KeyProof {
	return KeyProof{
		Schema: 1, Cluster: t.Cluster, User: t.User, Username: t.Username,
		Credential: t.Credential, Challenge: t.Challenge, SessionKey: t.SessionKey,
		Deadline: t.Deadline,
	}
}

// NewSessionApproval builds the unsigned approval of an issued key-login
// session for the user key that logged in. The browser signs
// SessionApprovalSigningBytes(approval) and the daemon sets Signature.
func NewSessionApproval(s Session, userKey [32]byte) SessionApproval {
	return SessionApproval{Schema: 1, PublicKey: userKey, Session: access.IssuedSessionDigest(s)}
}

// SessionApprovalSigningBytes is the exact byte string the browser signs to
// approve a session (domain mydc-user-session-approval-1).
func SessionApprovalSigningBytes(a SessionApproval) []byte { return access.SessionApprovalBytes(a) }

// TicketSigningBytes is the issuer-signed byte string of a Ticket
// (domain mydc-user-login-ticket-1). The browser may verify Ticket.Signature
// with Ticket.Issuer before signing a KeyProof.
func TicketSigningBytes(t Ticket) []byte {
	t.Signature = nil
	b, _ := json.Marshal(t)
	return append([]byte("mydc-user-login-ticket-1\x00"), b...)
}
