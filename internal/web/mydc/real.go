// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// RealConfig names the mydcd this daemon talks to: its management Unix
// socket and the identity it must present there. Cluster and NodeKey are
// pinned out of band (the node's install output, as for a CLI context); the
// adapter never trusts a key the socket offers.
type RealConfig struct {
	Socket  string   // e.g. /var/run/mydc.sock
	Cluster [32]byte // cluster ID
	Node    string   // the node's ID
	NodeKey [32]byte // the node's identity key
}

func (c RealConfig) valid() error {
	if mydcp.ValidateManagementSocket(c.Socket) != nil {
		return errors.New("mydc: socket must be a clean absolute Unix socket path")
	}
	if c.Cluster == ([32]byte{}) || c.NodeKey == ([32]byte{}) || c.Node == "" {
		return errors.New("mydc: cluster, node and node key are required")
	}
	return nil
}

// NewReal is the mydcd adapter over the management socket. Each Dial makes
// one login's Conn: a fresh session key, its own MYDCP transport and one
// userauth.Client (R03), so a Conn is never shared between users.
func NewReal(cfg RealConfig) (Client, error) {
	if err := cfg.valid(); err != nil {
		return nil, err
	}
	return realClient{cfg}, nil
}

type realClient struct{ cfg RealConfig }

func (r realClient) Dial(ctx context.Context) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fail("dial", CodeTransport, err.Error())
	}
	self, err := identity.Ephemeral()
	if err != nil {
		return nil, fail("dial", CodeTransport, err.Error())
	}
	peer := mydcp.Peer{ID: r.cfg.Node, Endpoint: "unix://" + r.cfg.Socket, Policy: mydcp.Policy{Key: mydcp.Identity(r.cfg.NodeKey), Respond: true}}
	mesh, err := mydcp.NewTransport(self, r.cfg.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) {
		return peer, key == peer.Key
	})
	if err != nil {
		clear(self.Private)
		return nil, fail("dial", CodeTransport, err.Error())
	}
	return &realConn{c: userauth.Client{Cluster: r.cfg.Cluster, Self: self, Mesh: mesh, Peers: []mydcp.Peer{peer}}, peer: peer}, nil
}

// realConn is one login. The transport keeps the Unix connection for up to
// 30 s idle and dials again after; the Session is bound to the session key
// (c.Self), not the connection, so it survives. A pending ticket is bound
// to the connection's challenge and is lost with it.
type realConn struct {
	c    userauth.Client
	peer mydcp.Peer

	// calls is held shared by every exchange in flight; Close takes it
	// exclusively so it never wipes the session key under a running call.
	calls sync.RWMutex

	mu       sync.Mutex
	closed   bool
	ticket   *Ticket
	selected mydcp.Peer // the ticket's issuer
	session  *Session
	loginKey [32]byte // the user key of the current key login
}

func (c *realConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed, c.ticket, c.session = true, nil, nil
	c.mu.Unlock()
	// Closing the transport first ends calls in flight (a long file
	// transfer too) instead of waiting them out; every call that passed
	// open holds calls shared, so the key is wiped only after they return.
	err := c.c.Mesh.Close()
	c.calls.Lock()
	defer c.calls.Unlock()
	clear(c.c.Self.Private)
	return err
}

func (c *realConn) Session() (Session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.session == nil {
		return Session{}, false
	}
	return *c.session, true
}

// open is the common start of an exchange: the Conn is open and, with
// needSession, logged in with an unexpired session. On success the caller
// must call done when the exchange ends, so Close can wait for it.
func (c *realConn) open(ctx context.Context, method string, needSession bool) (Session, func(), error) {
	if err := ctx.Err(); err != nil {
		return Session{}, nil, fail(method, CodeTransport, err.Error())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Session{}, nil, fail(method, CodeClosed, "connection closed")
	}
	if needSession {
		if c.session == nil {
			return Session{}, nil, fail(method, CodeNotLoggedIn, "")
		}
		if time.Now().Unix() >= c.session.ExpiresAt {
			return Session{}, nil, fail(method, CodeSessionExpired, "")
		}
	}
	// Taken under mu: Close marks closed under mu before it waits on calls,
	// so a call that saw the Conn open is always waited for.
	c.calls.RLock()
	var s Session
	if needSession {
		s = *c.session
	}
	return s, c.calls.RUnlock, nil
}

// realError classifies a userauth error. A reply code is passed through; a
// transport failure is CodeTransport only when nothing was sent, otherwise
// the outcome is CodeUnknown; a local refusal before sending is
// CodeInvalid.
func realError(method string, err error) error {
	if err == nil {
		return nil
	}
	var e *userauth.Error
	if errors.As(err, &e) {
		out := &Error{Code: Code(e.Code), Method: method}
		switch e.Code {
		case "transport":
			out.Code = CodeTransport
			if e.Phase != mydcp.NotSent {
				out.Code = CodeUnknown
			}
			out.Detail = err.Error()
		case "invalid":
			var input *deployment.InputError
			if errors.As(e.Cause, &input) {
				out.InputCode = input.Code
			}
		}
		return out
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fail(method, CodeTransport, err.Error())
	}
	if errors.Is(err, mydcp.ErrAdmission) || errors.Is(err, access.ErrInvalid) {
		return fail(method, CodeInvalid, "refused before sending")
	}
	if errors.Is(err, mydcp.ErrFrame) {
		return fail(method, CodeUnknown, "malformed reply")
	}
	return fail(method, CodeTransport, err.Error())
}

// --- login ---

func (c *realConn) CredentialChallenge(ctx context.Context, username string, method AuthMethod, credential string) (Ticket, error) {
	const m = "credential-challenge"
	_, done, err := c.open(ctx, m, false)
	if err != nil {
		return Ticket{}, err
	}
	defer done()
	if method != MethodPassword && method != MethodToken {
		return Ticket{}, fail(m, CodeInvalid, "method")
	}
	t, selected, err := c.c.CredentialChallenge(ctx, c.peer, username, method, credential)
	if err != nil {
		return Ticket{}, realError(m, err)
	}
	c.mu.Lock()
	c.ticket, c.selected, c.session, c.loginKey = &t, selected, nil, [32]byte{}
	c.mu.Unlock()
	return t, nil
}

func (c *realConn) CredentialLogin(ctx context.Context, t Ticket, secret []byte) (Session, error) {
	const m = "credential-login"
	selected, err := c.takeTicket(ctx, m, t)
	if err != nil {
		return Session{}, err
	}
	s, err := c.c.CredentialLogin(ctx, selected, t, secret)
	if err != nil {
		return Session{}, realError(m, err)
	}
	return c.setSession(s, [32]byte{}), nil
}

func (c *realConn) Challenge(ctx context.Context, username string, userKey [32]byte) (Ticket, error) {
	const m = "challenge"
	_, done, err := c.open(ctx, m, false)
	if err != nil {
		return Ticket{}, err
	}
	defer done()
	t, selected, err := c.c.KeyLoginChallenge(ctx, c.peer, username, userKey)
	if err != nil {
		return Ticket{}, realError(m, err)
	}
	c.mu.Lock()
	c.ticket, c.selected, c.session, c.loginKey = &t, selected, nil, [32]byte{}
	c.mu.Unlock()
	return t, nil
}

func (c *realConn) Login(ctx context.Context, t Ticket, proof KeyProof) (Session, error) {
	const m = "login"
	selected, err := c.takeTicket(ctx, m, t)
	if err != nil {
		return Session{}, err
	}
	s, err := c.c.KeyLogin(ctx, selected, t, proof)
	if err != nil {
		return Session{}, realError(m, err)
	}
	return c.setSession(s, t.UserKey), nil
}

// takeTicket checks that t is the pending ticket and uses it up: a ticket
// is sent once, whatever the answer.
func (c *realConn) takeTicket(ctx context.Context, m string, t Ticket) (mydcp.Peer, error) {
	_, done, err := c.open(ctx, m, false)
	if err != nil {
		return mydcp.Peer{}, err
	}
	defer done()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ticket == nil || c.ticket.Nonce != t.Nonce || c.ticket.Challenge != t.Challenge {
		return mydcp.Peer{}, fail(m, CodeExpired, "no pending login ticket")
	}
	c.ticket = nil
	return c.selected, nil
}

func (c *realConn) setSession(s Session, loginKey [32]byte) Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session, c.loginKey = &s, loginKey
	return s
}

func (c *realConn) ApproveSession(ctx context.Context, a SessionApproval) (Session, error) {
	const m = "approve-session"
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return Session{}, err
	}
	defer done()
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.Approval != nil || c.loginKey == ([32]byte{}) || c.loginKey != a.PublicKey {
		return Session{}, fail(m, CodeDenied, "")
	}
	approved, err := access.AttachSessionApproval(s, a)
	if err != nil {
		return Session{}, fail(m, CodeDenied, "")
	}
	c.session = &approved
	return approved, nil
}

// --- account ---

func (c *realConn) query(ctx context.Context, m, tenant string) (userauth.Reply, error) {
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return userauth.Reply{}, err
	}
	defer done()
	reply, err := c.c.Query(ctx, c.peer, s, m, tenant)
	return reply, realError(m, err)
}

func (c *realConn) Whoami(ctx context.Context) (Whoami, error) {
	const m = "whoami"
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return Whoami{}, err
	}
	defer done()
	reply, err := c.c.Query(ctx, c.peer, s, m, "")
	if err != nil {
		return Whoami{}, realError(m, err)
	}
	if reply.User == nil {
		return Whoami{}, fail(m, CodeUnknown, "reply without user")
	}
	// mydcd leaves ModuleEpoch out while it is still the first epoch
	// (userauth service: whoami and members set it only above 1).
	epoch := reply.ModuleEpoch
	if epoch == 0 {
		epoch = 1
	}
	return Whoami{User: *reply.User, RootRevision: reply.RootRevision, LedgerRootRevision: reply.LedgerRootRevision, LedgerEpoch: epoch, Session: s, Roots: map[string]uint64{
		control.CertificatesKey:        reply.CertificatesRootRevision,
		control.IngressManagementKey:   reply.IngressRootRevision,
		control.CompactKey:             reply.CompactRootRevision,
		control.TunnelReconnectKey:     reply.TunnelRootRevision,
		control.RegistryMaintenanceKey: reply.RegistryMaintenanceRootRevision,
		control.ImageBuildKey:          reply.ImageBuildRootRevision,
		control.ImageCacheKey:          reply.ImageCacheRootRevision,
	}}, nil
}

func (c *realConn) Tenants(ctx context.Context) ([]TenantView, error) {
	reply, err := c.query(ctx, "tenants", "")
	if err != nil {
		return nil, err
	}
	return reply.Tenants, nil
}

// SelectTenant: `select-tenant` checks Read on tenant and gives its
// revision and the allowed servers the caller may read; the role is the
// caller's `tenants` row (a system administrator is a manager everywhere).
func (c *realConn) SelectTenant(ctx context.Context, tenant string) (TenantView, error) {
	const m = "select-tenant"
	reply, err := c.query(ctx, m, tenant)
	if err != nil {
		return TenantView{}, err
	}
	nodes := reply.TenantAllowedNodes
	if nodes == nil {
		nodes = []string{}
	}
	view := TenantView{ID: tenant, Revision: reply.TenantRevision, AllowedNodes: nodes}
	if reply.User != nil && reply.User.SystemAdmin {
		view.Role = RoleManager
		return view, nil
	}
	rows, err := c.Tenants(ctx)
	if err != nil {
		return TenantView{}, err
	}
	for _, t := range rows {
		if t.ID == tenant {
			view.Role = t.Role
		}
	}
	return view, nil
}

// --- durable changes ---

func (c *realConn) Prepare(ctx context.Context, change Change, rootRevision uint64) (SignedOp, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fail("prepare", CodeTransport, err.Error())
	}
	return c.prepare(ctx, "web-"+hex.EncodeToString(id), change, nil)
}

func (c *realConn) PrepareRequest(ctx context.Context, requestID string, change Change, rootRevision uint64) (SignedOp, error) {
	if !validRequestID(requestID) {
		return nil, fail("prepare", CodeInvalid, "request ID")
	}
	return c.prepare(ctx, requestID, change, nil)
}

// PrepareReason signs the operation with its display reason inside the
// envelope (control.OperationReason), as mydcd records it.
func (c *realConn) PrepareReason(ctx context.Context, change Change, rootRevision uint64, reason OperationReason) (SignedOp, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fail("prepare", CodeTransport, err.Error())
	}
	return c.prepare(ctx, "web-"+hex.EncodeToString(id), change, opReason(reason))
}

func (c *realConn) PrepareRequestReason(ctx context.Context, requestID string, change Change, rootRevision uint64, reason OperationReason) (SignedOp, error) {
	if !validRequestID(requestID) {
		return nil, fail("prepare", CodeInvalid, "request ID")
	}
	return c.prepare(ctx, requestID, change, opReason(reason))
}

// prepare signs one original with the session key, as the CLI does:
// userauth.Client.Prepare reads the current root of the change's command
// key and signs it. The caller's rootRevision (Whoami.RootFor) is not
// needed; the change's Expected carries the CAS of what the user saw.
// Nothing is sent.
func (c *realConn) prepare(ctx context.Context, requestID string, change Change, reason *control.OperationReason) (SignedOp, error) {
	const m = "prepare"
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return nil, err
	}
	defer done()
	if change.Schema == 0 {
		change.Schema = 1
	}
	if change.Principal == "" {
		change.Principal = s.User
	}
	client := c.c
	client.OperationReason = reason
	op, err := client.Prepare(ctx, c.peer, s, requestID, change)
	if err != nil {
		return nil, realError(m, err)
	}
	raw, err := json.Marshal(op)
	if err != nil {
		return nil, fail(m, CodeInvalid, err.Error())
	}
	return raw, nil
}

func (c *realConn) operation(ctx context.Context, m string, raw SignedOp) (Result, bool, error) {
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return Result{}, false, err
	}
	defer done()
	op, err := DecodeOperation(raw)
	if err != nil {
		return Result{}, false, fail(m, CodeInvalid, "malformed signed operation")
	}
	var reply userauth.Reply
	switch m {
	case "submit":
		reply, err = c.c.Operation(ctx, c.peer, op, false)
	case "result":
		reply, err = c.c.Result(ctx, c.peer, s, op)
	default:
		reply, err = c.c.Resume(ctx, c.peer, s, op)
	}
	if err != nil {
		return Result{}, false, realError(m, err)
	}
	if m != "submit" && !reply.Found {
		return Result{}, false, nil
	}
	if reply.Result == nil {
		return Result{}, false, fail(m, CodeUnknown, "reply without result")
	}
	return *reply.Result, true, nil
}

func (c *realConn) Submit(ctx context.Context, op SignedOp) (Result, error) {
	res, _, err := c.operation(ctx, "submit", op)
	return res, err
}

func (c *realConn) Result(ctx context.Context, op SignedOp) (Result, bool, error) {
	return c.operation(ctx, "result", op)
}

func (c *realConn) Resume(ctx context.Context, op SignedOp) (Result, bool, error) {
	return c.operation(ctx, "resume", op)
}

var _ Conn = (*realConn)(nil)
