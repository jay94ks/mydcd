// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

type Error struct {
	Code  string
	Phase sfcp.Phase
	Cause error
	stage string
}

func (e *Error) Error() string {
	if e.Code == "transport" && e.stage != "" {
		return fmt.Sprintf("user request: transport (stage=%s cause=%s phase=%d)", e.stage, transportCause(e.Cause), e.Phase)
	}
	var input *deployment.InputError
	if e.Code == "invalid" && errors.As(e.Cause, &input) && validInputCode(input.Code) {
		return "user request: invalid (" + input.Code + ")"
	}
	return "user request: " + e.Code
}
func (e *Error) Unwrap() error { return e.Cause }

type Client struct {
	OperationReason *control.OperationReason
	checkerUpload   *[32]byte
	Mesh            *sfcp.Transport
	Self            *identity.Identity
	Cluster         [32]byte
	Peers           []sfcp.Peer
	Credentials     *CredentialStore
	Username        string
	// TrustIssuer records a session issuer that a pinned node vouched for
	// when it relayed a login (see KeyLogin); nil refuses such a login.
	TrustIssuer func(sfcp.Peer) error
}

func (c Client) exchange(ctx context.Context, target sfcp.Peer, makeEnvelope func(*sfcp.Session) (Envelope, error), redirect bool) (Reply, sfcp.Peer, error) {
	return c.exchangeKind(ctx, target, makeEnvelope, redirect, 1)
}

func (c Client) exchangeKind(ctx context.Context, target sfcp.Peer, makeEnvelope func(*sfcp.Session) (Envelope, error), redirect bool, kind uint8) (Reply, sfcp.Peer, error) {
	return c.exchangePurpose(ctx, target, makeEnvelope, redirect, kind, sfcp.User)
}
func (c Client) exchangePurpose(ctx context.Context, target sfcp.Peer, makeEnvelope func(*sfcp.Session) (Envelope, error), redirect bool, kind uint8, purpose sfcp.Purpose) (Reply, sfcp.Peer, error) {
	if c.Mesh == nil || c.Self == nil || c.Self.Public != [32]byte(c.Mesh.LocalKey()) {
		return Reply{}, target, sfcp.ErrAdmission
	}
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.Mesh.Dial(ctx, target)
		if err != nil {
			return Reply{}, target, &Error{Code: "transport", Phase: sfcp.NotSent, Cause: err, stage: "dial"}
		}
		envelope, err := makeEnvelope(conn)
		if err != nil {
			return Reply{}, target, err
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			return Reply{}, target, err
		}
		defer clear(raw)
		digest := sha256.Sum256(raw)
		var reply Reply
		id := c.Mesh.NextRequest()
		lifetime, _ := sfcp.NewRequest(fmt.Sprint(id), digest)
		stage := "encode"
		err = func() error {
			frame := sfcp.Frame{Purpose: purpose, Kind: kind, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}}
			response, err := conn.Call(ctx, frame, sfcp.CallOptions{Echo: digest[:], Management: true, CloseWrite: true, ExpectEOF: true, Sent: func() { lifetime, _ = lifetime.BeginSend() }})
			if err != nil {
				var call *sfcp.CallError
				if errors.As(err, &call) {
					stage = call.Stage
					if stage == "validate" {
						return sfcp.ErrFrame
					}
					return call.Err
				}
				return err
			}
			defer clear(response.Fields[0].Value)
			stage = "validate"
			if strict(response.Fields[0].Value, &reply) != nil || reply.Schema != 1 {
				return sfcp.ErrFrame
			}
			if reply.Code != "unknown" {
				lifetime, _ = lifetime.Reply(fmt.Sprint(id), digest)
			}
			return nil
		}()
		if err != nil {
			clear(reply.InitialCredentialToken)
			return Reply{}, target, &Error{Code: "transport", Phase: lifetime.Abandon().Phase(), Cause: err, stage: stage}
		}
		if reply.Code == "ok" {
			return reply, target, nil
		}
		if reply.Code == "not-leader" && redirect && attempt == 0 && reply.Leader != "" && reply.Leader != target.ID {
			found := false
			for _, peer := range c.Peers {
				if peer.ID == reply.Leader {
					target, found = peer, true
					break
				}
			}
			if found {
				continue
			}
		}
		phase := lifetime.Abandon().Phase()
		return reply, target, &Error{Code: reply.Code, Phase: phase, Cause: appPlanInputCause(reply)}
	}
	return Reply{}, target, errors.New("user leader redirect exhausted")
}

// Prepare obtains a current root CAS, then signs ONE immutable intent. The
// caller must durably retain this value before Submit; no implicit resubmission
// or CAS/request-ID replacement is performed by the transport.
func (c Client) Prepare(ctx context.Context, target sfcp.Peer, session access.Session, id string, change control.Change) (control.UserOperation, error) {
	if c.OperationReason != nil && !c.OperationReason.Valid() {
		return control.UserOperation{}, access.ErrInvalid
	}
	if change.Action == "set-node-gateways" {
		var q control.NodeGatewaysChange
		if json.Unmarshal(change.Payload, &q) != nil || q.Evidence != nil {
			return control.UserOperation{}, access.ErrInvalid
		}
		page, err := c.Ingresses(ctx, target, session, control.IngressQuery{Node: q.Node, Part: "gateways", Check: &control.NodeGatewaysCheck{Node: q.Node, External: q.External, Local: q.Local, Expected: change.Expected, Request: id}})
		if err != nil {
			return control.UserOperation{}, err
		}
		if page.GatewayCheckError != "" {
			return control.UserOperation{}, &Error{Code: "invalid", Cause: access.ErrInvalid}
		}
		if page.GatewayEvidence == nil {
			return control.UserOperation{}, sfcp.ErrAdmission
		}
		q.Evidence = page.GatewayEvidence
		change.Payload, _ = json.Marshal(q)
	}
	key := control.CommandKey(change.Action)
	var epoch, root uint64
	switch key {
	case control.NodeShellKey, control.MembersKey:
		method := "node-shell-policy"
		if key == control.MembersKey {
			method = "members"
		}
		view, err := c.Query(ctx, target, session, method, "")
		if err != nil {
			return control.UserOperation{}, err
		}
		epoch, root = view.ModuleEpoch, view.NodeShellRootRevision
		if key == control.MembersKey {
			root = view.MembersRootRevision
		}
	default:
		view, err := c.Whoami(ctx, target, session)
		if err != nil {
			return control.UserOperation{}, err
		}
		epoch, root = view.ModuleEpoch, view.Root(key)
	}
	return c.prepareOperation(session, id, change, epoch, root, time.Now().Unix())
}

// The query above owns current admission and the snapshot; this signing tail
// fixes one operation before StageOperation publishes it. Loading an original
// journal never calls this helper or changes its explicitly signed CAS mode.
func (c Client) prepareOperation(session access.Session, id string, change control.Change, epoch, root uint64, at int64) (control.UserOperation, error) {
	if c.OperationReason != nil && !c.OperationReason.Valid() {
		return control.UserOperation{}, access.ErrInvalid
	}
	if epoch == 0 {
		epoch = 1
	}
	op := control.UserOperation{Schema: 1, Session: session, At: at, Epoch: epoch, RequestID: id, RootRevision: root, Change: change}
	if c.OperationReason != nil {
		reason := *c.OperationReason
		op.Reason = &reason
	}
	if id == "" || change.Principal != session.User || change.Schema != 1 {
		return control.UserOperation{}, sfcp.ErrAdmission
	}
	op.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(op))
	_, err := op.Command()
	return op, err
}

func (c Client) Operation(ctx context.Context, target sfcp.Peer, op control.UserOperation, resultOnly bool) (Reply, error) {
	method := "submit"
	if resultOnly {
		method = "result"
	}
	return c.operationSession(ctx, target, op.Session, op, method)
}

// Result authenticates the current session while preserving the old operation.
// Re-login is permission to query one's own retained result, never to resubmit
// the old command as a new actor/session/CAS/request ID.
func (c Client) Result(ctx context.Context, target sfcp.Peer, current access.Session, op control.UserOperation) (Reply, error) {
	return c.operationSession(ctx, target, current, op, "result")
}

func (c Client) Resume(ctx context.Context, target sfcp.Peer, current access.Session, op control.UserOperation) (Reply, error) {
	return c.operationSession(ctx, target, current, op, "resume")
}

func (c Client) operationSession(ctx context.Context, target sfcp.Peer, current access.Session, op control.UserOperation, method string) (Reply, error) {
	if c.Self == nil || c.Self.Public != current.Key || current.User != op.Session.User || op.VerifyOriginal(c.Cluster) != nil || (method == "submit" && !sameSession(current, op.Session)) {
		return Reply{}, sfcp.ErrAdmission
	}
	body, err := requestBody(Request{Method: method, Operation: &op})
	if err != nil {
		return Reply{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *sfcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &current, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(current, conn.PeerChallenge(), body))}, nil
	}, true)
	return reply, err
}

func requestBody(r Request) ([]byte, error) {
	r.Schema = 1
	if _, err := rand.Read(r.Nonce[:]); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// A confirmed pre-ticket refusal may race a leader election. No credential
// proof has been sent here. Transport uncertainty and every other rejection
// remain terminal; this must not be used for proofs or management operations.
func retryLoginChallenge(ctx context.Context, target sfcp.Peer, exchange func(context.Context, sfcp.Peer) (Reply, sfcp.Peer, error)) (Reply, sfcp.Peer, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return Reply{}, target, err
		}
		reply, selected, err := exchange(ctx, target)
		var rejected *Error
		if attempt == 4 || len(reply.Data) != 0 || reply.Code != "not-leader" || !errors.As(err, &rejected) || rejected.Code != "not-leader" || rejected.Phase != sfcp.Completed {
			return reply, selected, err
		}
		timer := time.NewTimer((100 * time.Millisecond) << attempt)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Reply{}, selected, ctx.Err()
		case <-timer.C:
		}
		target = selected
	}
}

func (c Client) loginChallenge(ctx context.Context, target sfcp.Peer, body []byte) (Reply, sfcp.Peer, error) {
	return retryLoginChallenge(ctx, target, func(ctx context.Context, peer sfcp.Peer) (Reply, sfcp.Peer, error) {
		return c.exchange(ctx, peer, func(*sfcp.Session) (Envelope, error) { return Envelope{Body: body}, nil }, true)
	})
}

// Login is a private-key login whose user key is held by this process. It is
// KeyLoginChallenge, KeyLoginProof signed with private, KeyLogin and
// access.ApproveSession in that order.
func (c Client) Login(ctx context.Context, target sfcp.Peer, username string, private ed25519.PrivateKey) (access.Session, error) {
	if len(private) != ed25519.PrivateKeySize {
		return access.Session{}, sfcp.ErrAdmission
	}
	ticket, selected, err := c.KeyLoginChallenge(ctx, target, username, [32]byte(private.Public().(ed25519.PublicKey)))
	if err != nil {
		return access.Session{}, err
	}
	proof := c.KeyLoginProof(ticket)
	proof.Signature = ed25519.Sign(private, access.KeyProofBytes(proof))
	session, err := c.KeyLogin(ctx, selected, ticket, proof)
	if err != nil {
		return access.Session{}, err
	}
	return access.ApproveSession(session, private)
}

func (c Client) Verify(session access.Session) error {
	return c.verifyAt(session, time.Now().Unix())
}

// expired reports a session that fails only because its time has passed.
func (c Client) expired(session access.Session) bool {
	return session.ExpiresAt <= time.Now().Unix() && c.verifyAt(session, session.ExpiresAt-1) == nil
}

func (c Client) verifyAt(session access.Session, now int64) error {
	if c.Self == nil || c.Cluster == ([32]byte{}) {
		return sfcp.ErrAdmission
	}
	trusted := false
	for _, peer := range c.Peers {
		trusted = trusted || [32]byte(peer.Key) == session.Issuer
	}
	if !trusted || session.Schema != 1 || session.Cluster != c.Cluster || session.Key != c.Self.Public || session.IssuerEpoch != 1 || session.IssuedAt > now+access.MaxClockSkewSeconds || session.ExpiresAt <= now || session.ExpiresAt-session.IssuedAt > access.MaxSessionSeconds || session.ExpiresAt <= session.IssuedAt || !ed25519.Verify(ed25519.PublicKey(session.Issuer[:]), access.SessionBytes(session), session.Signature) {
		return sfcp.ErrAdmission
	}
	if session.Approval != nil && session.Approval.VerifyBinding(session) != nil {
		return sfcp.ErrAdmission
	}
	return nil
}

func (c Client) Query(ctx context.Context, target sfcp.Peer, session access.Session, method, tenant string) (Reply, error) {
	if method == "tenant-storage" {
		return c.TenantStoragePage(ctx, target, session, tenant, "", "")
	}
	return c.query(ctx, target, session, Request{Method: method, Tenant: tenant})
}

// MemberPage returns at most eight entries with the same committed root CAS.
// A caller collecting multiple pages must reject a changed root revision.
func (c Client) MemberPage(ctx context.Context, target sfcp.Peer, session access.Session, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "members", After: after})
}

// Combining definitions and maintenance summaries requires both
// RegistriesRootRevision and RegistryMaintenanceRootRevision to stay unchanged.
func (c Client) RegistryPage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "registries", Tenant: tenant, After: after})
}

// Combining pages requires the same ExternalRegistriesRootRevision.
func (c Client) ExternalRegistryPage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "external-registries", Tenant: tenant, After: after})
}

func (c Client) AppPage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "apps", Tenant: tenant, After: after})
}
func (c Client) AppOperation(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, request control.AppOperationRequest) (Reply, error) {
	reply, err := c.query(ctx, target, session, Request{Method: "app-operation", Tenant: tenant, AppOperation: &request})
	if err != nil {
		return reply, err
	}
	v := reply.AppOperation
	if v == nil || v.Tenant != tenant || (request.Standalone == "" && v.App != request.App || request.Standalone != "" && v.Standalone != request.Standalone) || v.ID != request.ID || v.Found != (v.Operation != nil) || !v.Found && v.Current || v.Found && (v.Operation.ID != request.ID || v.Operation.Plan == ([32]byte{}) || v.Operation.Epoch == 0 || v.Operation.Submitter == "" || v.Deployment == "" || v.Revision == 0) {
		return Reply{}, sfcp.ErrAdmission
	}
	return reply, nil
}
func (c Client) AppUploadPage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "app-uploads", Tenant: tenant, After: after})
}
func (c Client) PlanApp(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, request control.AppPlanRequest) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "app-plan", Tenant: tenant, AppPlan: &request})
}

func (c Client) NodeInvitation(ctx context.Context, target sfcp.Peer, session access.Session, node string) (membership.Invitation, error) {
	reply, err := c.query(ctx, target, session, Request{Method: "node-invitation", Node: node})
	if err != nil {
		return membership.Invitation{}, err
	}
	if reply.Invitation == nil {
		return membership.Invitation{}, sfcp.ErrAdmission
	}
	inv := *reply.Invitation
	err = c.verifyNodeInvitation(inv, node, nil)
	var untrusted *UntrustedSourceError
	if errors.As(err, &untrusted) {
		// The node the CLI talks to relays the request to the leader, which
		// signs as itself. That leader need not be pinned: the pinned node's
		// own member list vouches for it.
		var members []membership.Entry
		if members, err = c.memberEntry(ctx, target, session, inv.Source.ID); err == nil {
			err = c.verifyNodeInvitation(inv, node, members)
		}
	}
	if err != nil {
		return membership.Invitation{}, err
	}
	return inv, nil
}

// memberEntry pages the member list of target (a pinned node) up to the
// entry for id. It returns that one entry, or none.
func (c Client) memberEntry(ctx context.Context, target sfcp.Peer, session access.Session, id string) ([]membership.Entry, error) {
	after := ""
	for range 512 {
		page, err := c.MemberPage(ctx, target, session, after)
		if err != nil {
			return nil, err
		}
		for _, e := range page.Members {
			if e.Peer.ID == id {
				return []membership.Entry{e}, nil
			}
		}
		if page.MembersNext == "" || page.MembersNext <= after {
			return nil, nil
		}
		after = page.MembersNext
	}
	return nil, nil
}

// UntrustedSourceError: a node invitation is signed by a node this context
// does not trust, and the pinned node's member list does not vouch for it
// as a current voting member with that key and address.
type UntrustedSourceError struct {
	Node, Key string
}

func (e *UntrustedSourceError) Error() string {
	key := e.Key
	if len(key) > 16 {
		key = key[:16]
	}
	return fmt.Sprintf("node invitation: signed by node %s (key %s...), which this context does not trust and the cluster member list does not show as a voting member with that key and address; check the node, then run 'sfcli context trust CONTEXT ENDPOINT --key KEY' for it", e.Node, key)
}

func (e *UntrustedSourceError) Is(target error) bool { return target == sfcp.ErrAdmission }

// verifyNodeInvitation accepts an invitation for node signed by its Source:
// a pinned node (its pinned address, or a pinned local management socket),
// or else a member that members (the pinned node's member list) shows as a
// full voting member with the same key and address.
func (c Client) verifyNodeInvitation(inv membership.Invitation, node string, members []membership.Entry) error {
	if inv.Target.ID != node {
		return sfcp.ErrAdmission
	}
	var source [32]byte
	trusted := false
	for _, peer := range c.Peers {
		if peer.ID == inv.Source.ID {
			source = [32]byte(peer.Key)
			// A pinned Unix management address is local to the CLI host and
			// cannot be the source's routable join address. The same pinned
			// identity signs that address; network pins retain exact matching.
			local := strings.HasPrefix(peer.Endpoint, "unix:///") && sfcp.ValidateManagementSocket(strings.TrimPrefix(peer.Endpoint, "unix://")) == nil
			trusted = local || peer.Endpoint == inv.Source.Endpoint
		}
	}
	if !trusted {
		for _, e := range members {
			current := e.CurrentPeer()
			key, err := identity.ParseKey(current.Key)
			if err == nil && e.Peer.ID == inv.Source.ID && membership.FullMember(e) && e.Peer.Voter && current.Key == inv.Source.Key && current.Endpoint == inv.Source.Endpoint {
				source, trusted = [32]byte(key), true
			}
		}
	}
	if !trusted {
		return &UntrustedSourceError{Node: inv.Source.ID, Key: inv.Source.Key}
	}
	if inv.Verify(c.Cluster, source) != nil {
		return sfcp.ErrAdmission
	}
	return nil
}

// QueryRequest sends one finite user query exactly as r is built, with the
// same session check and method allow list as the typed reads. It is for
// clients that select or page beyond those helpers (the web adapter); it
// adds no authority: sfcd checks every field as for the CLI.
func (c Client) QueryRequest(ctx context.Context, target sfcp.Peer, session access.Session, r Request) (Reply, error) {
	return c.query(ctx, target, session, r)
}

func (c Client) query(ctx context.Context, target sfcp.Peer, session access.Session, r Request) (Reply, error) {
	if c.Verify(session) != nil {
		return Reply{}, sfcp.ErrAdmission
	}
	method := r.Method
	if !nodeShellQuery(method) && method != "standalone-list" && method != "standalone-get" && method != "standalone-plan" && method != "cd-probe" && method != "tenant-storage" && method != "events" && method != "login-records" && method != "own-sessions" && method != "app-cd-toggle-plan" && method != "image-cache-plan" && method != "image-cache-status" && method != "registry-action-plan" && method != "external-registry-bind-plan" && method != "registry-login-test" && method != "image-resolve" && method != "registry-maintenance-plan" && method != "registry-maintenance-status" && method != "image-usages" && method != "registry-catalog" && method != "registry-prune-preview" && method != "registry-prune-results" && method != "external-registry-pulls" && method != "task-restart-plan" && method != "task-restart-status" && method != "raft-status" && method != "app-source" && method != "app-revisions" && method != "my-credentials" && method != "users" && method != "tenant-members" && method != "app-log-clear-plan" && method != "app-log-clear-status" && method != "user-credentials" && method != "node-cli-policy" && method != "container-observe" && method != "tenant-retirement" && method != "members" && method != "node-invitation" && method != "node-storage" && method != "node-storage-space" && method != "apps" && method != "app-operation" && method != "app-cd-field" && method != "app-cd-history" && method != "app-cd-diff" && method != "app-cd-registration" && method != "app-uploads" && method != "app-plan" && method != "vault" && method != "vault-approval-plan" && method != "vault-write-plan" && method != "registries" && method != "external-registries" && method != "image-builds" && method != "build-zip-transfer" && method != "check-build-context" && method != "build-context-content" && method != "image-build-cache" && method != "image-build-logs" && method != "image-build-job-plan" && method != "build-draft" && method != "save-build-git" {
		return Reply{}, fmt.Errorf("unsupported user query")
	}
	body, err := requestBody(r)
	if err != nil {
		return Reply{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *sfcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, method != "cd-probe") // Installed Git profiles stay on the explicitly selected provider.
	return reply, err
}

// TenantRetirementPage is an authenticated system-admin observation, including
// a Deleted tombstone. It never creates or resumes a deletion.
func (c Client) TenantRetirementPage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "tenant-retirement", Tenant: tenant, After: after})
}
