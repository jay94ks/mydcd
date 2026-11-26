// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

type Error struct {
	Code  string
	Phase mydcp.Phase
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
	Mesh            *mydcp.Transport
	Self            *identity.Identity
	Cluster         [32]byte
	Peers           []mydcp.Peer
	Credentials     *CredentialStore
	Username        string
}

func (c Client) exchange(ctx context.Context, target mydcp.Peer, makeEnvelope func(*mydcp.Session) (Envelope, error), redirect bool) (Reply, mydcp.Peer, error) {
	return c.exchangeKind(ctx, target, makeEnvelope, redirect, 1)
}

func (c Client) exchangeKind(ctx context.Context, target mydcp.Peer, makeEnvelope func(*mydcp.Session) (Envelope, error), redirect bool, kind uint8) (Reply, mydcp.Peer, error) {
	return c.exchangePurpose(ctx, target, makeEnvelope, redirect, kind, mydcp.User)
}
func (c Client) exchangePurpose(ctx context.Context, target mydcp.Peer, makeEnvelope func(*mydcp.Session) (Envelope, error), redirect bool, kind uint8, purpose mydcp.Purpose) (Reply, mydcp.Peer, error) {
	if c.Mesh == nil || c.Self == nil || c.Self.Public != [32]byte(c.Mesh.LocalKey()) {
		return Reply{}, target, mydcp.ErrAdmission
	}
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.Mesh.Dial(ctx, target)
		if err != nil {
			return Reply{}, target, &Error{Code: "transport", Phase: mydcp.NotSent, Cause: err, stage: "dial"}
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
		stream, err := conn.OpenManagement(ctx)
		if err != nil {
			return Reply{}, target, &Error{Code: "transport", Phase: mydcp.NotSent, Cause: err, stage: "open"}
		}
		var reply Reply
		id := c.Mesh.NextRequest()
		lifetime, _ := mydcp.NewRequest(fmt.Sprint(id), digest)
		stage := "encode"
		err = func() error {
			defer stream.CancelRead(0)
			defer stream.Close()
			stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
			defer stop()
			frame := mydcp.Frame{Purpose: purpose, Kind: kind, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}}
			if _, err := mydcp.Encode(frame); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			lifetime, _ = lifetime.BeginSend()
			stage = "send"
			if err := mydcp.WriteFrame(stream, frame); err != nil {
				return err
			}
			stage = "send-eof"
			if err := stream.Close(); err != nil {
				return err
			}
			stage = "receive"
			response, err := mydcp.ReadFrame(stream, 128<<10)
			if err != nil {
				return err
			}
			if len(response.Fields) > 0 {
				defer clear(response.Fields[0].Value)
			}
			stage = "validate"
			if response.Request != id || response.Purpose != purpose || response.Kind != 2 || conn.Admit(response, purpose, false) != nil || !bytes.Equal(response.Fields[1].Value, digest[:]) || strict(response.Fields[0].Value, &reply) != nil || reply.Schema != 1 {
				return mydcp.ErrFrame
			}
			stage = "receive-eof"
			if err := streamEOF(stream); err != nil {
				return err
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
func (c Client) Prepare(ctx context.Context, target mydcp.Peer, session access.Session, id string, change control.Change) (control.UserOperation, error) {
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
			return control.UserOperation{}, mydcp.ErrAdmission
		}
		q.Evidence = page.GatewayEvidence
		change.Payload, _ = json.Marshal(q)
	}
	method := "whoami"
	if control.CommandKey(change.Action) == control.NodeShellKey {
		method = "node-shell-policy"
	}
	if control.CommandKey(change.Action) == control.MembersKey {
		method = "members"
	}
	view, err := c.Query(ctx, target, session, method, "")
	if err != nil {
		return control.UserOperation{}, err
	}
	return c.prepareOperation(session, id, change, view, time.Now().Unix())
}

// The query above owns current admission and the snapshot; this signing tail
// fixes one operation before StageOperation publishes it. Loading an original
// journal never calls this helper or changes its explicitly signed CAS mode.
func (c Client) prepareOperation(session access.Session, id string, change control.Change, view Reply, at int64) (control.UserOperation, error) {
	if c.OperationReason != nil && !c.OperationReason.Valid() {
		return control.UserOperation{}, access.ErrInvalid
	}
	epoch := view.ModuleEpoch
	if epoch == 0 {
		epoch = 1
	}
	op := control.UserOperation{Schema: 1, Session: session, At: at, Epoch: epoch, RequestID: id, RootRevision: view.RootRevision, Change: change}
	if c.OperationReason != nil {
		reason := *c.OperationReason
		op.Reason = &reason
	}
	if control.CommandKey(change.Action) == control.NodeShellKey {
		op.RootRevision = view.NodeShellRootRevision
	}
	if control.CommandKey(change.Action) == control.MembersKey {
		op.RootRevision = view.MembersRootRevision
	}
	if control.CommandKey(change.Action) == control.ResourcesKey {
		op.RootRevision = view.ResourcesRootRevision
	}
	if control.CommandKey(change.Action) == control.VolumesKey {
		op.RootRevision = view.VolumesRootRevision
	}
	if control.CommandKey(change.Action) == control.VaultKey {
		op.RootRevision = view.VaultRootRevision
	}
	if control.CommandKey(change.Action) == control.AppsKey {
		op.RootRevision = view.AppsRootRevision
	}
	if control.CommandKey(change.Action) == control.RegistryMaintenanceKey {
		op.RootRevision = view.RegistryMaintenanceRootRevision
	}
	if control.CommandKey(change.Action) == control.ImageBuildKey {
		op.RootRevision = view.ImageBuildRootRevision
	}
	if control.CommandKey(change.Action) == control.CertificatesKey {
		op.RootRevision = view.CertificatesRootRevision
	}
	if control.CommandKey(change.Action) == control.IngressManagementKey {
		op.RootRevision = view.IngressRootRevision
	}
	if control.CommandKey(change.Action) == control.ImageCacheKey {
		op.RootRevision = view.ImageCacheRootRevision
	}
	if control.CommandKey(change.Action) == control.TunnelReconnectKey {
		op.RootRevision = view.TunnelRootRevision
	}
	if control.CommandKey(change.Action) == control.CompactKey {
		op.RootRevision = view.CompactRootRevision
	}
	if control.CommandKey(change.Action) == control.StorageKey {
		op.RootRevision = view.LedgerRootRevision
	}
	if control.CommandKey(change.Action) == control.NodeStorageKey {
		op.RootRevision = view.NodeStorageRootRevision
	}
	if control.CommandKey(change.Action) == control.LifecycleKey {
		op.RootRevision = view.LifecycleRootRevision
	}
	if control.CommandKey(change.Action) == control.RegistriesKey {
		op.RootRevision = view.RegistriesRootRevision
	}
	if control.CommandKey(change.Action) == control.ExternalRegistriesKey {
		op.RootRevision = view.ExternalRegistriesRootRevision
	}
	if id == "" || change.Principal != session.User || change.Schema != 1 {
		return control.UserOperation{}, mydcp.ErrAdmission
	}
	op.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(op))
	_, err := op.Command()
	return op, err
}

func (c Client) Operation(ctx context.Context, target mydcp.Peer, op control.UserOperation, resultOnly bool) (Reply, error) {
	method := "submit"
	if resultOnly {
		method = "result"
	}
	return c.operationSession(ctx, target, op.Session, op, method)
}

// Result authenticates the current session while preserving the old operation.
// Re-login is permission to query one's own retained result, never to resubmit
// the old command as a new actor/session/CAS/request ID.
func (c Client) Result(ctx context.Context, target mydcp.Peer, current access.Session, op control.UserOperation) (Reply, error) {
	return c.operationSession(ctx, target, current, op, "result")
}

func (c Client) Resume(ctx context.Context, target mydcp.Peer, current access.Session, op control.UserOperation) (Reply, error) {
	return c.operationSession(ctx, target, current, op, "resume")
}

func (c Client) operationSession(ctx context.Context, target mydcp.Peer, current access.Session, op control.UserOperation, method string) (Reply, error) {
	if c.Self == nil || c.Self.Public != current.Key || current.User != op.Session.User || op.VerifyOriginal(c.Cluster) != nil || (method == "submit" && !sameSession(current, op.Session)) {
		return Reply{}, mydcp.ErrAdmission
	}
	body, err := requestBody(Request{Method: method, Operation: &op})
	if err != nil {
		return Reply{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *mydcp.Session) (Envelope, error) {
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
func retryLoginChallenge(ctx context.Context, target mydcp.Peer, exchange func(context.Context, mydcp.Peer) (Reply, mydcp.Peer, error)) (Reply, mydcp.Peer, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return Reply{}, target, err
		}
		reply, selected, err := exchange(ctx, target)
		var rejected *Error
		if attempt == 4 || reply.Ticket != nil || reply.Code != "not-leader" || !errors.As(err, &rejected) || rejected.Code != "not-leader" || rejected.Phase != mydcp.Completed {
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

func (c Client) loginChallenge(ctx context.Context, target mydcp.Peer, body []byte) (Reply, mydcp.Peer, error) {
	return retryLoginChallenge(ctx, target, func(ctx context.Context, peer mydcp.Peer) (Reply, mydcp.Peer, error) {
		return c.exchange(ctx, peer, func(*mydcp.Session) (Envelope, error) { return Envelope{Body: body}, nil }, true)
	})
}

// Login is a private-key login whose user key is held by this process. It is
// KeyLoginChallenge, KeyLoginProof signed with private, KeyLogin and
// access.ApproveSession in that order.
func (c Client) Login(ctx context.Context, target mydcp.Peer, username string, private ed25519.PrivateKey) (access.Session, error) {
	if len(private) != ed25519.PrivateKeySize {
		return access.Session{}, mydcp.ErrAdmission
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
		return mydcp.ErrAdmission
	}
	trusted := false
	for _, peer := range c.Peers {
		trusted = trusted || [32]byte(peer.Key) == session.Issuer
	}
	if !trusted || session.Schema != 1 || session.Cluster != c.Cluster || session.Key != c.Self.Public || session.IssuerEpoch != 1 || session.IssuedAt > now || session.ExpiresAt <= now || session.ExpiresAt-session.IssuedAt > access.MaxSessionSeconds || session.ExpiresAt <= session.IssuedAt || !ed25519.Verify(ed25519.PublicKey(session.Issuer[:]), access.SessionBytes(session), session.Signature) {
		return mydcp.ErrAdmission
	}
	if session.Approval != nil && session.Approval.VerifyBinding(session) != nil {
		return mydcp.ErrAdmission
	}
	return nil
}

func (c Client) Query(ctx context.Context, target mydcp.Peer, session access.Session, method, tenant string) (Reply, error) {
	if method == "tenant-storage" {
		return c.TenantStoragePage(ctx, target, session, tenant, "", "")
	}
	return c.query(ctx, target, session, Request{Method: method, Tenant: tenant})
}

// MemberPage returns at most eight entries with the same committed root CAS.
// A caller collecting multiple pages must reject a changed root revision.
func (c Client) MemberPage(ctx context.Context, target mydcp.Peer, session access.Session, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "members", After: after})
}

func (c Client) ResourcePage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "resources", Tenant: tenant, After: after})
}

// LifecyclePage reads one bounded metadata item. Readers joining pages must
// require the same LifecycleRootRevision rather than merging different views.
func (c Client) LifecyclePage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "lifecycles", Tenant: tenant, After: after})
}

// Combining definitions and maintenance summaries requires both
// RegistriesRootRevision and RegistryMaintenanceRootRevision to stay unchanged.
func (c Client) RegistryPage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "registries", Tenant: tenant, After: after})
}

// Combining pages requires the same ExternalRegistriesRootRevision.
func (c Client) ExternalRegistryPage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "external-registries", Tenant: tenant, After: after})
}

func (c Client) VolumeBackupPage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "volume-backups", Tenant: tenant, After: after})
}

func (c Client) VolumePage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "volumes", Tenant: tenant, After: after})
}

func (c Client) AppPage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "apps", Tenant: tenant, After: after})
}
func (c Client) AppOperation(ctx context.Context, target mydcp.Peer, session access.Session, tenant string, request control.AppOperationRequest) (Reply, error) {
	reply, err := c.query(ctx, target, session, Request{Method: "app-operation", Tenant: tenant, AppOperation: &request})
	if err != nil {
		return reply, err
	}
	v := reply.AppOperation
	if v == nil || v.Tenant != tenant || (request.Standalone == "" && v.App != request.App || request.Standalone != "" && v.Standalone != request.Standalone) || v.ID != request.ID || v.Found != (v.Operation != nil) || !v.Found && v.Current || v.Found && (v.Operation.ID != request.ID || v.Operation.Plan == ([32]byte{}) || v.Operation.Epoch == 0 || v.Operation.Submitter == "" || v.Deployment == "" || v.Revision == 0) {
		return Reply{}, mydcp.ErrAdmission
	}
	return reply, nil
}
func (c Client) AppUploadPage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "app-uploads", Tenant: tenant, After: after})
}
func (c Client) PlanApp(ctx context.Context, target mydcp.Peer, session access.Session, tenant string, request control.AppPlanRequest) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "app-plan", Tenant: tenant, AppPlan: &request})
}

func (c Client) NodeInvitation(ctx context.Context, target mydcp.Peer, session access.Session, node string) (membership.Invitation, error) {
	reply, err := c.query(ctx, target, session, Request{Method: "node-invitation", Node: node})
	if err != nil {
		return membership.Invitation{}, err
	}
	if reply.Invitation == nil {
		return membership.Invitation{}, mydcp.ErrAdmission
	}
	if err := c.verifyNodeInvitation(*reply.Invitation, node); err != nil {
		return membership.Invitation{}, err
	}
	return *reply.Invitation, nil
}

func (c Client) verifyNodeInvitation(inv membership.Invitation, node string) error {
	var source [32]byte
	trusted := false
	for _, peer := range c.Peers {
		if peer.ID == inv.Source.ID {
			source = [32]byte(peer.Key)
			// A pinned Unix management address is local to the CLI host and
			// cannot be the source's routable join address. The same pinned
			// identity signs that address; network pins retain exact matching.
			local := strings.HasPrefix(peer.Endpoint, "unix:///") && mydcp.ValidateManagementSocket(strings.TrimPrefix(peer.Endpoint, "unix://")) == nil
			trusted = local || peer.Endpoint == inv.Source.Endpoint
		}
	}
	if !trusted || inv.Target.ID != node || inv.Verify(c.Cluster, source) != nil {
		return mydcp.ErrAdmission
	}
	return nil
}

// QueryRequest sends one finite user query exactly as r is built, with the
// same session check and method allow list as the typed reads. It is for
// clients that select or page beyond those helpers (the web adapter); it
// adds no authority: mydcd checks every field as for the CLI.
func (c Client) QueryRequest(ctx context.Context, target mydcp.Peer, session access.Session, r Request) (Reply, error) {
	return c.query(ctx, target, session, r)
}

func (c Client) query(ctx context.Context, target mydcp.Peer, session access.Session, r Request) (Reply, error) {
	if c.Verify(session) != nil {
		return Reply{}, mydcp.ErrAdmission
	}
	method := r.Method
	if !nodeShellQuery(method) && method != "node-force-remove-plan" && method != "node-drain-plan" && method != "node-drain-status" && method != "node-diagnostics" && method != "node-demote-plan" && method != "node-remove-plan" && method != "lifecycle-source" && !control.PublicReadMethod(method) && method != "standalone-list" && method != "standalone-get" && method != "standalone-plan" && method != "volume-file-plan" && method != "volume-file-status" && method != "cd-probe" && method != "certificates" && method != "ingresses" && method != "tenant-storage" && method != "events" && method != "app-cd-toggle-plan" && method != "image-cache-plan" && method != "image-cache-status" && method != "tunnel-reconnect-plan" && method != "tunnel-reconnect-status" && method != "registry-action-plan" && method != "external-registry-bind-plan" && method != "registry-login-test" && method != "image-resolve" && method != "registry-maintenance-plan" && method != "registry-maintenance-status" && method != "image-usages" && method != "registry-catalog" && method != "registry-prune-preview" && method != "registry-prune-results" && method != "external-registry-pulls" && method != "raft-compact-plan" && method != "raft-compact-status" && method != "task-restart-plan" && method != "task-restart-status" && method != "raft-status" && method != "node-summary" && method != "node-disks" && method != "node-tenant-usage" && method != "mesh-links" && method != "app-source" && method != "app-revisions" && method != "tasks" && method != "my-credentials" && method != "users" && method != "tenant-members" && method != "app-log-clear-plan" && method != "app-log-clear-status" && method != "user-credentials" && method != "node-cli-policy" && method != "container-observe" && method != "tenant-retirement" && method != "whoami" && method != "tenants" && method != "select-tenant" && method != "members" && method != "node-invitation" && method != "node-storage" && method != "node-storage-space" && method != "resources" && method != "volumes" && method != "volume-backups" && method != "volume-restores" && method != "volume-usage" && method != "volume-backup-source" && method != "apps" && method != "app-operation" && method != "app-cd-field" && method != "app-cd-history" && method != "app-cd-diff" && method != "app-cd-registration" && method != "app-uploads" && method != "app-plan" && method != "vault" && method != "vault-approval-plan" && method != "vault-write-plan" && method != "lifecycles" && method != "registries" && method != "external-registries" && method != "image-builds" && method != "build-zip-transfer" && method != "check-build-context" && method != "build-context-content" && method != "image-build-cache" && method != "image-build-logs" && method != "image-build-job-plan" && method != "build-draft" && method != "save-build-git" {
		return Reply{}, fmt.Errorf("unsupported user query")
	}
	body, err := requestBody(r)
	if err != nil {
		return Reply{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *mydcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, method != "cd-probe") // Installed Git profiles stay on the explicitly selected provider.
	return reply, err
}

func (c Client) VolumeRestorePage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "volume-restores", Tenant: tenant, After: after})
}

// TenantRetirementPage is an authenticated system-admin observation, including
// a Deleted tombstone. It never creates or resumes a deletion.
func (c Client) TenantRetirementPage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "tenant-retirement", Tenant: tenant, After: after})
}
