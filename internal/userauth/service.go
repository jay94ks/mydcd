// SPDX-License-Identifier: Apache-2.0

// Package userauth is the SFCP user authentication adapter. It grants neither
// node membership nor legacy management rights to a user/session transport key.
package userauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/credentials"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/jay94ks/seafield/internal/loginlog"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/servicecall"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/vps"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type Ticket struct {
	Schema                                uint8
	Cluster                               [32]byte
	User, Username, Credential            string
	AccountRevision                       uint64
	SessionKey, UserKey, Challenge, Nonce [32]byte
	Issuer                                [32]byte
	IssuedAt, Deadline                    int64
	Signature                             []byte
	AuthMethod                            access.Method `json:",omitempty"`
	VerifierRef                           string        `json:",omitempty"`
}

func ticketBytes(t Ticket) []byte {
	t.Signature = nil
	b, _ := json.Marshal(t)
	return append([]byte("sfc-user-login-ticket-1\x00"), b...)
}

type Request struct {
	// Params is a typed method's request (methods.go). A typed method's
	// Request has nothing else but Schema, Method and Nonce.
	Params            json.RawMessage             `json:",omitempty"`
	Standalone        *control.StandaloneQuery    `json:",omitempty"`
	AppCDRead         *control.AppCDReadRequest   `json:",omitempty"`
	InitialCredential *credentials.InitialRequest `json:",omitempty"`
	CDToggle          *control.CDToggleQuery      `json:",omitempty"`
	AppSource         *control.AppSourceSelection `json:",omitempty"`
	TaskRestart       *control.TaskRestartQuery   `json:",omitempty"`
	Container         *containerops.Query         `json:",omitempty"`
	Schema            uint8
	Method            string
	UserKey           [32]byte               `json:",omitempty"`
	Tenant            string                 `json:",omitempty"`
	After             string                 `json:",omitempty"`
	Node              string                 `json:",omitempty"`
	Operation         *control.UserOperation `json:",omitempty"`
	Enrollment        *control.Enrollment    `json:",omitempty"`
	Nonce             [32]byte
	Secret            []byte                        `json:",omitempty"`
	AppPlan           *control.AppPlanRequest       `json:",omitempty"`
	AppOperation      *control.AppOperationRequest  `json:",omitempty"`
	AppCDField        *control.AppCDFieldRequest    `json:",omitempty"`
	AppCDApproval     *control.AppCDApprovalRequest `json:",omitempty"`
	AppInput          *AppPlanInput                 `json:",omitempty"`
}
type Envelope struct {
	Body      []byte
	Session   *access.Session `json:",omitempty"`
	Signature []byte          `json:",omitempty"`
	Relay     *Relay          `json:",omitempty"`
}

// envelopeWire carries Body as itself, not base64 (design O4).
type envelopeWire struct {
	Body      json.RawMessage
	Session   *access.Session `json:",omitempty"`
	Signature []byte          `json:",omitempty"`
	Relay     *Relay          `json:",omitempty"`
}

func (e Envelope) MarshalJSON() ([]byte, error) {
	body, err := sfcp.RawBody(e.Body)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelopeWire{body, e.Session, e.Signature, e.Relay})
}

func (e *Envelope) UnmarshalJSON(raw []byte) error {
	var w envelopeWire
	if err := sfcp.StrictJSON(raw, &w); err != nil {
		return err
	}
	*e = Envelope{Body: bytes.Clone(w.Body), Session: w.Session, Signature: w.Signature, Relay: w.Relay}
	return nil
}

type UserView struct {
	ID, Username string
	Revision     uint64
	SystemAdmin  bool
}
type TenantView struct {
	ID           string
	Revision     uint64
	Role         access.Role
	AllowedNodes []string
}
type Reply struct {
	// Data is a typed method's reply (methods.go).
	Data                    json.RawMessage                  `json:",omitempty"`
	Certificate             *certstore.Certificate           `json:",omitempty"`
	VPSCredential           *vps.SealedCredential            `json:",omitempty"`
	Standalones             []control.StandaloneView         `json:",omitempty"`
	StandaloneNext          string                           `json:",omitempty"`
	StandaloneExtension     *control.StandaloneExtensionPlan `json:",omitempty"`
	StandaloneExtensionCode string                           `json:",omitempty"`
	InitialCredentialFact   *credentials.InitialFact         `json:",omitempty"`
	// InitialCredentialProfile is the provider a server uses when the
	// caller names none: its installed external Vault, else builtin.
	InitialCredentialProfile string                             `json:",omitempty"`
	InitialCredentialToken   []byte                             `json:",omitempty"`
	CDTogglePlan             *control.CDTogglePlan              `json:",omitempty"`
	OperationReason          *control.OperationReason           `json:",omitempty"`
	RaftStatus               *RaftStatus                        `json:",omitempty"`
	AppSource                *control.AppSourcePart             `json:",omitempty"`
	AppRevisions             []control.AppRevisionView          `json:",omitempty"`
	AppRevisionsNext         string                             `json:",omitempty"`
	AppRevisionsRootRevision uint64                             `json:",omitempty"`
	TaskRestartPlan          *control.TaskRestartPlan           `json:",omitempty"`
	TaskRestartStatus        *control.TaskRestartStatus         `json:",omitempty"`
	Container                *containerops.Result               `json:",omitempty"`
	ContainerViewIndex       uint64                             `json:",omitempty"`
	AppCDRegistration        *control.AppCDApprovalRegistration `json:",omitempty"`
	AppCDField               *control.AppCDField                `json:",omitempty"`
	AppCDHistory             *control.AppCDHistoryPage          `json:",omitempty"`
	AppCDSnapshot            *control.AppCDSnapshotPart         `json:",omitempty"`
	Schema                   uint8
	Code                     string
	InputCode                string       `json:",omitempty"`
	Node                     string       `json:",omitempty"`
	RelayedBy                string       `json:",omitempty"`
	SessionIssuer            *config.Peer `json:",omitempty"`
	Leader                   string       `json:",omitempty"`
	User                     *UserView    `json:",omitempty"`
	Tenant                   string       `json:",omitempty"`
	RootRevision             uint64
	Result                   *state.Result             `json:",omitempty"`
	Found                    bool                      `json:",omitempty"`
	ImageBuildRootRevision   uint64                    `json:",omitempty"`
	ModuleEpoch              uint64                    `json:",omitempty"`
	AppsRootRevision         uint64                    `json:",omitempty"`
	AppRevision              uint64                    `json:",omitempty"`
	Apps                     []control.AppView         `json:",omitempty"`
	AppsNext                 string                    `json:",omitempty"`
	Uploads                  []control.AppUploadView   `json:",omitempty"`
	UploadsNext              string                    `json:",omitempty"`
	AppPlan                  *control.AppPlanPart      `json:",omitempty"`
	AppOperation             *control.AppOperationView `json:",omitempty"`
	VaultObservation         *secrets.WriteObservation `json:",omitempty"`
	VaultApproval            *secrets.Approval         `json:",omitempty"`
}

// lenient decodes a reply from sfcd: one JSON value, unknown fields
// ignored. Within a major sfcd may add reply fields in any release, and an
// older CLI or sfc-web skips the ones it does not know (Jay 2026-11-28
// 10:01 KST, devel/design/upgrades.md 3-3 rule 8a). Requests and signed or
// stored values stay strict.
func lenient(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return sfcp.ErrFrame
	}
	return nil
}

func strict(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return sfcp.ErrFrame
	}
	b, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, b) {
		return sfcp.ErrFrame
	}
	return nil
}

type Service struct {
	// Changes, when set, serves change watches (purpose ChangeWatch).
	Changes *ChangeFeed
	// Events, when set, carries the event topics a change watch may add.
	Events              *eventbus.Bus
	CertificateWriter   func(context.Context, access.Session, CertificateInput) (certstore.Certificate, error)
	VPSCredentialSealer func(context.Context, access.Session, VPSCredentialInput) (vps.SealedCredential, error)
	// VPSOfferReader reads an account's live catalogue (voters only).
	VPSOfferReader func(context.Context, access.Session, control.VPSOfferQuery) (control.VPSOffer, error)
	// VPSStatusReader reads the leader's live VPS cost watch.
	VPSStatusReader func(context.Context) (control.VPSStatus, error)
	// ClusterBackupMaster returns this voter's cluster master key for a
	// cluster backup; the caller clears it.
	ClusterBackupMaster   func() ([]byte, error)
	IngressObserver       func(context.Context, control.IngressRead) (control.IngressPage, error)
	ServiceCaller         func(context.Context, control.ServiceCallRead) (servicecall.Result, error)
	ServiceCallLimiter    *servicecall.Limiter
	CDProber              func(context.Context, control.CDProbeRead) (deployment.GitProbeResult, error)
	VolumeFiles           VolumeFileRunner
	DNSObserver           func(context.Context, control.NetworkDNSTarget) (control.DNSPolicyView, error)
	NetworkObserver       func(context.Context, control.NetworkReadTarget) (control.NetworkClosureStatus, error)
	NodeDrainPlanner      func(context.Context, cluster.View, access.Session, int64, control.NodeDrainQuery) (control.NodeDrainPlan, error)
	NodeDiagnostics       func(context.Context, control.NodeDiagnosticsRead) (control.NodeDiagnosticsBundle, error)
	NodeLogs              func(context.Context, control.NodeLogsRead) (control.NodeLogsPage, error)
	NodeDiskChanger       func(context.Context, control.NodeDiskRead) (control.NodeDiskResult, error)
	LogsClearer           func(context.Context, access.Session, control.LogsClear) ([]control.LogsClearNode, error)
	StoredLogsReader      func(context.Context, access.Session, control.StoredLogsQuery) ([]control.StoredLogsNode, error)
	NodeFirewall          func(context.Context, control.NodeFirewallRead) (control.NodeFirewallResult, error)
	NodeForceProbe        func(context.Context, cluster.View, control.NodeForcePlan) (lifecycle.RemovalProbe, error)
	ImageBuildDraft       func(context.Context, control.ImageBuildDraftCall) (imagebuild.DraftResponse, error)
	ImageBuildGit         func(context.Context, control.ImageBuildGitCall) (imagebuild.GitSaveResponse, error)
	ImageBuildSource      func(context.Context, control.ImageBuildSourceRead) (control.ImageBuildSourceResult, error)
	ImageBuildContent     func(context.Context, control.ImageBuildContentRead) (control.ImageBuildContentPage, error)
	ImageBuildCache       func(context.Context, control.ImageBuildCacheRead) (control.ImageBuildCachePage, error)
	ImageBuildCaches      func(context.Context, access.Session, string, control.ImageBuildQuery, string) (control.ImageBuildPage, error)
	ImageBuildLogs        func(context.Context, control.ImageBuildLogRead) (control.ImageBuildLogPage, error)
	ImageBuildTransfer    func(context.Context, cluster.View, control.ImageBuildIOCall) (control.ImageBuildIOResult, error)
	ImageContent          func(context.Context, control.ImageContentRead) (ImageContentSource, error)
	ImageBuildBaseContent func(context.Context, control.ImageBuildBaseContentRead) (ImageContentSource, error)
	RegistryCatalog       func(context.Context, control.RegistryCatalogueRead) (control.RegistryCatalogueResult, error)
	RegistryPrune         func(context.Context, control.RegistryPruneRead, bool) (control.RegistryPruneView, error)

	EventReader func(context.Context, cluster.View, access.Session, eventlog.Query) (eventlog.Page, error)
	// LoginRecorder keeps one judged login on this node (loginlog); it runs
	// on the login path. LoginRecords reads a user's records cluster-wide.
	LoginRecorder    func(loginlog.Record)
	LoginRecords     func(context.Context, cluster.View, access.Session, loginlog.Query) (loginlog.Page, error)
	NodeObservations NodeObservations
	// WantObservations keeps every server's node observations arriving
	// while a watch on report events is open (node-observation-topics.md
	// 2: web and AI readers). Nil when the node has no Topic channel.
	WantObservations       func() (release func())
	NodeShellLifetime      context.Context
	NodeShellOpen          func(context.Context, string) (NodeShellStream, error)
	ContainerLifetime      context.Context
	ContainerPlanner       func(context.Context, control.ContainerSessionPlan) (containerops.Target, error)
	ContainerRunner        func(context.Context, access.Session, containerops.SessionIntent, *ContainerChannel) error
	ContainerExecObserver  func(context.Context, access.Session, containerops.SessionIntent) (containerops.ExecStatus, error)
	ImageCachePlanner      func(context.Context, control.ImageCacheRead) (imagecache.Plan, error)
	ContainerObserver      func(context.Context, control.ContainerRead) (containerops.Result, error)
	ImageResolver          func(context.Context, control.ImageResolveRead) (control.ImageResolveResult, error)
	ExternalRegistryProber func(context.Context, control.ExternalRegistryProbeRead) (json.RawMessage, error)
	Engine                 *cluster.Engine
	Mesh                   *sfcp.Transport
	Self                   *identity.Identity
	Policy                 control.Policy
	// Optional committed policy gate for an existing static root. No credential
	// provider or streaming adapter may run before its activation boundary.
	Enabled               func(state.State) bool
	Credentials           *credentials.Backend
	LifecycleSourceReader func(context.Context, control.LifecycleSourceRead) (checker.SourcePage, error)
	CheckerSources        SourceArtifacts
	VaultWriter           func(context.Context, access.Session, SecretRequest) (secrets.WriteObservation, error)
	VaultApprover         func(context.Context, access.Session, SecretRequest, string) (secrets.Approval, error)
	VolumeObserver        func(context.Context, volumes.NativeReady) (volumes.Usage, error)
	VolumeSourceObserver  func(context.Context, volumes.NativeReady) (control.VolumeBackupSource, error)
	VolumeMoveObserver    func(context.Context, volumes.NativeReady) (control.VolumeMoveRecipe, error)
	NodeStorageObserver   func(context.Context, nodestorage.Root) (nodestorage.Space, error)
}

func (s Service) Serve() error {
	if s.Engine == nil || s.Mesh == nil || s.Self == nil || s.Self.Public != [32]byte(s.Mesh.LocalKey()) || s.Policy.Cluster == ([32]byte{}) {
		return sfcp.ErrAdmission
	}
	if err := s.Mesh.OnManagement(sfcp.User, s.handle); err != nil {
		return err
	}
	if err := s.Mesh.OnManagement(sfcp.NodeShell, s.handleNodeShell); err != nil {
		return err
	}
	if err := s.Mesh.OnManagement(sfcp.ClusterBackup, s.handleClusterBackup); err != nil {
		return err
	}
	if s.VolumeFiles != nil {
		if err := s.Mesh.OnManagement(sfcp.VolumeFile, s.handleVolumeFile); err != nil {
			return err
		}
	}
	if s.ImageContent != nil || s.ImageBuildBaseContent != nil {
		if err := s.Mesh.OnManagement(sfcp.ImageContent, s.handleImageContent); err != nil {
			return err
		}
	}
	if s.ContainerPlanner != nil || s.ContainerRunner != nil || s.ContainerExecObserver != nil {
		if err := s.Mesh.OnManagement(sfcp.ContainerSession, s.handleContainerSession); err != nil {
			return err
		}
	}
	if s.Changes != nil {
		if err := s.Mesh.OnManagement(sfcp.ChangeWatch, s.handleChangeWatch); err != nil {
			return err
		}
	}
	if s.VaultWriter != nil || s.VaultApprover != nil || s.CertificateWriter != nil {
		return s.Mesh.OnManagement(sfcp.SecretInput, s.secretInput)
	}
	return nil
}

func (s Service) handle(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
	if frame.Kind != 1 && frame.Kind != 3 {
		return sfcp.ErrFrame
	}
	digest := sha256.Sum256(frame.Fields[0].Value)
	if !bytes.Equal(digest[:], frame.Fields[1].Value) {
		return sfcp.ErrFrame
	}
	var envelope Envelope
	var request Request
	if strict(frame.Fields[0].Value, &envelope) != nil || strict(envelope.Body, &request) != nil || request.Schema != 1 || request.Nonce == ([32]byte{}) {
		return sfcp.ErrFrame
	}
	credentialRequest := request.credentialRequest()
	if credentialRequest || request.Secret != nil {
		defer clear(request.Secret)
		defer clear(request.Params)
		defer clear(envelope.Body)
		defer clear(frame.Fields[0].Value)
	}
	// Finite RPCs send their write EOF before receiving the result. Consume
	// it before even an early denial: otherwise the QUIC handler can return
	// and STOP_SENDING before the client sends FIN, losing a valid reply at
	// send-eof. It also prevents trailing bytes from accompanying an effect.
	// These input streams negotiate continue before their body/EOF.
	if request.Method != "lifecycle-source-stage" && request.Method != "lifecycle-module-stage" && request.Method != "service-call" && request.Method != "app-plan-stream" && request.Method != "checker-source-stage" && request.Method != "checker-module-stage" {
		if err := streamEOF(stream); err != nil {
			return err
		}
	}
	// This finite, sessionless query identifies this responding daemon, including
	// before enrollment or while quorum is unavailable. No relay or login grant
	// is accepted, and no cluster catalog is read for this public metadata.
	if request.Method == ServerVersionMethod.Name {
		if _, ok := paramsOf(request, ServerVersionMethod); !ok || frame.Kind != 1 || envelope.Session != nil || envelope.Relay != nil || len(envelope.Signature) != 0 {
			return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
		}
		if _, err := s.binding(conn, frame.Kind, envelope); err != nil {
			return err
		}
		v := localServerVersion()
		v.Features, v.ClusterFeatures = buildinfo.Own.Names(), s.Engine.ClusterFeatures().Names()
		return s.respond(stream, frame, digest, sessionlessReply(v))
	}
	if s.Enabled != nil {
		local, err := s.Engine.Read(ctx, false)
		if err != nil || !s.Enabled(local.State) {
			return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
		}
	}
	if !request.validMethodFields() {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
	}
	if !request.validCredentialFields(envelope, frame.Kind) {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
	}
	keyLogin := request.Method == "challenge" || request.Method == "login"
	binding, err := s.relayBinding(conn, frame.Kind, envelope, keyLogin)
	if err != nil {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
	}
	if frame.Kind == 3 && request.Method == "enroll-admin" {
		return sfcp.ErrAdmission
	}

	local, err := s.Engine.Read(ctx, false)
	if err != nil {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "unavailable"})
	}
	catalog, err := s.Policy.Catalog(local.State)
	if err == nil && (keyLogin || request.Method == "credential-challenge" || request.Method == "credential-login") && !s.nodeLoginAllowed(local.State, catalog, "") {
		// A member that cannot issue sessions (a non-voter, such as a public
		// gateway that only takes connections) relays a private-key login to
		// the leader, which issues the session; the user's proof is bound to
		// the caller's key and this connection, so the relay learns nothing
		// it could reuse. A password or token is never relayed.
		if keyLogin && frame.Kind == 1 {
			return s.respond(stream, frame, digest, s.forwardLogin(ctx, local.State, envelope, binding))
		}
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "not-session-issuer"})
	}
	if err != nil || !s.nodeRequestAllowed(local.State, catalog, request, envelope) {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
	}

	if envelope.Relay != nil && envelope.Relay.ServiceCall != nil && request.Method != "service-call" {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "invalid"})
	}
	// A Git probe consumes credentials installed on this exact provider. It
	// must never become a leader relay with another node's local profiles.
	if request.Method == CDProbeMethod.Name && envelope.Relay != nil {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
	}
	if request.Method == "service-call" {
		return s.streamServiceCall(ctx, conn, stream, frame, digest, envelope, request, binding)
	}
	if request.lifecycleEditorRequest() {
		return s.streamLifecycleSource(ctx, conn, stream, frame, digest, envelope, request, binding)
	}
	if request.Method == "app-plan-stream" {
		return s.streamAppPlan(ctx, conn, stream, frame, digest, envelope, request, binding)
	}
	if request.initialCredentialRequest() {
		return s.handleInitialCredential(ctx, conn, stream, frame, digest, envelope, request, binding)
	}
	if request.checkerArtifactRequest() {
		return s.streamCheckerSource(ctx, conn, stream, frame, digest, envelope, request, binding)
	}
	reply := Reply{Schema: 1, Code: "denied"}
	if request.Method != "raft-status" && request.Method != CDProbeMethod.Name && !s.Engine.IsLeader() && frame.Kind == 1 && envelope.Session != nil {
		reply = s.forward(ctx, envelope, binding)
		return s.respond(stream, frame, digest, reply)
	}
	var view cluster.View
	if request.Method == "raft-status" {
		view, err = s.Engine.Read(ctx, false)
	} else if request.Method == "challenge" || request.Method == "login" || credentialRequest || request.Method == CDProbeMethod.Name {
		view, err = s.authenticationView(ctx)
	} else {
		view, err = s.Engine.Read(ctx, true)
	}
	if err == nil && s.Enabled != nil && !s.Enabled(view.State) {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
	}
	if err == nil {
		s.Policy, err = s.Policy.Current(view.State)
	}
	if err != nil {
		reply.Code = "unavailable"
		if !s.Engine.IsLeader() && request.Method != CDProbeMethod.Name {
			reply.Code = "not-leader"
			_, id := s.Engine.Leader()
			reply.Leader = string(id)
		}
	} else if catalog, err := s.Policy.Catalog(view.State); err == nil {
		if !s.nodeRequestAllowed(view.State, catalog, request, envelope) {
			return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
		}
		if request.Method == "enroll-admin" {
			reply = s.enroll(ctx, view, catalog, binding, request, envelope)
		} else if request.Enrollment != nil {
			reply.Code = "denied"
		} else if request.Method == "submit" || request.Method == "result" || request.Method == "resume" {
			reply = s.operation(ctx, view, catalog, binding, request, envelope)
			if reply.Code == "ok" && reply.Result != nil && request.Operation != nil && request.Operation.Reason != nil {
				reason := *request.Operation.Reason
				reply.OperationReason = &reason
			}
		} else if request.Operation == nil {
			if credentialRequest {
				source, sourceErr := conn.CredentialSource()
				if sourceErr == nil {
					reply = s.credential(ctx, catalog, binding, request, envelope, source)
				}
			} else if keyLogin {
				reply = s.keyLogin(catalog, binding, request, envelope)
				if q, ok := paramsOf(request, LoginMethod); ok {
					source, _ := conn.CredentialSource()
					s.recordLogin(&q.Ticket, q.LoginClient, source, reply, "denied")
				}
			} else if _, typed := methodRules[request.Method]; typed && request.Method != CDProbeMethod.Name {
				reply = s.typedQuery(ctx, view, catalog, binding, request, envelope)
			} else {
				reply = s.execute(catalog, binding, request, envelope)
			}
			if reply.Code == "ok" && request.Method == "app-cd-toggle-plan" {
				reply = s.cdTogglePlan(view, request, *envelope.Session)
			}
			if reply.Code == "ok" && (request.Method == "standalone-list" || request.Method == "standalone-get") {
				rows, next, err := s.Policy.StandalonePage(view.State, *envelope.Session, time.Now().Unix(), request.Tenant, request.Standalone.Name, request.After)
				if err != nil {
					reply = Reply{Schema: 1, Code: "denied"}
				} else {
					reply.Standalones, reply.StandaloneNext = rows, next
					reply.AppsRootRevision = view.State.Object(control.AppsKey).Revision
				}
			}
			if reply.Code == "ok" && request.Method == CDProbeMethod.Name {
				reply = s.cdProbeReply(ctx, view, *envelope.Session, request)
			}
			if reply.Code == "ok" && request.Method == "raft-status" {
				reply = s.raftStatusReply(ctx, view, *envelope.Session, request.After)
			}
			if reply.Code == "ok" && (request.Method == "app-source" || request.Method == "app-revisions") {
				reply = s.appSourceQueryReply(view, *envelope.Session, request)
			}
			if reply.Code == "ok" && (request.Method == "task-restart-plan" || request.Method == "task-restart-status") {
				reply = s.taskRestartQuery(view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "container-observe" {
				reply = s.containerObservation(ctx, view, request, *envelope.Session)
			}

			if reply.Code == "ok" && (request.Method == "app-cd-history" || request.Method == "app-cd-diff") {
				reply = s.appCDReadReply(view, *envelope.Session, request)
			}
			if reply.Code == "ok" && request.Method == "app-cd-field" {
				field, err := s.Policy.AppDeliveryField(view.State, catalog, envelope.Session.User, request.Tenant, *request.AppCDField)
				if err != nil {
					reply = Reply{Schema: 1, Code: "denied"}
				} else {
					reply.AppCDField = &field
				}
			}
			if reply.Code == "ok" && request.Method == "app-cd-registration" {
				registration, err := s.Policy.AppDeliveryApprovalRegistration(view.State, *envelope.Session, time.Now().Unix(), request.Tenant, *request.AppCDApproval)
				if err != nil {
					reply = Reply{Schema: 1, Code: "denied"}
				} else {
					reply.AppCDRegistration = &registration
				}
			}
			if reply.Code == "ok" && (request.Method == "apps" || request.Method == "app-operation" || request.Method == "app-uploads") {
				reply = s.appsQueryReply(view, catalog, *envelope.Session, request, reply)
				if reply.Code == "ok" && reply.AppOperation != nil && len(reply.AppOperation.Waiting) > 0 {
					reply.AppOperation.Waiting = append(reply.AppOperation.Waiting, s.tunnelWaits(ctx, view, request.Tenant)...)
				}
			}
			if reply.Code == "ok" && (request.Method == "app-plan" || request.Method == "standalone-plan") {
				part, err := s.Policy.PlanApp(view.State, *envelope.Session, time.Now().Unix(), request.Tenant, *request.AppPlan)
				if err == nil {
					reply.AppPlan = &part
				} else {
					reply = appPlanErrorReply(err)
				}
			}
		}
		if reply.RootRevision == 0 {
			reply.RootRevision = view.State.Object(control.CatalogKey).Revision
		}
	}
	return s.respond(stream, frame, digest, reply)
}

func (s Service) respond(stream sfcp.Stream, frame sfcp.Frame, digest [32]byte, reply Reply) error {
	if reply.Node == "" {
		reply.Node = s.Self.Actor()
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	defer clear(raw)
	return sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.User, Kind: 2, Request: frame.Request, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}})
}

func (s Service) operation(ctx context.Context, view cluster.View, c access.Catalog, binding userBinding, r Request, envelope Envelope) (reply Reply) {
	reply = Reply{Schema: 1, Code: "denied"}
	defer func() {
		if r.Operation != nil {
			addStandaloneExtensionOutcome(&reply, *r.Operation)
		}
	}()
	if r.Operation == nil || envelope.Session == nil || r.UserKey != ([32]byte{}) || r.Tenant != "" || r.After != "" || r.Node != "" {
		return reply
	}
	op := *r.Operation

	command, err := op.Command()
	current := *envelope.Session
	if err != nil || current.User != op.Session.User || current.Key != binding.key || access.VerifyRequest(current, binding.challenge, envelope.Body, envelope.Signature) != nil {
		return reply
	}
	if r.Method == "result" {
		if sameSession(current, op.Session) && op.SelfLogout() {
			_, err = s.Policy.Operation(c, command, true)
		} else {
			err = c.VerifySession(current, s.Policy.Cluster, s.Policy.Issuer(current.Issuer), time.Now().Unix())
		}
		if err != nil || op.VerifyOriginal(s.Policy.Cluster) != nil {
			return reply
		}
		result, found := view.State.LookupResult(command)
		reply.Code, reply.Found = "ok", found
		if found {
			reply.Result = &result
		} else if view.State.ModuleExpired(command) {
			reply.Code = "expired"
		}
		return reply
	}
	if r.Method == "resume" {
		now := time.Now().Unix()
		if op.VerifyOriginal(s.Policy.Cluster) != nil || op.At > now || s.Policy.AuthorizeResume(view.State, c, op, current, now) != nil {
			return reply
		}
		if result, found := view.State.LookupResult(command); found {
			return Reply{Schema: 1, Code: "ok", Found: true, Result: &result}
		}
		if view.State.ModuleExpired(command) {
			return Reply{Schema: 1, Code: "expired"}
		}
		// Missing is uncertain; the caller explicitly authorized replay of the
		// SAME immutable command, never a new actor/ID/CAS or automatic retry.
		if _, err = s.Policy.Operation(c, command, false); err != nil {
			return reply
		}
	} else {
		if !sameSession(current, op.Session) {
			return reply
		}
		if _, err = s.Policy.Operation(c, command, false); err != nil {
			return reply
		}
		now := time.Now().Unix()
		if op.At > now || now-op.At > 300 || c.VerifySession(op.Session, s.Policy.Cluster, s.Policy.Issuer(op.Session.Issuer), now) != nil {
			return reply
		}
	}
	if view.State.ModuleExpired(command) {
		if result, found := view.State.LookupResult(command); found {
			return Reply{Schema: 1, Code: "ok", Found: true, Result: &result}
		}
		return Reply{Schema: 1, Code: "expired"}
	}
	if result, found := view.State.LookupResult(command); found {
		return Reply{Schema: 1, Code: "ok", Found: true, Result: &result}
	}
	if s.Policy.CheckAppSubmission(view.State, op) != nil {
		return reply
	}
	if err := s.Policy.CheckStandaloneExtensionSubmission(view.State, op, time.Now().Unix()); err != nil {
		if errors.Is(err, control.ErrStandaloneExtensionExpired) {
			reply.Code = "conflict"
			reply.StandaloneExtensionCode = "STANDALONE_TTL_EXPIRED"
		}
		return reply
	}
	if op.Change.Action == "force-remove-node" {
		var force control.NodeForceChange
		decoded, decodeErr := schema.Decode[control.NodeForceChange](op.Change.Payload)
		if decodeErr != nil {
			return reply
		}
		force = decoded
		now := time.Now().Unix()
		if !force.Probe.Valid() || force.Probe.FinishedAt > now || now-force.Probe.FinishedAt > 30 {
			return Reply{Schema: 1, Code: "conflict"}
		}
	}
	committed, err := s.Engine.Submit(ctx, command)
	if err != nil {
		reply.Code = "unavailable"
		if errors.Is(err, cluster.ErrUnknown) {
			reply.Code = "unknown"
		}
		return reply
	}
	if committed.Result.Code == state.Expired {
		return Reply{Schema: 1, Code: "expired"}
	}
	if committed.Result.Code == state.LedgerFull {
		return Reply{Schema: 1, Code: "ledger-full"}
	}
	return Reply{Schema: 1, Code: "ok", RootRevision: committed.Result.Revision, Result: &committed.Result, Found: true}
}

func (s Service) execute(c access.Catalog, binding userBinding, r Request, envelope Envelope) Reply {
	reply := Reply{Schema: 1, Code: "denied"}
	if !r.validQuerySelectors() {
		return reply
	}
	now := time.Now().Unix()
	if envelope.Session == nil || r.UserKey != ([32]byte{}) {
		return reply
	}
	session := *envelope.Session
	policy := s.Policy.Issuer(session.Issuer)
	if session.Key != binding.key || c.VerifySession(session, s.Policy.Cluster, policy, now) != nil || access.VerifyRequest(session, binding.challenge, envelope.Body, envelope.Signature) != nil {
		return reply
	}
	switch r.Method {
	case "service-call", "cd-probe":
		action, tenant := access.CallService, ""
		if q, ok := paramsOf(r, CDProbeMethod); ok {
			action, tenant = access.Deploy, q.Tenant
		} else if call, ok := r.serviceCall(); ok {
			tenant = call.Tenant
		} else {
			return reply
		}
		if tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, tenant, action, "") != nil || c.OperationAllowed(session, r.Method) != nil {
			return reply
		}
		return Reply{Schema: 1, Code: "ok"}
	case "lifecycle-source-stage", "lifecycle-module-stage", "lifecycle-source-recover", "lifecycle-module-recover":
		recover := recoverMethod(r.Method)
		q, ok := r.checkerStage()
		if !ok {
			return reply
		}
		var err error
		if recover {
			err = c.AuthorizeSessionCleanup(session, s.Policy.Cluster, policy, now, q.Tenant, access.ManageServices)
		} else {
			err = c.AuthorizeSession(session, s.Policy.Cluster, policy, now, q.Tenant, access.ManageServices, "")
		}
		if err != nil || !recover && c.OperationAllowed(session, "lifecycle-source-upload") != nil {
			return reply
		}
		return Reply{Schema: 1, Code: "ok"}
	case "standalone-list", "standalone-get":
		if r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil {
			return reply
		}
		return Reply{Schema: 1, Code: "ok", Tenant: r.Tenant}
	case "app-cd-toggle-plan", "task-restart-plan", "task-restart-status", "raft-status", "app-source", "app-revisions", "container-observe", "apps", "app-operation", "app-cd-field", "app-cd-history", "app-cd-diff", "app-cd-registration", "app-uploads", "app-plan", "standalone-plan", "app-plan-stream":
		if r.Method == "raft-status" {
			if c.AuthorizeSession(session, s.Policy.Cluster, policy, now, "", access.ManageCluster, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "app-source" || r.Method == "app-revisions" {
			if r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "task-restart-plan" || r.Method == "task-restart-status" {
			if r.TaskRestart == nil || !r.TaskRestart.Valid(r.Method == "task-restart-plan") || r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil {
				return reply
			}
		}
		if r.Method == "container-observe" && (r.Container == nil || r.Container.Validate() != nil || r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil) {
			return reply
		}
		if r.Method == "app-cd-toggle-plan" {
			if r.Tenant == "" || r.CDToggle == nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "volumes" {
			if r.Tenant == "" {
				if c.AuthorizeSession(session, s.Policy.Cluster, policy, now, "", access.ManageCluster, "") != nil {
					return reply
				}
			} else if c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil {
				return reply
			}
		}

		if r.Method == "apps" || r.Method == "app-operation" || (r.Method == "app-cd-field" || r.Method == "app-cd-history" || r.Method == "app-cd-diff") || r.Method == "app-cd-registration" || r.Method == "app-uploads" || r.Method == "app-plan" || r.Method == "standalone-plan" || r.Method == "app-plan-stream" {
			action := access.Read
			if r.Method != "apps" && r.Method != "app-operation" && r.Method != "app-cd-field" && r.Method != "app-cd-history" && r.Method != "app-cd-diff" && r.Method != "app-cd-registration" {
				action = access.Deploy
			}
			if r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, action, "") != nil {
				return reply
			}
		}
		if r.Tenant != "" && r.Method != "task-restart-plan" && r.Method != "task-restart-status" && r.Method != "container-observe" && r.Method != "apps" && r.Method != "app-operation" && r.Method != "app-cd-field" && r.Method != "app-cd-history" && r.Method != "app-cd-diff" && r.Method != "app-cd-registration" && r.Method != "app-uploads" && r.Method != "app-plan" && r.Method != "standalone-plan" && r.Method != "app-plan-stream" {
			return reply
		}
		u, _ := c.User(session.User)
		reply = Reply{Schema: 1, Code: "ok", User: &UserView{u.ID, u.Username, u.Revision, u.SystemAdmin}, Tenant: r.Tenant}
	default:
		reply.Code = "unsupported"
	}
	return reply
}

var ErrPrivateState = errors.New("invalid or unavailable private user session state")

// ErrSessionExpired is a saved login that was valid but has expired. Only
// a new login renews it; nothing is refreshed silently.
var ErrSessionExpired = errors.New("your login has expired; run 'sfcli login'")
