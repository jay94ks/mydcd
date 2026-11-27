// SPDX-License-Identifier: Apache-2.0

// Package userauth is the SFCP user authentication adapter. It grants neither
// node membership nor legacy management rights to a user/session transport key.
package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
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
	Params                json.RawMessage                     `json:",omitempty"`
	ServiceCall           *servicecall.Request                `json:",omitempty"`
	ServiceInput          *ServiceCallInput                   `json:",omitempty"`
	CDProbe               *deployment.GitProbeRequest         `json:",omitempty"`
	Standalone            *control.StandaloneQuery            `json:",omitempty"`
	AppCDRead             *control.AppCDReadRequest           `json:",omitempty"`
	Events                *eventlog.Query                     `json:",omitempty"`
	InitialCredential     *credentials.InitialRequest         `json:",omitempty"`
	CDToggle              *control.CDToggleQuery              `json:",omitempty"`
	RegistryMaintenance   *control.RegistryMaintenanceQuery   `json:",omitempty"`
	RegistryPrune         *control.RegistryPruneQuery         `json:",omitempty"`
	ImageCache            *imagecache.Query                   `json:",omitempty"`
	RegistryCatalog       *control.RegistryCatalogueQuery     `json:",omitempty"`
	ImageUsage            *control.ImageUsageQuery            `json:",omitempty"`
	ImageResolve          *control.ImageResolveQuery          `json:",omitempty"`
	ExternalRegistryProbe *control.ExternalRegistryProbeQuery `json:",omitempty"`
	ExternalRegistryBind  *control.ExternalRegistryBindQuery  `json:",omitempty"`
	RegistryAction        *control.RegistryActionQuery        `json:",omitempty"`
	AppSource             *control.AppSourceSelection         `json:",omitempty"`
	TaskRestart           *control.TaskRestartQuery           `json:",omitempty"`
	LogClear              *control.AppLogClearQuery           `json:",omitempty"`
	TargetUser            string                              `json:",omitempty"`
	Container             *containerops.Query                 `json:",omitempty"`
	LoginQuery            *loginlog.Query                     `json:",omitempty"`
	Schema                uint8
	Method                string
	UserKey               [32]byte               `json:",omitempty"`
	Tenant                string                 `json:",omitempty"`
	After                 string                 `json:",omitempty"`
	Node                  string                 `json:",omitempty"`
	State                 string                 `json:",omitempty"`
	Operation             *control.UserOperation `json:",omitempty"`
	Enrollment            *control.Enrollment    `json:",omitempty"`
	Nonce                 [32]byte
	Secret                []byte                            `json:",omitempty"`
	AppPlan               *control.AppPlanRequest           `json:",omitempty"`
	AppOperation          *control.AppOperationRequest      `json:",omitempty"`
	AppCDField            *control.AppCDFieldRequest        `json:",omitempty"`
	AppCDApproval         *control.AppCDApprovalRequest     `json:",omitempty"`
	AppInput              *AppPlanInput                     `json:",omitempty"`
	VaultPlan             *control.VaultApprovalPlanRequest `json:",omitempty"`
	VaultWritePlan        *control.VaultWritePlanRequest    `json:",omitempty"`
	NodeStorage           *control.NodeStorageSelection     `json:",omitempty"`
	CheckerUpload         *[32]byte                         `json:",omitempty"`
	CheckerSource         *checker.SourceDescriptor         `json:",omitempty"`
	CheckerModule         *checker.ModulePin                `json:",omitempty"`
	Registry              *RegistryCredentialRequest        `json:",omitempty"`
	ImageBuild            *control.ImageBuildQuery          `json:",omitempty"`
	ImageBuildDraft       *imagebuild.DraftRequest          `json:",omitempty"`
	ImageBuildGit         *imagebuild.GitSaveRequest        `json:",omitempty"`
	ImageBuildTransfer    *imagebuild.Transfer              `json:",omitempty"`
	ImageBuildSource      *control.ImageBuildSourceQuery    `json:",omitempty"`
	ImageBuildContent     *imagebuild.ContentQuery          `json:",omitempty"`
	ImageBuildCache       *imagebuild.CacheQuery            `json:",omitempty"`
	ImageBuildLog         *imagebuild.LogQuery              `json:",omitempty"`
	ImageBuildJob         *control.ImageBuildJobQuery       `json:",omitempty"`
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
	Data                     json.RawMessage                  `json:",omitempty"`
	NodeShellPolicy          *control.NodeShellPolicyView     `json:",omitempty"`
	NodeShellSessions        *control.NodeShellSessionsPage   `json:",omitempty"`
	NodeShellRootRevision    uint64                           `json:",omitempty"`
	LifecycleStage           *LifecycleStageResult            `json:",omitempty"`
	TenantStorage            []control.TenantStorageRoot      `json:",omitempty"`
	TenantStorageNext        string                           `json:",omitempty"`
	TenantStorageViewIndex   uint64                           `json:",omitempty"`
	Certificate              *certstore.Certificate           `json:",omitempty"`
	CertificatesRootRevision uint64                           `json:",omitempty"`
	VPSCredential            *vps.SealedCredential            `json:",omitempty"`
	VPSRootRevision          uint64                           `json:",omitempty"`
	IngressRootRevision      uint64                           `json:",omitempty"`
	ServiceCall              *servicecall.Result              `json:",omitempty"`
	CDProbe                  *deployment.GitProbeResult       `json:",omitempty"`
	Standalones              []control.StandaloneView         `json:",omitempty"`
	StandaloneNext           string                           `json:",omitempty"`
	StandaloneExtension      *control.StandaloneExtensionPlan `json:",omitempty"`
	StandaloneExtensionCode  string                           `json:",omitempty"`
	Events                   *eventlog.Page                   `json:",omitempty"`
	LoginPage                *loginlog.Page                   `json:",omitempty"`
	LoginBudget              *LoginBudget                     `json:",omitempty"`
	OwnSessions              *loginlog.Page                   `json:",omitempty"`
	InitialCredentialFact    *credentials.InitialFact         `json:",omitempty"`
	// InitialCredentialProfile is the provider a server uses when the
	// caller names none: its installed external Vault, else builtin.
	InitialCredentialProfile        string                               `json:",omitempty"`
	InitialCredentialToken          []byte                               `json:",omitempty"`
	CDTogglePlan                    *control.CDTogglePlan                `json:",omitempty"`
	RegistryMaintenancePlan         *control.RegistryMaintenancePlan     `json:",omitempty"`
	RegistryMaintenanceStatus       *control.RegistryMaintenanceStatus   `json:",omitempty"`
	RegistryMaintenanceRootRevision uint64                               `json:",omitempty"`
	ImageCachePlan                  *imagecache.Plan                     `json:",omitempty"`
	ImageCacheStatus                *control.ImageCacheStatus            `json:",omitempty"`
	ImageCacheRootRevision          uint64                               `json:",omitempty"`
	TunnelRootRevision              uint64                               `json:",omitempty"`
	RegistryPulls                   *control.RegistryPullPage            `json:",omitempty"`
	RegistryCatalog                 *control.RegistryCatalogueResult     `json:",omitempty"`
	RegistryPrune                   *control.RegistryPruneView           `json:",omitempty"`
	ImageUsages                     *control.ImageUsagesPage             `json:",omitempty"`
	ImageResolve                    *control.ImageResolveResult          `json:",omitempty"`
	ExternalRegistryProbe           *control.ExternalRegistryProbeResult `json:",omitempty"`
	ExternalRegistryBindPlan        *control.ExternalRegistryBindPlan    `json:",omitempty"`
	RegistryActionPlan              *control.RegistryActionPlan          `json:",omitempty"`
	CompactRootRevision             uint64                               `json:",omitempty"`
	ClusterBackupRootRevision       uint64                               `json:",omitempty"`
	OperationReason                 *control.OperationReason             `json:",omitempty"`
	RaftStatus                      *RaftStatus                          `json:",omitempty"`
	AppSource                       *control.AppSourcePart               `json:",omitempty"`
	AppRevisions                    []control.AppRevisionView            `json:",omitempty"`
	AppRevisionsNext                string                               `json:",omitempty"`
	AppRevisionsRootRevision        uint64                               `json:",omitempty"`
	SelfCredentials                 *access.PublicUser                   `json:",omitempty"`
	Users                           []access.PublicUser                  `json:",omitempty"`
	UsersNext                       string                               `json:",omitempty"`
	UsersRevision                   uint64                               `json:",omitempty"`
	TenantMembers                   []access.TenantMember                `json:",omitempty"`
	TenantMembersNext               string                               `json:",omitempty"`
	TenantAllowedNodes              []string                             `json:",omitempty"`
	TenantRevision                  uint64                               `json:",omitempty"`
	TenantMembersRevision           uint64                               `json:",omitempty"`
	TaskRestartPlan                 *control.TaskRestartPlan             `json:",omitempty"`
	TaskRestartStatus               *control.TaskRestartStatus           `json:",omitempty"`
	LogClearPlan                    *control.AppLogClearPlan             `json:",omitempty"`
	LogClearStatus                  *control.AppLogClearStatus           `json:",omitempty"`
	CredentialUser                  *access.User                         `json:",omitempty"`
	NodeCLI                         *access.NodeCLIPolicy                `json:",omitempty"`
	Container                       *containerops.Result                 `json:",omitempty"`
	ContainerViewIndex              uint64                               `json:",omitempty"`
	TenantRetirement                *control.TenantRetirementStatus      `json:",omitempty"`
	AppCDRegistration               *control.AppCDApprovalRegistration   `json:",omitempty"`
	AppCDField                      *control.AppCDField                  `json:",omitempty"`
	AppCDHistory                    *control.AppCDHistoryPage            `json:",omitempty"`
	AppCDSnapshot                   *control.AppCDSnapshotPart           `json:",omitempty"`
	Schema                          uint8
	Code                            string
	InputCode                       string       `json:",omitempty"`
	Node                            string       `json:",omitempty"`
	RelayedBy                       string       `json:",omitempty"`
	SessionIssuer                   *config.Peer `json:",omitempty"`
	Leader                          string       `json:",omitempty"`
	User                            *UserView    `json:",omitempty"`
	Tenant                          string       `json:",omitempty"`
	RootRevision                    uint64
	Result                          *state.Result                   `json:",omitempty"`
	Found                           bool                            `json:",omitempty"`
	ExternalRegistriesRootRevision  uint64                          `json:",omitempty"`
	ExternalRegistries              []control.ExternalRegistryView  `json:",omitempty"`
	ExternalRegistriesNext          string                          `json:",omitempty"`
	RegistriesRootRevision          uint64                          `json:",omitempty"`
	ImageBuildRootRevision          uint64                          `json:",omitempty"`
	ImageBuild                      *control.ImageBuildPage         `json:",omitempty"`
	ImageBuildDraft                 *imagebuild.DraftResponse       `json:",omitempty"`
	ImageBuildGit                   *imagebuild.GitSaveResponse     `json:",omitempty"`
	ImageBuildIO                    *control.ImageBuildIOResult     `json:",omitempty"`
	ImageBuildSource                *control.ImageBuildSourceResult `json:",omitempty"`
	ImageBuildContent               *control.ImageBuildContentPage  `json:",omitempty"`
	ImageBuildCache                 *control.ImageBuildCachePage    `json:",omitempty"`
	ImageBuildLog                   *control.ImageBuildLogPage      `json:",omitempty"`
	ImageBuildJobPlan               *control.ImageBuildJobPlan      `json:",omitempty"`
	RegistriesRevision              uint64                          `json:",omitempty"`
	Registries                      []control.RegistryView          `json:",omitempty"`
	RegistriesNext                  string                          `json:",omitempty"`
	RegistryCredential              []byte                          `json:",omitempty"`
	RegistryAuthority               string                          `json:",omitempty"`
	RegistryCredentialExpires       int64                           `json:",omitempty"`
	CheckerSource                   *checker.SourceFact             `json:",omitempty"`
	CheckerModule                   *checker.ModuleFact             `json:",omitempty"`
	MembersRootRevision             uint64                          `json:",omitempty"`
	NodeLifecycle                   []membership.NodeView           `json:",omitempty"`
	NodeRuntimeRevision             uint64                          `json:",omitempty"`
	NodeOperationEpoch              uint64                          `json:",omitempty"`
	NodeConfigurationIndex          uint64                          `json:",omitempty"`
	NodeVoters                      int                             `json:",omitempty"`
	NodeQuorum                      int                             `json:",omitempty"`
	NodeStorageRootRevision         uint64                          `json:",omitempty"`
	NodeStorageRevision             uint64                          `json:",omitempty"`
	NodeStorage                     []nodestorage.Root              `json:",omitempty"`
	NodeStorageNext                 string                          `json:",omitempty"`
	NodeStorageSpace                *nodestorage.Space              `json:",omitempty"`
	NodeStorageObservedIndex        uint64                          `json:",omitempty"`
	Members                         []membership.Entry              `json:",omitempty"`
	MembersNext                     string                          `json:",omitempty"`
	Invitation                      *membership.Invitation          `json:",omitempty"`
	ModuleEpoch                     uint64                          `json:",omitempty"`
	LedgerRootRevision              uint64                          `json:",omitempty"`
	AppsRootRevision                uint64                          `json:",omitempty"`
	AppRevision                     uint64                          `json:",omitempty"`
	Apps                            []control.AppView               `json:",omitempty"`
	AppsNext                        string                          `json:",omitempty"`
	Uploads                         []control.AppUploadView         `json:",omitempty"`
	UploadsNext                     string                          `json:",omitempty"`
	AppPlan                         *control.AppPlanPart            `json:",omitempty"`
	AppOperation                    *control.AppOperationView       `json:",omitempty"`
	VaultRootRevision               uint64                          `json:",omitempty"`
	VaultRevision                   uint64                          `json:",omitempty"`
	VaultTreeRevision               uint64                          `json:",omitempty"`
	VaultWriteEpoch                 uint64                          `json:",omitempty"`
	VaultApprovalRevision           uint64                          `json:",omitempty"`
	Vault                           []control.VaultView             `json:",omitempty"`
	VaultNext                       string                          `json:",omitempty"`
	VaultObservation                *secrets.WriteObservation       `json:",omitempty"`
	VaultApproval                   *secrets.Approval               `json:",omitempty"`
	VaultWritePlan                  *control.VaultWritePlan         `json:",omitempty"`
	VaultPlan                       *control.VaultApprovalPart      `json:",omitempty"`
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
	LoginRecorder          func(loginlog.Record)
	LoginRecords           func(context.Context, cluster.View, access.Session, loginlog.Query) (loginlog.Page, error)
	NodeObservations       NodeObservations
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
		return s.respond(stream, frame, digest, sessionlessReply(localServerVersion()))
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
	if request.Method == "cd-probe" && envelope.Relay != nil {
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
	if request.Method != "raft-status" && request.Method != "cd-probe" && !s.Engine.IsLeader() && frame.Kind == 1 && envelope.Session != nil {
		reply = s.forward(ctx, envelope, binding)
		return s.respond(stream, frame, digest, reply)
	}
	var view cluster.View
	if request.Method == "raft-status" {
		view, err = s.Engine.Read(ctx, false)
	} else if request.Method == "challenge" || request.Method == "login" || credentialRequest || request.Method == "cd-probe" {
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
		if !s.Engine.IsLeader() && request.Method != "cd-probe" {
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
			} else if _, typed := methodRules[request.Method]; typed {
				reply = s.typedQuery(ctx, view, catalog, binding, request, envelope)
			} else {
				reply = s.execute(catalog, binding, request, envelope)
			}
			if reply.Code == "ok" && nodeShellQuery(request.Method) {
				reply = s.nodeShellQueryReply(view, *envelope.Session, request)
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
			if reply.Code == "ok" && request.Method == "events" {
				reply = s.eventQuery(ctx, view, *envelope.Session, *request.Events)
			}
			if reply.Code == "ok" && request.Method == "login-records" {
				reply = s.loginRecordsQuery(ctx, view, *envelope.Session, *request.LoginQuery)
			}
			if reply.Code == "ok" && request.Method == "own-sessions" {
				reply = s.ownSessions(ctx, view, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "image-build-job-plan" {
				now := time.Now().Unix()
				plan, err := s.Policy.ImageBuildJobPlan(view.State, *envelope.Session, now, request.Tenant, *request.ImageBuildJob)
				if err == nil && s.NodeObservations != nil {
					// The build server's own report, when fresh, can rule it out.
					if reports, rerr := s.NodeObservations(ctx, view); rerr == nil {
						err = s.Policy.CheckBuildNode(view.State, plan.Spec.Context.Root.Node, reports, now)
					}
				}
				if errors.Is(err, control.ErrBuildDisabled) {
					reply = Reply{Schema: 1, Code: "build-disabled"}
				} else if err != nil {
					reply = imageBuildError(err)
				} else {
					reply.ImageBuildJobPlan = &plan
				}
			}
			if reply.Code == "ok" && request.Method == "image-builds" {
				page, err := s.Policy.ImageBuildPage(view.State, *envelope.Session, time.Now().Unix(), request.Tenant, *request.ImageBuild, request.After)
				if err == nil && request.ImageBuild.Part == "caches" {
					if s.ImageBuildCaches == nil {
						err = imagebuild.ErrStorage
					} else {
						page, err = s.ImageBuildCaches(ctx, *envelope.Session, request.Tenant, *request.ImageBuild, request.After)
						if err == nil && (page.Tenant != request.Tenant || !control.ValidImageBuildCacheInventoryPage(page, *request.ImageBuild, request.After, true)) {
							err = imagebuild.ErrStorage
						}
					}
				}
				if err != nil {
					reply = imageBuildError(err)
				} else {
					reply.ImageBuild = &page
					reply.ImageBuildRootRevision = page.RootRevision
				}
			}
			if reply.Code == "ok" && request.Method == "image-build-cache" {
				read, err := s.Policy.ImageBuildCacheRead(view.State, *envelope.Session, time.Now().Unix(), request.Tenant, *request.ImageBuildCache, request.After)
				if err != nil {
					reply = imageBuildError(err)
				} else if s.ImageBuildCache == nil {
					reply = Reply{Schema: 1, Code: "unavailable"}
				} else {
					out, err := s.ImageBuildCache(ctx, read)
					if err != nil {
						reply = imageBuildError(err)
					} else if !out.Valid(read) {
						reply = Reply{Schema: 1, Code: "unavailable"}
					} else {
						reply.ImageBuildCache = &out
					}
				}
			}
			if reply.Code == "ok" && request.Method == "image-build-logs" {
				read, err := s.Policy.ImageBuildLogRead(view.State, *envelope.Session, time.Now().Unix(), request.Tenant, *request.ImageBuildLog, request.After)
				if err != nil {
					reply = imageBuildError(err)
				} else if s.ImageBuildLogs == nil {
					reply = Reply{Schema: 1, Code: "unavailable"}
				} else {
					out, err := s.ImageBuildLogs(ctx, read)
					if err != nil {
						reply = imageBuildError(err)
					} else if !out.Valid(read) {
						reply = Reply{Schema: 1, Code: "unavailable"}
					} else {
						reply.ImageBuildLog = &out
					}
				}
			}
			if reply.Code == "ok" && request.Method == "cd-probe" {
				if s.CDProber == nil {
					reply = Reply{Schema: 1, Code: "unavailable"}
				} else {
					out, err := s.CDProber(ctx, control.CDProbeRead{Session: *envelope.Session, Tenant: request.Tenant, Query: *request.CDProbe, Epoch: view.State.ModuleEpoch()})
					if err != nil {
						reply = imageBuildError(err)
					} else if !out.Valid() {
						reply = Reply{Schema: 1, Code: "unavailable"}
					} else {
						reply.CDProbe = &out
					}
				}
			}
			if reply.Code == "ok" && request.Method == "build-context-content" {
				read, err := s.Policy.ImageBuildContentRead(view.State, *envelope.Session, time.Now().Unix(), request.Tenant, *request.ImageBuildContent, request.After)
				if err != nil {
					reply = imageBuildError(err)
				} else if s.ImageBuildContent == nil {
					reply = Reply{Schema: 1, Code: "unavailable"}
				} else {
					out, err := s.ImageBuildContent(ctx, read)
					if err != nil {
						reply = imageBuildError(err)
					} else if !out.Valid(read) {
						reply = Reply{Schema: 1, Code: "unavailable"}
					} else {
						reply.ImageBuildContent = &out
					}
				}
			}
			if reply.Code == "ok" && request.Method == "check-build-context" {
				read, err := s.Policy.ImageBuildSourceRead(view.State, *envelope.Session, time.Now().Unix(), request.Tenant, *request.ImageBuildSource)
				if err != nil {
					reply = imageBuildError(err)
				} else if s.ImageBuildSource == nil {
					reply = Reply{Schema: 1, Code: "unavailable"}
				} else {
					out, err := s.ImageBuildSource(ctx, read)
					if err != nil {
						reply = imageBuildError(err)
					} else if !out.Valid(read) {
						reply = Reply{Schema: 1, Code: "unavailable"}
					} else {
						reply.ImageBuildSource = &out
					}
				}
			}
			if reply.Code == "ok" && request.Method == "save-build-git" {
				call := control.ImageBuildGitCall{Session: *envelope.Session, Tenant: request.Tenant, Request: *request.ImageBuildGit, At: time.Now().Unix()}
				if _, err := s.Policy.ImageBuildGitWork(view.State, call); err != nil {
					reply = imageBuildError(err)
				} else if s.ImageBuildGit == nil {
					reply = Reply{Schema: 1, Code: "unavailable"}
				} else {
					out, err := s.ImageBuildGit(ctx, call)
					if err != nil {
						reply = imageBuildError(err)
					} else if !out.Valid(call.Request) {
						reply = Reply{Schema: 1, Code: "unavailable"}
					} else {
						reply.ImageBuildGit = &out
					}
				}
			}
			if reply.Code == "ok" && request.Method == "build-draft" {
				call := control.ImageBuildDraftCall{Session: *envelope.Session, Tenant: request.Tenant, Request: *request.ImageBuildDraft, At: time.Now().Unix()}
				work, err := s.Policy.ImageBuildDraftWork(view.State, call)
				if err != nil {
					reply = imageBuildError(err)
				} else if s.ImageBuildDraft == nil {
					reply = Reply{Schema: 1, Code: "unavailable"}
				} else {
					out, err := s.ImageBuildDraft(ctx, call)
					if err != nil {
						reply = imageBuildError(err)
					} else if !out.Valid(call.Request) || out.Scope != work.Scope {
						reply = Reply{Schema: 1, Code: "unavailable"}
					} else {
						reply.ImageBuildDraft = &out
					}
				}
			}
			if reply.Code == "ok" && request.Method == "build-zip-transfer" {
				if s.ImageBuildTransfer == nil {
					reply = Reply{Schema: 1, Code: "unavailable"}
				} else {
					call := control.ImageBuildIOCall{Session: *envelope.Session, Tenant: request.Tenant, Request: *request.ImageBuildTransfer, At: time.Now().Unix()}
					out, err := s.ImageBuildTransfer(ctx, view, call)
					if err != nil {
						reply = imageBuildError(err)
					} else {
						reply.ImageBuildIO = &out
					}
				}
			}
			if reply.Code == "ok" && (request.Method == "image-cache-plan" || request.Method == "image-cache-status") {
				reply = s.imageCacheQuery(ctx, view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "registry-action-plan" {
				reply = s.registryActionPlan(view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "raft-status" {
				reply = s.raftStatusReply(ctx, view, *envelope.Session, request.After)
			}
			if reply.Code == "ok" && (request.Method == "app-source" || request.Method == "app-revisions") {
				reply = s.appSourceQueryReply(view, *envelope.Session, request)
			}
			if reply.Code == "ok" && request.Method == "tenant-retirement" {
				status, err := s.Policy.TenantRetirementStatus(view.State, request.Tenant, request.After)
				if err != nil {
					reply = Reply{Schema: 1, Code: "unavailable"}
				} else {
					reply.TenantRetirement = &status
				}
			}
			if reply.Code == "ok" && (request.Method == "registry-maintenance-plan" || request.Method == "registry-maintenance-status") {
				reply = s.registryMaintenanceQuery(view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "external-registry-pulls" {
				reply = s.registryPulls(ctx, view, request, *envelope.Session)
			}
			if reply.Code == "ok" && (request.Method == "registry-prune-preview" || request.Method == "registry-prune-results") {
				reply = s.registryPruneQuery(ctx, view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "registry-catalog" {
				reply = s.registryCatalog(ctx, view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "image-usages" {
				reply = s.imageUsages(view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "image-resolve" {
				reply = s.imageResolve(ctx, view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "registry-login-test" {
				reply = s.externalRegistryProbe(ctx, view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "external-registry-bind-plan" {
				reply = s.externalRegistryBindPlan(view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "registry-credential" {
				reply = s.registryCredential(ctx, view, *envelope.Session, request.Tenant, *request.Registry)
			}
			if reply.Code == "ok" && (request.Method == "task-restart-plan" || request.Method == "task-restart-status") {
				reply = s.taskRestartQuery(view, request, *envelope.Session)
			}
			if reply.Code == "ok" && (request.Method == "app-log-clear-plan" || request.Method == "app-log-clear-status") {
				reply = s.logClearQuery(view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "container-observe" {
				reply = s.containerObservation(ctx, view, request, *envelope.Session)
			}
			if reply.Code == "ok" && request.Method == "node-storage-space" {
				reply = s.nodeStorageSpace(ctx, view, request, *envelope.Session)
			}
			if reply.Code == "ok" && (request.Method == "registries" || request.Method == "external-registries") {
				reply = s.registryQueryReply(view, *envelope.Session, request, reply)
			}
			if reply.Code == "ok" && (request.Method == "node-storage" || request.Method == "tenant-storage") {
				reply = s.storageQueryReply(view, catalog, *envelope.Session, request, reply)
			}
			if reply.Code == "ok" && request.Method == "vault" {
				reply = s.vaultQueryReply(view, catalog, *envelope.Session, request, reply)
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
			if reply.Code == "ok" && request.Method == "vault-approval-plan" {
				part, err := s.Policy.PlanVaultApproval(view.State, *envelope.Session, time.Now().Unix(), request.Tenant, *request.VaultPlan)
				if err != nil {
					reply = Reply{Schema: 1, Code: "denied"}
				} else {
					reply.VaultPlan = &part
				}
			}
			if reply.Code == "ok" && request.Method == "vault-write-plan" {
				plan, err := s.Policy.PlanVaultWrite(view.State, *envelope.Session, time.Now().Unix(), *request.VaultWritePlan)
				if err != nil {
					reply = Reply{Schema: 1, Code: "denied"}
				} else {
					reply.VaultWritePlan = &plan
				}
			}
			if reply.Code == "ok" && request.Method == "members" {
				if d, err := s.Policy.Members(view.State); err == nil {
					reply.MembersRootRevision = view.State.Object(control.MembersKey).Revision
					if topology, topologyErr := d.Topology(); topologyErr == nil {
						configuration := topology.Configuration()
						reply.NodeRuntimeRevision, reply.NodeOperationEpoch = topology.Revision(), topology.Epoch()
						reply.NodeConfigurationIndex, reply.NodeVoters, reply.NodeQuorum = configuration.Index, configuration.Voters(), configuration.Quorum()
					}
					for _, entry := range d.Entries {
						if entry.Peer.ID <= request.After {
							continue
						}
						if len(reply.Members) == 8 {
							reply.MembersNext = reply.Members[len(reply.Members)-1].Peer.ID
							break
						}
						reply.Members = append(reply.Members, entry)
						if lifecycle, found := s.Policy.PublicNodeView(view.State, entry.Peer.ID); found {
							if d.MemberKey(lifecycle.Node.Member.Key) {
								activity, activityErr := s.Policy.NodeActivity(view.State, lifecycle.Node.Member.Key)
								if activityErr != nil {
									reply = Reply{Schema: 1, Code: "unavailable"}
									break
								}
								lifecycle.SharedActivity = &activity
							}
							reply.NodeLifecycle = append(reply.NodeLifecycle, lifecycle)
						}
					}
				} else {
					reply = Reply{Schema: 1, Code: "unavailable"}
				}
			}
			if reply.Code == "ok" && request.Method == "node-invitation" {
				d, err := s.Policy.Members(view.State)
				target, found := d.Entry(request.Node)
				var source config.Peer
				for _, entry := range d.Entries {
					if entry.CurrentPeer().Key == s.Self.Actor() && membership.FullMember(entry) {
						source = entry.Peer
					}
				}
				if err != nil || !found || target.Phase != membership.Invited && target.Phase != membership.Learner && target.Phase != membership.Ready || !source.Voter {
					reply = Reply{Schema: 1, Code: "denied"}
				} else {
					inv := membership.Invitation{Schema: 1, Cluster: s.Policy.Cluster, Admin: s.Policy.BootstrapKey, Genesis: d.Genesis, Source: source, Target: target.Peer, JoinID: target.JoinID, ApprovalRevision: target.Job.Desired.Revision, MinimumIndex: view.RaftIndex}
					inv.Signature = ed25519.Sign(s.Self.Private, membership.InvitationBytes(inv))
					reply.Invitation = &inv
				}
			}
		}
		if reply.RootRevision == 0 {
			reply.RootRevision = view.State.Object(control.CatalogKey).Revision
		}
		if reply.Code == "ok" && (request.Method == "user-credentials" || request.Method == "node-cli-policy") {
			if view.State.ModuleEpoch() > 1 {
				reply.ModuleEpoch = view.State.ModuleEpoch()
			}
			reply.CertificatesRootRevision = view.State.Object(control.CertificatesKey).Revision
			reply.VPSRootRevision = view.State.Object(control.VPSKey).Revision
			reply.IngressRootRevision = view.State.Object(control.IngressManagementKey).Revision
			reply.CompactRootRevision = view.State.Object(control.CompactKey).Revision
			reply.ClusterBackupRootRevision = view.State.Object(control.ClusterBackupKey).Revision
			reply.TunnelRootRevision = view.State.Object(control.TunnelReconnectKey).Revision
			reply.RegistryMaintenanceRootRevision = view.State.Object(control.RegistryMaintenanceKey).Revision
			reply.ImageBuildRootRevision = view.State.Object(control.ImageBuildKey).Revision
			reply.ImageCacheRootRevision = view.State.Object(control.ImageCacheKey).Revision
			reply.LedgerRootRevision = view.State.Object(control.StorageKey).Revision
		}
		if reply.Code == "ok" && request.Method == "members" && view.State.ModuleEpoch() > 1 {
			reply.ModuleEpoch = view.State.ModuleEpoch()
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
	case "node-shell-policy", "node-shell-sessions":

		return Reply{Schema: 1, Code: "ok"}
	case "service-call", "cd-probe":
		action := access.CallService
		if r.Method == "cd-probe" {
			action = access.Deploy
		}
		if r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, action, "") != nil || c.OperationAllowed(session, r.Method) != nil {
			return reply
		}
		return Reply{Schema: 1, Code: "ok"}
	case "lifecycle-source-stage", "lifecycle-module-stage", "lifecycle-source-recover", "lifecycle-module-recover":
		recover := r.Method == "lifecycle-source-recover" || r.Method == "lifecycle-module-recover"
		if !r.validLifecycleSourceFields() {
			return reply
		}
		var err error
		if recover {
			err = c.AuthorizeSessionCleanup(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageServices)
		} else {
			err = c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageServices, "")
		}
		if err != nil || !recover && c.OperationAllowed(session, "lifecycle-source-upload") != nil {
			return reply
		}
		return Reply{Schema: 1, Code: "ok"}
	case "login-records", "own-sessions":
		// Every signed-in user reads only their own records.
		if (r.LoginQuery == nil) != (r.Method == "own-sessions") || r.Tenant != "" {
			return reply
		}
		return Reply{Schema: 1, Code: "ok"}
	case "events":
		if r.Events == nil || !r.Events.Valid() || r.Tenant != r.Events.Tenant {
			return reply
		}
		action := access.Read
		if r.Tenant == "" {
			action = access.ManageCluster
		}
		if c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, action, "") != nil {
			return reply
		}
		return Reply{Schema: 1, Code: "ok"}
	case "tenant-storage":
		if c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageVolumes, r.Node) != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, r.Node) != nil {
			return reply
		}
		return Reply{Schema: 1, Code: "ok"}
	case "standalone-list", "standalone-get":
		if r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil {
			return reply
		}
		return Reply{Schema: 1, Code: "ok", Tenant: r.Tenant}
	case "app-cd-toggle-plan", "image-cache-plan", "image-cache-status", "registry-action-plan", "external-registry-bind-plan", "registry-login-test", "image-resolve", "image-usages", "external-registry-pulls", "registry-catalog", "registry-prune-preview", "registry-prune-results", "registry-maintenance-plan", "registry-maintenance-status", "task-restart-plan", "task-restart-status", "raft-status", "app-source", "app-revisions", "my-credentials", "users", "tenant-members", "app-log-clear-plan", "app-log-clear-status", "user-credentials", "node-cli-policy", "container-observe", "tenant-retirement", "members", "node-invitation", "node-storage", "node-storage-space", "apps", "app-operation", "app-cd-field", "app-cd-history", "app-cd-diff", "app-cd-registration", "app-uploads", "app-plan", "standalone-plan", "app-plan-stream", "vault", "vault-approval-plan", "vault-write-plan", "registries", "external-registries", "registry-credential", "image-builds", "build-zip-transfer", "check-build-context", "build-context-content", "image-build-cache", "image-build-logs", "image-build-job-plan", "build-draft", "save-build-git":
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
		if r.Method == "my-credentials" {
			if r.Tenant != "" {
				return reply
			}
			u, _ := c.User(session.User)
			public := access.PublicUserOf(u)
			return Reply{Schema: 1, Code: "ok", SelfCredentials: &public}
		}
		if r.Method == "users" || r.Method == "tenant-members" {
			return s.catalogQueryReply(c, session, policy, now, r)
		}
		if r.Method == "user-credentials" || r.Method == "node-cli-policy" {
			if r.Tenant != "" || r.After != "" || r.Node != "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, "", access.ManageCluster, "") != nil {
				return reply
			}
			if r.Method == "node-cli-policy" {
				value := c.NodeCLI()
				return Reply{Schema: 1, Code: "ok", NodeCLI: &value}
			}
			user, exists := c.Username(r.TargetUser)
			if !exists {
				return reply
			}
			return Reply{Schema: 1, Code: "ok", CredentialUser: &user}
		}
		if r.Method == "task-restart-plan" || r.Method == "task-restart-status" {
			if r.TaskRestart == nil || !r.TaskRestart.Valid(r.Method == "task-restart-plan") || r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil {
				return reply
			}
		}
		if r.Method == "app-log-clear-plan" || r.Method == "app-log-clear-status" {
			if r.LogClear == nil || !r.LogClear.Valid(r.Method == "app-log-clear-plan") || r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil {
				return reply
			}
		}
		if r.Method == "container-observe" && (r.Container == nil || r.Container.Validate() != nil || r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil) {
			return reply
		}
		if r.Method == "tenant-retirement" && (r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, "", access.ManageCluster, "") != nil) {
			return reply
		}
		if r.Method == "app-cd-toggle-plan" {
			if r.Tenant == "" || r.CDToggle == nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "image-cache-plan" || r.Method == "image-cache-status" {
			if r.ImageCache == nil || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, "", access.ManageCluster, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "external-registry-pulls" {
			if r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "image-build-job-plan" {
			if r.ImageBuildJob == nil || !r.ImageBuildJob.Valid() || c.OperationAllowed(session, "begin-image-build") != nil || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "image-builds" {
			if r.ImageBuild == nil || !r.ImageBuild.Valid() || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "image-build-cache" {
			if r.ImageBuildCache == nil || !r.ImageBuildCache.Valid() || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "image-build-logs" {
			if r.ImageBuildLog == nil || !r.ImageBuildLog.Valid() || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "build-context-content" {
			if r.ImageBuildContent == nil || !r.ImageBuildContent.Valid() || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "check-build-context" {
			if r.ImageBuildSource == nil || !r.ImageBuildSource.Valid() || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "save-build-git" {
			if r.ImageBuildGit == nil || !r.ImageBuildGit.Valid() || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "build-draft" {
			if r.ImageBuildDraft == nil || !r.ImageBuildDraft.Valid() || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "build-zip-transfer" {
			if r.ImageBuildTransfer == nil || !r.ImageBuildTransfer.Valid() || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "registry-maintenance-plan" || r.Method == "registry-maintenance-status" {
			action := access.ManageRegistry
			if r.Method == "registry-maintenance-status" {
				action = access.Read
			}
			if r.RegistryMaintenance == nil || r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, action, "") != nil && (r.Method != "registry-maintenance-status" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil) {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "registry-prune-preview" || r.Method == "registry-prune-results" {
			if r.RegistryPrune == nil || r.Tenant == "" {
				return reply
			}
			if c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil && (r.Method != "registry-prune-results" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil) {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "registry-catalog" {
			if r.RegistryCatalog == nil || r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "image-usages" {
			if r.Tenant == "" || r.ImageUsage == nil || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "image-resolve" {
			if r.Tenant == "" || r.ImageResolve == nil || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "registry-login-test" {
			if r.Tenant == "" || r.ExternalRegistryProbe == nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "external-registry-bind-plan" {
			if r.Tenant == "" || r.ExternalRegistryBind == nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "registry-action-plan" {
			if r.Tenant == "" || r.RegistryAction == nil {
				return reply
			}
			return Reply{Schema: 1, Code: "ok"}
		}
		if r.Method == "registry-credential" && (r.Tenant == "" || r.Registry == nil) {
			return reply
		}
		if r.Method == "external-registries" && (r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil) {
			return reply
		}
		if r.Method == "registries" && (r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Read, "") != nil && c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.ManageRegistry, "") != nil) {
			return reply
		}
		if (r.Method == "node-storage" || r.Method == "node-storage-space") && (r.Tenant != "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, "", access.ManageCluster, "") != nil) {
			return reply
		}
		if r.Method == "node-storage-space" && r.NodeStorage == nil {
			return reply
		}
		if r.Method == "vault-approval-plan" && (r.Tenant == "" || c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, access.Deploy, "") != nil) {
			return reply
		}
		if r.Method == "vault" || r.Method == "vault-write-plan" {
			action := access.ManageSecrets
			if r.Tenant == "" {
				action = access.ManageCluster
			}
			allowed := c.AuthorizeSession(session, s.Policy.Cluster, policy, now, r.Tenant, action, "")
			if r.Method == "vault" && r.Tenant != "" {
				// Read-only metadata remains available to current cleanup
				// authority after retirement blocks new value/metadata writes.
				allowed = c.AuthorizeSessionCleanup(session, s.Policy.Cluster, policy, now, r.Tenant, action)
			}
			if allowed != nil {
				return reply
			}
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
		if (r.Method == "members" || r.Method == "node-invitation") && (c.AuthorizeSession(session, s.Policy.Cluster, policy, now, "", access.ManageCluster, "") != nil) {
			return reply
		}
		if r.Tenant != "" && r.Method != "task-restart-plan" && r.Method != "task-restart-status" && r.Method != "container-observe" && r.Method != "app-log-clear-plan" && r.Method != "app-log-clear-status" && r.Method != "tenant-retirement" && r.Method != "apps" && r.Method != "app-operation" && r.Method != "app-cd-field" && r.Method != "app-cd-history" && r.Method != "app-cd-diff" && r.Method != "app-cd-registration" && r.Method != "app-uploads" && r.Method != "app-plan" && r.Method != "standalone-plan" && r.Method != "app-plan-stream" && r.Method != "vault" && r.Method != "vault-approval-plan" && r.Method != "vault-write-plan" && r.Method != "registries" && r.Method != "external-registries" && r.Method != "registry-credential" {
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
