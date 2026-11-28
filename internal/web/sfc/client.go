// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"io"

	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/servicecall"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/vps"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// Client opens connections to sfcd. One browser login owns one Conn: one
// session key, one transport and one userauth.Client (R03). The login
// Session is bound to the session key, not to a connection, so a Conn is
// never shared between users but survives reconnects.
type Client interface {
	Dial(ctx context.Context) (Conn, error)
}

// Conn is one login's management client. Every method fails with a *Error.
// When sfcd closes the connection (30 s idle, restart) the Conn dials again
// on the next call and keeps its Session; only a pending login ticket is
// lost. Methods may be called concurrently: the transport serializes
// exchanges per connection. CodeClosed means the Conn itself was closed.
//
// Each method's wire name, status against sfcd and real userauth.Client
// call is listed in apps/sfc-web/CLUSTER_METHODS.md (R04).
type Conn interface {
	// --- login (no session) ---

	// CredentialChallenge: `credential-challenge`. method is MethodPassword or
	// MethodToken; credential optionally selects one credential ID.
	CredentialChallenge(ctx context.Context, username string, method AuthMethod, credential string) (Ticket, error)
	// CredentialLogin: `credential-login`. secret is used once and not kept.
	CredentialLogin(ctx context.Context, ticket Ticket, secret []byte) (Session, error)
	// Challenge: `challenge` for a private-key login. The Conn generates the
	// session key; Ticket.SessionKey is its public half.
	Challenge(ctx context.Context, username string, userKey [32]byte) (Ticket, error)
	// Login: `login` with the browser-signed proof (see NewKeyProof and
	// KeyProofSigningBytes).
	Login(ctx context.Context, ticket Ticket, proof KeyProof) (Session, error)
	// ApproveSession attaches the user approval the browser signed for the
	// session Login returned (R02: userauth.KeyLogin returns it unapproved,
	// access.AttachSessionApproval adds it). a must be NewSessionApproval
	// of that session signed with the login's user key; sfcd checks the
	// key's registration on each request. Password/token logins have no
	// approval.
	ApproveSession(ctx context.Context, a SessionApproval) (Session, error)
	// Session returns the current login, if any.
	Session() (Session, bool)
	Close() error

	// --- account ---

	Whoami(ctx context.Context) (Whoami, error)
	Tenants(ctx context.Context) ([]TenantView, error)
	SelectTenant(ctx context.Context, tenant string) (TenantView, error)
	// UserCredentials: `user-credentials` (typed Data, system
	// admin).
	UserCredentials(ctx context.Context, username string) (User, error)
	// IssueInvite: the provider step of an invitation's single-use token
	// (system admin); the caller submits ActionIssueInitialCredential with
	// its Fact (invite.go).
	IssueInvite(ctx context.Context, username string, seconds int64) (InviteIssue, error)
	// OwnCredentials: `my-credentials` (typed Data) — the
	// caller's own public User record for "내 계정". Revision is the account
	// revision add/disable expect.
	OwnCredentials(ctx context.Context) (PublicUser, error)
	// LoginRecords: `login-records` — the caller's own recent logins on
	// every server, newest first (LoginRecordsPage at a time).
	LoginRecords(ctx context.Context, after string) (LoginPage, error)
	// OwnSessions: `own-sessions` — the caller's sessions that may still be
	// open, newest first. Ending one is `revoke-session`.
	OwnSessions(ctx context.Context) (SessionsPage, error)
	// Users: `users` (userauth.UsersPage, system admin).
	Users(ctx context.Context, after string) (Page[PublicUser], error)
	// TenantMembers: `tenant-members` (userauth.TenantMembersPage, system
	// admin or tenant manager). Rows are access.TenantMember: Enabled is the
	// membership, AccountEnabled the account. Revision = TenantRevision
	// (member changes' Expected); Collection = TenantMembersRevision, the
	// catalog revision that volume-file-grant/-revoke carry as Expected.
	TenantMembers(ctx context.Context, tenant, after string) (Page[TenantMember], error)
	// NodeCLIPolicy: `node-cli-policy` (system admin).
	NodeCLIPolicy(ctx context.Context) (NodeCLIPolicy, error)
	TenantRetirement(ctx context.Context, tenant, after string) (TenantRetirement, error)

	// --- cluster / nodes ---

	// Members: `members` (system admin).
	Members(ctx context.Context, after string) (MembersPage, error)
	// NodeInvitation: `node-invitation` (system administrator): the signed
	// non-voter invitation of an invited/learner/ready node. The real
	// adapter checks the signature against the pinned peers as the CLI does.
	NodeInvitation(ctx context.Context, node string) (NodeInvitation, error)
	// NodeSummary: `node-summary`. tenant "" is the cluster-wide admin view
	// (system admin; rows carry Admin: host, disks, role, per-tenant usage);
	// otherwise Read on tenant and only its allowed nodes, rows carry that
	// tenant's Usage. node empty = every visible node. Timestamps Unix ms.
	NodeSummary(ctx context.Context, tenant, node, after string) (NodeSummaryPage, error)
	// NodeStorage: `node-storage`, system admin. Rows are nodestorage.Root
	// (Reply.NodeStorage); Revision is Reply.NodeStorageRootRevision.
	NodeStorage(ctx context.Context, node, after string) (Page[StorageRoot], error)
	// NodeStorageSpace: `node-storage-space`, system admin.
	NodeStorageSpace(ctx context.Context, node, id string) (StorageSpace, error)
	// TenantStoragePage: REQ-30/58 in sfcd's real shape (userauth.Client.
	// TenantStoragePage): roots the tenant may use, 8 a page, node "" = all
	// (ManageVolumes or ManageRegistry). Each row carries the whole Root
	// reference a build policy names.
	// (No CapacityBytes or Attested in the real row.)
	TenantStoragePage(ctx context.Context, tenant, node, after string) (control.TenantStoragePage, error)
	// NodeDisks: `node-disks`. tenant empty = the cluster-wide admin view
	// (system admin, ManageCluster); otherwise ManageVolumes on tenant and
	// only that tenant's storage-root disks of its allowed nodes, without
	// device names. node empty = every visible node. Timestamps are Unix ms.
	NodeDisks(ctx context.Context, tenant, node, after string) (NodeDisksPage, error)
	// MeshLinks: `mesh-links`. tenant as NodeDisks but Read is enough;
	// node empty = every pair. Ends (each side's observation) only in the
	// cluster-wide admin view. Timestamps are Unix ms.
	MeshLinks(ctx context.Context, tenant, node, after string) (MeshLinksPage, error)
	// RaftStatus: `raft-status`, system admin (ManageCluster). Timestamps
	// are Unix ms; LastManualCompact and each node's LastManualCompact are
	// the last manual compaction.
	RaftStatus(ctx context.Context) (RaftStatus, error)
	// Events: `events`. q.Tenant "" is the cluster-wide view (system
	// admin), otherwise Read on that tenant; App/Node/Kind narrow it. After
	// is the previous page's Cursor; Limit at most 100 (0 = sfcd's
	// default). Page.Cursor always resumes; More: more rows wait. An old
	// cursor fails with CodeCursorExpired. At is Unix ms.
	Events(ctx context.Context, q EventQuery) (EventsPage, error)

	// --- tenant resources ---

	// Resources: one sfcd `resources` page (control.ResourceEntry rows, 8 a
	// page; Revision = ResourcesRootRevision, Collection = NetworkRevision,
	// QuotaRevision). The screen form (one row per network) is built by
	// internal/web/server.
	Resources(ctx context.Context, tenant, after string) (Page[control.ResourceEntry], error)
	// NetworkDNSNames: `network-dns-names` — the names the network's managed
	// DNS answers (control.NetworkDNSNames). Read on the tenant.
	NetworkDNSNames(ctx context.Context, tenant, network string) (NetworkDNSNames, error)
	Volumes(ctx context.Context, tenant, after string) (Page[VolumeView], error)
	VolumeBackups(ctx context.Context, tenant, after string) (Page[VolumeBackupView], error)
	// VolumeRestores: `volume-restores`.
	VolumeRestores(ctx context.Context, tenant, after string) (Page[VolumeRestoreView], error)
	// VolumeArchives: `volume-archives` — archive rows and the public
	// recipient keys new packages are sealed to (userauth.VolumeArchivesPage).
	VolumeArchives(ctx context.Context, tenant, after string) (userauth.VolumeArchivesPage, error)
	// VolumeBackupSource: `volume-backup-source` for an app volume (TM Volumes).
	VolumeBackupSource(ctx context.Context, tenant string, q control.VolumeSelector) (VolumeSource, error)
	// Vault: one sfcd `vault` page (control.VaultView rows — an Object or a
	// Write — in ID order; Revision = RootRevision, Collection =
	// TreeRevision, ApprovalRevision). The screen rows (paths, the root's
	// parent) are built by internal/web/server.
	Vault(ctx context.Context, tenant, after string) (Page[control.VaultView], error)
	VaultWriter
	VaultApprover
	Lifecycles(ctx context.Context, tenant, after string) (userauth.LifecyclesPage, error)
	// REQ-39/40 in the real shape (docs/reference/lifecycle-sources.md,
	// ManageServices): the original nonzero upload ID is the caller's and
	// is kept across retries; node "" lets sfcd pick (keep the reply Node
	// for later ZIPs, the root and recover). Stage the lock's module ZIPs
	// first, then the source. Diagnostics (no fact) or one Source/Module
	// fact; Source goes into put-lifecycle-script as is. Recover returns
	// only the original fact. LifecycleSourcePage is one page; the package
	// function ReadLifecycleSource(ctx, c, …) reads all pages and checks them.
	LifecycleSourceStage(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte, source []byte) (userauth.LifecycleStageResult, error)
	LifecycleModuleStage(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte, module checker.ModuleArchive) (userauth.LifecycleStageResult, error)
	LifecycleSourceRecover(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte) (userauth.LifecycleStageResult, error)
	LifecycleModuleRecover(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte, pin checker.ModulePin) (userauth.LifecycleStageResult, error)
	LifecycleSourcePage(ctx context.Context, tenant string, q control.LifecycleSourceQuery) (checker.SourcePage, error)
	Registries(ctx context.Context, tenant, after string) (userauth.RegistriesPage, error)
	// RegistryCredential: `registry-credential` (pull needs Deploy or
	// ManageRegistry, push ManageRegistry on the registry's node): a
	// login for an enabled, running registry. The real adapter checks the
	// grant (issuer, audience, scope, session) as `sfcli registry
	// credential` does.
	RegistryCredential(ctx context.Context, tenant string, q RegistryCredentialRequest) (userauth.RegistryCredential, error)

	// --- apps ---

	Apps(ctx context.Context, tenant, after string) (Page[AppView], error)
	AppOperation(ctx context.Context, tenant, app, id string) (AppOperation, error)
	AppUploads(ctx context.Context, tenant, after string) (Page[AppUploadView], error)
	// AppPlan: `app-plan-stream` (document streamed with kind4, plan parts
	// joined and digest-checked by the adapter).
	AppPlan(ctx context.Context, req AppPlanRequest) (AppPlan, error)
	// AppSource / AppRevisions: REQ-5 (mock). version 0 = running version.
	AppSource(ctx context.Context, tenant, app string, version uint64) (AppSource, error)
	AppRevisions(ctx context.Context, tenant, app, after string) (Page[AppRevision], error)
	// ResolveImage: REQ-31 (real) `image-resolve` (tenant Read or
	// ManageRegistry), the same shape as userauth.Client.ResolveImage.
	// docs/reference/image-resolution.md.
	ResolveImage(ctx context.Context, tenant string, q control.ImageResolveQuery) (control.ImageResolveResult, error)
	// Tasks: REQ-1 (mock).
	Tasks(ctx context.Context, f TaskFilter, after string) (Page[Task], error)
	// ContainerObserve: `container-observe` (finite logs/top/stats).
	// Selection.Standalone selects a standalone container.
	ContainerObserve(ctx context.Context, tenant string, q ContainerQuery) (ContainerResult, error)

	// AppDeliveryField: `app-cd-field` (tenant Read), one field a CD app's
	// runtime override may set: its target, revision, current override and
	// the task it applies to (Refs).
	AppDeliveryField(ctx context.Context, tenant string, q control.AppCDFieldRequest) (AppCDField, error)
	// AppDeliveryLocal: the services the web added to a CD app apart from
	// Git, from the apps row and app-source pending-local (tenant Read;
	// changes are put-/clear-app-local-services).
	AppDeliveryLocal(ctx context.Context, tenant, app string) (AppCDLocal, error)
	// AppDeliveryHistory: REQ-46 (mock) `app-cd-history`, a CD app's
	// candidates and their results, newest first (tenant Read).
	AppDeliveryHistory(ctx context.Context, tenant, app, after string) (Page[CDHistoryRow], error)
	// AppDeliveryValues: REQ-46 (mock), an app-cd-field path's Git value at
	// the running and candidate commits and the value in force (tenant
	// Read). Secret projections give selectors, never values.
	AppDeliveryValues(ctx context.Context, tenant string, q control.AppCDFieldRequest) (CDFieldValues, error)
	// AppDeliveryChanges: REQ-46 (mock), what the candidate changes against
	// the running commit; Count = AppCD.ChangeCount (tenant Read).
	AppDeliveryChanges(ctx context.Context, tenant, app string) (CDChanges, error)
	// REQ-28 files in a tenant volume (docs/reference/volume-files.md):
	// `volume-file-plan` (tenant manager or a folder grant covering Path)
	// gives the change to sign as Method with Expected = Revision; Submit
	// reserves a job; VolumeFile streams once (put reads source, get
	// writes to; Result = path/size/digest, list = Entries/Next); a put
	// with source nil recovers the outcome of a lost reply and never
	// rewrites. `volume-file-status` reads the job by VolumeFileID(op).
	VolumeFilePlan(ctx context.Context, tenant string, q control.VolumeFileQuery) (control.VolumeFilePlan, error)
	VolumeFile(ctx context.Context, op SignedOp, source io.Reader, to io.Writer) (userauth.VolumeFileReply, error)
	VolumeFileStatus(ctx context.Context, tenant, id string) (control.VolumeFileView, error)
	// REQ-20 (mock) one container beyond container-observe: applied
	// settings and drift, exit/check history, logs by cursor with secret
	// values masked, kept stats (tenant Read; restart-task is an action).
	TaskDetail(ctx context.Context, tenant string, sel ContainerSelection) (TaskDetail, error)
	TaskHistory(ctx context.Context, tenant string, sel ContainerSelection, limit int) (TaskHistory, error)
	TaskLogs(ctx context.Context, tenant string, q TaskLogQuery) (TaskLogPage, error)
	TaskStats(ctx context.Context, tenant string, sel ContainerSelection) ([]TaskStatsSample, error)
	// Log clearing (devel/proposals/seafield-log-clear.md): logs-clear
	// clears every server's log store for a selection (containers are not
	// touched; each server answers for itself), stored-logs lists what the
	// stores keep, including logs of containers that are gone (fake_log_clear.go).
	ClearLogs(ctx context.Context, tenant string, q LogsClear) (control.LogsClearReply, error)
	StoredLogs(ctx context.Context, tenant string, q LogsClear, node string) (control.StoredLogsReply, error)
	// REQ-9 (mock) incident-response account: `account-scope` (system admin
	// or self; change: set-account-scope), Prepare with display-only reason
	// metadata, and `operation-reason` to read it back.
	AccountScope(ctx context.Context, user string) (AccountScope, error)
	PrepareReason(ctx context.Context, change Change, rootRevision uint64, reason OperationReason) (SignedOp, error)
	// PrepareRequestReason: PrepareReason with a caller-chosen RequestID
	// (PrepareRequest's rules), e.g. an incident's put-certificate.
	PrepareRequestReason(ctx context.Context, requestID string, change Change, rootRevision uint64, reason OperationReason) (SignedOp, error)
	// REQ-11 (mock) incident actions: `node-image-prune-plan` (system
	// admin; change prune-node-images). cordon-/uncordon-node are actions
	// only.
	// REQ-67/68 server shell: see node_shell.go. NodeShellSessions pages 8
	// by SessionID (Next → after). OpenNodeShell takes the same Prepare'd
	// open-node-shell op (Expected 0, at most 30 s old) after Submit
	// accepted it (queued); its RequestID is the SessionID.
	NodeShellPolicy(ctx context.Context) (NodeShellPolicy, error)
	NodeShellSessions(ctx context.Context, after string) (NodeShellSessionsPage, error)
	// REQ-69 (mock): the same read with State (open / closed / "") and Node.
	QueryNodeShellSessions(ctx context.Context, q NodeShellSessionsQuery) (NodeShellSessionsPage, error)
	OpenNodeShell(ctx context.Context, op SignedOp) (NodeShell, error)
	// RQ4 (real, docs/reference/tunnel-reconnect.md) node-pair link
	// reconnect, system admin only: `tunnel-reconnect-plan` Tunnel:{Node,
	// Peer} (node = the owner that dials) and `tunnel-reconnect-status`
	// Tunnel:{Operation}. Apply with reconnect-tunnel, Expected 0, payload
	// control.TunnelChange{Operation, Plan}, root RootFor (TunnelReconnectKey).
	PlanTunnelReconnect(ctx context.Context, node, peer string) (control.TunnelPlan, error)
	TunnelReconnectStatus(ctx context.Context, operation string) (control.TunnelStatus, error)
	// raft-compact-plan Compact:{Selection, After} and raft-compact-status
	// Compact:{Operation, After} (system admin).
	RaftCompactPlan(ctx context.Context, sel CompactSelection, after string) (CompactPlanPage, error)
	RaftCompactStatus(ctx context.Context, operation, after string) (CompactStatusPage, error)
	// image-cache-plan ImageCache:{Node, After | Images} and
	// image-cache-status ImageCache:{Operation} (system admin).
	ImageCachePlan(ctx context.Context, q ImageCacheQuery) (ImageCachePlan, error)
	ImageCacheStatus(ctx context.Context, operation string) (ImageCacheStatus, error)
	// RQ12, system admin: node-remove-plan, node-demote-plan,
	// node-drain-plan / -status {Node, Operation}, node-force-remove-plan
	// {Node, Operation} and node-diagnostics (fake_node_ops_real.go).
	PlanNodeRemoval(ctx context.Context, node string) (control.NodeRemovePlan, error)
	PlanNodeDemotion(ctx context.Context, node string) (control.NodeVotingPlan, error)
	PlanNodeDrain(ctx context.Context, q control.NodeDrainQuery) (control.NodeDrainPlan, error)
	NodeDrainStatus(ctx context.Context, q control.NodeDrainQuery) (control.NodeDrainStatus, error)
	PlanNodeForceRemoval(ctx context.Context, q control.NodeForceQuery) (control.NodeForcePlan, error)
	ReadNodeDiagnostics(ctx context.Context, node string) (control.NodeDiagnosticsBundle, error)
	// NodeDisk: `node-disk`, system admin. Format, mount or unmount one
	// additional disk of a server, or read that operation back (Action
	// status). No Raft: the server keeps the operation in its own journal.
	NodeDisk(ctx context.Context, op control.NodeDiskOp) (control.NodeDiskResult, error)
	// NodeFirewall: `node-firewall`, system admin. Show, change (revision
	// + delta) or read the change log of one server's own firewall chain.
	// No Raft: the server applies a change at once.
	NodeFirewall(ctx context.Context, op control.NodeFirewallOp) (control.NodeFirewallResult, error)
	// ClusterFirewall: `cluster-firewall`, system admin. The committed
	// cluster firewall every managed server applies under its own; changes
	// are the signed action set-cluster-firewall (revision + delta).
	ClusterFirewall(ctx context.Context) (control.ClusterFirewallView, error)
	// ProbeCD: REQ-56 `cd-probe` (docs/reference/service-diagnostics.md),
	// read a Git source once before connecting CD (the app's Deploy). A
	// failed read is GitProbeResult.Code (with Node only).
	ProbeCD(ctx context.Context, tenant string, q deployment.GitProbeRequest) (deployment.GitProbeResult, error)
	// PublicRead: RQ10 reads in sfcd's common envelope (method one of
	// control.PublicReadMethod, selector control.PublicReadQuery, After =
	// page.Next); see fake_public_read.go. The per-method reads below stay
	// until the daemon moves.
	PublicRead(ctx context.Context, method, tenant string, q control.PublicReadQuery, after string) (control.PublicReadPage, error)
	// ServerVersion: REQ-48 (mock) `server-version`, the connected sfcd's
	// build and SFCP Protocol; needs no login.
	ServerVersion(ctx context.Context) (ServerVersion, error)
	// CallService: REQ-24/55 `service-call` (docs/reference/
	// service-diagnostics.md), one POST from inside the tenant network to
	// an app service port (tenant manager or system admin; call-service).
	// Never retried; timeout or a lost reply does not mean the app did not
	// run it. A failed call is servicecall.Result.Code.
	CallService(ctx context.Context, tenant string, q servicecall.Request) (servicecall.Result, error)
	// REQ-17 (mock) external registry logins: rows hold vault references
	// only (tenant Read); the login test returns a code (ManageRegistry).
	// REQ-17 in sfcd's real shape (docs/reference/external-registries.md,
	// as userauth.Client). put-external-registry {Spec imagesource.Source}
	// and delete/unbind {Tenant, ID} take Expected = the record Revision;
	// bind-external-registry sends PlanExternalRegistryBind's Selection with
	// its Expected, after the vault Group approvals of its Uses
	// (PlanVaultApprovals with that original). ProbeExternalRegistry
	// (`registry-login-test`, ManageRegistry) needs a bound, not draining
	// reader. RegistryPulls: `external-registry-pulls`. ImageUsages:
	// `image-usages`, with ExternalSource = the source's users.
	ExternalRegistryPage(ctx context.Context, tenant, after string) (userauth.ExternalRegistriesPage, error)
	PlanExternalRegistryBind(ctx context.Context, tenant string, q control.ExternalRegistryBindQuery) (control.ExternalRegistryBindPlan, error)
	ProbeExternalRegistry(ctx context.Context, tenant string, q control.ExternalRegistryProbeQuery) (control.ExternalRegistryProbeResult, error)
	RegistryPulls(ctx context.Context, tenant, after string) (control.RegistryPullPage, error)
	ImageUsages(ctx context.Context, tenant string, q control.ImageUsageQuery, after string) (control.ImageUsagesPage, error)
	// Image builds in sfcd's real contract (image_builds.go; same shapes
	// as userauth.Client, tenant Read unless noted).
	// ImageBuilds: `image-builds`, one Part (policy, contexts, versions,
	// uploads, missing, jobs, caches, cache-prunes) a call.
	ImageBuilds(ctx context.Context, tenant string, q control.ImageBuildQuery, after string) (control.ImageBuildPage, error)
	// BuildContextContent: `build-context-content`, a version's tree or
	// Dockerfile only.
	BuildContextContent(ctx context.Context, tenant string, q imagebuild.ContentQuery, after string) (control.ImageBuildContentPage, error)
	// CheckBuildContext: `check-build-context` (Git contexts).
	CheckBuildContext(ctx context.Context, tenant string, q control.ImageBuildSourceQuery) (control.ImageBuildSourceResult, error)
	// PlanImageBuildJob: `image-build-job-plan` (ManageRegistry); its
	// Change is the begin-image-build payload.
	PlanImageBuildJob(ctx context.Context, tenant string, q control.ImageBuildJobQuery) (control.ImageBuildJobPlan, error)
	// build-draft (as userauth.Client): BuildDraft sends plan/tree/
	// file-status; the others sign a DraftProof with the session key.
	BuildDraft(ctx context.Context, tenant string, q imagebuild.DraftRequest) (imagebuild.DraftResponse, error)
	EditBuildDraft(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, data []byte) (imagebuild.DraftResponse, error)
	PutDraftFilePart(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, index uint32, data []byte) (imagebuild.DraftResponse, error)
	CommitDraftFile(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit) (imagebuild.DraftResponse, error)
	DraftFileStatus(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, offset uint32) (imagebuild.DraftResponse, error)
	DraftEditResult(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit) (imagebuild.DraftResponse, error)
	FreezeBuildDraft(ctx context.Context, plan imagebuild.DraftFreezePlan) (imagebuild.DraftResponse, error)
	DraftFreezeResult(ctx context.Context, plan imagebuild.DraftFreezePlan) (imagebuild.DraftResponse, error)
	// build-zip-transfer (as userauth.Client): one ≤24 KiB part of a
	// real-shape zip upload, signed with the session key → the owner's
	// PartReceipt for put-build-zip-part; SealBuildZIP once every part is
	// recorded → the SealReceipt for upload-build-zip. scope is the upload's
	// (image-builds Part uploads). Code OK·DIGEST_MISMATCH·INVALID_ZIP·
	// STORAGE_UNAVAILABLE·CONFLICT. record=true (1add789): the owner also
	// confirms the slot (no put-build-zip-part); the answer has Recorded and
	// UploadRevision ≥ expected, the next part's expected.
	PutBuildZIPPart(ctx context.Context, scope imagebuild.UploadScope, expected uint64, index uint32, data []byte, record ...bool) (control.ImageBuildIOResult, error)
	SealBuildZIP(ctx context.Context, scope imagebuild.UploadScope, expected uint64) (control.ImageBuildIOResult, error)
	// ImageBuildLogs: `image-build-logs`, byte pages with a cursor.
	ImageBuildLogs(ctx context.Context, tenant string, q imagebuild.LogQuery, after string) (control.ImageBuildLogPage, error)
	// ImageBuildCacheUsage: `image-build-cache`, one cache scope's entries.
	ImageBuildCacheUsage(ctx context.Context, tenant string, q imagebuild.CacheQuery, after string) (control.ImageBuildCachePage, error)

	// --- registry images: REQ-18 ---

	// REQ-18 real (docs/reference/registry-images.md, registry-maintenance.md),
	// the same shapes as userauth.Client:
	// RegistryCatalogue: `registry-catalog` (Read or ManageRegistry), 8 a
	// page; Repository "" lists repositories.
	RegistryCatalogue(ctx context.Context, tenant string, q control.RegistryCatalogueQuery, after string) (control.RegistryCatalogueResult, error)
	// PlanRegistryMaintenance: `registry-maintenance-plan` (ManageRegistry)
	// for delete-registry-image / gc-registry; submit the action with the
	// plan's Change (Operation = a stable job ID) and Expected.
	PlanRegistryMaintenance(ctx context.Context, tenant string, q control.RegistryMaintenanceQuery) (control.RegistryMaintenancePlan, error)
	// RegistryMaintenanceStatus: `registry-maintenance-status` (Read).
	RegistryMaintenanceStatus(ctx context.Context, tenant, operation string) (control.RegistryMaintenanceStatus, error)
	// RegistryPrune: `registry-prune-preview` (results false, ManageRegistry)
	// or `registry-prune-results` (results true, Read).
	RegistryPrune(ctx context.Context, tenant string, q control.RegistryPruneQuery, after string, results bool) (control.RegistryPruneView, error)

	// --- ingress: REQ-22 ---

	// QueryIngresses: REQ-22 real `ingresses` (docs/reference/ingress-management.md),
	// the same shape as userauth.Client.Ingresses. Part mappings (default; one mapping a
	// page, After = Next; Offset/Next page its listeners, routes, backends,
	// blocks and Runtime.Certificates by 4, Nodes[].Gateways bindings by 4),
	// metrics (dimensions by 4), errors (16), blocks (8, Offset) or policies
	// (4, Offset). Changes under control/ingress-management (RootFor):
	// ingress-block {control.IngressBlockChange} Expected 0;
	// ingress-unblock / ingress-block-extend {control.IngressBlockSelection}
	// Expected = block Revision; set-ingress-host-policy
	// {control.IngressHostPolicyChange} (system admin) Expected = policy
	// Revision (0 = new).
	QueryIngresses(ctx context.Context, q control.IngressQuery) (control.IngressPage, error)

	// --- standalone containers: REQ-29 (mock) ---

	// Standalones: `standalone-list` (tenant Read; another user's temp
	// containers only for a tenant manager).
	Standalones(ctx context.Context, tenant, after string) (Page[StandaloneView], error)
	// Standalone: `standalone-get`.
	Standalone(ctx context.Context, tenant, name string) (StandaloneView, error)
	// Plans and up: AppPlan with Standalone (StandalonePlan is its summary),
	// then begin-app-upload/put-app-part and standalone-up control.AppBegin.
	// TaskRestartPlan / TaskRestartStatus: real `task-restart-plan` /
	// `task-restart-status` for standalone-stop/-start/-restart (tenant
	// Read; the change needs Deploy). Sign control.TaskRestartChange
	// {Tenant, Standalone, Operation, Selection{Service, Instance} =
	// plan.Container, Target, ManagementTarget} with Expected =
	// plan.StandaloneRevision; status by Selection{Standalone} + Operation.
	// The fake models standalone selections only.
	TaskRestartPlan(ctx context.Context, tenant string, q control.TaskRestartQuery) (control.TaskRestartPlan, error)
	// StandaloneOperation: `app-operation` AppOperationRequest{Standalone,
	// ID}, the result of a standalone-up original (sfcd's shape: AppPlan
	// with AppPlanRequest.Standalone → begin-app-upload/put-app-part →
	// standalone-up control.AppBegin, see fake_standalone_real.go).
	StandaloneOperation(ctx context.Context, tenant, name, id string) (AppOperation, error)
	TaskRestartStatus(ctx context.Context, tenant string, q control.TaskRestartQuery) (control.TaskRestartStatus, error)

	// --- container streams (purpose15 ContainerSession) ---

	// ResolveStream: `resolve`. Read on tenant; exec also needs Deploy.
	// sel.Standalone selects a standalone container.
	ResolveStream(ctx context.Context, tenant string, sel ContainerSelection, spec StreamSpec) (StreamTarget, error)
	// PrepareStream signs a SessionIntent with the session key. requestID is
	// the exec operation ID chosen by the user/daemon ("" = generated, fine
	// for logs/top/stats). Nothing is sent; store exec intents first.
	PrepareStream(ctx context.Context, target StreamTarget, spec StreamSpec, requestID string) (SignedIntent, error)
	// OpenStream: `open`. The intent must be at most 30 s old and signed by
	// the current session.
	OpenStream(ctx context.Context, tenant string, intent SignedIntent) (Stream, error)
	// ExecStatus: `status` for a stored exec intent (works after the original
	// login expired, with the same account's current Read/Deploy).
	ExecStatus(ctx context.Context, tenant string, intent SignedIntent) (ExecStatus, error)

	// --- change watch (purpose ChangeWatch) ---

	// WatchChanges: which records this session may see that committed
	// changes touched, after from (0: from now). each gets every frame
	// until ctx ends, the session expires (CodeDenied after a revocation)
	// or sfcd ends the watch; the last delivered index is returned so the
	// caller resumes from it. A watch owns its own connection.
	WatchChanges(ctx context.Context, from uint64, each func(ChangeBatch) error) (uint64, error)

	// --- certificate store: REQ-21, system admin ---

	// docs/reference/certificate-store.md, the same shapes as
	// userauth.Client:
	// QueryCertificates: the `certificates` list in ID order (q {After}, 32
	// rows a page, the first page also carries the domain list; After is
	// the page Next and conflicts once Revision moved), or one certificate
	// with its public chain (q {ID}; a missing ID is an empty page). System
	// admin.
	QueryCertificates(ctx context.Context, q control.CertificateQuery) (control.CertificatePage, error)
	// WriteCertificate: the protected input (chain and key PEM, each at most
	// 8 KiB) → the sealed public receipt. Then sign put-certificate with
	// PrepareRequest(receipt.Request), Payload control.CertificatePut{
	// Certificate: receipt}, Expected 0. Recover re-reads the receipt of the
	// same Request. A chain whose ID is already stored is a conflict: look
	// the ID up first. delete-certificate / disable-certificate take
	// control.CertificateSelection{ID}, Expected 0.
	WriteCertificate(ctx context.Context, in userauth.CertificateInput) (certstore.Certificate, error)

	// --- VPS servers: devel/design/vps-nodes.md, system admin ---

	// QueryVPS: the provider accounts (no sealed keys) and the VPS servers
	// with the catalog Revision every VPS change sends as Expected.
	QueryVPS(ctx context.Context) (control.VPSPage, error)
	// QueryVPSStatus: the leader's 10-minute cost watch (memory only).
	// unavailable when the leader cannot be reached.
	QueryVPSStatus(ctx context.Context) (control.VPSStatus, error)
	// QueryVPSOffer: what an account's vendor sells now, read by the voter
	// answering (zones, images, types with prices, SSH keys, scripts).
	// unavailable when the vendor cannot be read or the server is not a
	// voter.
	QueryVPSOffer(ctx context.Context, q control.VPSOfferQuery) (control.VPSOffer, error)
	// SealVPSCredential: a provider key pair → the sealed credential for
	// put-vps-account (Request = that operation's ID). The keys are not
	// kept; the server must be a voter. Sealing changes nothing, so a lost
	// reply is asked again.
	SealVPSCredential(ctx context.Context, in userauth.VPSCredentialInput) (vps.SealedCredential, error)

	// --- durable changes ---

	// Prepare builds and signs the original UserOperation with the session
	// key. Nothing is sent. Store the returned bytes before Submit.
	Prepare(ctx context.Context, change Change, rootRevision uint64) (SignedOp, error)
	// PrepareRequest is Prepare with a caller-chosen RequestID (at most 128
	// bytes, no control characters), as userauth.Client.Prepare takes one.
	PrepareRequest(ctx context.Context, requestID string, change Change, rootRevision uint64) (SignedOp, error)
	// Submit sends a prepared original operation (`submit`). After a send,
	// a lost reply is CodeUnknown: keep the SignedOp and use Result/Resume;
	// never Prepare a new ID to retry.
	Submit(ctx context.Context, op SignedOp) (Result, error)
	// Result: `result` for the stored original. found=false is not proof
	// that it did not run.
	Result(ctx context.Context, op SignedOp) (res Result, found bool, err error)
	// Resume: `resume` the same original with the current session.
	Resume(ctx context.Context, op SignedOp) (res Result, found bool, err error)
}

// Action names used with Change.Action. Real actions are in
// internal/cluster/control; REQ-n actions are provisional names from
// REQUEST.md and may be renamed when sfcd publishes them.
const (
	ActionCreateTenant     = "create-tenant"
	ActionSetMembership    = "set-membership"
	ActionSetTrust         = "set-trust"
	ActionSetNodes         = "set-nodes"
	ActionPutUser          = "put-user"
	ActionRevokeSession    = "revoke-session"
	ActionSetNodeCLIPolicy = "set-node-cli-policy"
	ActionIsolateNode      = "isolate-node"
	ActionRestoreNode      = "restore-node"
	ActionRemoveNode       = "remove-node"
	ActionBeginAppUpload   = "begin-app-upload"
	ActionPutAppPart       = "put-app-part"
	ActionAbortAppUpload   = "abort-app-upload"
	ActionBeginApp         = "begin-app"
	ActionDownApp          = "down-app"

	// Node join (control.NodeInvitation / NodeSelection).
	ActionInviteNode  = "invite-node"
	ActionPromoteNode = "promote-node"

	// Built-in registries (control.RegistryPut / RegistrySelection).
	ActionPutRegistry    = "put-registry"
	ActionStartRegistry  = "start-registry"
	ActionStopRegistry   = "stop-registry"
	ActionDeleteRegistry = "delete-registry"

	// CD (control.AppCDChange / AppOverrideChange).
	ActionSyncApp         = "sync-app"
	ActionRecoverApp      = "recover-app"
	ActionReplanApp       = "replan-app"
	ActionConfigureAppCD  = "configure-app-cd"
	ActionPauseAppCD      = "pause-app-cd"
	ActionResumeAppCD     = "resume-app-cd"
	ActionAbandonAppSync  = "abandon-app-sync"
	ActionOverrideApp     = "override-app"
	ActionReleaseOverride = "release-app-override"

	// Shared tenant resources (real actions; the fake models creation only).
	ActionCreateTUNNetwork    = "create-tun-network"
	ActionConfigureNetworkDNS = "configure-network-dns"
	ActionProposeRoute        = "propose-route"
	ActionApproveRoute        = "approve-route"
	ActionWithdrawRoute       = "withdraw-route"
	ActionPlanNetworkChange   = "plan-network-change"
	ActionDrainNetwork        = "drain-network"
	ActionCancelNetworkChange = "cancel-network-change"
	ActionFenceNetworkChange  = "fence-network-change"
	ActionCommitNetworkChange = "commit-network-change"
	ActionReconfigureTUN      = "reconfigure-tun-network"
	ActionJoinTUN             = "join-tun-network"
	ActionLeaveTUN            = "leave-tun-network"
	ActionSetNetworkToggle    = "set-network-toggle"
	ActionBeginVolumeCreate   = "begin-volume-create"
	ActionRegisterFixedVolume = "register-fixed-volume"
	ActionBeginVolumeBackup   = "begin-volume-backup"
	ActionCancelVolumeBackup  = "cancel-volume-backup"
	ActionDeleteVolumeBackup  = "delete-volume-backup"
	ActionBeginVolumeRestore  = "begin-volume-restore"
	ActionCancelVolumeRestore = "cancel-volume-restore"
	ActionSetVolumeCapacity   = "set-volume-capacity"
	ActionDeleteVolume        = "delete-volume"
	ActionBeginVolumeMove     = "begin-volume-move"
	ActionCancelVolumeMove    = "cancel-volume-move"
	ActionDeleteRetained      = "delete-retained-volume"
	ActionUnregisterFixed     = "unregister-fixed-volume"
	ActionArchiveVolume       = "archive-volume"
	ActionCancelArchive       = "cancel-volume-archive"
	ActionUnarchiveVolume     = "unarchive-volume"
	ActionDiscardArchive      = "discard-volume-archive"
	ActionSetArchiveAdminKey  = "set-volume-archive-admin-key"
	ActionVaultInit           = "vault-init"
	ActionVaultCreate         = "vault-create"
	ActionVaultACL            = "vault-acl"
	ActionVaultMove           = "vault-move"
	ActionVaultRevoke         = "vault-revoke"
	ActionVaultRetire         = "vault-retire"
	ActionVaultApprovalAge    = "vault-approval-age"
	ActionVaultRegistryShared = "vault-registry-shared"

	// lifecycle (state check) scripts and the tenant policy
	ActionSetLifecyclePolicy    = "set-lifecycle-policy"
	ActionPutLifecycleScript    = "put-lifecycle-script"
	ActionRetireLifecycleScript = "retire-lifecycle-script"
	ActionDeleteLifecycleScript = "delete-lifecycle-script"

	// node storage roots and node limits (system administrator)
	ActionAddNodeStorage        = "add-node-storage"
	ActionSetNodeStoragePolicy  = "set-node-storage-policy"
	ActionSetNodeArchiveDefault = "set-node-archive-default"
	ActionDrainNodeStorage      = "drain-node-storage"
	ActionRemoveNodeStorage     = "remove-node-storage"
	ActionSetNodeQuota          = "set-node-quota"
	ActionRotateLedger          = "rotate-ledger"

	// tenant retirement (system administrator)
	ActionBeginTenantRetirement  = "begin-tenant-retirement"
	ActionFinishTenantRetirement = "finish-tenant-retirement"

	// REQ-4 (mock): own browser key registration / disable.
	ActionAddCredential     = "add-credential"
	ActionDisableCredential = "disable-credential"
)
