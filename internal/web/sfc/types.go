// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// View types. Field names follow the sfcd reply (docs/reference/unix-sockets.md,
// internal/cluster/control) or, for REQ-n methods, the REQUEST.md request text.
// They carry the subset of fields the web screens use; the real adapter maps
// the full product structs onto them.

// Page is one page of a paginated method. Pass Next as the next call's after
// argument; empty Next means the last page. Revision is the method's root
// revision for this page (e.g. AppsRootRevision). Pages with different
// revisions are not one snapshot.
type Page[T any] struct {
	Items    []T
	Next     string
	Revision uint64
	// Collection is the revision a create in this list is checked against
	// (Change.Expected): Networks.Revision (NetworkRevision) for resources,
	// the tenant's Vault tree revision (VaultTreeRevision) for vault, the
	// catalog revision (TenantMembersRevision) for tenant-members, which
	// volume-file-grant/-revoke carry. Zero for other methods.
	Collection uint64 `json:",omitempty"`
	// ApprovalRevision: vault only, sfcd's Reply.VaultApprovalRevision
	// (the realm's Approvals revision, Expected of vault-revoke-approval).
	ApprovalRevision uint64 `json:",omitempty"`
	// QuotaRevision: resources only, sfcd's Reply.QuotaRevision (a joined
	// read checks it stays the same across pages).
	QuotaRevision uint64 `json:",omitempty"`
}

// Whoami: `whoami`.
type Whoami struct {
	User UserView
	// RootRevision: the catalog root (control.CatalogKey). Sign with
	// RootFor(action): sfcd checks each command key against its own
	// root (userauth.Client.Prepare).
	RootRevision       uint64
	LedgerRootRevision uint64
	// Roots: root revision per control.CommandKey (control/apps,
	// control/vault, control/image-builds, …). The real adapter fills
	// them from the module query replies (AppsRootRevision, …).
	Roots map[string]uint64 `json:",omitempty"`
	// LedgerEpoch is ModuleEpoch (sfcd omits it while it is 1; the adapter
	// reports 1 then). rotate-ledger's Expected.
	LedgerEpoch uint64
	Session     Session
}

// RootFor: the root revision to sign action with (Roots by
// control.CommandKey, else RootRevision).
func (w Whoami) RootFor(action string) uint64 {
	if r, ok := w.Roots[control.CommandKey(action)]; ok {
		return r
	}
	if control.CommandKey(action) == control.StorageKey {
		return w.LedgerRootRevision
	}
	return w.RootRevision
}

// Node phases as reported in members (lifecycle.Phase text).
const (
	NodePhaseActive   = "active"
	NodePhaseIsolated = "isolated"
	NodePhasePending  = "pending"
	NodePhaseRemoved  = "removed"
)

// FixtureMember: the fake's seed server, one membership entry plus its
// lifecycle row; the fake builds the real `members` rows from it (real()).
type FixtureMember struct {
	ID         string
	Key        string // hex Ed25519 key
	Endpoint   string
	JoinID     string
	Revision   uint64
	Phase      string
	Voter      bool
	AdmitsWork bool
	// Cordoned: no new placement; tasks there stay.
	Cordoned     bool   `json:",omitempty"`
	CordonReason string `json:",omitempty"`
	// CordonedBy (username) / CordonedAt (RFC 3339 on the wire): REQ-50
	// (mock), cleared by uncordon-node.
	CordonedBy string     `json:",omitempty"`
	CordonedAt *time.Time `json:",omitempty"`
	// Identity: the server's latest identity rotation (NodeView.Identity),
	// set by rotate-node-identity in the fake.
	Identity *membership.IdentityRotationView `json:",omitempty"`
	// PendingOperation is the unfinished node operation ID, if any.
	PendingOperation string `json:",omitempty"`
	// Join is the membership phase (membership.Entry.Phase): invited →
	// learner → ready (installed and acknowledged; promote-node allowed,
	// Expected = Revision) → promoting → active.
	Join string `json:",omitempty"`
}

// Membership phases (membership.Phase).
const (
	JoinInvited   = "invited"
	JoinLearner   = "learner"
	JoinReady     = "ready"
	JoinPromoting = "promoting"
	JoinActive    = "active"
)

// NodeInvitation: `node-invitation`, the signed file `sfcd join` reads.
type NodeInvitation = membership.Invitation

// NodeInvite: invite-node's payload (control.NodeInvitation); promote-node
// takes control.NodeSelection.
type NodeInvite = control.NodeInvitation

// MembersPage: `members` as sfcd answers it. Entries (Reply.Members) are
// the membership directory, 8 a page by Peer.ID (Next = the last ID);
// Nodes (Reply.NodeLifecycle) are the lifecycle rows of the entries on the
// page that have one (an invited or learner server has none yet).
type MembersPage struct {
	Entries                []membership.Entry
	Nodes                  []membership.NodeView
	Next                   string
	RootRevision           uint64 // MembersRootRevision
	NodeRuntimeRevision    uint64
	NodeOperationEpoch     uint64 // node operation (topology) epoch, not the ledger
	NodeConfigurationIndex uint64
	NodeVoters             int
	NodeQuorum             int
}

// FixtureNodeSummary: the fake's seed server summary (seconds). The fake
// builds the real node-summary rows (NodeSummaryView) from it; not a Conn
// type. Containers, ObserveLimitSeconds and the cordon fields are filled
// on read.
type FixtureNodeSummary struct {
	Node       string
	Status     string // ready / degraded / unreachable / isolated
	Role       string // leader / voter / non-voter
	CPUPercent float64
	MemUsed    uint64
	MemTotal   uint64
	DiskUsed   uint64
	DiskTotal  uint64
	// Containers counts only tasks the caller may read.
	Containers int
	ObservedAt int64
	// ObserveLimitSeconds (REQ-53, real: control.NodeSummaryView, today
	// 120 s): how long after ObservedAt sfcd calls the server unreachable
	// (the same rule as Status). Cluster-wide; the UI shows "N초 넘게 소식
	// 없음" from it.
	ObserveLimitSeconds int64
	// CordonedBy / CordonedAt / Scheduling: REQ-50 (real shape), as on the
	// members row; empty when not cordoned.
	CordonedBy string `json:",omitempty"`
	CordonedAt string `json:",omitempty"`
	Scheduling membership.CordonView
}

// FixtureStorageRoot: the fake's seed storage root. The fake builds the
// real node-storage rows (nodestorage.Root) from it; not a Conn type.
type FixtureStorageRoot struct {
	Node, ID, Path       string
	Tenants              []string
	AllTenants           bool
	CapacityBytes        uint64
	Generation, Revision uint64
	Draining             bool
	// Attested: the node reported the root's filesystem (Attestation set);
	// only then can fixed volumes be made on it. Closed: after a drain the
	// node reported the root closed (Closed set); remove needs it.
	Attested, Closed bool
	// ArchiveDefault: the node's default Volume archive location.
	ArchiveDefault bool
}

// StorageSpace: `node-storage-space` — the node's signed-off space sample
// (Reply.NodeStorageSpace) and the ledger index it was read at
// (Reply.NodeStorageObservedIndex).
type StorageSpace struct {
	nodestorage.Space
	ObservedIndex uint64
}

// FixtureDisk: a fake seed disk row (seconds). The fake builds the real
// node-disks rows (NodeDiskView) from it; it is not a Conn type.
type FixtureDisk struct {
	Node, Mount, Device, FSType string
	Purpose                     string // system / container-runtime / storage-root
	StorageRootID               string `json:",omitempty"`
	Total, Used, Free           uint64
	InodesFree                  uint64
	ObservedAt                  int64
}

// FixtureLink: a fake seed link row (seconds). The fake builds the real
// mesh-links rows (MeshLinkView) from it; it is not a Conn type.
type FixtureLink struct {
	NodeA, NodeB    string
	State           string // up / degraded / down / pending
	RTTMillis       float64
	LossPercent     float64
	LastHandshakeAt int64
	LastChangeAt    int64
	ObservedBy      string
	ObservedAt      int64
}

// FixtureRaft: the fake's seed raft state (seconds). The fake builds the
// real raft-status reply (userauth.RaftStatus) from it; not a Conn type.
type FixtureRaft struct {
	Leader             string
	Term               uint64
	CommitIndex        uint64
	ConfigurationIndex uint64
	Stale              bool
	Servers            []FixtureRaftServer
	LastSnapshotIndex  uint64
	LastSnapshotAt     int64
	Elections          []FixtureRaftElection
	// LastCompaction: REQ-23 (mock) the last manual raft-compact.
	LastCompaction *FixtureRaftCompaction `json:",omitempty"`
}
type FixtureRaftServer struct {
	Node          string
	Suffrage      string // voter / non-voter
	MatchIndex    uint64
	AppliedIndex  uint64
	Lag           uint64
	LogBytes      uint64
	LastContactAt int64
	// REQ-23 (mock): snapshot position, log entries kept, bolt file size.
	SnapshotIndex uint64 `json:",omitempty"`
	LogEntries    uint64 `json:",omitempty"`
	LogFileBytes  uint64 `json:",omitempty"`
}
type FixtureRaftElection struct {
	Term   uint64
	Leader string
	At     int64
	Reason string
}

// ResourceEntry: `resources` (control.ResourceEntry, one of the typed parts).
type ResourceEntry struct {
	Key     string
	Tenant  string
	Network *Network   `json:",omitempty"`
	Route   *Route     `json:",omitempty"`
	Bridge  *Bridge    `json:",omitempty"`
	Limit   *NodeLimit `json:",omitempty"`
}
type Network struct {
	Name, Kind, CIDR string // Kind: bridge / tun
	Nodes            []string
	Revision         uint64
	// DNS is the network's managed DNS policy (tun only), nil when never
	// configured. Revision is configure-network-dns's Expected.
	DNS *NetworkDNS `json:",omitempty"`
	// Members: one tenancy.Network row per server (a bridge network has
	// one, a TUN network one per member), with its pending change.
	Members []NetworkMember `json:",omitempty"`
	// Toggles: the TUN network's toggles that are on (tenancy.NetworkToggle,
	// e.g. "local": kept on one server). set-network-toggle changes them.
	Toggles []tenancy.NetworkToggle `json:",omitempty"`
	// Apps / Standalones: how many apps and standalone containers use it
	// (REQ-35 mock, filled on read; NetworkUsers lists them).
	Apps        int `json:",omitempty"`
	Standalones int `json:",omitempty"`
}

// NetworkMember is one member row (tenancy.Network) and its change
// (control.NetworkChangeStatus).
type NetworkMember struct {
	Node, ID string
	CIDR     string
	Tunnel   string `json:",omitempty"`
	// Resolver: the managed DNS address containers on this member ask
	//, when DNS is on.
	Resolver string `json:",omitempty"`
	// DNS is this member's own managed DNS readback (the network's DNS
	// shows one member's; each server observes its own).
	DNS                  *MemberDNS `json:",omitempty"`
	Generation, Revision uint64
	Draining             bool
	Change               *NetworkChange `json:",omitempty"`
	// Source is the row itself; the daemon builds change payloads from it.
	Source tenancy.Network `json:"-"`
}

// NetworkChange: control.NetworkChangeStatus (Target reduced to its pool).
type NetworkChange struct {
	ID                                   string
	Generation, Revision, TargetRevision uint64
	Phase                                string // reserved / draining / fenced / committed / cancelled
	TargetCIDR                           string
	MetadataOnly                         bool `json:",omitempty"`
}

// MemberDNS is one server's managed DNS readback for a network member.
type MemberDNS struct {
	State     string
	Ready     *bool `json:",omitempty"`
	Resolvers []string
}

// NetworkDNS: a configure-network-dns policy (services.ManagedDNSPolicy).
// REQ-36 (real): sfcd's `resources` network row carries
// control.DNSPolicyView{Revision, Policy, Resolvers, Ready?, State}; this is
// that row flattened for the screen. Resolvers are the address:53 the DNS
// owner really listens on (empty when not running); Ready is omitted until
// the new revision is observed. The fake answers ready / stopped.
type NetworkDNS struct {
	Zone        string
	Enabled     bool
	Revision    uint64
	Upstreams   []string // address:port
	TTL         uint32   `json:"ttl"`
	NegativeTTL uint32   `json:"negativeTtl"`
	Reverse     bool
	// Policy is the whole policy; a change keeps the fields the screen
	// does not set (client zone, transports, limits).
	Policy    services.ManagedDNSPolicy `json:"-"`
	Resolvers []string
	Ready     *bool `json:",omitempty"`
	State     string
}

// Route: a cross-tenant route (`resources` route/<source tenant>/<id>,
// tenancy.Route). It is visible to readers of either side.
type Route struct {
	ID, SourceTenant     string
	Source, Destination  RouteSide
	Protocol             string // tcp / udp
	Ports                []RoutePorts
	Phase                string // pending / active / revoking
	Approvals            []RouteApproval
	Generation, Revision uint64
	// Raw is the sfcd row.
	Raw tenancy.Route `json:"-"`
}

// RouteSide: one endpoint (tenancy.Binding). Network is the member network
// ID, Name its network name (control.RouteNames). CIDR is its pool on this
// tenant's own side only: sfcd leaves the other tenant's prefix out.
type RouteSide struct {
	Tenant, Network, Node string
	Name                  string `json:",omitempty"`
	CIDR                  string `json:",omitempty"`
}
type RoutePorts struct{ First, Last uint16 }
type RouteApproval struct{ Tenant, User string }

// RouteView converts a sfcd route row and its network names.
func RouteView(r tenancy.Route, names control.RouteNames) Route {
	side := func(b tenancy.Binding, name string) RouteSide {
		v := RouteSide{Tenant: b.Tenant, Network: b.Network, Node: b.Node, Name: name}
		if b.Prefix.IsValid() {
			v.CIDR = b.Prefix.String()
		}
		return v
	}
	v := Route{ID: r.ID, SourceTenant: r.Source.Tenant, Source: side(r.Source, names.Source), Destination: side(r.Destination, names.Destination), Protocol: "tcp",
		Ports: []RoutePorts{}, Phase: string(r.Phase), Approvals: []RouteApproval{}, Generation: r.Generation, Revision: r.Revision, Raw: r}
	if r.Protocol == 17 {
		v.Protocol = "udp"
	}
	for _, p := range r.Ports {
		v.Ports = append(v.Ports, RoutePorts{p.First, p.Last})
	}
	for _, a := range r.Approvals {
		v.Approvals = append(v.Approvals, RouteApproval{a.Tenant, a.User})
	}
	return v
}

type NodeLimit struct {
	Node          string
	CPUs          float64
	MemoryBytes   uint64
	MaxContainers int
	Revision      uint64
	// The rest of tenancy.NodeLimit; set-node-quota replaces the whole
	// limit, so an edit of CPUs/memory carries these over.
	Networks              uint64
	MaxConsumers          int `json:",omitempty"`
	PacketQueuePackets    int `json:",omitempty"`
	PacketQueueBytes      int `json:",omitempty"`
	MaxIngressInstances   int `json:",omitempty"`
	MaxIngressListeners   int `json:",omitempty"`
	MaxIngressRequests    int `json:",omitempty"`
	MaxIngressConnections int `json:",omitempty"`
	IngressBufferBytes    int `json:",omitempty"`
}

// OperationSummary is the app row's last operation.
type OperationSummary = deployment.OperationSummary

// AppView: `apps` (control.AppView subset).
type AppView struct {
	Tenant, App, Deployment string
	Revision                uint64
	Operation               OperationSummary
	Claims                  int
	Health                  string `json:",omitempty"` // healthy / degraded / unhealthy / unknown
	// HealthReason: the first cause when Health is not healthy (sfcd
	// deployment.HealthReason: Code, Key, Kind, Name, Node, Exit, Failure).
	HealthReason *deployment.HealthReason `json:",omitempty"`
	ObservedAt   uint64                   `json:",omitempty"`
	Retiring     bool                     `json:",omitempty"`
	CD           *AppCD                   `json:",omitempty"`
}
type AppCD struct {
	Revision   uint64
	Repository string
	Branch     string
	Mode       string // automatic / manual
	Paused     bool
	Running    string `json:",omitempty"` // commit
	Candidate  string `json:",omitempty"`
	// CandidateDigest selects the candidate for Group approval
	// (AppApprovalSelection.Candidate); zero when there is none.
	CandidateDigest [32]byte `json:",omitempty"`
	SourceError     string   `json:",omitempty"`

	// From control.AppCDView (the apps row's CD view; the real adapter maps
	// it, the fake derives it). Expected of the CD actions is Revision;
	// configure-app-cd also carries PolicyRevision, override actions the
	// field's revision. Target is the execution intent target the CLI puts
	// in AppCDChange.Target; Registration the registered origin's digest.
	PolicyRevision, OverrideRevision uint64
	Principal                        string                          `json:",omitempty"`
	Policy                           *deployment.DeliveryDeclaration `json:",omitempty"`
	Blocked                          string                          `json:",omitempty"` // unavailable / current-inputs / current-authority / group-approval
	// Status (deployment.DeliveryStatus subset).
	Sync, EffectiveSync, Operation, Health, Source string     `json:",omitempty"`
	Transition, TransitionPhase                    string     `json:",omitempty"`
	LastSuccessCommit, ActiveOperation             string     `json:",omitempty"`
	OverridePaths                                  [][]string `json:",omitempty"`
	ChangeCount, OverrideCount                     int        `json:",omitempty"`
	Target                                         [32]byte   `json:"-"`
	Registration                                   [32]byte   `json:"-"`
	// Approvers: user IDs that may approve or reject this app's
	// candidates without ManageCD (grant-/revoke-cd-approver).
	Approvers []string `json:"-"`
	// Local services (put-app-local-services): names, revision, last
	// actor and the target a local change pins.
	LocalServices []string `json:"-"`
	LocalRevision uint64   `json:"-"`
	LocalActor    string   `json:"-"`
	LocalTarget   [32]byte `json:"-"`
}

// AppCDField: `app-cd-field`, one overridable field of a CD app.
type AppCDField = control.AppCDField

// AppOperation: `app-operation`.
type AppOperation struct {
	Tenant, App, ID string
	Status          string // pending / running / succeeded / failed / unknown
	Failed          bool
	Submitter       string
	StartedAt       int64
	CompletedAt     int64
	Steps           []string
}

// AppUploadView: `app-uploads`.
type AppUploadView = control.AppUploadView

// AppSource: REQ-5 (mock) `app-source` — the accepted app.yaml original.
type AppSource struct {
	Tenant, App string
	Version     uint64
	Document    []byte
	Digest      [32]byte
	Submitter   string
	Operation   string
	AcceptedAt  int64
	// Kind: who made the version: "" = a user's up,
	// "cd" = a CD sync, "web-local" = a change of the web's local services.
	Kind string `json:",omitempty"`
}

// AppRevision: REQ-5 (mock) `app-revisions` row.
type AppRevision struct {
	Version    uint64
	Digest     [32]byte
	Submitter  string
	Operation  string
	Status     string
	AcceptedAt int64
	Kind       string `json:",omitempty"` // as AppSource.Kind
}

// AppPlanRequest: `app-plan-stream` input (document + options).
type AppPlanRequest struct {
	Tenant     string
	Document   []byte
	Project    string
	Deployment string
	Node       string
	Diff       bool
	// Force lets a route share a host+prefix another app of the tenant
	// serves (`sfcli app deploy --force`); the web asks the person first.
	Force bool `json:",omitempty"`
	// Move: a volume move plan (`sfcli volume move-plan`). The reply's
	// AppPlan.Move holds the decoded control.AppMovePlan; Data is then
	// the whole move plan and Move.Artifact the app artifact to upload.
	Move *control.AppMovePlanRequest `json:",omitempty"`
	// Standalone: REQ-29 `standalone-plan` in sfcd's shape. Document is
	// then a compose document with exactly one service; AppPlan.App is
	// the internal scope to upload under.
	Standalone *control.StandaloneDefinition `json:",omitempty"`
}

// AppPlan: the decoded plan. Data is the full plan bytes (all parts joined and
// digest-checked); Services/Diff are a parsed summary for display.
type AppPlan struct {
	Digest   [32]byte
	Length   int
	Data     []byte
	App      string
	Services []PlannedService
	Diff     string `json:",omitempty"`
	// Changes: the diff as rows (AppPlanRequest.Diff), in sfcd's order.
	Changes []PlanChange         `json:",omitempty"`
	Move    *control.AppMovePlan `json:",omitempty"`
	// Standalone: the standalone plan summary when the request had
	// AppPlanRequest.Standalone (impact, limits, changes).
	Standalone *StandalonePlan `json:",omitempty"`
}

// PlanChange is one row of a plan diff. Interruption, for a replaced
// Task, is sfcd's code for why its service stops while it is replaced
// (VOLUME_WRITER, HOST_PORT, STATIC_ADDRESS, SINGLE_INSTANCE, VOLUME_MOVE,
// and later codes such as QUOTA); "" when other replicas serve.
type PlanChange struct {
	Action, Key  string
	Reason       string `json:",omitempty"`
	Interruption string `json:",omitempty"`
}

type PlannedService struct {
	Name, Image, Node string
	// Nodes: REQ-8 (mock) replica servers in update order (one per
	// server, replaced one at a time); empty for a single task.
	Nodes []string `json:",omitempty"`
	// SecretEnv: REQ-16 (mock) variables fed a secret value; a secret
	// rotation then needs a new task generation (the web says so).
	SecretEnv []string `json:",omitempty"`
	Change    string   // add / update / remove / keep
}

// Task: REQ-1 (mock) `tasks`.
type Task struct {
	Tenant, App, Service string
	// Instance is the logical task key used by container-observe Selection.
	Instance   string
	Node       string
	Image      string
	Generation uint64
	Desired    string // running / stopped
	Observed   string // running / exited / restarting / created / missing
	Health     string // healthy / unhealthy / starting / none
	Restarts   int
	ExitCode   int   `json:",omitempty"`
	StartedAt  int64 `json:",omitempty"`
	ObservedAt int64
	LastCheck  string `json:",omitempty"`
}

// TaskFilter selects tasks; empty fields match all within the caller's scope.
type TaskFilter struct {
	Tenant, App, Node string
}

// VolumeView: a `volumes` row (Scope Tenant/App/ID, Owner.Node, Kind
// "node-fixed" or "", Retained sources of finished moves).
type VolumeView = control.VolumeView

// FixtureBackup: a fake seed backup (seconds). The fake builds the real
// volume-backups row (control.VolumeBackupView) from it; it is not a Conn
// type.
type FixtureBackup struct {
	Key, Tenant, Volume, ID, Node, Phase string
	Revision, Bytes                      uint64
	CreatedAt                            int64
	Failure                              string
}

// VaultView: `vault` public metadata (no secret values).
type VaultView struct {
	Realm, Path, Kind string // Kind: object / group
	Profile           string
	Keys              []string
	Revision          uint64
	Group             string `json:",omitempty"`
	// Protected: a Group with a password (verifier) set.
	Protected bool `json:",omitempty"`
	// ID / Parent: the secrets.Object identity (Path is its display path);
	// the root group's ID is the tenant. Status: active / password-pending
	// / revoking / retired / reference-pending.
	ID, Parent     string
	Status         string
	ACL            VaultACL
	PendingWrite   string `json:",omitempty"`
	MaxApprovalAge int64  `json:",omitempty"` // seconds, groups
}

// VaultACL: secrets.ACL (sorted name lists; TenantGrants only on a shared
// realm's root).
type VaultACL struct {
	Users, Services, DenyUsers, DenyServices []string
	TenantGrants                             []string `json:",omitempty"`
}

// LifecycleEntry: `lifecycles` item. Key "policy" carries the tenant's
// current policy (RecordRevision = policy revision);
// "script/{name}/{revision:%020d}" carries one source version (RecordRevision
// = the script record's CAS revision, SourceRevision = that version).
type LifecycleEntry = control.LifecycleEntry

// FixtureRegistry: one built-in registry in the fake's state. The fake
// answers `registries` with its control.RegistryView (view). Endpoint is
// the fixture authority until a spec carries one; Name and Repositories
// are fixture extras the real rows do not have. Not a Conn type.
type FixtureRegistry struct {
	Tenant, ID, Name, Endpoint string
	Revision, Generation       uint64
	Active                     bool
	Repositories               int

	Node, Address              string `json:",omitempty"`
	Volume                     string `json:",omitempty"` // Spec.Volume.ID
	Enabled, Deleted, Draining bool   `json:",omitempty"`
	// ObservedAt: the node's report that the current spec serves (Unix
	// ms); 0 = no observation.
	ObservedAt int64 `json:",omitempty"`
	// Maintenance: REQ-18 list summary (pending job, last GC).
	Maintenance *control.RegistryMaintenanceSummary `json:",omitempty"`
	Spec        registry.Specification              `json:"-"`
}

// view is the row in sfcd's real shape.
func (r FixtureRegistry) view() control.RegistryView {
	v := control.RegistryView{Spec: r.Spec, Revision: r.Revision, Generation: r.Generation, Deleted: r.Deleted, Draining: r.Draining, Active: r.Active, Maintenance: r.Maintenance}
	if r.ObservedAt != 0 {
		v.Observation = &control.RegistryObservation{At: r.ObservedAt}
	}
	return v
}

// FixtureEvent: the fake's seed observation event (seconds). The fake
// gives it as the real events row (eventlog.Item): Target fields to
// eventlog.Target, Detail text to Detail.Reason, CD / Ingress /
// ShellClosedBy to their Detail and Target fields. Target text is not
// sent (sfcd has none). Not a Conn type.
type FixtureEvent struct {
	Cursor string
	Time   int64
	Scope  string // tenant / app / node / cluster
	Tenant string `json:",omitempty"`
	App    string `json:",omitempty"`
	Node   string `json:",omitempty"`
	// Network: the TUN network of a tunnel-down / tunnel-up event,
	// with Tenant; one event per network the node pair carries.
	Network string `json:",omitempty"`
	// PairID: eventlog Target.PairID, the sorted node pair "node-a/node-b"
	// (same as mesh-links and tunnel-reconnect plans). Target repeats it.
	PairID string `json:",omitempty"`
	Kind   string // task-restarted / task-exited / probe-failed / node-unreachable / ...
	Target string
	Detail string
	CD     *CDEvent `json:",omitempty"` // REQ-25 cd-* kinds
	// Ingress: REQ-22 G ingress-* fault kinds (mock).
	Ingress *IngressEvent `json:",omitempty"`
	// ShellClosedBy: REQ-68 (mock) node-shell-closed by close-node-shell
	// or a policy change: who closed it.
	ShellClosedBy *NodeShellUser `json:",omitempty"`
}

// ContainerSelection is the logical task key (containerops Selection).
// Standalone selects a standalone container by name instead of
// an app task; App/Service/Instance are then ignored.
type ContainerSelection struct {
	App, Service, Instance string
	Standalone             string `json:",omitempty"`
}

// ContainerQuery: `container-observe` (finite logs/top/stats).
type ContainerQuery struct {
	Selection ContainerSelection
	Kind      string // logs / top / stats
	Tail      int
	Stdout    bool
	Stderr    bool
	Since     int64 // Unix seconds (sfcd: RFC 3339)
	Until     int64
}

// ContainerResult: `container-observe` result subset.
type ContainerResult struct {
	Selection  ContainerSelection
	Node       string
	NativeID   string
	Kind       string
	Logs       []LogLine       `json:",omitempty"`
	Truncated  bool            `json:",omitempty"`
	LogDriver  string          `json:",omitempty"`
	Processes  []Process       `json:",omitempty"`
	Stats      *ContainerStats `json:",omitempty"`
	ObservedAt int64
	ViewIndex  uint64
}
type LogLine struct {
	Time   int64
	Stream string // stdout / stderr
	Text   string
}
type Process struct {
	PID     int
	User    string
	Command string
	CPU     float64
	MemRSS  uint64
}
type ContainerStats struct {
	CPUPercent float64
	MemUsed    uint64
	MemLimit   uint64
	NetRxBytes uint64
	NetTxBytes uint64
	BlockRead  uint64
	BlockWrite uint64
	PIDs       int
}
