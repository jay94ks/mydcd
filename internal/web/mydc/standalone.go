// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"

	"github.com/jay94ks/mydcd/internal/containerops"
)

// REQ-29 standalone containers (mydcd done, docs/reference/standalone.md):
// one container owned by a tenant, not by an app.
const (
	ActionStandaloneUp      = "standalone-up"
	ActionStandalonePin     = "standalone-pin"
	ActionStandaloneExtend  = "standalone-extend"
	ActionStandaloneStop    = "standalone-stop"
	ActionStandaloneStart   = "standalone-start"
	ActionStandaloneRestart = "standalone-restart"
	ActionStandaloneRemove  = "standalone-remove"
)

const (
	LimitUserTemp = "limit-user-temp"
	LimitTenant   = "limit-tenant"
	LimitNode     = "limit-node"
)

// mydcd's standalone limit refusals (deployment.InputError codes): the real
// up order (AppPlan with Standalone) fails with Error.InputCode set to one of
// these, and a standalone-up that crosses a limit after the plan is
// ConditionFailed.
const (
	StandaloneUserLimit   = "STANDALONE_USER_LIMIT"   // the caller's temp containers in the tenant (8)
	StandaloneTenantLimit = "STANDALONE_TENANT_LIMIT" // all standalone containers in the tenant (32)
	StandaloneNodeLimit   = "STANDALONE_NODE_LIMIT"   // all standalone containers on the server (64)
)

// LimitInputCode returns the frontend error code of a mydcd standalone
// limit refusal (Error.InputCode), or "".
func LimitInputCode(inputCode string) string {
	switch inputCode {
	case StandaloneUserLimit:
		return LimitUserTemp
	case StandaloneTenantLimit:
		return LimitTenant
	case StandaloneNodeLimit:
		return LimitNode
	}
	return ""
}

// LimitCode returns the error-code name of a mock-only result code
// (remove-node refusals, REQ-18 image-in-use), or "" for the real state
// codes. Same as ResultErrorCode. Standalone limits are LimitInputCode.
func LimitCode(c ResultCode) string { return ResultErrorCode(c) }

// ResultErrorCode returns the error-code name of a mock-only result code, or
// "" for the real state codes.
func ResultErrorCode(c ResultCode) string {
	switch c {
	case ResultImageInUse:
		return ImageInUse
	}
	return state.RejectionReason(c)
}

const (
	LifetimeTemp   = "temp"
	LifetimeFixed  = "fixed"
	ModeShell      = "shell"
	ModeEntrypoint = "entrypoint"
)

// REQ-61 standalone-extend (mydcd's shape, docs/reference/unix-sockets.md
// '임시 단독 컨테이너 TTL 연장'): payload control.StandaloneExtendChange{Tenant,
// Name, Scope, Operation, CreatedAt, PreviousExpiresAt, TTLSeconds, Target}
// from the StandaloneView (Scope, CreatedAt, ExpiresAt, Target), Expected =
// its Revision; mydcd uses the management-target CAS for it
// (control.StandaloneCASAllowed). Tenant Deploy and, for another
// user's temp, a manager. The new expiry is the signed At + TTLSeconds: above
// the current expiry and at most CreatedAt + 86400. A refused one is
// ConditionFailed; read why with StandaloneExtensionOutcome. A new submission
// after the current expiry is an error with CodeConflict and the message
// STANDALONE_TTL_EXPIRED (no result).
const StandaloneTTLExpired = "STANDALONE_TTL_EXPIRED"

// StandaloneExtensionOutcome is what mydcd's reply adds to a standalone-extend
// result (Reply.StandaloneExtension / StandaloneExtensionCode, the CLI's
// extension / extension_applied / extension_code): the ORIGINAL signed
// coordinates' arithmetic. Applied only when res.Code is Applied; Code names
// the refusal (STANDALONE_TTL_LIMIT / _EXPIRED / _NOT_INCREASED) when known.
// Pass only a result that was found; an unknown one says nothing.
type StandaloneExtensionOutcome struct {
	Extension control.StandaloneExtensionPlan
	Applied   bool
	Code      string `json:",omitempty"`
}

// StandaloneExtension computes the outcome of a standalone-extend original
// from its signed At and payload, as mydcd does for the reply.
func StandaloneExtension(op SignedOp, res Result) (StandaloneExtensionOutcome, error) {
	u, err := DecodeOperation(op)
	if err != nil {
		return StandaloneExtensionOutcome{}, err
	}
	var q control.StandaloneExtendChange
	if u.Change.Action != ActionStandaloneExtend || !control.StandaloneCASAllowed(u.Change) || json.Unmarshal(u.Change.Payload, &q) != nil {
		return StandaloneExtensionOutcome{}, errors.New("mydc: not a standalone-extend operation")
	}
	plan, err := control.PlanStandaloneExtension(q.CreatedAt, q.PreviousExpiresAt, u.At, q.TTLSeconds)
	if errors.Is(err, access.ErrInvalid) {
		return StandaloneExtensionOutcome{}, err
	}
	out := StandaloneExtensionOutcome{Extension: plan, Applied: res.Code == ResultApplied}
	if !out.Applied && err != nil {
		out.Code = err.Error()
	}
	return out, nil
}

// StandaloneView: REQ-29 (mock) `standalone-list` / `standalone-get` row.
type StandaloneView struct {
	Name, Tenant string
	Lifetime     string // temp / fixed
	Mode         string // shell / entrypoint
	Image, Node  string
	// State: running / exited / restarting / created / missing / pending /
	// removed (ended or removed; listed for 1 h with EndedAt).
	State    string
	ExitCode *int `json:",omitempty"`
	Restarts int
	// RestartPolicy: fixed only (no / on-failure / always).
	RestartPolicy string `json:",omitempty"`
	// ExpiresAt, GraceSeconds, DisconnectedAt: temp only. DisconnectedAt is
	// when the last connection closed (0 while connected).
	ExpiresAt      int64 `json:",omitempty"`
	GraceSeconds   int   `json:",omitempty"`
	DisconnectedAt int64 `json:",omitempty"`
	Connections    int
	Owner          string // user ID that created it
	Revision       uint64
	Generation     uint64
	Document       []byte // definition source YAML
	CreatedAt      int64  // Unix seconds, as all times here
	EndedAt        int64  `json:",omitempty"`
	ObservedAt     int64
	// Selection opens logs/top/stats/exec exactly like an app Task.
	Selection ContainerSelection
	// Target: mydcd's management target (digest32), signed into
	// standalone-pin/-remove (control.StandaloneChange.Target) and checked
	// against the stop/start/restart plan. It changes with accepted
	// management intent, not with connection samples.
	Target [32]byte
	// Scope: mydcd's internal workload name (Metadata.Scope), fixed for
	// life; standalone-extend signs it.
	Scope string
	// RemainingSeconds: temp only, until the current expiry (mydcd's
	// StandaloneView.RemainingSeconds).
	RemainingSeconds int64 `json:",omitempty"`
}

// StandaloneViewOf flattens mydcd's standalone-list/-get row
// (control.StandaloneView) into the web's row. document is the stored
// definition read through app-source (nil when not read). State comes from
// the first Task's Observed; with no Task it is "pending" while Desired is
// running and "exited" once stopped, and "removed" when cleanup has started.
// mydcd has no EndedAt; the row keeps 0.
func StandaloneViewOf(tenant string, v control.StandaloneView, document []byte) StandaloneView {
	m := v.Metadata
	out := StandaloneView{Name: m.Name, Tenant: tenant, Lifetime: m.Lifetime, Mode: m.Mode, Node: m.Node, Connections: m.Connections,
		Owner: m.Creator, Revision: m.Revision, CreatedAt: m.CreatedAt, Selection: ContainerSelection{Standalone: m.Name}, Target: v.Target,
		Scope: m.Scope, Document: document, State: "pending"}
	if m.Lifetime == LifetimeTemp {
		out.ExpiresAt, out.GraceSeconds, out.DisconnectedAt, out.RemainingSeconds = m.ExpiresAt, int(m.GraceSeconds), m.DisconnectedAt, v.RemainingSeconds
	} else {
		out.RestartPolicy = m.Restart
	}
	if m.Desired == "stopped" {
		out.State = "exited"
	}
	if len(v.Tasks) > 0 {
		t := v.Tasks[0]
		out.Image, out.Generation, out.ObservedAt = t.Image, t.Generation, int64(t.ObservedAt)
		if t.Observed != "" {
			out.State = t.Observed
		}
		if t.RestartCount != nil {
			out.Restarts = int(*t.RestartCount)
		}
		if t.ExitCode != nil {
			c := int(*t.ExitCode)
			out.ExitCode = &c
		}
	}
	if m.Cleanup != nil {
		out.State = "removed"
	}
	return out
}

// StandalonePlan: REQ-29 (mock) `standalone-plan`.
type StandalonePlan struct {
	Name   string
	Digest [32]byte // SHA-256 of the planned flat definition
	// Revision is the current StandaloneView.Revision (Change.Expected); 0 =
	// the name is new.
	Revision uint64
	Create   bool
	// Recreate: the container is rebuilt (image, command, node, mode ...).
	Recreate bool
	Changes  []StandaloneChange
	Impact   []StandaloneImpact
	Limits   StandaloneLimits
}

// StandaloneChange is one changed definition field (before/after display).
type StandaloneChange struct {
	Field, Before, After string
}

// StandaloneImpact: Kind network / volume / ingress / limit. Blocking means
// standalone-up will be refused as it stands.
type StandaloneImpact struct {
	Kind, Target, Detail string
	// Code: mydcd's refusal code when there is one (VolumeWriterConflict).
	Code     string `json:",omitempty"`
	Blocking bool
}

// VolumeWriterConflict: mydcd refuses a mount that writes beside another
// task's use of the volume, or reads beside another task's writer.
const VolumeWriterConflict = "VOLUME_WRITER_CONFLICT"

// StandaloneLimits: Mine = the caller's temp containers in the tenant, Node
// = standalone containers of every tenant on the target server.
type StandaloneLimits struct {
	Mine, MineMax, Tenant, TenantMax int
	Node, NodeMax                    int
}

// The fake's internal task form of a standalone container (Task.App and
// Task.Instance). It never reaches the wire: Ops and stream targets use
// mydcd's Standalone field. App tasks never use an Instance with this prefix.
const (
	standaloneApp    = "standalone"
	standalonePrefix = "standalone:"
)

// Ops returns the containerops form used in signed stream intents. A
// standalone container is mydcd's Selection{Standalone: name}; its target
// carries Standalone and the internal scope as App.
func (s ContainerSelection) Ops() containerops.Selection {
	if s.Standalone != "" {
		return containerops.Selection{Standalone: s.Standalone}
	}
	return containerops.Selection{App: s.App, Service: s.Service, Instance: s.Instance}
}

func selectionOf(app, service, instance string) ContainerSelection {
	if app == standaloneApp && instance == standalonePrefix+service {
		return ContainerSelection{Standalone: service}
	}
	return ContainerSelection{App: app, Service: service, Instance: instance}
}
