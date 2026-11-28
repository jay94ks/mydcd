// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/secrets"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

const AppsKey = "control/apps"
const maxApps = 64
const maxAppUploads = 32
const maxAppCheckpoint = 16 << 20

type AppUploadBegin struct {
	Tenant, App, Deployment, ID string
	Length                      int
	Digest                      [32]byte
}
type AppUploadPart struct {
	Tenant, ID string
	Index      int
	Data       []byte
}
type AppUploadSelection struct {
	Tenant, ID string
	User       string `json:",omitempty"`
}
type AppBegin struct {
	Standalone                                 *StandaloneDefinition `json:",omitempty"`
	Target                                     *[32]byte             `json:",omitempty"`
	Tenant, App, Deployment, Upload, Operation string
	Prune                                      bool
	DefaultNode                                string `json:",omitempty"`
	// DisableCD confirms that deploying a file without x-sfc.cd turns the
	// app's CD off (the person said yes, or gave --force).
	DisableCD bool `json:",omitempty"`
}
type AppDown struct {
	Tenant, App, Operation string
	Target                 *[32]byte `json:",omitempty"`
}

func appDownTarget(origin UserOperation) [32]byte {
	return sha256.Sum256(append([]byte("sfc-app-down-target-1\x00"), OperationBytes(origin)...))
}

type appEntry struct {
	Standalone        *StandaloneMetadata  `json:",omitempty"`
	Local             *AppLocalGrant       `json:",omitempty"`
	LocalEdit         *UserOperation       `json:",omitempty"`
	CDHistory         []AppCDHistoryRecord `json:",omitempty"`
	CDHistoryNext     uint64               `json:",omitempty"`
	CDDecision        *AppCDDecision       `json:",omitempty"`
	TaskRestarts      []TaskRestartRecord  `json:",omitempty"`
	LastVersion       uint64               `json:",omitempty"`
	Versions          []appVersion         `json:",omitempty"`
	Inventory         deployment.Inventory
	Origin            UserOperation
	Down              *UserOperation               `json:",omitempty"`
	Compacted         *deployment.OperationSummary `json:",omitempty"`
	Delivery          *deployment.Delivery
	DeliveryInput     *AppDeliveryInput
	Sync, PendingSync *AppDeliverySync
}
type appRow struct {
	Standalone    *StandaloneMetadata  `json:",omitempty"`
	Local         *AppLocalGrant       `json:",omitempty"`
	LocalEdit     *UserOperation       `json:",omitempty"`
	CDHistory     []AppCDHistoryRecord `json:",omitempty"`
	CDHistoryNext uint64               `json:",omitempty"`
	CDDecision    *AppCDDecision       `json:",omitempty"`
	TaskRestarts  []TaskRestartRecord  `json:",omitempty"`
	LastVersion   uint64               `json:",omitempty"`
	Versions      []appVersion         `json:",omitempty"`
	Inventory     json.RawMessage      `json:",omitempty"`
	Origin        UserOperation
	Down          *UserOperation               `json:",omitempty"`
	Compacted     *deployment.OperationSummary `json:",omitempty"`
	Delivery      json.RawMessage              `json:",omitempty"`
	DeliveryInput *AppDeliveryInput            `json:",omitempty"`
	Sync          *AppDeliverySync             `json:",omitempty"`
	PendingSync   *AppDeliverySync             `json:",omitempty"`
}
type appCheckpoint struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Uploads  []deployment.Upload
	Apps     []appRow
	Bindings json.RawMessage    `json:",omitempty"`
	Sources  []AppBindingSource `json:",omitempty"`
	Network  json.RawMessage    `json:",omitempty"`
}
type Apps struct {
	Revision uint64
	uploads  []deployment.Upload
	entries  map[string]appEntry
	bindings deployment.Bindings
	sources  []AppBindingSource
	network  *appNetworkState
}

func appKey(tenant, app string) string     { return tenant + "/" + app }
func uploadKey(u deployment.Upload) string { return u.Tenant + "/" + u.User + "/" + u.ID }

func (p Policy) emptyApps() Apps {
	a := Apps{entries: map[string]appEntry{}}
	a.bindings, _ = deployment.NewBindings(p.Cluster)
	return a
}

// Apps owns its mutable control metadata. Deployment core values are immutable:
// their transitions clone before writes and their accessors own mutable output.
func (p Policy) Apps(s state.State) (Apps, error) {
	a, err := p.readOnlyApps(s)
	if err != nil {
		return p.emptyApps(), err
	}
	return a.owned()
}

func (a Apps) owned() (Apps, error) {
	// Only control metadata is copied through JSON. The private deployment
	// records would serialize as {}, so restore those immutable values below.
	// Decode into a zero destination: reusing a's maps/slices here would let
	// json.Unmarshal overwrite the borrowed interpretation in place.
	type metadata struct {
		Sources []AppBindingSource
		Entries map[string]appEntry
	}
	raw, err := json.Marshal(metadata{a.sources, a.entries})
	var copied metadata
	if err != nil || json.Unmarshal(raw, &copied) != nil {
		return Apps{}, ErrCatalog
	}
	for key, entry := range a.entries {
		owned := copied.Entries[key]
		owned.Inventory = entry.Inventory
		if entry.Delivery != nil {
			delivery := *entry.Delivery
			owned.Delivery = &delivery
		}
		copied.Entries[key] = owned
	}
	uploads := slices.Clone(a.uploads)
	for i := range uploads {
		uploads[i].Parts = slices.Clone(uploads[i].Parts)
		for j, part := range uploads[i].Parts {
			uploads[i].Parts[j] = bytes.Clone(part)
		}
	}
	out := Apps{Revision: a.Revision, uploads: uploads, entries: copied.Entries, sources: copied.Sources, bindings: a.bindings}
	if a.network != nil {
		out.network, err = a.network.owned()
		if err != nil {
			return Apps{}, err
		}
	}
	return out, nil
}

// decodeApps returns an owned view for reducers and ordinary callers.
func (p Policy) decodeApps(s state.State, raw []byte, revision uint64) (Apps, error) {
	a := p.emptyApps()
	var disk appCheckpoint
	if canonical(raw, &disk) != nil || disk.Schema != 1 || disk.Cluster != p.Cluster || disk.Revision != revision || revision == 0 || len(disk.Uploads) > maxAppUploads || len(disk.Apps) > maxApps {
		return a, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return a, err
	}
	last := ""
	for _, upload := range disk.Uploads {
		key := uploadKey(upload)
		_, exists := c.Tenant(upload.Tenant)
		_, userExists := c.User(upload.User)
		if upload.Validate() != nil || key <= last || !exists || !userExists {
			return a, ErrCatalog
		}
		if len(upload.Missing()) == 0 {
			if _, err := upload.Complete(); err != nil {
				return a, ErrCatalog
			}
		}
		last = key
	}
	last = ""
	for _, row := range disk.Apps {
		var delivery *deployment.Delivery
		var inventory deployment.Inventory
		if len(row.Delivery) != 0 {
			if len(row.Inventory) != 0 {
				return a, ErrCatalog
			}
			d, decodeErr := deployment.DecodeDelivery(row.Delivery)
			if decodeErr != nil {
				return a, ErrCatalog
			}
			delivery, inventory = &d, d.Inventory()
		} else {
			inventory, err = deployment.DecodeInventory(row.Inventory)
		}
		scope := inventory.Scope()
		identity, originErr := appExecutionOrigin(row.Origin, row.Sync, scope)
		if err != nil || scope.Cluster != p.Cluster || row.Origin.VerifyOriginal(p.Cluster) != nil || originErr != nil {
			return a, ErrCatalog
		}
		_, exists := c.Tenant(scope.Tenant)
		_, userExists := c.User(row.Origin.Session.User)
		key := appKey(scope.Tenant, scope.App)
		if key <= last || !exists || !userExists {
			return a, ErrCatalog
		}
		execution, _ := inventory.Execution()
		active, ok := inventory.Operation(identity.Operation)
		if row.Compacted != nil {
			if ok || !validCompactedAppSource(inventory, row.Origin, row.Down, row.Sync, *row.Compacted) {
				return a, ErrCatalog
			}
			active, ok = *row.Compacted, true
		}
		_, executing := inventory.Execution()
		if !ok || active.ID != identity.Operation || active.Submitter != identity.Submitter || active.Epoch != identity.Epoch || executing && execution.Scope().Actor != row.Origin.Session.User {
			return a, ErrCatalog
		}
		last = key
		entry := appEntry{Standalone: row.Standalone, LocalEdit: row.LocalEdit, Local: row.Local, CDHistory: row.CDHistory, CDHistoryNext: row.CDHistoryNext, CDDecision: row.CDDecision, TaskRestarts: row.TaskRestarts, LastVersion: row.LastVersion, Versions: row.Versions, Inventory: inventory, Origin: row.Origin, Down: row.Down, Compacted: row.Compacted, Delivery: delivery, DeliveryInput: row.DeliveryInput, Sync: row.Sync, PendingSync: row.PendingSync}
		for _, claim := range entry.Inventory.Claims() {
			if claim.Observation != nil && !validUserRestart(entry, *claim.Observation) {
				return a, ErrCatalog
			}
		}
		if !validStandaloneMetadata(entry.Standalone, scope) || !validStandaloneExtensionOrigin(entry) || entry.Standalone != nil && (entry.Delivery != nil || entry.Sync != nil || entry.Local != nil) || !validCDHistory(entry) || !validCDDecision(entry.CDDecision, scope) || !validAppVersions(entry) || p.validateAppEntryDown(entry) != nil || validateTaskRestarts(entry.TaskRestarts, scope) != nil {
			return a, ErrCatalog
		}
		if validateAppDelivery(entry, disk.Uploads) != nil || validateAppLocal(entry) != nil {
			return a, ErrCatalog
		}
		a.entries[key] = entry
	}
	a.Revision, a.uploads = revision, disk.Uploads
	if disk.Bindings != nil {
		a.bindings, err = deployment.DecodeBindings(disk.Bindings)
		if err != nil || a.bindings.Revision() == 0 || a.bindings.Cluster() != p.Cluster {
			return a, ErrCatalog
		}
	}
	a.sources = disk.Sources
	if disk.Network != nil {
		a.network, err = decodeAppNetwork(disk.Network, p.Cluster)
		if err != nil {
			return a, err
		}
	}
	if p.validateAppBindingSources(a) != nil {
		return a, ErrCatalog
	}
	if p.validateMoveAppOrigins(s, a) != nil {
		return a, ErrCatalog
	}
	return a, nil
}

func (p Policy) appsCheckpoint(s state.State, a Apps, signedAt ...uint64) (map[string][]byte, state.Code) {
	if a.Revision == ^uint64(0) || len(a.entries) > maxApps || len(a.uploads) > maxAppUploads {
		return nil, state.Invalid
	}
	at := uint64(0)
	if len(signedAt) > 1 {
		return nil, state.Invalid
	}
	if len(signedAt) == 1 {
		at = signedAt[0]
	}
	previous, previousErr := p.readOnlyApps(s)
	if previousErr != nil {
		return nil, state.Invalid
	}
	disk := appCheckpoint{Schema: 1, Cluster: p.Cluster, Revision: a.Revision + 1, Uploads: slices.Clone(a.uploads)}
	if a.network != nil {
		var err error
		disk.Network, err = a.network.encode()
		if err != nil {
			return nil, state.Invalid
		}
	}
	if a.bindings.Revision() != 0 {
		var err error
		disk.Bindings, err = a.bindings.Encode()
		if err != nil {
			return nil, state.Invalid
		}
		disk.Sources = a.sources
	}
	slices.SortFunc(disk.Uploads, func(a, b deployment.Upload) int { return strings.Compare(uploadKey(a), uploadKey(b)) })
	keys := make([]string, 0, len(a.entries))
	for key := range a.entries {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		e, versionErr := captureAppVersion(a.entries[key])
		if versionErr != nil || !validAppVersions(e) || validateAppLocal(e) != nil {
			return nil, state.Invalid
		}
		row := appRow{Standalone: e.Standalone, LocalEdit: e.LocalEdit, Local: ownLocalGrant(e.Local), CDDecision: e.CDDecision, TaskRestarts: e.TaskRestarts, LastVersion: e.LastVersion, Versions: e.Versions, Origin: e.Origin, Down: e.Down, Compacted: e.Compacted, DeliveryInput: e.DeliveryInput, Sync: e.Sync, PendingSync: e.PendingSync}
		var err error
		if e.Delivery != nil {
			d, followErr := e.Delivery.FollowInventory(e.Delivery.Revision(), e.Inventory)
			if followErr != nil {
				return nil, state.Invalid
			}
			e.Delivery = &d
			e, err = captureCDHistory(e, previous.entries[key], at)
			if err != nil || !validCDHistory(e) {
				return nil, state.Invalid
			}
			row.CDHistory, row.CDHistoryNext = e.CDHistory, e.CDHistoryNext
			row.Delivery, err = d.Encode()
		} else {
			row.Inventory, err = e.Inventory.Encode()
		}
		if err != nil {
			return nil, state.Invalid
		}
		disk.Apps = append(disk.Apps, row)
	}
	raw, err := json.Marshal(disk)
	if err != nil || len(raw) > maxAppCheckpoint {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, AppsKey, p.Cluster, p.TrustRoot, disk.Revision, raw)
}

func (p Policy) authorizeApp(c access.Catalog, op UserOperation) error {
	if c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return access.ErrDenied
	}
	tenant := ""
	cleanup := false
	switch op.Change.Action {
	case "standalone-extend":
		return p.authorizeStandaloneExtension(c, op)
	case "standalone-pin", "standalone-remove":
		return p.authorizeStandalone(c, op)
	case "cd-approve", "cd-reject":
		// Session and tenant read here; ManageCD or this app's approver
		// grant is the Delivery's own check (MayDecide) in the reducer.
		var q AppCDDecisionChange
		if canonical(op.Change.Payload, &q) != nil || !q.valid() {
			return access.ErrInvalid
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.Read, "")
	case "grant-cd-approver", "revoke-cd-approver":
		var q AppCDApproverChange
		if canonical(op.Change.Payload, &q) != nil || !q.valid() {
			return access.ErrInvalid
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.ManageCD, "")
	case "standalone-stop", "standalone-start", "standalone-restart", "restart-task":
		var q TaskRestartChange
		if canonical(op.Change.Payload, &q) != nil || !q.valid() {
			return access.ErrInvalid
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.Deploy, "")
	case "put-app-local-services", "clear-app-local-services":
		var q AppLocalChange
		if canonical(op.Change.Payload, &q) != nil || !q.valid(op.Change.Action) {
			return access.ErrInvalid
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.Deploy, "")
	case "override-app", "release-app-override":
		var q AppOverrideChange
		if canonical(op.Change.Payload, &q) != nil || q.Tenant == "" || q.App == "" {
			return access.ErrInvalid
		}
		if op.Change.Action == "release-app-override" {
			return c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.ManageCD)
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.ManageCD, "")
	case "sync-app", "recover-app", "replan-app", "configure-app-cd", "pause-app-cd", "resume-app-cd", "abandon-app-sync":
		var q AppCDChange
		if canonical(op.Change.Payload, &q) != nil || q.Tenant == "" || q.App == "" {
			return access.ErrInvalid
		}
		if op.Change.Action == "pause-app-cd" || op.Change.Action == "abandon-app-sync" {
			return c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.ManageCD)
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.ManageCD, "")
	case "begin-app-upload":
		var v AppUploadBegin
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant = v.Tenant
	case "put-app-part":
		var v AppUploadPart
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant = v.Tenant
	case "abort-app-upload":
		var v AppUploadSelection
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, cleanup = v.Tenant, true
	case "begin-app", "standalone-up":
		var v AppBegin
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant = v.Tenant
	case "rotate-app-history":
		var v AppHistorySelection
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, cleanup = v.Tenant, true
	case "down-app":
		var v AppDown
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, cleanup = v.Tenant, true
	case "resume-app-retirement":
		var v AppRetirementReplay
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, cleanup = v.Tenant, true
	case "resume-app-step":
		var v AppStepReplay
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, cleanup = v.Tenant, true
	default:
		return access.ErrInvalid
	}
	if tenant == "" {
		return access.ErrDenied
	}
	if cleanup {
		return c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, tenant, access.Deploy)
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, tenant, access.Deploy, "")
}

// AppPlanning consumes committed policy only. Features describe implemented
// declaration/adapter contracts, never an Applied/native-ready observation.
func (p Policy) AppPlanning(s state.State, actor, tenant string) (deployment.PlanningContext, error) {
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return deployment.PlanningContext{}, err
	}
	return p.appPlanningFromApps(s, actor, tenant, apps)
}

// The caller checked apps against this exact immutable state. No grant or
// decoded view survives the call; public planning outputs still own their data.
func (p Policy) appPlanningFromApps(s state.State, actor, tenant string, apps Apps) (deployment.PlanningContext, error) {
	base, err := p.Resources(s)
	if err != nil {
		return deployment.PlanningContext{}, err
	}
	v, err := p.Volumes(s)
	if err != nil {
		return deployment.PlanningContext{}, err
	}
	projected, err := p.projectResources(s, base, apps, v)
	if err != nil || !projected.Compatible {
		return deployment.PlanningContext{}, ErrCatalog
	}
	ctx, err := p.planningResources(s, actor, tenant, projected)
	if err != nil {
		return ctx, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ctx, err
	}
	ctx.Volumes = map[string]volumes.State{}
	ctx.ExternalRegistries, err = p.externalRegistryDefinitions(s, tenant)
	if err != nil {
		return ctx, err
	}
	ctx.Checkers, err = p.Lifecycles(s)
	if err != nil {
		return ctx, err
	}
	vault, err := p.Vault(s)
	if err != nil {
		return ctx, err
	}
	ctx.SecretRevisions = secretRevisions(vault.Trees)
	members, err := p.Members(s)
	if err != nil {
		return ctx, err
	}
	ctx.CheckerProviders = map[[32]byte]bool{}
	for _, key := range members.Issuers() {
		ctx.CheckerProviders[key] = true
	}
	// Source availability is a retained-resource projection, never a TLS,
	// session issuer or command key lookup. Exact facts remain unchanged.
	for _, member := range members.Entries {
		for _, transition := range member.Keys {
			old := transition.Proof.Old
			if p.currentResourceKey(s, old, true) != ([32]byte{}) {
				ctx.CheckerProviders[old] = true
			}
		}
	}
	ctx.CheckerPrograms = map[deployment.AppScope]checker.FrozenProgram{}
	// Planning only reads accepted recipes. The returned program is cloned by
	// CheckerProgram; callers never receive the borrowed Apps internals.
	for _, entry := range apps.entries {
		if entry.Inventory.Scope().Tenant != tenant {
			continue
		}
		var plan deployment.Blueprint
		if entry.Delivery != nil {
			// Retirement may clear Execution before the original accepted CD
			// target is continued. That frozen target remains the recipe owner.
			var exists bool
			plan, exists = entry.Delivery.AcceptedPlan()
			if !exists {
				continue
			}
		} else if execution, exists := entry.Inventory.Execution(); exists {
			plan = execution.Blueprint()
		} else {
			continue
		}
		if program := plan.CheckerProgram(); program != nil {
			ctx.CheckerPrograms[plan.Scope()] = *program
		}
	}
	ctx.FixedVolumes = map[string]volumes.NativeReady{}
	shares, err := p.VolumeShares(s)
	if err != nil {
		return ctx, err
	}
	ctx.Shares = shares.planning(tenant)
	for key, entry := range v.entries {
		if entry.State.Scope().Tenant == tenant {
			ctx.Volumes[key] = entry.State
			if entry.State.Fixed() && entry.State.DeleteRevision() == 0 && p.canUseFixedVolume(s, c, actor, entry) == nil {
				ctx.FixedVolumes[key] = entry.Native
			}
		}
	}
	// Advertise connected declaration/adapter inputs. Native readiness is
	// established by the original execution and current owner observations.
	ctx.Features = map[string]bool{"core": true, "inputs": true, "volumes": true, "fixed-volumes": true, "network-reference": true, "network-dns": true, "managed-dns": true, "lifecycle": true, "git-cd": true}
	return ctx, nil
}

func (p Policy) reduceApps(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind == state.ModuleReport && cmd.Key == AppsKey && strings.HasPrefix(cmd.Actor, "node/") {
		if standalonePolicyValue([]byte(cmd.Value)) {
			return p.reduceStandalonePolicy(s, cmd)
		}
		if taskRestartReportValue([]byte(cmd.Value)) {
			return p.reduceTaskRestart(s, cmd)
		}
		if appDeliveryReportValue([]byte(cmd.Value)) {
			return p.reduceAppDelivery(s, cmd)
		}
		if routeRetirementReportValue([]byte(cmd.Value)) {
			return p.reduceRouteRetirement(s, cmd)
		}
		if routeDispatchReportValue([]byte(cmd.Value)) {
			return p.reduceRouteDispatch(s, cmd)
		}
		if networkDNSReportValue([]byte(cmd.Value)) {
			return p.reduceNetworkDNSProgress(s, cmd)
		}
		return p.reduceAppProgress(s, cmd)
	}
	if cmd.Kind != state.Module && cmd.Kind != state.ModuleUpload && cmd.Kind != state.ModuleAppDown || cmd.Key != AppsKey || !strings.HasPrefix(cmd.Actor, "user/") {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || p.authorizeApp(c, op) != nil {
		return nil, state.Forbidden
	}
	a, err := p.Apps(s)
	if err != nil {
		return nil, state.Invalid
	}
	change := op.Change
	if !strings.HasPrefix(change.Action, "standalone-") && change.Action != "begin-app-upload" {
		var target struct{ Tenant, App string }
		_ = json.Unmarshal(change.Payload, &target)
		if a.IsStandalone(target.Tenant, target.App) {
			return nil, state.Forbidden
		}
	}
	switch change.Action {
	case "standalone-extend":
		return p.reduceStandaloneExtension(s, a, c, op)
	case "standalone-pin", "standalone-remove":
		if op.Change.Action == "standalone-remove" {
			return p.reduceStandaloneRemove(s, a, c, op)
		}
		return p.reduceStandalonePin(s, a, op)
	case "put-app-local-services", "clear-app-local-services":
		return p.reduceAppLocal(s, a, op)
	case "cd-approve", "cd-reject":
		return p.reduceCDDecision(s, a, op)
	case "grant-cd-approver", "revoke-cd-approver":
		return p.reduceCDApprover(s, a, op)
	case "standalone-stop", "standalone-start", "standalone-restart", "restart-task":
		return p.beginTaskRestart(s, a, op)
	case "resume-app-retirement":
		return p.reduceAppRetirementReplay(s, a, op)
	case "resume-app-step":
		return p.reduceAppStepReplay(s, a, op)
	case "override-app", "release-app-override":
		return p.reduceAppOverride(s, a, op)
	case "sync-app", "recover-app", "replan-app", "configure-app-cd", "pause-app-cd", "resume-app-cd", "abandon-app-sync":
		return p.reduceUserCD(s, a, op)
	case "begin-app-upload":
		var v AppUploadBegin
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		u, err := deployment.NewUpload(v.Tenant, v.App, v.Deployment, change.Principal, v.ID, v.Length, v.Digest)
		if err != nil {
			return nil, state.Invalid
		}
		if change.Expected != 0 || len(a.uploads) >= maxAppUploads || slices.ContainsFunc(a.uploads, func(old deployment.Upload) bool { return uploadKey(old) == uploadKey(u) }) {
			return nil, state.ConditionFailed
		}
		a.uploads = append(slices.Clone(a.uploads), u)
	case "put-app-part", "abort-app-upload":
		var v AppUploadPart
		user := change.Principal
		if change.Action == "put-app-part" {
			if canonical(change.Payload, &v) != nil {
				return nil, state.Invalid
			}
		} else {
			var selectUpload AppUploadSelection
			if canonical(change.Payload, &selectUpload) != nil {
				return nil, state.Invalid
			}
			v.Tenant, v.ID = selectUpload.Tenant, selectUpload.ID
			if selectUpload.User != "" && selectUpload.User != user {
				if !c.SystemAllowed(user) {
					return nil, state.Forbidden
				}
				user = selectUpload.User
			}
		}
		index := slices.IndexFunc(a.uploads, func(u deployment.Upload) bool {
			return u.Tenant == v.Tenant && u.User == user && u.ID == v.ID
		})
		if index < 0 || a.uploads[index].Revision != change.Expected {
			return nil, state.ConditionFailed
		}
		if a.deliveryUploadHeld(a.uploads[index]) {
			return nil, state.ConditionFailed
		}
		a.uploads = slices.Clone(a.uploads)
		if change.Action == "abort-app-upload" {
			if p.moveUploadHeld(s, a.uploads[index]) {
				return nil, state.ConditionFailed
			}
			a.uploads = slices.Delete(a.uploads, index, index+1)
		} else {
			a.uploads[index], err = a.uploads[index].Add(v.Index, v.Data)
			if err != nil {
				return nil, state.Invalid
			}
		}
	case "begin-app", "standalone-up":
		var v AppBegin
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		registry, err := p.Volumes(s)
		if err != nil {
			return nil, state.Invalid
		}
		if registry.appMovePending(v.Tenant, v.App) {
			return nil, state.ConditionFailed
		}
		index := slices.IndexFunc(a.uploads, func(u deployment.Upload) bool {
			return u.Tenant == v.Tenant && u.User == change.Principal && u.ID == v.Upload && u.App == v.App && u.Deployment == v.Deployment
		})
		if index < 0 {
			return nil, state.ConditionFailed
		}
		if a.deliveryUploadHeld(a.uploads[index]) {
			return nil, state.ConditionFailed
		}
		if p.moveUploadHeld(s, a.uploads[index]) {
			return nil, state.ConditionFailed
		}
		raw, err := a.uploads[index].Complete()
		if err != nil {
			return nil, state.ConditionFailed
		}
		plan, err := deployment.DecodeBlueprint(raw)
		scope := plan.Scope()
		if err != nil || plan.HasDocumentOverrides() || scope.Cluster != p.Cluster || scope.Actor != change.Principal || scope.Tenant != v.Tenant || scope.App != v.App || scope.Deployment != v.Deployment || plan.CDDefaultNode() != v.DefaultNode {
			return nil, state.Invalid
		}
		if p.admitIngressBlueprint(s, plan) != nil {
			return nil, state.Forbidden
		}
		if p.imageCacheBlueprintAvailable(s, plan) != nil {
			return nil, state.ConditionFailed
		}
		ctx, err := p.AppPlanning(s, change.Principal, v.Tenant)
		if err != nil {
			return nil, state.Forbidden
		}
		ctx.Project, ctx.Deployment, ctx.DefaultNode = v.App, v.Deployment, v.DefaultNode
		for _, step := range plan.Steps() {
			if c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, v.Tenant, step.Action(), step.Node) != nil {
				return nil, state.Forbidden
			}
		}
		key := appKey(v.Tenant, v.App)
		entry, exists := a.entries[key]
		if change.Action == "begin-app" && (v.Standalone != nil || exists && entry.Standalone != nil || plan.StandaloneName() != "") {
			return nil, state.Forbidden
		}
		if change.Action == "standalone-up" {
			if v.Standalone == nil || plan.StandaloneName() == "" || !exists && v.App != deployment.StandaloneScopeName(v.Tenant, v.Standalone.Name) || exists && (entry.Standalone == nil || entry.Standalone.Name != v.Standalone.Name || entry.Standalone.Scope != v.App) {
				return nil, state.Forbidden
			}
			node := v.DefaultNode
			for _, step := range plan.Steps() {
				if step.Kind == "task" {
					node = step.Node
				}
			}
			if !exists && standaloneQuota(a, v.Tenant, change.Principal, node, v.Standalone.Lifetime) != nil {
				return nil, state.ConditionFailed
			}
			if admitAppVolumeConsumers(plan, op.Session.Key, ctx.Volumes, a) != nil {
				return nil, state.ConditionFailed
			}
		}
		if !exists {
			if change.Expected != 0 || len(a.entries) >= maxApps {
				return nil, state.ConditionFailed
			}
			if v.Target != nil && *v.Target != AppCreateTarget(p.Cluster, v.Tenant, v.App, v.Deployment) {
				return nil, state.ConditionFailed
			}
			entry.Inventory, err = deployment.NewInventory(p.Cluster, v.Tenant, v.App, v.Deployment)
			if err != nil {
				return nil, state.Invalid
			}
		} else if v.Target != nil {
			allowed := AppBeginCASAllowed(change)
			if change.Action == "standalone-up" {
				allowed = StandaloneCASAllowed(change)
			}
			if change.Expected == 0 || !allowed || *v.Target != entry.beginTarget() || change.Expected > entry.Inventory.Revision() {
				return nil, state.ConditionFailed
			}
		} else if entry.Inventory.Revision() != change.Expected {
			return nil, state.ConditionFailed
		}
		if change.Action == "standalone-up" {
			node := v.DefaultNode
			for _, step := range plan.Steps() {
				if step.Kind == "task" {
					node = step.Node
				}
			}
			m, err := v.Standalone.metadata(v.Tenant, change.Principal, node, op.At)
			if err != nil {
				return nil, state.Invalid
			}
			if entry.Standalone != nil {
				old := entry.Standalone
				if !standaloneActor(c, entry, change.Principal) || old.Cleanup != nil || old.Lifetime == "fixed" && m.Lifetime != "fixed" {
					return nil, state.ConditionFailed
				}
				m.Scope, m.Creator, m.Revision = old.Scope, old.Creator, old.Revision+1
			}
			entry.Standalone = &m
		}
		previousRevision := entry.Inventory.Revision()
		if entry.PendingSync != nil {
			// An accepted recreation remains owned even after positive removal
			// while its continuation is waiting on current authority/placement.
			return nil, state.ConditionFailed
		}
		if entry.Delivery != nil {
			// A local upload never replaces the execution Git selected. A
			// file with x-sfc.cd changes only the policy (its services are
			// not deployed); a file without it turns CD off, confirmed by
			// DisableCD, and then deploys as an ordinary app.
			if c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, v.Tenant, access.ManageCD, "") != nil {
				return nil, state.Forbidden
			}
			if policy, enabled := plan.DeliveryPolicy(); enabled {
				d := *entry.Delivery
				pctx := ctx
				pctx.Actor = d.Principal()
				configured, err := d.Configure(d.Revision(), d.PolicyRevision(), c, pctx, op.Session.User, policy)
				if err != nil {
					return nil, state.ConditionFailed
				}
				if configured.PolicyRevision() != d.PolicyRevision() {
					a, entry = clearDeliveryInput(a, entry)
				}
				entry.Delivery = &configured
				a.entries[key] = entry
				a.uploads = slices.Delete(slices.Clone(a.uploads), index, index+1)
				break
			}
			if !v.DisableCD || !entry.Delivery.Quiescent() {
				return nil, state.ConditionFailed
			}
			a, entry = clearDeliveryInput(a, entry)
			entry.Delivery, entry.CDDecision = nil, nil
		}
		begin := entry.Inventory.Begin
		if change.Action == "begin-app" {
			begin = entry.Inventory.BeginDeploy
		}
		entry.Inventory, err = begin(entry.Inventory.Revision(), c, ctx, plan, v.Operation, cmd.Actor, cmd.Epoch, v.Prune)
		if err != nil {
			return nil, state.ConditionFailed
		}
		if entry.Inventory.Revision() != previousRevision {
			entry.Origin = op
			// A new explicit app acceptance is its own source. Historical
			// recreation records keep their original signed proof separately.
			entry.Sync = nil
			entry.Down = nil
			entry.Compacted = nil
			if deliveryPolicy, enabled := plan.DeliveryPolicy(); enabled {
				if deliveryPolicy.Sync.Prune != v.Prune || c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, v.Tenant, access.ManageCD, "") != nil {
					return nil, state.Forbidden
				}
				d, attachErr := deployment.NewAcceptedDelivery(plan, entry.Inventory, c)
				if attachErr != nil {
					return nil, state.ConditionFailed
				}
				entry.Delivery = &d
			}
		}
		a.entries[key] = entry
		a.uploads = slices.Delete(slices.Clone(a.uploads), index, index+1)
	case "down-app":
		var v AppDown
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		entry, ok := a.entries[appKey(v.Tenant, v.App)]
		if !ok || entry.Standalone != nil {
			return nil, state.ConditionFailed
		}
		expected := change.Expected
		if AppDownCASAllowed(op.Change) {
			if v.Target == nil || *v.Target != entry.downTarget() || expected > entry.Inventory.Revision() || entry.Down != nil {
				return nil, state.ConditionFailed
			}
			expected = entry.Inventory.Revision()
		} else if expected != entry.Inventory.Revision() {
			return nil, state.ConditionFailed
		}
		if entry.Delivery != nil {
			ctx, contextErr := p.AppPlanning(s, op.Session.User, v.Tenant)
			if contextErr != nil {
				return nil, state.ConditionFailed
			}
			ctx.Project, ctx.Deployment, ctx.Actor = v.App, entry.Inventory.Scope().Deployment, entry.Delivery.Principal()
			d, downErr := entry.Delivery.BeginTransition(entry.Delivery.Revision(), c, ctx, op.Session.User, v.Operation, cmd.Actor, cmd.Epoch, deployment.DeliveryDown)
			if downErr != nil {
				return nil, state.ConditionFailed
			}
			a, entry = clearDeliveryInput(a, entry)
			entry.Delivery, entry.Inventory = &d, d.Inventory()
		} else {
			entry.Inventory, err = entry.Inventory.Retire(expected, c, change.Principal, v.Operation, cmd.Actor, cmd.Epoch, nil, true)
		}
		if err != nil {
			return nil, state.ConditionFailed
		}
		entry.Down = &op
		a.entries[appKey(v.Tenant, v.App)] = entry
	case "rotate-app-history":
		var v AppHistorySelection
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		if entry, exists := a.entries[appKey(v.Tenant, v.App)]; exists && entry.Delivery != nil && c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, v.Tenant, access.ManageCD) != nil {
			return nil, state.Forbidden
		}
		a, err = a.rotateHistory(change.Expected, c, change.Principal, s, v)
		if err != nil {
			return nil, state.ConditionFailed
		}
	default:
		return nil, state.Invalid
	}
	return p.appsCheckpoint(s, a, uint64(op.At))
}

type AppView struct {
	Replacement             *deployment.ReplacementProgress `json:",omitempty"`
	Tenant, App, Deployment string
	Revision                uint64
	Operation               deployment.OperationSummary
	Claims                  int
	Retirement              *AppRetirementStatus `json:",omitempty"`
	Health                  string               `json:",omitempty"`
	// HealthReason is the first cause when Health is not Healthy, for
	// status display only.
	HealthReason                  *deployment.HealthReason `json:",omitempty"`
	ObservedAt, ObservationMaxAge uint64                   `json:",omitempty"`
	DownTarget                    *[32]byte                `json:",omitempty"`
	BeginTarget                   *[32]byte                `json:",omitempty"`
	CD                            *AppCDView               `json:",omitempty"`
	ImageSourceNoLongerTrusted    bool                     `json:",omitempty"`
}
type AppRetirementStatus struct {
	ID, Status string
	Pending    *AppRetirementPending `json:",omitempty"`
}

// One next unresolved mutation keeps ordinary app status bounded. Its digest
// identifies the immutable command without exposing its body or credentials.
type AppRetirementPending struct {
	Retirement, Key, Phase, Request string
	Command                         [32]byte
	ReplayAuthorized                bool
}
type AppUploadView struct {
	ID, App, Deployment string
	Revision            uint64
	Length              int
	Digest              [32]byte
	Missing             []int
}

func (a Apps) Page(c access.Catalog, actor, tenant, after string) ([]AppView, string, error) {
	if tenant == "" || c.Authorize(actor, tenant, access.Read, "") != nil {
		return nil, "", access.ErrDenied
	}
	var keys []string
	for key, e := range a.entries {
		if e.Standalone == nil && e.Inventory.Scope().Tenant == tenant && key > after {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	var out []AppView
	for _, key := range keys {
		if len(out) == 8 {
			return out, keys[len(out)-1], nil
		}
		i := a.entries[key].Inventory
		scope := i.Scope()
		v := appView(a.entries[key], scope)
		v.ImageSourceNoLongerTrusted = i.ImageSourceNoLongerTrusted(c)
		target := a.entries[key].downTarget()
		v.DownTarget = &target
		out = append(out, v)
	}
	return out, "", nil
}

// ObservedPage evaluates stored owner signatures at the adapter's current time.
// Operation success is historical; it does not substitute for fresh health.
func (a Apps) ObservedPage(c access.Catalog, actor, tenant, after string, now uint64) ([]AppView, string, error) {
	if now == 0 {
		return nil, "", ErrCatalog
	}
	rows, next, err := a.Page(c, actor, tenant, after)
	if err != nil {
		return nil, "", err
	}
	for n := range rows {
		row := &rows[n]
		row.Health, row.ObservedAt, row.ObservationMaxAge = "Unknown", now, AppObservationMaxAge
		if row.Retirement != nil {
			continue
		}
		i := a.entries[appKey(tenant, row.App)].Inventory
		if e, ok := i.Execution(); ok && e.Status() != "Stopping" && e.Status() != "Closed" {
			row.Health, row.HealthReason = e.HealthWithReason(now)
		}
	}
	return rows, next, nil
}

func (a Apps) Uploads(c access.Catalog, actor, tenant, after string) ([]AppUploadView, string, error) {
	if c.Authorize(actor, tenant, access.Deploy, "") != nil {
		return nil, "", access.ErrDenied
	}
	var out []AppUploadView
	for _, u := range a.uploads {
		if u.Tenant == tenant && u.User == actor && u.ID > after {
			if len(out) == 8 {
				return out, out[len(out)-1].ID, nil
			}
			out = append(out, AppUploadView{u.ID, u.App, u.Deployment, u.Revision, u.Length, u.Digest, u.Missing()})
		}
	}
	return out, "", nil
}

func (a Apps) Quiescent() bool {
	if len(a.uploads) != 0 || len(a.bindings.Live()) != 0 {
		return false
	}
	if a.network != nil {
		for _, group := range a.network.Groups {
			for _, owner := range group.Owners {
				ref, known := a.network.Authority.ReferenceConsumer(owner.Reference)
				if !known || ref.Closed == nil {
					return false
				}
			}
		}
	}
	for _, e := range a.entries {
		if pendingTaskRestarts(e) || !e.Inventory.Quiescent() || e.PendingSync != nil || e.DeliveryInput != nil || e.Delivery != nil && !e.Delivery.Quiescent() {
			return false
		}
	}
	return true
}

// appsBook is the AppsKey book (books.go).
var appsBook = Book{Key: AppsKey, Reduce: byKind(map[state.CommandKind]reducer{state.Module: Policy.reduceApps, state.ModuleReport: Policy.reduceApps, state.ModuleUpload: Policy.reduceApps, state.ModuleAppDown: Policy.reduceApps})}

// secretRevisions digests the current value references behind an app
// service's inputs from these committed trees. No value is read.
func secretRevisions(trees map[string]secrets.Tree) func([]deployment.Source) string {
	return func(sources []deployment.Source) string {
		h := sha256.New()
		for _, source := range sources {
			_, _ = io.WriteString(h, source.Realm)
			h.Write([]byte{0})
			tree, ok := trees[source.Realm]
			if !ok {
				_, _ = io.WriteString(h, source.Object)
				h.Write([]byte{0})
				continue
			}
			tree.WriteReferences(h, source.Object)
		}
		return hex.EncodeToString(h.Sum(nil))
	}
}
