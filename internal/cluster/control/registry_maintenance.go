// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/registryclient"
)

const RegistryMaintenanceKey = "control/registry-maintenance"

type RegistryMaintenanceQuery struct {
	Action, ID, Repository, Reference, Digest, Operation string
	External                                             bool `json:",omitempty"`
}

func (q RegistryMaintenanceQuery) Valid(plan bool) bool {
	if !plan {
		return q.Operation != "" && len(q.Operation) <= 256 && !strings.ContainsAny(q.Operation, "\x00\r\n") && q.Action == "" && q.ID == "" && q.Repository == "" && q.Reference == "" && q.Digest == "" && !q.External
	}
	if q.Operation != "" || !validID(q.ID) {
		return false
	}
	if q.Action == "gc-registry" || q.Action == RegistryPruneAction {
		return (q.Action == RegistryPruneAction || !q.External) && q.Repository == "" && q.Reference == "" && q.Digest == ""
	}
	if q.Action != "delete-registry-image" {
		return false
	}
	return (registry.ImageDelete{Operation: "validation", Authority: "registry.example", Repository: q.Repository, Reference: q.Reference, ExpectedDigest: q.Digest}).Valid()
}

type RegistryMaintenanceChange struct {
	Tenant, Operation             string
	Run                           RegistryRunRef
	Repository, Reference, Digest string
	External                      *ExternalRegistryMaintenanceTarget `json:",omitempty"`
	Prune                         *RegistryPruneTarget               `json:",omitempty"`
}

func (q RegistryMaintenanceChange) Query(action string) RegistryMaintenanceQuery {
	return RegistryMaintenanceQuery{Action: action, ID: q.RegistryID(), Repository: q.Repository, Reference: q.Reference, Digest: q.Digest, External: q.External != nil}
}
func freezeMaintenanceRun(run RegistryRunRef) RegistryRunRef { run.Ready = nil; return run }
func sameMaintenanceRun(a, b RegistryRunRef) bool {
	a = freezeMaintenanceRun(a)
	b = freezeMaintenanceRun(b)
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
func (q RegistryMaintenanceChange) Valid(cluster [32]byte, action string) bool {
	if !validID(q.Tenant) || q.Operation == "" || len(q.Operation) > 256 || strings.ContainsAny(q.Operation, "\x00\r\n") || !q.Query(action).Valid(true) {
		return false
	}
	if (q.Prune != nil) != (action == RegistryPruneAction) || q.Prune != nil && !q.Prune.Valid(cluster, q) {
		return false
	}
	if q.External != nil {
		zero, _ := json.Marshal(RegistryRunRef{})
		run, _ := json.Marshal(q.Run)
		_, matches := q.External.Spec.Match(access.Image{Registry: q.Authority(), Repository: q.Repository})
		return cluster != ([32]byte{}) && (action == "delete-registry-image" || action == RegistryPruneAction) && q.External.Valid(q.Tenant) && string(zero) == string(run) && (matches || action == RegistryPruneAction)
	}
	return q.Tenant == q.Run.Spec.Tenant && q.Run.Spec.Validate(cluster) == nil && q.Run.Owner != ([32]byte{}) && q.Run.Generation > 0 && q.Run.SpecRevision > 0 && q.Run.DefinitionDigest != ([32]byte{}) && q.Run.OriginDigest != ([32]byte{}) && !q.Run.Draining && q.Run.Ready == nil
}
func (q RegistryMaintenanceChange) DigestValue() [32]byte {
	raw, _ := json.Marshal(q)
	return sha256.Sum256(append([]byte("sfc-registry-maintenance-target-1\x00"), raw...))
}

type RegistryMaintenancePlan struct {
	Schema                        uint8
	Cluster                       [32]byte
	Tenant, Action                string
	Expected, RootRevision, Epoch uint64
	Change                        RegistryMaintenanceChange
	InUse                         bool
}
type RegistryMaintenanceResult struct {
	Code           string
	At             uint64
	ReclaimedBytes int64
	Native         [32]byte
	Prune          *RegistryPruneSummary `json:",omitempty"`
}

func (r RegistryMaintenanceResult) Valid() bool {
	if r.At == 0 || r.ReclaimedBytes < 0 || r.Prune != nil && !r.Prune.Valid() {
		return false
	}
	switch r.Code {
	case "OK", "ALREADY_ABSENT", "PARTIAL":
		return r.Native != ([32]byte{})
	case "IMAGE_IN_USE", "REFERENCE_CHANGED", "DENIED", "UPLOADS_IN_PROGRESS", "UNAVAILABLE", "UNSUPPORTED", "REGISTRY_BUDGET", "PREVIEW_UNAVAILABLE":
		return true
	}
	return false
}

type RegistryMaintenanceRecord struct {
	Origin       UserOperation
	Change       RegistryMaintenanceChange
	State        string
	Revision, At uint64
	Result       *RegistryMaintenanceResult `json:",omitempty"`
}

func (r RegistryMaintenanceRecord) Pending() bool {
	return r.State == "queued" || r.State == "running" || r.State == "unknown"
}

type RegistryMaintenanceJobs struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Records  []RegistryMaintenanceRecord
}

func (j RegistryMaintenanceJobs) Record(id string) (RegistryMaintenanceRecord, bool) {
	for _, row := range j.Records {
		if row.Change.Operation == id {
			raw, _ := json.Marshal(row)
			var own RegistryMaintenanceRecord
			_ = json.Unmarshal(raw, &own)
			return own, true
		}
	}
	return RegistryMaintenanceRecord{}, false
}
func (j RegistryMaintenanceJobs) Quiescent() bool {
	for _, row := range j.Records {
		if row.Pending() {
			return false
		}
	}
	return true
}

// Summary is derived from the same signed owner results, not from elapsed
// time, free-space deltas or a second observation database. Record order is
// acceptance order; at most one job per registry may remain pending.
type RegistryMaintenanceSummary struct {
	PendingOperation, PendingState string `json:",omitempty"`
	LastGCOperation                string `json:",omitempty"`
	LastGCAt                       uint64 `json:",omitempty"`
	ReclaimedBytes                 int64
}

func (j RegistryMaintenanceJobs) Summary(tenant, id string) *RegistryMaintenanceSummary {
	var out *RegistryMaintenanceSummary
	for _, row := range j.Records {
		if row.Change.Tenant != tenant || row.Change.RegistryID() != id || row.Change.External != nil {
			continue
		}
		if row.Pending() {
			if out == nil {
				out = &RegistryMaintenanceSummary{}
			}
			out.PendingOperation, out.PendingState = row.Change.Operation, row.State
		} else if row.Result != nil && (row.State == "done" && row.Origin.Change.Action == "gc-registry" || row.Change.Prune != nil && row.Result.Prune != nil && row.Result.Prune.GCCode == "OK") {
			if out == nil {
				out = &RegistryMaintenanceSummary{}
			}
			out.LastGCOperation, out.LastGCAt, out.ReclaimedBytes = row.Change.Operation, row.Result.At, row.Result.ReclaimedBytes
			if row.Result.Prune != nil {
				out.LastGCAt = row.Result.Prune.GCAt
			}
		}
	}
	return out
}

func (p Policy) RegistryMaintenanceJobs(s state.State) (RegistryMaintenanceJobs, error) {
	out := RegistryMaintenanceJobs{Schema: 1, Cluster: p.Cluster}
	raw, rev, err := readCheckpoint(s, RegistryMaintenanceKey, p.Cluster, p.TrustRoot)
	if err != nil || raw == nil {
		return out, err
	}
	if canonical(raw, &out) != nil || out.Schema != 1 || out.Cluster != p.Cluster || out.Revision != rev || len(out.Records) > 128 {
		return out, ErrCatalog
	}
	ids := map[string]bool{}
	pending := map[string]bool{}
	for _, row := range out.Records {
		var q RegistryMaintenanceChange
		if row.Origin.VerifyOriginal(p.Cluster) != nil || canonical(row.Origin.Change.Payload, &q) != nil || q.DigestValue() != row.Change.DigestValue() || !q.Valid(p.Cluster, row.Origin.Change.Action) || row.Origin.Change.Expected != q.ExpectedRevision() || row.Revision == 0 || row.At < uint64(row.Origin.At) || ids[q.Operation] {
			return out, ErrCatalog
		}
		if q.Prune != nil && (row.Origin.At <= 0 || uint64(row.Origin.At) < q.Prune.Fact.At || uint64(row.Origin.At)-q.Prune.Fact.At > RegistryPrunePreviewSeconds) {
			return out, ErrCatalog
		}
		ids[q.Operation] = true
		if row.Pending() {
			if row.Result != nil || pending[q.pendingKey()] || row.State == "unknown" && q.External == nil {
				return out, ErrCatalog
			}
			pending[q.pendingKey()] = true
		} else if row.State == "done" || row.State == "failed" {
			if row.Result == nil || !RegistryMaintenanceResultFor(q, *row.Result) || (row.State == "done") != (row.Result.Code == "OK" || row.Result.Code == "ALREADY_ABSENT") {
				return out, ErrCatalog
			}
		} else {
			return out, ErrCatalog
		}
	}
	return out, nil
}
func (p Policy) registryMaintenanceAuth(c access.Catalog, session access.Session, at int64, action, tenant, node string, accepted bool) error {
	if c.OperationAllowed(session, action) != nil {
		return access.ErrDenied
	}
	if accepted {
		return c.AuthorizeAccepted(session, p.Cluster, at, tenant, access.ManageRegistry, node)
	}
	return c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, node)
}
func (p Policy) authorizeRegistryMaintenance(c access.Catalog, op UserOperation) error {
	var q RegistryMaintenanceChange
	if canonical(op.Change.Payload, &q) != nil || !q.Valid(p.Cluster, op.Change.Action) {
		return access.ErrDenied
	}
	if op.Change.Action == RegistryPruneAction && p.pruneChangeAuthorized(c, op, q) != nil {
		return access.ErrDenied
	}
	return p.registryMaintenanceAuth(c, op.Session, op.At, op.Change.Action, q.Tenant, q.NodeID(), false)
}
func (p Policy) maintenanceCurrentRun(s state.State, q RegistryMaintenanceChange, at int64) error {
	if q.External != nil {
		return p.currentExternalMaintenance(s, q, at)
	}
	book, err := p.Registries(s)
	if err != nil {
		return err
	}
	entry, ok := book.Entry(q.Tenant, q.Run.Spec.ID)
	if !ok || entry.Deleted || !entry.Spec.Enabled || entry.Spec != q.Run.Spec || entry.Active == nil || entry.Active.Draining || entry.Active.Ready == nil || !sameMaintenanceRun(entry.Active.Reference(), q.Run) {
		return access.ErrConflict
	}
	work, err := p.RegistryWork(s, q.Run.Owner, RegistryWorkRequest{RegistrySelection: RegistrySelection{Tenant: q.Tenant, ID: q.Run.Spec.ID}, At: at})
	if err != nil || !work.MayStart {
		return access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(q.Run.Owner) {
		return access.ErrDenied
	}
	return nil
}
func (p Policy) maintenanceImagesInUse(s state.State, tenant string, images []string) (bool, error) {
	if len(images) == 0 {
		return false, nil
	}
	rows, err := p.ImageReferences(s, tenant, "")
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		for _, image := range images {
			if row.MatchImage(image) != "" {
				return true, nil
			}
		}
	}
	return false, nil
}
func maintenanceDeleteRefs(q RegistryMaintenanceChange) []string {
	refs := []string{q.Authority() + "/" + q.Repository + "@" + q.Digest}
	if !strings.HasPrefix(q.Reference, "sha256:") {
		refs = append(refs, q.Authority()+"/"+q.Repository+":"+q.Reference)
	}
	return refs
}
func (p Policy) PlanRegistryMaintenance(s state.State, session access.Session, at int64, tenant string, q RegistryMaintenanceQuery) (RegistryMaintenancePlan, error) {
	p, err := p.Current(s)
	if err != nil {
		return RegistryMaintenancePlan{}, err
	}
	if !q.Valid(true) {
		return RegistryMaintenancePlan{}, access.ErrInvalid
	}
	var change RegistryMaintenanceChange
	var expected uint64
	if q.External {
		target, e := p.externalMaintenanceTarget(s, tenant, q.ID, q.Repository, at)
		if e != nil {
			return RegistryMaintenancePlan{}, e
		}
		change = RegistryMaintenanceChange{Tenant: tenant, External: &target, Repository: q.Repository, Reference: q.Reference, Digest: q.Digest}
		expected = target.Revision
	} else {
		book, e := p.Registries(s)
		if e != nil {
			return RegistryMaintenancePlan{}, e
		}
		entry, ok := book.Entry(tenant, q.ID)
		if !ok || entry.Active == nil {
			return RegistryMaintenancePlan{}, access.ErrDenied
		}
		change = RegistryMaintenanceChange{Tenant: tenant, Run: freezeMaintenanceRun(entry.Active.Reference()), Repository: q.Repository, Reference: q.Reference, Digest: q.Digest}
		expected = entry.Revision
	}
	c, err := p.Catalog(s)
	if err != nil {
		return RegistryMaintenancePlan{}, err
	}
	if !change.Query(q.Action).Valid(true) || p.registryMaintenanceAuth(c, session, at, q.Action, tenant, change.NodeID(), false) != nil {
		return RegistryMaintenancePlan{}, access.ErrDenied
	}
	if p.maintenanceCurrentRun(s, change, at) != nil {
		return RegistryMaintenancePlan{}, access.ErrConflict
	}
	if held, e := p.registryMaintenancePending(s, tenant, q.ID, q.External); e != nil || held {
		if e != nil {
			err = e
		} else {
			err = access.ErrConflict
		}
		return RegistryMaintenancePlan{}, err
	}
	if q.Action == "delete-registry-image" {
		if err := p.maintenanceDeleteAdmission(s, change); err != nil {
			return RegistryMaintenancePlan{}, err
		}
	}
	inUse := false
	if q.Action == "delete-registry-image" {
		inUse, err = p.maintenanceImagesInUse(s, tenant, maintenanceDeleteRefs(change))
		if err != nil {
			return RegistryMaintenancePlan{}, err
		}
	}
	return RegistryMaintenancePlan{Schema: 1, Cluster: p.Cluster, Tenant: tenant, Action: q.Action, Expected: expected, RootRevision: s.Object(RegistryMaintenanceKey).Revision, Epoch: s.ModuleEpoch(), Change: change, InUse: inUse}, nil
}
func (p Policy) registryMaintenanceCheckpoint(s state.State, j RegistryMaintenanceJobs) (map[string][]byte, state.Code) {
	if j.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	j.Revision++
	raw, err := json.Marshal(j)
	if err != nil || len(raw) > 4<<20 {
		return nil, state.ConditionFailed
	}
	return writeCheckpoint(s, RegistryMaintenanceKey, p.Cluster, p.TrustRoot, j.Revision, raw)
}
func (p Policy) reduceRegistryMaintenance(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind == state.ModuleReport {
		return p.reduceRegistryMaintenanceReport(s, cmd)
	}
	p, err := p.Current(s)
	if err != nil || cmd.Kind != state.Module || cmd.Key != RegistryMaintenanceKey {
		return nil, state.Forbidden
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || p.authorizeRegistryMaintenance(c, op) != nil {
		return nil, state.Forbidden
	}
	var q RegistryMaintenanceChange
	if canonical(op.Change.Payload, &q) != nil || !q.Valid(p.Cluster, op.Change.Action) || op.Change.Expected != q.ExpectedRevision() {
		return nil, state.Invalid
	}
	held, e := p.registryMaintenancePending(s, q.Tenant, q.RegistryID(), q.External != nil)
	if p.maintenanceCurrentRun(s, q, op.At) != nil || e != nil || held {
		return nil, state.ConditionFailed
	}
	if op.Change.Action == RegistryPruneAction && p.pruneAdmission(s, q) != nil {
		return nil, state.ConditionFailed
	}
	if op.Change.Action == "delete-registry-image" && p.maintenanceDeleteAdmission(s, q) != nil {
		return nil, state.ConditionFailed
	}
	// Native refusal has an original asynchronous result (IMAGE_IN_USE), not
	// an indistinguishable generic CAS failure. The pending fence is installed
	// here; the owner rechecks the same references before any native effect.
	jobs, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return nil, state.Invalid
	}
	if len(jobs.Records) >= 128 {
		return nil, state.ConditionFailed
	}
	if _, exists := jobs.Record(q.Operation); exists {
		return nil, state.ConditionFailed
	}
	jobs.Records = append(jobs.Records, RegistryMaintenanceRecord{Origin: op, Change: q, State: "queued", Revision: 1, At: uint64(op.At)})
	return p.registryMaintenanceCheckpoint(s, jobs)
}

func (p Policy) RegistryPushAvailable(s state.State, spec registry.Specification) error {
	jobs, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return err
	}
	for _, row := range jobs.Records {
		if row.Pending() && row.Change.External == nil && row.Change.Tenant == spec.Tenant && row.Change.RegistryID() == spec.ID {
			return access.ErrConflict
		}
	}
	return nil
}
func (p Policy) registryMaintenanceImageAvailable(s state.State, ref string) error {
	_, authority, repo, err := registryclient.Normalize(ref)
	if err != nil {
		return nil
	} // a bare native config ID has no registry audience
	jobs, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return err
	}
	for _, row := range jobs.Records {
		if !row.Pending() || row.Change.Authority() != authority {
			continue
		}
		if row.Change.Prune != nil {
			if row.Change.Prune.Conditions.GC || row.Change.PruneRepository(repo) {
				return access.ErrConflict
			}
			continue
		}
		if row.Origin.Change.Action == "gc-registry" {
			return access.ErrConflict
		}
		if row.Change.Repository != repo {
			continue
		}
		candidate := ImageReference{Image: ref}
		for _, target := range maintenanceDeleteRefs(row.Change) {
			if candidate.MatchImage(target) != "" {
				return access.ErrConflict
			}
		}
	}
	return nil
}

// A new source ID/definition is not a new lifetime for a pending remote image.
// Reuse the same image fence across source IDs and tenants at that authority.
func (p Policy) maintenanceDeleteAdmission(s state.State, q RegistryMaintenanceChange) error {
	for _, ref := range maintenanceDeleteRefs(q) {
		if err := p.registryMaintenanceImageAvailable(s, ref); err != nil {
			return err
		}
	}
	return nil
}

func (p Policy) RegistryMaintenancePending(s state.State, tenant, id string) (bool, error) {
	return p.registryMaintenancePending(s, tenant, id, false)
}
func (p Policy) registryMaintenancePending(s state.State, tenant, id string, external bool) (bool, error) {
	jobs, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return false, err
	}
	for _, row := range jobs.Records {
		if row.Pending() && row.Change.Tenant == tenant && row.Change.RegistryID() == id && (row.Change.External != nil) == external {
			return true, nil
		}
	}
	return false, nil
}

// registryMaintenanceBook is the RegistryMaintenanceKey book (books.go).
var registryMaintenanceBook = Book{Key: RegistryMaintenanceKey, Reduce: Policy.reduceRegistryMaintenance}
