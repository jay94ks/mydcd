// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"math"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/secrets"
)

type ImageBuildJobSelection struct{ Tenant, ID string }
type ImageBuildJobQuery struct {
	ID, Context string
	Version     [32]byte
}

func (q ImageBuildJobQuery) Valid() bool {
	return validID(q.ID) && validID(q.Context) && q.Version != ([32]byte{})
}

type ImageBuildJobStart struct {
	Tenant, ID, Context string
	Version, Snapshot   [32]byte
	At                  uint64
}
type ImageBuildJobPlan struct {
	Schema                     uint8
	Spec                       imagebuild.JobSpec
	Change                     ImageBuildJobStart
	RootRevision, Epoch, Index uint64
	Uses                       map[string][]secrets.Use `json:",omitempty"`
}
type ImageBuildJobRecord struct {
	Run         imagebuild.JobRun
	Origin      UserOperation
	CancelledBy *UserOperation       `json:",omitempty"`
	Progress    *ImageBuildJobReport `json:",omitempty"`
	Begin       *ImageBuildJobReport `json:",omitempty"`
	OwnerSteps  uint8                `json:",omitempty"`
	Deleted     bool
	DeletedBy   *UserOperation                `json:",omitempty"`
	Grants      []secrets.Grant               `json:",omitempty"`
	Sources     []ImageBuildSourceBinding     `json:",omitempty"`
	Automatic   *ImageBuildAutomaticGitReport `json:",omitempty"`
}
type ImageBuildJobView struct {
	ID, Context, Node, User, Phase        string
	Version                               [32]byte
	Number, Revision, CreatedAt, ClosedAt uint64
	Cancel, Deleted                       bool
	Result                                *imagebuild.JobResult `json:",omitempty"`
	Automatic                             bool                  `json:",omitempty"`
}

func imageBuildJobView(r ImageBuildJobRecord) ImageBuildJobView {
	s := r.Run.Spec
	v := ImageBuildJobView{ID: s.ID, Context: s.Context.ID, Node: s.Scope.Root.Node, User: r.Origin.Session.User, Phase: r.Run.Phase, Version: s.Version, Number: s.Number, Revision: r.Run.Revision, CreatedAt: s.CreatedAt, Cancel: r.Run.Cancel, Deleted: r.Deleted}
	v.Automatic = r.Automatic != nil
	if r.Run.Closure != nil {
		result := r.Run.Closure.Result
		v.Result = &result
		v.ClosedAt = r.Run.Closure.At
	}
	return v
}

func (b ImageBuildCatalog) Job(tenant, id string) (ImageBuildJobRecord, bool) {
	for _, r := range b.Jobs {
		if r.Run.Spec.Tenant == tenant && r.Run.Spec.ID == id {
			return r, true
		}
	}
	return ImageBuildJobRecord{}, false
}
func (b ImageBuildCatalog) VersionUsed(tenant string, version [32]byte) bool {
	for _, r := range b.Jobs {
		if !r.Deleted && r.Run.Spec.Tenant == tenant && r.Run.Spec.Version == version {
			return true
		}
	}
	return false
}
func (p Policy) ImageBuildJobPlan(s state.State, session access.Session, at int64, tenant string, q ImageBuildJobQuery) (ImageBuildJobPlan, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildJobPlan{}, err
	}
	if at <= 0 || !validID(tenant) || !q.Valid() {
		return ImageBuildJobPlan{}, access.ErrInvalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildJobPlan{}, err
	}
	if c.OperationAllowed(session, "begin-image-build") != nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return ImageBuildJobPlan{}, access.ErrDenied
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildJobPlan{}, err
	}
	return p.planImageBuildJob(s, c, b, session, at, 0, tenant, q)
}

// acceptedAt is nonzero only for an already committed automatic context
// definition, whose origin and current capabilities the caller has checked.
func (p Policy) planImageBuildJob(s state.State, c access.Catalog, b ImageBuildCatalog, session access.Session, at, acceptedAt int64, tenant string, q ImageBuildJobQuery) (ImageBuildJobPlan, error) {
	if _, exists := b.Job(tenant, q.ID); exists {
		return ImageBuildJobPlan{}, access.ErrConflict
	}
	ctx, ok := b.Context(tenant, q.Context)
	policy, hasPolicy := b.Policy(tenant)
	v, hasVersion := b.Version(tenant, q.Version)
	if !ok || ctx.Deleted || !hasPolicy || policy.Deleted || !hasVersion || v.Deleted || v.Context != q.Context || !ctx.Spec.Under(policy.Spec) {
		return ImageBuildJobPlan{}, access.ErrConflict
	}
	u, ok := b.Upload(tenant, v.Upload)
	var rootError error
	if acceptedAt > 0 {
		rootError = p.buildRootAccepted(s, c, session, acceptedAt, tenant, u.Scope.Root)
	} else {
		rootError = p.buildRootCurrent(s, c, session, at, tenant, u.Scope.Root)
	}
	if !ok || !u.Closed || u.Reclaimed != nil || u.Version != v.ID || ctx.Spec.Root != u.Scope.Root || rootError != nil {
		return ImageBuildJobPlan{}, access.ErrDenied
	}
	registries, err := p.Registries(s)
	if err != nil {
		return ImageBuildJobPlan{}, err
	}
	registry, ok := registries.Entry(tenant, policy.Spec.Registry)
	if !ok || registry.Deleted || !registry.Spec.Enabled || registry.Generation == 0 {
		return ImageBuildJobPlan{}, access.ErrConflict
	}
	if _, err := c.CheckImageTrust(tenant, policy.Spec.BuilderImage); err != nil {
		return ImageBuildJobPlan{}, access.ErrDenied
	}
	if p.imageCacheAvailable(s, ctx.Spec.Root.Node, policy.Spec.BuilderImage) != nil {
		return ImageBuildJobPlan{}, access.ErrConflict
	}
	queued := 0
	for _, r := range b.Jobs {
		if r.Run.Spec.Tenant == tenant && !r.Run.Terminal() {
			queued++
		}
	}
	if queued >= 128 {
		return ImageBuildJobPlan{}, access.ErrConflict
	}
	context := ctx.Spec.Own()
	context.Dockerfile = u.Scope.Dockerfile
	spec := imagebuild.JobSpec{Schema: 1, Cluster: p.Cluster, Tenant: tenant, ID: q.ID, Version: v.ID, Number: v.Number, Scope: u.Scope, Seal: v.Fact, Context: context, Policy: policy.Spec, ContextRevision: ctx.Revision, PolicyRevision: policy.Revision, RegistryAuthority: registry.Spec.Authority, RegistryGeneration: registry.Generation, RegistrySpec: registry.Spec.Digest(), Commit: v.Commit, CreatedAt: uint64(at)}
	if spec.Validate() != nil {
		return ImageBuildJobPlan{}, access.ErrInvalid
	}
	for _, tag := range mustJobTags(spec) {
		if p.registryMaintenanceImageAvailable(s, tag) != nil {
			return ImageBuildJobPlan{}, access.ErrConflict
		}
	}
	raw, err := json.Marshal(spec)
	if err != nil || len(raw) > 24<<10 {
		return ImageBuildJobPlan{}, access.ErrInvalid
	}
	change := ImageBuildJobStart{Tenant: tenant, ID: q.ID, Context: q.Context, Version: q.Version, Snapshot: spec.Digest(), At: uint64(at)}
	return ImageBuildJobPlan{Schema: 1, Spec: spec.Own(), Change: change, RootRevision: s.Object(ImageBuildKey).Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), Uses: ImageBuildSecretUses(spec, session)}, nil
}
func (p Policy) reduceImageBuildJob(s state.State, b ImageBuildCatalog, op UserOperation, writes map[string][]byte) (ImageBuildCatalog, state.Code) {
	if op.Change.Action == "begin-image-build" {
		var q ImageBuildJobStart
		if canonical(op.Change.Payload, &q) != nil || q.At == 0 || q.At > math.MaxInt64 || q.At > uint64(op.At) || uint64(op.At)-q.At > 120 || op.Change.Expected != 0 {
			return b, state.ConditionFailed
		}
		plan, err := p.ImageBuildJobPlan(s, op.Session, int64(q.At), q.Tenant, ImageBuildJobQuery{ID: q.ID, Context: q.Context, Version: q.Version})
		if err != nil || plan.Change != q {
			return b, state.ConditionFailed
		}
		run, err := imagebuild.NewJob(plan.Spec)
		if err != nil {
			return b, state.Invalid
		}
		r := ImageBuildJobRecord{Run: run, Origin: op}
		if err := p.acquireImageBuildSecrets(s, &r, writes); err != nil {
			return b, state.ConditionFailed
		}
		if !imageBuildRecordBudget(r) {
			return b, state.ConditionFailed
		}
		if writeBuildRecord(writes, "job", q.Tenant, q.ID, r) != nil {
			return b, state.Invalid
		}
		b.Jobs = append(b.Jobs, r)
		return b, state.Applied
	}
	var q ImageBuildJobSelection
	if canonical(op.Change.Payload, &q) != nil || !validID(q.Tenant) || !validID(q.ID) {
		return b, state.Invalid
	}
	r, ok := b.Job(q.Tenant, q.ID)
	if !ok || r.Deleted || r.Run.Revision != op.Change.Expected {
		return b, state.ConditionFailed
	}
	if op.Change.Action == "cancel-image-build" {
		run, err := r.Run.RequestCancel(op.Change.Expected)
		if err != nil {
			return b, state.ConditionFailed
		}
		r.Run = run
		r.CancelledBy = &op
		if !imageBuildRecordBudget(r) {
			return b, state.ConditionFailed
		}
	} else if op.Change.Action == "delete-image-build-job" {
		if !r.Run.Terminal() {
			return b, state.ConditionFailed
		}
		r.Deleted, r.DeletedBy = true, &op
	} else {
		return b, state.Invalid
	}
	if writeBuildRecord(writes, "job", q.Tenant, q.ID, r) != nil {
		return b, state.Invalid
	}
	return b, state.Applied
}

func validateImageBuildJob(r ImageBuildJobRecord, cluster [32]byte) error {
	if !validImageBuildSecretGrants(r) || !validImageBuildSources(r.Run.Spec, r.Run.Inputs, r.Sources) {
		return ErrCatalog
	}
	spec := r.Run.Spec
	var start ImageBuildJobStart
	if r.Run.Shape() != nil || spec.Cluster != cluster || spec.Validate() != nil || r.Origin.VerifyOriginal(cluster) != nil || r.Origin.At <= 0 || r.OwnerSteps > 3 {
		return ErrCatalog
	}
	if r.Automatic != nil {
		if !validAutomaticGitJob(r, cluster) {
			return ErrCatalog
		}
	} else if spec.CreatedAt > uint64(r.Origin.At) || uint64(r.Origin.At)-spec.CreatedAt > 120 || r.Origin.Change.Action != "begin-image-build" || r.Origin.Change.Expected != 0 || canonical(r.Origin.Change.Payload, &start) != nil || start.Tenant != spec.Tenant || start.ID != spec.ID || start.Context != spec.Context.ID || start.Version != spec.Version || start.At != spec.CreatedAt || start.Snapshot != spec.Digest() {
		return ErrCatalog
	}
	cancelStep := uint64(0)
	if r.CancelledBy != nil {
		cancelStep = 1
		var q ImageBuildJobSelection
		if r.CancelledBy.VerifyOriginal(cluster) != nil || r.CancelledBy.Change.Action != "cancel-image-build" || canonical(r.CancelledBy.Change.Payload, &q) != nil || q.Tenant != spec.Tenant || q.ID != spec.ID || r.CancelledBy.Change.Expected == 0 || r.CancelledBy.Change.Expected >= r.Run.Revision {
			return ErrCatalog
		}
	}
	if r.Run.Cancel != (r.CancelledBy != nil) || r.Run.Revision != 1+uint64(r.OwnerSteps)+cancelStep || (r.Progress == nil) != (r.OwnerSteps == 0) || r.Deleted != (r.DeletedBy != nil) {
		return ErrCatalog
	}
	if r.OwnerSteps == 0 && r.Run.Phase != "queued" {
		return ErrCatalog
	}
	if r.Progress != nil {
		last := *r.Progress
		if last.Action == "begin" {
			last.Inputs = r.Run.Inputs
			last.Sources = r.Sources
		}
		if !last.Valid(spec) || last.Expected == 0 || last.Expected >= r.Run.Revision || last.Expected+1 != r.Run.Revision && !(r.CancelledBy != nil && last.Expected+2 == r.Run.Revision && r.CancelledBy.Change.Expected+1 == r.Run.Revision) {
			return ErrCatalog
		}
		switch last.Action {
		case "begin":
			if r.Run.Phase != "running" || r.OwnerSteps != 1 {
				return ErrCatalog
			}
		case "uncertain":
			if r.Run.Phase != "unknown" || r.OwnerSteps != 2 {
				return ErrCatalog
			}
		case "complete":
			if !r.Run.Terminal() || !buildJSONEqual(last.Closure, r.Run.Closure) || r.Run.Closure.Result.Code == "OK" && r.OwnerSteps < 2 {
				return ErrCatalog
			}
		default:
			return ErrCatalog
		}
	}
	if r.Begin != nil {
		begin := *r.Begin
		begin.Inputs = r.Run.Inputs
		begin.Sources = r.Sources
		if begin.Action != "begin" || !begin.Valid(spec) || begin.Expected != 1 || r.Run.Phase == "queued" || r.CancelledBy != nil && r.CancelledBy.Change.Expected <= begin.Expected {
			return ErrCatalog
		}
	} else if r.Run.Phase == "running" || r.Run.Phase == "unknown" || len(r.Run.Inputs) != 0 || len(r.Sources) != 0 || r.Run.Terminal() && r.Run.Closure.Result.Code == "OK" {
		return ErrCatalog
	}
	if r.Begin == nil && r.OwnerSteps > 0 && (r.OwnerSteps != 1 || r.Progress.Action != "complete") {
		return ErrCatalog
	}
	if r.Run.Terminal() && !r.Run.Closure.Valid(spec) {
		return ErrCatalog
	}
	if r.DeletedBy != nil {
		var q ImageBuildJobSelection
		if !r.Run.Terminal() || r.DeletedBy.VerifyOriginal(cluster) != nil || r.DeletedBy.Change.Action != "delete-image-build-job" || r.DeletedBy.Change.Expected != r.Run.Revision || canonical(r.DeletedBy.Change.Payload, &q) != nil || q.Tenant != spec.Tenant || q.ID != spec.ID {
			return ErrCatalog
		}
	}
	return nil
}
