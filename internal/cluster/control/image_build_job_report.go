// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/secrets"
)

type ImageBuildJobWorkQuery struct {
	Tenant, ID string
	At         int64
}
type ImageBuildJobWork struct {
	Schema                     uint8
	Run                        imagebuild.JobRun
	Allowed                    bool
	RootRevision, Epoch, Index uint64
	Blocked                    string `json:",omitempty"`
}

func (p Policy) ImageBuildJobWork(s state.State, caller [32]byte, q ImageBuildJobWorkQuery) (ImageBuildJobWork, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildJobWork{}, err
	}
	if !validID(q.Tenant) || !validID(q.ID) || q.At <= 0 {
		return ImageBuildJobWork{}, access.ErrInvalid
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildJobWork{}, err
	}
	r, ok := b.Job(q.Tenant, q.ID)
	if !ok || r.Run.Spec.Scope.Root.Key != caller || r.Deleted {
		return ImageBuildJobWork{}, access.ErrDenied
	}
	spec := r.Run.Spec
	owner, err := p.nodeOwner(s, spec.Scope.Root.Node)
	if err != nil || owner != caller {
		return ImageBuildJobWork{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildJobWork{}, err
	}
	allowed := !r.Run.Cancel && !r.Run.Terminal() && uint64(q.At) >= spec.CreatedAt && uint64(q.At) < spec.CreatedAt+spec.Policy.Seconds
	if c.OperationAllowed(r.Origin.Session, "begin-image-build") != nil || c.AuthorizeAccepted(r.Origin.Session, p.Cluster, r.Origin.At, q.Tenant, access.ManageRegistry, spec.Scope.Root.Node) != nil {
		allowed = false
	}
	if len(spec.Context.Secrets) > 0 {
		v, err := p.Vault(s)
		if err != nil {
			return ImageBuildJobWork{}, err
		}
		if c.AuthorizeAccepted(r.Origin.Session, p.Cluster, r.Origin.At, q.Tenant, access.Deploy, spec.Scope.Root.Node) != nil {
			allowed = false
		}
		if _, err := p.bindingGrantReads(s, v, c, r.Grants, q.At); err != nil {
			allowed = false
		}
	}
	policy, ok := b.Policy(q.Tenant)
	ctx, hasContext := b.Context(q.Tenant, spec.Context.ID)
	v, hasVersion := b.Version(q.Tenant, spec.Version)
	if !ok || policy.Deleted || policy.Revision != spec.PolicyRevision || !hasContext || ctx.Deleted || ctx.Revision != spec.ContextRevision || !hasVersion || v.Deleted {
		allowed = false
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return ImageBuildJobWork{}, err
	}
	root, err := roots.CanBuild(c, r.Origin.Session.User, q.Tenant, spec.Scope.Root.Node, spec.Scope.Root.ID, spec.Scope.Root.Generation)
	if err != nil || root.Reference(p.Cluster) != spec.Scope.Root {
		allowed = false
	}
	if work, err := p.workNodeOwner(s, spec.Scope.Root.Node); err != nil || work != caller {
		allowed = false
	}
	if _, err := c.CheckImageRefTrust(q.Tenant, spec.Policy.BuilderImage); err != nil {
		allowed = false
	}
	if err := p.imageCacheAvailable(s, spec.Scope.Root.Node, spec.Policy.BuilderImage); err != nil {
		allowed = false
	}
	registries, err := p.Registries(s)
	if err != nil {
		return ImageBuildJobWork{}, err
	}
	registry, ok := registries.Entry(q.Tenant, spec.Policy.Registry)
	if !ok || registry.Deleted || !registry.Spec.Enabled || registry.Generation != spec.RegistryGeneration || registry.Spec.Digest() != spec.RegistrySpec || registry.Active == nil || registry.Active.Draining || registry.Active.Spec.Digest() != spec.RegistrySpec {
		allowed = false
	}
	for _, tag := range mustJobTags(spec) {
		if p.registryMaintenanceImageAvailable(s, tag) != nil {
			allowed = false
		}
	}
	for _, input := range r.Run.Frozen() {
		if _, err := c.CheckImageTrust(q.Tenant, input.Image); err != nil {
			allowed = false
		}
		if p.imageCacheAvailable(s, spec.Scope.Root.Node, input.Image) != nil {
			allowed = false
		}
	}
	if allowed && r.Begin != nil {
		current, err := p.imageBuildSourceBindings(s, c, spec, r.Run.Read(), q.At)
		if err != nil || !buildJSONEqual(current, r.Sources) {
			allowed = false
		}
	}
	if r.Run.Phase == "queued" {
		if allowed && b.CachePruneBlocks(imagebuild.CacheIdentity(spec), r.SubmissionRootRevision()) {
			return ImageBuildJobWork{Schema: 1, Run: r.Run, RootRevision: s.Object(ImageBuildKey).Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), Blocked: "WAITING_FOR_CACHE"}, nil
		}
		active := b.activeBuildWorkers(q.Tenant)
		if allowed && active >= spec.Policy.Concurrency {
			return ImageBuildJobWork{Schema: 1, Run: r.Run, RootRevision: s.Object(ImageBuildKey).Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), Blocked: "WAITING_FOR_SLOT"}, nil
		}
		if allowed && !p.imageBuildBudgetAvailable(s, ImageBuildJobWork{Run: r.Run}) {
			return ImageBuildJobWork{Schema: 1, Run: r.Run, RootRevision: s.Object(ImageBuildKey).Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), Blocked: "WAITING_FOR_BUDGET"}, nil
		}
	}
	blocked := ""
	if !allowed {
		blocked = "PERMISSION_REVOKED"
		switch {
		case r.Run.Terminal():
			blocked = "CLOSED"
		case r.Run.Cancel:
			blocked = "CANCELLED"
		case uint64(q.At) >= spec.CreatedAt+spec.Policy.Seconds:
			blocked = "TIMEOUT"
		case uint64(q.At) < spec.CreatedAt:
			blocked = "NOT_READY"
		}
	}
	return ImageBuildJobWork{Schema: 1, Run: r.Run, Allowed: allowed, RootRevision: s.Object(ImageBuildKey).Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), Blocked: blocked}, nil
}

// frozen is the begin report's pinned images, builder included.
func (r ImageBuildJobReport) frozen() []imagebuild.FrozenSource {
	out := append([]imagebuild.FrozenSource(nil), r.Inputs...)
	if r.Builder != nil {
		out = append(out, *r.Builder)
	}
	return out
}

// read is frozen without a builder taken from the node's local copy: only
// registry reads carry a source binding.
func (r ImageBuildJobReport) read() []imagebuild.FrozenSource {
	if r.BuilderLocal != "" {
		return append([]imagebuild.FrozenSource(nil), r.Inputs...)
	}
	return r.frozen()
}

func mustJobTags(spec imagebuild.JobSpec) []string { tags, _ := spec.OutputTags(); return tags }

type ImageBuildJobReport struct {
	Schema                            uint8
	Kind                              string
	Cluster, Owner                    [32]byte
	Tenant, Job, Action               string
	Expected, RootRevision, Epoch, At uint64
	Inputs                            []imagebuild.FrozenSource `json:",omitempty"`
	Builder                           *imagebuild.FrozenSource  `json:",omitempty"`
	BuilderLocal                      string                    `json:",omitempty"`
	Sources                           []ImageBuildSourceBinding `json:",omitempty"`
	Closure                           *imagebuild.JobClosure    `json:",omitempty"`
	Secrets                           []secrets.UseGone         `json:",omitempty"`
	Signature                         []byte
}

func ImageBuildJobReportBytes(r ImageBuildJobReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-imagebuild-job-report-1\x00"), raw...)
}
func (r ImageBuildJobReport) Valid(spec imagebuild.JobSpec) bool {
	if r.Schema != 1 || r.Kind != "job" || r.Cluster != spec.Cluster || r.Owner != spec.Scope.Root.Key || r.Tenant != spec.Tenant || r.Job != spec.ID || r.At < spec.CreatedAt || r.At > math.MaxInt64 || r.Expected == 0 || r.Epoch == 0 || !ed25519.Verify(r.Owner[:], ImageBuildJobReportBytes(r), r.Signature) {
		return false
	}
	switch r.Action {
	case "begin":
		return r.Closure == nil && len(r.Secrets) == 0 && imagebuild.ValidateJobInputs(spec, r.Inputs) == nil && (r.Builder == nil && r.BuilderLocal == "" || imagebuild.ValidateJobBuilder(spec, r.Builder, r.BuilderLocal) == nil) && validImageBuildSources(spec, r.read(), r.Sources)
	case "uncertain":
		return r.Closure == nil && len(r.Inputs) == 0 && r.Builder == nil && r.BuilderLocal == "" && len(r.Sources) == 0 && len(r.Secrets) == 0
	case "complete":
		return len(r.Inputs) == 0 && r.Builder == nil && r.BuilderLocal == "" && len(r.Sources) == 0 && r.Closure != nil && r.Closure.Valid(spec) && r.Closure.At <= r.At
	}
	return false
}
func (r ImageBuildJobReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Owner[:]), Epoch: r.Epoch, Key: ImageBuildKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) imageBuildJobReport(s state.State, cmd state.Command) (ImageBuildJobReport, ImageBuildJobWork, error) {
	var r ImageBuildJobReport
	if cmd.Kind != state.ModuleReport || cmd.Key != ImageBuildKey || canonical([]byte(cmd.Value), &r) != nil || r.Kind != "job" || r.Epoch != s.ModuleEpoch() {
		return r, ImageBuildJobWork{}, access.ErrInvalid
	}
	want, err := r.Command()
	if err != nil || want != cmd {
		return r, ImageBuildJobWork{}, access.ErrInvalid
	}
	work, err := p.ImageBuildJobWork(s, r.Owner, ImageBuildJobWorkQuery{Tenant: r.Tenant, ID: r.Job, At: int64(r.At)})
	if err != nil || !r.Valid(work.Run.Spec) || r.Expected != work.Run.Revision {
		return r, work, access.ErrDenied
	}
	if r.Action == "complete" {
		b, err := p.ImageBuilds(s)
		if err != nil {
			return r, work, err
		}
		row, ok := b.Job(r.Tenant, r.Job)
		if !ok || len(r.Secrets) != len(row.Grants) {
			return r, work, access.ErrDenied
		}
		for i, grant := range row.Grants {
			if !validImageBuildSecretProof(work.Run.Spec, grant, r.Secrets[i]) {
				return r, work, access.ErrDenied
			}
		}
	}
	if r.Action == "begin" {
		if !work.Allowed || work.Run.Phase != "queued" {
			return r, work, access.ErrDenied
		}
		c, err := p.Catalog(s)
		if err != nil {
			return r, work, err
		}
		for _, input := range r.frozen() {
			if _, err := c.CheckImageTrust(r.Tenant, input.Image); err != nil || p.imageCacheAvailable(s, work.Run.Spec.Scope.Root.Node, input.Image) != nil {
				return r, work, access.ErrDenied
			}
		}
		sources, err := p.imageBuildSourceBindings(s, c, work.Run.Spec, r.read(), int64(r.At))
		if err != nil || !buildJSONEqual(sources, r.Sources) {
			return r, work, access.ErrDenied
		}
	}
	return r, work, nil
}
func (p Policy) ResolveImageBuildJobReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r ImageBuildJobReport
	if canonical(raw, &r) != nil || r.Owner != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := r.Command()
	if err != nil {
		return cmd, err
	}
	_, _, err = p.imageBuildJobReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceImageBuildJobReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, work, err := p.imageBuildJobReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return nil, state.Invalid
	}
	row, _ := b.Job(r.Tenant, r.Job)
	var run imagebuild.JobRun
	switch r.Action {
	case "begin":
		run, err = work.Run.Begin(r.Expected, r.At, r.Inputs, r.Builder, r.BuilderLocal)
		row.Sources = r.Sources
	case "uncertain":
		run, err = work.Run.Uncertain(r.Expected)
	case "complete":
		run, err = work.Run.Complete(r.Expected, *r.Closure)
	default:
		return nil, state.Invalid
	}
	if err != nil || row.OwnerSteps >= 3 {
		return nil, state.ConditionFailed
	}
	row.Run = run
	row.OwnerSteps++
	r.Inputs = nil                      // normalized proof: its signed inputs live once in Run.Inputs
	r.Builder, r.BuilderLocal = nil, "" // and its builder pin in Run.Builder
	r.Sources = nil                     // original source references live once in the same row
	row.Progress = &r
	if r.Action == "begin" {
		row.Begin = &r
	}
	writes := map[string][]byte{ImageBuildKey: []byte(s.Object(ImageBuildKey).Value)}
	if r.Action == "complete" && len(row.Grants) > 0 {
		v, err := p.Vault(s)
		if err != nil {
			return nil, state.Invalid
		}
		for _, proof := range r.Secrets {
			v.Approvals, err = v.Approvals.ReleaseUse(proof)
			if err != nil {
				return nil, state.ConditionFailed
			}
		}
		extra, code := p.vaultCheckpoint(s, v)
		if code != state.Applied {
			return nil, code
		}
		for key, value := range extra {
			writes[key] = value
		}
	}
	if !imageBuildRecordBudget(row) {
		return nil, state.ConditionFailed
	}
	if writeBuildRecord(writes, "job", r.Tenant, r.Job, row) != nil {
		return nil, state.Invalid
	}
	return writes, state.Applied
}
