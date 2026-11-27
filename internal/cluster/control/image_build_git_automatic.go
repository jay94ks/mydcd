// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/secrets"
)

// The context definition is the accepted user authority. This report is the
// owner's stored-archive evidence and exact proposed job, never a new login.
type ImageBuildAutomaticGitReport struct {
	Schema                             uint8
	Kind                               string
	Cluster, Owner, Definition         [32]byte
	Tenant, Context                    string
	RootRevision, Epoch, At, StartedAt uint64
	Saved                              imagebuild.SavedGit
	Snapshot                           [32]byte
	Signature                          []byte
}

func ImageBuildAutomaticGitID(definition [32]byte, policyRevision uint64, commit string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("sfc-imagebuild-automatic-git-id-1\x00%x\x00%d\x00%s", definition, policyRevision, commit)))
	return "auto-" + hex.EncodeToString(hash[:24])
}

func ImageBuildAutomaticGitReportBytes(report ImageBuildAutomaticGitReport) []byte {
	report.Signature = nil
	raw, _ := json.Marshal(report)
	return append([]byte("sfc-imagebuild-automatic-git-report-1\x00"), raw...)
}

// The next version number belongs to the FSM allocator. Excluding just that
// number lets unrelated manual publications precede this original intent
// without changing its archive, user, policy, destination or start time.
func ImageBuildAutomaticGitSnapshot(spec imagebuild.JobSpec) [32]byte {
	spec.Number = 0
	raw, _ := json.Marshal(spec)
	return sha256.Sum256(append([]byte("sfc-imagebuild-automatic-git-intent-1\x00"), raw...))
}

func (p Policy) ImageBuildAutomaticGitSavePlan(s state.State, caller [32]byte, tenant, id string, at int64, original *imagebuild.GitSavePlan) (imagebuild.GitSavePlan, error) {
	work, err := p.ImageBuildGitWatchWork(s, caller, tenant, id, at)
	if err != nil {
		return imagebuild.GitSavePlan{}, err
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return imagebuild.GitSavePlan{}, err
	}
	context, _ := book.Context(tenant, id)
	if context.GitObservation == nil || !context.GitObservation.Report.Result.Valid(work.Read) || context.GitObservation.Report.Result.Code != "OK" {
		return imagebuild.GitSavePlan{}, reconcile.ErrPending
	}
	observation := context.GitObservation.Report
	createdAt := observation.At
	plan := imagebuild.GitSavePlan{Schema: 1, Tenant: tenant, Context: id, ID: ImageBuildAutomaticGitID(work.Definition, work.Read.PolicyRevision, observation.Result.Commit), Creator: context.Definition.Session.User, Root: work.Read.Spec.Root, ContextRevision: work.Read.ContextRevision, PolicyRevision: work.Read.PolicyRevision, Dockerfile: work.Read.Spec.Dockerfile, ExpandedLimit: work.Read.Policy.WorkspaceBytes, Commit: observation.Result.Commit, Tree: observation.Result.Tree, CreatedAt: createdAt, ExpiresAt: createdAt + imagebuild.MaxUploadLifetime}
	if original != nil {
		plan.CreatedAt, plan.ExpiresAt = original.CreatedAt, original.ExpiresAt
		if plan != *original {
			return imagebuild.GitSavePlan{}, access.ErrConflict
		}
	}
	if plan.Validate() != nil || plan.CreatedAt < uint64(context.Definition.At) || uint64(at) < plan.CreatedAt || uint64(at) >= plan.ExpiresAt {
		return imagebuild.GitSavePlan{}, imagebuild.ErrExpired
	}
	return plan, nil
}

func (p Policy) ImageBuildAutomaticGitSaveWork(s state.State, caller [32]byte, plan imagebuild.GitSavePlan, at int64) (ImageBuildGitWork, error) {
	if _, err := p.ImageBuildAutomaticGitSavePlan(s, caller, plan.Tenant, plan.Context, at, &plan); err != nil {
		return ImageBuildGitWork{}, err
	}
	work, err := p.ImageBuildGitWatchWork(s, caller, plan.Tenant, plan.Context, at)
	if err != nil {
		return ImageBuildGitWork{}, err
	}
	users, err := p.Catalog(s)
	if err != nil {
		return ImageBuildGitWork{}, err
	}
	for _, action := range []string{"publish-build-git", "begin-image-build"} {
		if users.OperationAllowed(work.Read.Session, action) != nil {
			return ImageBuildGitWork{}, access.ErrDenied
		}
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return ImageBuildGitWork{}, err
	}
	root, ok := roots.Root(plan.Root.Node, plan.Root.ID)
	if !ok || root.Reference(p.Cluster) != plan.Root {
		return ImageBuildGitWork{}, access.ErrConflict
	}
	return ImageBuildGitWork{Read: work.Read, Root: root}, nil
}

func (report ImageBuildAutomaticGitReport) Command() (state.Command, error) {
	raw, err := json.Marshal(report)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(report.Owner[:]), Epoch: report.Epoch, Key: ImageBuildKey, Expected: report.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func validAutomaticGitOrigin(origin UserOperation, report ImageBuildAutomaticGitReport, cluster [32]byte) bool {
	var put ImageBuildContextPut
	plan := report.Saved.Plan
	if origin.VerifyOriginal(cluster) != nil || origin.At <= 0 || origin.Change.Action != "put-build-context" || canonical(origin.Change.Payload, &put) != nil || put.Spec.Validate() != nil || put.Spec.Kind != "git" || put.Spec.Git == nil || !put.Spec.Git.Automatic || report.Schema != 1 || report.Kind != "automatic-git" || report.Cluster != cluster || report.Owner != put.Spec.Root.Key || report.Definition != sha256.Sum256(OperationBytes(origin)) || report.Tenant != put.Spec.Tenant || report.Context != put.Spec.ID || report.RootRevision < origin.RootRevision || report.Epoch < origin.Epoch || report.Snapshot == ([32]byte{}) || !report.Saved.Valid() || plan.Root != put.Spec.Root || plan.Tenant != put.Spec.Tenant || plan.Context != put.Spec.ID || plan.Creator != origin.Session.User || plan.ContextRevision != origin.Change.Expected+1 || plan.Dockerfile != put.Spec.Dockerfile || plan.ID != ImageBuildAutomaticGitID(report.Definition, plan.PolicyRevision, plan.Commit) || plan.CreatedAt < uint64(origin.At) || report.StartedAt < plan.CreatedAt || report.StartedAt > math.MaxInt64 || report.At < report.StartedAt || report.At >= plan.ExpiresAt || report.At > math.MaxInt64 {
		return false
	}
	return ed25519.Verify(report.Owner[:], ImageBuildAutomaticGitReportBytes(report), report.Signature)
}

// Only actual, owner-sealed bytes may become a prospective version. Planning
// uses the same job core as manual begin, before any shared reservation exists.
func (p Policy) ImageBuildAutomaticGitPlan(s state.State, caller [32]byte, saved imagebuild.SavedGit, startedAt, at int64) (ImageBuildJobPlan, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildJobPlan{}, err
	}
	if !saved.Valid() || startedAt <= 0 || at < startedAt || uint64(startedAt) < saved.Plan.CreatedAt || uint64(at) >= saved.Plan.ExpiresAt {
		return ImageBuildJobPlan{}, access.ErrInvalid
	}
	plan := saved.Plan
	work, err := p.ImageBuildGitWatchWork(s, caller, plan.Tenant, plan.Context, at)
	if err != nil {
		return ImageBuildJobPlan{}, err
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildJobPlan{}, err
	}
	row, _ := book.Context(plan.Tenant, plan.Context)
	policy, _ := book.Policy(plan.Tenant)
	if row.GitObservation == nil || !row.GitObservation.Report.Result.Valid(work.Read) || row.GitObservation.Report.Result.Code != "OK" || row.GitObservation.Report.Result.Commit != plan.Commit || row.GitObservation.Report.Result.Tree != plan.Tree || row.GitObservation.Report.Result.Entries != saved.Fact.Entries || row.GitObservation.Report.Result.ExpandedBytes != saved.Fact.ExpandedBytes || plan.ID != ImageBuildAutomaticGitID(work.Definition, work.Read.PolicyRevision, plan.Commit) || plan.Creator != row.Definition.Session.User || plan.ContextRevision != work.Read.ContextRevision || plan.PolicyRevision != work.Read.PolicyRevision || plan.Root != row.Spec.Root || plan.Dockerfile != row.Spec.Dockerfile || plan.ExpandedLimit != policy.Spec.WorkspaceBytes || plan.CreatedAt < uint64(row.Definition.At) || row.NextVersion == math.MaxUint64 || uint64(at-startedAt) >= policy.Spec.Seconds {
		return ImageBuildJobPlan{}, access.ErrConflict
	}
	if _, exists := book.Job(plan.Tenant, plan.ID); exists {
		return ImageBuildJobPlan{}, imagebuild.ErrUsed // Includes deleted history.
	}
	if _, exists := book.Upload(plan.Tenant, plan.ID); exists {
		return ImageBuildJobPlan{}, access.ErrConflict
	}
	for _, job := range book.Jobs {
		if job.Automatic != nil && job.Run.Spec.Tenant == plan.Tenant && job.Run.Spec.Context.ID == plan.Context && !job.Run.Terminal() {
			return ImageBuildJobPlan{}, reconcile.ErrPending
		}
	}
	users, err := p.Catalog(s)
	if err != nil {
		return ImageBuildJobPlan{}, err
	}
	for _, action := range []string{"publish-build-git", "begin-image-build"} {
		if users.OperationAllowed(row.Definition.Session, action) != nil {
			return ImageBuildJobPlan{}, access.ErrDenied
		}
	}
	if len(row.Spec.Secrets) > 0 && users.AuthorizeAccepted(row.Definition.Session, p.Cluster, row.Definition.At, plan.Tenant, access.Deploy, plan.Root.Node) != nil {
		return ImageBuildJobPlan{}, access.ErrDenied
	}
	versionID := imagebuild.VersionID(saved.Fact)
	if _, exists := book.Version(plan.Tenant, versionID); exists {
		return ImageBuildJobPlan{}, access.ErrConflict
	}
	upload := ImageBuildUploadRecord{Scope: saved.Scope, Revision: 1, Closed: true, Version: versionID, Begin: row.Definition, Origin: row.Definition}
	version := ImageBuildVersionRecord{Tenant: plan.Tenant, Context: plan.Context, Upload: plan.ID, Number: row.NextVersion + 1, ID: versionID, Fact: saved.Fact, Origin: row.Definition, Commit: plan.Commit}
	book.Uploads = append(book.Uploads, upload)
	book.Versions = append(book.Versions, version)
	return p.planImageBuildJob(s, users, book, row.Definition.Session, startedAt, row.Definition.At, plan.Tenant, ImageBuildJobQuery{ID: plan.ID, Context: plan.Context, Version: versionID})
}

func (p Policy) imageBuildAutomaticGitReport(s state.State, cmd state.Command) (ImageBuildAutomaticGitReport, ImageBuildJobPlan, error) {
	var report ImageBuildAutomaticGitReport
	if cmd.Kind != state.ModuleReport || cmd.Key != ImageBuildKey || canonical([]byte(cmd.Value), &report) != nil || report.Kind != "automatic-git" || report.Epoch != s.ModuleEpoch() || report.At == 0 || report.At > math.MaxInt64 || report.StartedAt == 0 || report.StartedAt > math.MaxInt64 {
		return report, ImageBuildJobPlan{}, access.ErrInvalid
	}
	want, err := report.Command()
	if err != nil || want != cmd {
		return report, ImageBuildJobPlan{}, access.ErrInvalid
	}
	plan, err := p.ImageBuildAutomaticGitPlan(s, report.Owner, report.Saved, int64(report.StartedAt), int64(report.At))
	if err != nil {
		return report, plan, err
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return report, plan, err
	}
	context, _ := book.Context(report.Tenant, report.Context)
	if !validAutomaticGitOrigin(context.Definition, report, p.Cluster) || report.RootRevision != plan.RootRevision || report.Epoch != plan.Epoch || report.Snapshot != ImageBuildAutomaticGitSnapshot(plan.Spec) {
		return report, plan, access.ErrDenied
	}
	return report, plan, nil
}

func (p Policy) ResolveImageBuildAutomaticGitReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var report ImageBuildAutomaticGitReport
	if canonical(raw, &report) != nil || report.Owner != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := report.Command()
	if err != nil {
		return cmd, err
	}
	_, _, err = p.imageBuildAutomaticGitReport(s, cmd)
	return cmd, err
}

// Admission preview shares the exact reducer, including current Group/provider
// checks. It publishes no state and does not claim any native work completed.
func (p Policy) CheckImageBuildAutomaticGit(s state.State, caller [32]byte, report ImageBuildAutomaticGitReport) error {
	if report.Owner != caller {
		return access.ErrDenied
	}
	cmd, err := report.Command()
	if err != nil {
		return err
	}
	_, code := p.reduceImageBuildAutomaticGit(s, cmd)
	switch code {
	case state.Applied:
		return nil
	case state.ConditionFailed:
		return reconcile.ErrPending
	case state.Forbidden:
		return access.ErrDenied
	default:
		return ErrCatalog
	}
}

func (p Policy) reduceImageBuildAutomaticGit(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	report, plan, err := p.imageBuildAutomaticGitReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return nil, state.Invalid
	}
	context, _ := book.Context(report.Tenant, report.Context)
	policy, _ := book.Policy(report.Tenant)
	writes := map[string][]byte{}
	put := func(kind, tenant, id string, value any) bool {
		return writeBuildRecord(writes, kind, tenant, id, value) == nil
	}
	if code := publishBuildArchive(&book, context, policy, context.Definition, report.Saved.Scope, report.Saved.Fact, report.Saved.Plan.Commit, put); code != state.Applied {
		return nil, code
	}
	upload := &book.Uploads[len(book.Uploads)-1]
	upload.Automatic = &report
	// Include the new provenance when reserving eventual reclaim metadata.
	reserve := *upload
	var maxHash [32]byte
	for i := range maxHash {
		maxHash[i] = 255
	}
	reserve.Reclaimed = &imagebuild.ReclaimReceipt{Schema: 1, Scope: upload.Scope.Hash(), Version: upload.Version, Native: maxHash, At: math.MaxInt64, Signature: make([]byte, ed25519.SignatureSize)}
	if raw, err := json.Marshal(reserve); err != nil || len(raw) > 64<<10 {
		return nil, state.ConditionFailed
	}
	if !put("upload", report.Tenant, upload.Scope.Upload, *upload) {
		return nil, state.Invalid
	}
	run, err := imagebuild.NewJob(plan.Spec)
	if err != nil {
		return nil, state.Invalid
	}
	job := ImageBuildJobRecord{Run: run, Origin: context.Definition, Automatic: &report}
	if err := p.acquireImageBuildSecrets(s, &job, writes); err != nil {
		return nil, state.ConditionFailed
	}
	if !imageBuildRecordBudget(job) {
		return nil, state.ConditionFailed
	}
	if !put("job", report.Tenant, plan.Spec.ID, job) {
		return nil, state.Invalid
	}
	book.Jobs = append(book.Jobs, job)
	raw, err := book.root(p.Cluster)
	if err != nil {
		return nil, state.ConditionFailed
	}
	writes[ImageBuildKey] = raw
	return writes, state.Applied
}

func validAutomaticGitJob(row ImageBuildJobRecord, cluster [32]byte) bool {
	if row.Automatic == nil || !validAutomaticGitOrigin(row.Origin, *row.Automatic, cluster) {
		return false
	}
	spec := row.Run.Spec
	r := row.Automatic
	var definition ImageBuildContextPut
	if canonical(row.Origin.Change.Payload, &definition) != nil {
		return false
	}
	return ImageBuildAutomaticGitSnapshot(spec) == r.Snapshot && spec.ID == r.Saved.Plan.ID && spec.ContextRevision == r.Saved.Plan.ContextRevision && spec.PolicyRevision == r.Saved.Plan.PolicyRevision && spec.CreatedAt == r.StartedAt && r.At-spec.CreatedAt < spec.Policy.Seconds && spec.Scope == r.Saved.Scope && buildJSONEqual(spec.Seal, r.Saved.Fact) && spec.Version == imagebuild.VersionID(r.Saved.Fact) && spec.Commit == r.Saved.Plan.Commit && buildJSONEqual(spec.Context, definition.Spec)
}

// Original policy acceptance remains the authority time; ordering/resource
// acquisition use the distinct automatic submission, not that older config.
func (row ImageBuildJobRecord) SubmissionRootRevision() uint64 {
	if row.Automatic != nil {
		return row.Automatic.RootRevision
	}
	return row.Origin.RootRevision
}

func (row ImageBuildJobRecord) acquisitionAt() int64 {
	if row.Automatic != nil {
		return int64(row.Automatic.At)
	}
	return row.Origin.At
}

// Reuse the existing Vault approval entrypoints with the original accepted
// context operation. The observed commit fixes the exact future build use;
// no invented job/spec or approval from another commit is used.
func (p Policy) automaticImageBuildApprovalUses(s state.State, session access.Session, at int64, origin *UserOperation, selection *AppApprovalSelection) (map[string][]secrets.Use, error) {
	if origin == nil || selection != nil || origin.VerifyOriginal(p.Cluster) != nil || origin.Change.Action != "put-build-context" || origin.Session.User != session.User || origin.Change.Principal != session.User || at < origin.At {
		return nil, access.ErrDenied
	}
	var put ImageBuildContextPut
	if canonical(origin.Change.Payload, &put) != nil || put.Spec.Git == nil || !put.Spec.Git.Automatic {
		return nil, access.ErrDenied
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return nil, err
	}
	row, ok := book.Context(put.Spec.Tenant, put.Spec.ID)
	if !ok || !buildJSONEqual(row.Definition, *origin) || row.GitObservation == nil {
		return nil, access.ErrDenied
	}
	work, err := p.ImageBuildGitWatchWork(s, row.Spec.Root.Key, row.Spec.Tenant, row.Spec.ID, at)
	if err != nil {
		return nil, err
	}
	observed := row.GitObservation.Report.Result
	if !observed.Valid(work.Read) || observed.Code != "OK" {
		return nil, access.ErrConflict
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	for _, action := range []access.Action{access.ManageRegistry, access.Deploy} {
		if users.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, row.Spec.Tenant, action, row.Spec.Root.Node) != nil || users.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, row.Spec.Tenant, action, row.Spec.Root.Node) != nil {
			return nil, access.ErrDenied
		}
	}
	for _, action := range []string{"publish-build-git", "begin-image-build"} {
		if users.OperationAllowed(session, action) != nil || users.OperationAllowed(origin.Session, action) != nil {
			return nil, access.ErrDenied
		}
	}
	id := ImageBuildAutomaticGitID(work.Definition, work.Read.PolicyRevision, observed.Commit)
	return imageBuildSecretUsesFor(row.Spec.Tenant, row.Spec.ID, id, row.Spec.Root.Node, row.Spec.Root.Key, row.Spec.Secrets, origin.Session), nil
}
