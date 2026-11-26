// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// Observations consume an accepted Automatic context definition. They are not
// user operations, published versions, build submissions or new Secret grants.
type ImageBuildGitWatchWork struct {
	Read                   ImageBuildSourceRead
	Definition             [32]byte
	Expected, RootRevision uint64
	Index                  uint64
}

type ImageBuildGitObservationReport struct {
	Schema                            uint8
	Kind                              string
	Cluster, Owner, Definition        [32]byte
	Tenant                            string
	Expected, RootRevision, Epoch, At uint64
	Result                            ImageBuildSourceResult
	Signature                         []byte
}

type ImageBuildGitObservation struct {
	Revision uint64
	Report   ImageBuildGitObservationReport
}

type ImageBuildGitObservationView struct {
	Revision, At, ContextRevision, PolicyRevision, Epoch uint64
	Code, Commit                                         string
	Tree                                                 [32]byte
	Entries, BaseSources                                 uint32
	ExpandedBytes                                        int64
}

func imageBuildContextDefinition(row ImageBuildContextRecord) [32]byte {
	return sha256.Sum256(OperationBytes(row.Definition))
}

func (p Policy) ImageBuildGitWatchWork(s state.State, caller [32]byte, tenant, id string, at int64) (ImageBuildGitWatchWork, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildGitWatchWork{}, err
	}
	if at <= 0 || !validID(tenant) || !validID(id) {
		return ImageBuildGitWatchWork{}, access.ErrInvalid
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildGitWatchWork{}, err
	}
	row, exists := b.Context(tenant, id)
	policy, configured := b.Policy(tenant)
	if !exists || row.Deleted || !configured || policy.Deleted || row.Spec.Kind != "git" || row.Spec.Git == nil || !row.Spec.Git.Automatic || !row.Spec.Under(policy.Spec) {
		return ImageBuildGitWatchWork{}, access.ErrConflict
	}
	owner, err := p.workNodeOwner(s, row.Spec.Root.Node)
	if err != nil || owner != caller || row.Spec.Root.Key != caller {
		return ImageBuildGitWatchWork{}, access.ErrDenied
	}
	users, err := p.Catalog(s)
	if err != nil {
		return ImageBuildGitWatchWork{}, err
	}
	origin := row.Definition
	var put ImageBuildContextPut
	if origin.VerifyOriginal(p.Cluster) != nil || origin.Change.Action != "put-build-context" || canonical(origin.Change.Payload, &put) != nil || !buildJSONEqual(put.Spec, row.Spec) || origin.Change.Expected+1 != row.Revision || at < origin.At || users.OperationAllowed(origin.Session, "put-build-context") != nil || users.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, tenant, access.ManageRegistry, row.Spec.Root.Node) != nil {
		return ImageBuildGitWatchWork{}, access.ErrDenied
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return ImageBuildGitWatchWork{}, err
	}
	root, err := roots.CanBuild(users, origin.Session.User, tenant, row.Spec.Root.Node, row.Spec.Root.ID, row.Spec.Root.Generation)
	if err != nil || root.Reference(p.Cluster) != row.Spec.Root {
		return ImageBuildGitWatchWork{}, access.ErrDenied
	}
	var expected uint64
	if row.GitObservation != nil {
		expected = row.GitObservation.Revision
	}
	read := ImageBuildSourceRead{Session: origin.Session, Tenant: tenant, Query: ImageBuildSourceQuery{ID: id}, Spec: row.Spec.Own(), Policy: policy.Spec, ContextRevision: row.Revision, PolicyRevision: policy.Revision, Epoch: s.ModuleEpoch()}
	return ImageBuildGitWatchWork{Read: read, Definition: imageBuildContextDefinition(row), Expected: expected, RootRevision: s.Object(ImageBuildKey).Revision, Index: s.Index()}, nil
}

func ImageBuildGitObservationReportBytes(report ImageBuildGitObservationReport) []byte {
	report.Signature = nil
	raw, _ := json.Marshal(report)
	return append([]byte("mydc-imagebuild-git-observation-1\x00"), raw...)
}

func (report ImageBuildGitObservationReport) Command() (state.Command, error) {
	raw, err := json.Marshal(report)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(report.Owner[:]), Epoch: report.Epoch, Key: ImageBuildKey, Expected: report.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func validImageBuildGitObservation(row ImageBuildContextRecord, cluster [32]byte) bool {
	if row.GitObservation == nil {
		return true
	}
	observation := row.GitObservation
	r := observation.Report
	if observation.Revision == 0 || r.Schema != 1 || r.Kind != "git-observation" || r.Cluster != cluster || r.Owner != row.Spec.Root.Key || r.Definition != imageBuildContextDefinition(row) || r.Tenant != row.Spec.Tenant || row.Spec.Git == nil || !row.Spec.Git.Automatic || r.Expected == math.MaxUint64 || r.Expected+1 != observation.Revision || r.RootRevision == 0 || r.Epoch == 0 || r.At == 0 || r.At > math.MaxInt64 || row.Definition.At <= 0 || r.At < uint64(row.Definition.At) || r.Result.ContextRevision != row.Definition.Change.Expected+1 || r.Result.PolicyRevision == 0 || r.Result.Epoch != r.Epoch || !ed25519.Verify(r.Owner[:], ImageBuildGitObservationReportBytes(r), r.Signature) {
		return false
	}
	// A previous policy may have changed since this read-only fact. Validate
	// retained shape against the protocol maximum, not today's smaller limit.
	read := ImageBuildSourceRead{Spec: row.Spec, Policy: imagebuild.Policy{WorkspaceBytes: imagebuild.MaxExpandedBytes}, ContextRevision: r.Result.ContextRevision, PolicyRevision: r.Result.PolicyRevision, Epoch: r.Epoch}
	return r.Result.Valid(read) && (r.Result.Code != "OK" || imagebuild.ValidGitCommit(r.Result.Commit))
}

func (p Policy) imageBuildGitObservationReport(s state.State, cmd state.Command) (ImageBuildGitObservationReport, ImageBuildGitWatchWork, error) {
	var report ImageBuildGitObservationReport
	if cmd.Kind != state.ModuleReport || cmd.Key != ImageBuildKey || canonical([]byte(cmd.Value), &report) != nil || report.Kind != "git-observation" || report.Epoch != s.ModuleEpoch() || report.At == 0 || report.At > math.MaxInt64 {
		return report, ImageBuildGitWatchWork{}, access.ErrInvalid
	}
	want, err := report.Command()
	if err != nil || want != cmd {
		return report, ImageBuildGitWatchWork{}, access.ErrInvalid
	}
	work, err := p.ImageBuildGitWatchWork(s, report.Owner, report.Tenant, report.Result.Context, int64(report.At))
	if err != nil {
		return report, work, err
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return report, work, err
	}
	row, _ := book.Context(report.Tenant, report.Result.Context)
	previous := row.GitObservation
	row.GitObservation = &ImageBuildGitObservation{Revision: report.Expected + 1, Report: report}
	if !validImageBuildGitObservation(row, p.Cluster) || report.Definition != work.Definition || report.Expected != work.Expected || report.RootRevision != work.RootRevision || !report.Result.Valid(work.Read) || previous != nil && (report.At < previous.Report.At || report.Result.PolicyRevision < previous.Report.Result.PolicyRevision) {
		return report, work, access.ErrConflict
	}
	return report, work, nil
}

func (p Policy) ResolveImageBuildGitObservationReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var report ImageBuildGitObservationReport
	if canonical(raw, &report) != nil || report.Owner != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := report.Command()
	if err != nil {
		return cmd, err
	}
	_, _, err = p.imageBuildGitObservationReport(s, cmd)
	return cmd, err
}

func (p Policy) reduceImageBuildGitObservation(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	report, _, err := p.imageBuildGitObservationReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return nil, state.Invalid
	}
	row, _ := book.Context(report.Tenant, report.Result.Context)
	row.GitObservation = &ImageBuildGitObservation{Revision: report.Expected + 1, Report: report}
	if raw, err := json.Marshal(row); err != nil || len(raw) > 64<<10 {
		return nil, state.ConditionFailed
	}
	writes := map[string][]byte{ImageBuildKey: []byte(s.Object(ImageBuildKey).Value)}
	if writeBuildRecord(writes, "context", report.Tenant, report.Result.Context, row) != nil {
		return nil, state.Invalid
	}
	return writes, state.Applied
}

func imageBuildGitObservationView(observation *ImageBuildGitObservation) *ImageBuildGitObservationView {
	if observation == nil {
		return nil
	}
	r := observation.Report
	return &ImageBuildGitObservationView{Revision: observation.Revision, At: r.At, ContextRevision: r.Result.ContextRevision, PolicyRevision: r.Result.PolicyRevision, Epoch: r.Epoch, Code: r.Result.Code, Commit: r.Result.Commit, Tree: r.Result.Tree, Entries: r.Result.Entries, BaseSources: r.Result.BaseSources, ExpandedBytes: r.Result.ExpandedBytes}
}

// Same observed outcome needs no replicated heartbeat. At records the last
// changed fact, not a proof that the source is currently reachable.
func (observation ImageBuildGitObservation) Same(work ImageBuildGitWatchWork, result ImageBuildSourceResult) bool {
	return observation.Report.Definition == work.Definition && observation.Report.Result == result
}
