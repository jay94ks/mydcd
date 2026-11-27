// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

// Digest names the original authorized maintenance, not its changing progress.
func (r ImageBuildCachePruneRecord) Digest() [32]byte {
	raw, _ := json.Marshal(struct {
		Origin       UserOperation
		Source       string
		SourceDigest [32]byte
		Automatic    *ImageBuildCacheAutomaticReport `json:",omitempty"`
	}{r.Origin, r.Source, r.SourceDigest, r.Automatic})
	return sha256.Sum256(append([]byte("sfc-build-cache-prune-intent-1\x00"), raw...))
}

type ImageBuildCachePruneReport struct {
	Schema                            uint8
	Kind                              string
	Cluster, Owner, Intent            [32]byte
	Tenant, ID, Action                string
	Expected, RootRevision, Epoch, At uint64
	Native                            *[32]byte `json:",omitempty"`
	Code                              string    `json:",omitempty"`
	ClosedAt, RemovedCount            uint64    `json:",omitempty"`
	ReportedBytes                     int64     `json:",omitempty"`
	Signature                         []byte
}

func ImageBuildCachePruneReportBytes(r ImageBuildCachePruneReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-build-cache-prune-report-1\x00"), raw...)
}
func (r ImageBuildCachePruneReport) valid(row ImageBuildCachePruneRecord, spec imagebuild.JobSpec, signature bool) bool {
	q, err := row.Change()
	if err != nil || r.Schema != 1 || r.Kind != "cache-prune" || r.Cluster != spec.Cluster || r.Owner != spec.Scope.Root.Key || r.Intent != row.Digest() || r.Tenant != q.Tenant || r.ID != q.ID || r.At < row.AcceptedAt() || r.At > math.MaxInt64 || r.Expected == 0 || r.RootRevision <= row.SubmissionRootRevision() || r.Epoch < row.SubmissionEpoch() {
		return false
	}
	if signature && !ed25519.Verify(r.Owner[:], ImageBuildCachePruneReportBytes(r), r.Signature) {
		return false
	}
	switch r.Action {
	case "begin", "uncertain":
		return r.Native == nil && r.Code == "" && r.ClosedAt == 0 && r.RemovedCount == 0 && r.ReportedBytes == 0
	case "complete":
		if r.Native == nil || *r.Native == ([32]byte{}) || r.ClosedAt < row.AcceptedAt() || r.ClosedAt > r.At || r.ReportedBytes < 0 {
			return false
		}
		switch r.Code {
		case "OK", "FAILED", "PERMISSION_REVOKED", "TIMEOUT":
			return true
		}
	}
	return false
}
func (r ImageBuildCachePruneReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Owner[:]), Epoch: r.Epoch, Key: ImageBuildKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

// Replay the bounded original reports on restore as well as mutation. A lost
// current authority does not erase an installed owner's actual closure proof.
func cachePruneReportState(row ImageBuildCachePruneRecord, spec imagebuild.JobSpec, signature bool) (string, uint64, uint64, error) {
	phase, revision, at := "queued", uint64(1), row.AcceptedAt()
	var began uint64
	lastRoot, lastEpoch := row.SubmissionRootRevision(), row.SubmissionEpoch()
	if len(row.Reports) > 3 {
		return "", 0, 0, ErrCatalog
	}
	for _, r := range row.Reports {
		if !r.valid(row, spec, signature) || r.Expected != revision || r.At < at || r.RootRevision <= lastRoot || r.Epoch < lastEpoch {
			return "", 0, 0, ErrCatalog
		}
		switch r.Action {
		case "begin":
			if phase != "queued" {
				return "", 0, 0, ErrCatalog
			}
			phase, began = "running", r.At
		case "uncertain":
			if phase != "running" {
				return "", 0, 0, ErrCatalog
			}
			phase = "unknown"
		case "complete":
			if phase != "queued" && phase != "running" && phase != "unknown" || phase == "queued" && (r.Code == "OK" || r.RemovedCount != 0 || r.ReportedBytes != 0) || r.ClosedAt < began {
				return "", 0, 0, ErrCatalog
			}
			phase = "failed"
			if r.Code == "OK" {
				phase = "succeeded"
			}
		default:
			return "", 0, 0, ErrCatalog
		}
		revision++
		at = r.At
		lastRoot, lastEpoch = r.RootRevision, r.Epoch
	}
	return phase, revision, at, nil
}
func (p Policy) imageBuildCachePruneReport(s state.State, cmd state.Command) (ImageBuildCachePruneReport, ImageBuildCachePruneWork, error) {
	var report ImageBuildCachePruneReport
	if cmd.Kind != state.ModuleReport || cmd.Key != ImageBuildKey || canonical([]byte(cmd.Value), &report) != nil || report.Kind != "cache-prune" || report.Epoch != s.ModuleEpoch() {
		return report, ImageBuildCachePruneWork{}, access.ErrInvalid
	}
	want, err := report.Command()
	if err != nil || want != cmd {
		return report, ImageBuildCachePruneWork{}, access.ErrInvalid
	}
	work, err := p.ImageBuildCachePruneWork(s, report.Owner, ImageBuildCachePruneWorkQuery{Tenant: report.Tenant, ID: report.ID, At: int64(report.At)})
	if err != nil || !report.valid(work.Record, work.Source, true) || !work.Record.Pending() || report.Expected != work.Record.Revision || len(work.Record.Reports) >= 3 {
		return report, work, access.ErrDenied
	}
	if report.Action == "begin" && (!work.Allowed || work.Record.State != "queued") {
		return report, work, access.ErrDenied
	}
	candidate := work.Record
	candidate.Reports = append(append([]ImageBuildCachePruneReport(nil), candidate.Reports...), report)
	if _, _, _, err := cachePruneReportState(candidate, work.Source, true); err != nil {
		return report, work, access.ErrDenied
	}
	return report, work, nil
}
func (p Policy) ResolveImageBuildCachePruneReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var report ImageBuildCachePruneReport
	if canonical(raw, &report) != nil || report.Owner != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := report.Command()
	if err != nil {
		return cmd, err
	}
	_, _, err = p.imageBuildCachePruneReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceImageBuildCachePruneReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	report, work, err := p.imageBuildCachePruneReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	row := work.Record
	row.Reports = append(row.Reports, report)
	row.State, row.Revision, row.At, err = cachePruneReportState(row, work.Source, true)
	if err != nil {
		return nil, state.Invalid
	}
	writes := map[string][]byte{ImageBuildKey: []byte(s.Object(ImageBuildKey).Value)}
	if writeCachePruneRecord(writes, row) != nil {
		return nil, state.ConditionFailed
	}
	return writes, state.Applied
}

func (b ImageBuildCatalog) activeBuildWorkers(tenant string) uint32 {
	var n uint32
	for _, row := range b.Jobs {
		if row.Run.Spec.Tenant == tenant && !row.Run.Terminal() && row.Run.Phase != "queued" {
			n++
		}
	}
	for _, row := range b.CachePrunes {
		q, err := row.Change()
		if err == nil && q.Tenant == tenant && row.Pending() && row.State != "queued" {
			n++
		}
	}
	return n
}
