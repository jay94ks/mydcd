// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagecache"
)

type ImageCacheReport struct {
	Schema                            uint8
	Cluster, Owner                    [32]byte
	Operation, Action                 string
	Expected, RootRevision, Epoch, At uint64
	Part                              *imagecache.Part `json:",omitempty"`
	Signature                         []byte
}

func ImageCacheReportBytes(r ImageCacheReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-image-cache-report-1\x00"), raw...)
}
func (r ImageCacheReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Owner[:]), Epoch: r.Epoch, Key: ImageCacheKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) imageCacheReport(s state.State, cmd state.Command) (ImageCacheReport, error) {
	var r ImageCacheReport
	if cmd.Kind != state.ModuleReport || cmd.Key != ImageCacheKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || r.Expected == 0 || r.At == 0 || r.At > math.MaxInt64 || !ed25519.Verify(r.Owner[:], ImageCacheReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || cmd != want {
		return r, ErrCatalog
	}
	jobs, err := p.ImageCacheJobs(s)
	if err != nil {
		return r, err
	}
	row, ok := jobs.Record(r.Operation)
	if !ok || row.Plan.Owner != r.Owner || p.currentImageCacheOwner(s, row.Plan.Node, r.Owner) != nil {
		return r, access.ErrDenied
	}
	if r.Action == "begin" {
		if r.Part != nil {
			return r, ErrCatalog
		}
	} else if r.Action == "item" {
		if r.Part == nil || !r.Part.Valid() || len(row.Parts) >= len(row.Plan.Images) || r.Part.ID != row.Plan.Images[len(row.Parts)].ID {
			return r, ErrCatalog
		}
	} else {
		return r, ErrCatalog
	}
	return r, nil
}
func (p Policy) ResolveImageCacheReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r ImageCacheReport
	if canonical(raw, &r) != nil || r.Owner != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := r.Command()
	if err != nil {
		return cmd, err
	}
	_, err = p.imageCacheReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceImageCacheReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.imageCacheReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	jobs, err := p.ImageCacheJobs(s)
	if err != nil {
		return nil, state.Invalid
	}
	for i, row := range jobs.Records {
		if row.Operation != r.Operation {
			continue
		}
		if row.Revision != r.Expected || row.Revision == ^uint64(0) {
			return nil, state.ConditionFailed
		}
		if r.Action == "begin" {
			if row.State != "queued" {
				return nil, state.ConditionFailed
			}
			// Beginning metadata alone performs no deletion. Revoked owners may
			// begin only to report explicit per-image unsent failures.
			row.State = "running"
		} else {
			if row.State != "running" {
				return nil, state.ConditionFailed
			}
			row.Parts = append(row.Parts, *r.Part)
			if len(row.Parts) == len(row.Plan.Images) {
				row.State = "done"
				for _, part := range row.Parts {
					if part.State == "failed" || part.State == "skipped" {
						row.State = "failed"
						break
					}
				}
			}
		}
		row.Revision++
		row.At = max(row.At, r.At)
		jobs.Records[i] = row
		return p.imageCacheCheckpoint(s, jobs)
	}
	return nil, state.ConditionFailed
}

type ImageCacheWorkRequest struct{ Operation string }
type ImageCacheWork struct {
	Schema                               uint8
	Cluster, Owner                       [32]byte
	Operation, State                     string
	Revision, RootRevision, Epoch, Index uint64
	Plan                                 imagecache.Plan
	Parts                                []imagecache.Part
	References                           []uint64
	Allowed                              bool
}

func (p Policy) ImageCacheWork(s state.State, caller [32]byte, q ImageCacheWorkRequest) (ImageCacheWork, error) {
	var out ImageCacheWork
	p, err := p.Current(s)
	if err != nil {
		return out, err
	}
	jobs, err := p.ImageCacheJobs(s)
	if err != nil {
		return out, err
	}
	row, ok := jobs.Record(q.Operation)
	if !ok || row.Plan.Owner != caller || p.currentImageCacheOwner(s, row.Plan.Node, caller) != nil {
		return out, access.ErrDenied
	}
	refs, err := p.imageCacheReferences(s, row.Plan.Node)
	if err != nil {
		return out, err
	}
	counts := make([]uint64, len(row.Plan.Images))
	for i, image := range row.Plan.Images {
		counts[i] = cacheReferenceCount(image, refs)
	}
	return ImageCacheWork{Schema: 1, Cluster: p.Cluster, Owner: caller, Operation: row.Operation, State: row.State, Revision: row.Revision, RootRevision: s.Object(ImageCacheKey).Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), Plan: row.Plan, Parts: row.Parts, References: counts, Allowed: p.imageCacheAuthorized(s, row.Origin.Session, row.Origin.At, true) == nil}, nil
}

type ImageCacheRead struct {
	Owner   [32]byte
	Index   uint64
	Session access.Session
	Query   imagecache.Query
	Images  []imagecache.Image
}
type ImageCachePermit struct {
	Node         string
	Owner        [32]byte
	Index, Epoch uint64
	References   []uint64
}

func (p Policy) ImageCacheReadPermit(s state.State, caller [32]byte, at int64, q ImageCacheRead) (ImageCachePermit, error) {
	var out ImageCachePermit
	p, err := p.Current(s)
	if err != nil {
		return out, err
	}
	if q.Owner != caller || q.Index == 0 || s.Index() < q.Index || !q.Query.Valid(true) || len(q.Images) > imagecache.MaxImages || p.currentImageCacheOwner(s, q.Query.Node, caller) != nil || p.imageCacheAuthorized(s, q.Session, at, false) != nil {
		return out, access.ErrDenied
	}
	refs, err := p.imageCacheReferences(s, q.Query.Node)
	if err != nil {
		return out, err
	}
	counts := make([]uint64, len(q.Images))
	for i, image := range q.Images {
		if !image.Valid() || i > 0 && q.Images[i-1].ID >= image.ID {
			return out, ErrCatalog
		}
		counts[i] = cacheReferenceCount(image, refs)
	}
	return ImageCachePermit{Node: q.Query.Node, Owner: caller, Index: s.Index(), Epoch: s.ModuleEpoch(), References: counts}, nil
}

type ImageCacheStatus struct {
	Schema                     uint8
	Operation, User, State     string
	Revision, RootRevision, At uint64
	Plan                       imagecache.Plan
	Parts                      []imagecache.Part
	Reason                     *OperationReason `json:",omitempty"`
}

func (p Policy) ImageCacheStatus(s state.State, session access.Session, at int64, q imagecache.Query) (ImageCacheStatus, error) {
	var out ImageCacheStatus
	if !q.Valid(false) {
		return out, access.ErrInvalid
	}
	p, err := p.Current(s)
	if err != nil {
		return out, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return out, err
	}
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return out, access.ErrDenied
	}
	jobs, err := p.ImageCacheJobs(s)
	if err != nil {
		return out, err
	}
	row, ok := jobs.Record(q.Operation)
	if !ok {
		return out, access.ErrConflict
	}
	return ImageCacheStatus{Schema: 1, Operation: row.Operation, User: row.Origin.Session.User, State: row.State, Revision: row.Revision, RootRevision: s.Object(ImageCacheKey).Revision, At: row.At, Plan: row.Plan, Parts: row.Parts, Reason: row.Origin.Reason}, nil
}
