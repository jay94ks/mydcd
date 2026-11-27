// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"github.com/jay94ks/seafield/internal/eventlog"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/imagecache"
)

const ImageCacheKey = "control/image-cache"

type ImageCacheRecord struct {
	Origin       UserOperation
	Operation    string
	Plan         imagecache.Plan
	State        string
	Revision, At uint64
	Parts        []imagecache.Part
}
type ImageCacheJobs struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Records  []ImageCacheRecord
}

func (j ImageCacheJobs) Record(id string) (ImageCacheRecord, bool) {
	for _, r := range j.Records {
		if r.Operation == id {
			raw, _ := json.Marshal(r)
			var own ImageCacheRecord
			_ = json.Unmarshal(raw, &own)
			return own, true
		}
	}
	return ImageCacheRecord{}, false
}
func (j ImageCacheJobs) Quiescent() bool {
	for _, r := range j.Records {
		if r.State == "queued" || r.State == "running" {
			return false
		}
	}
	return true
}

func (p Policy) ImageCacheJobs(s state.State) (ImageCacheJobs, error) {
	out := ImageCacheJobs{Schema: 1, Cluster: p.Cluster}
	raw, revision, err := readCheckpoint(s, ImageCacheKey, p.Cluster, p.TrustRoot)
	if err != nil || raw == nil {
		return out, err
	}
	if canonical(raw, &out) != nil || out.Schema != 1 || out.Cluster != p.Cluster || out.Revision != revision || len(out.Records) > 128 {
		return out, ErrCatalog
	}
	seen := map[string]bool{}
	for _, r := range out.Records {
		var change imagecache.Change
		if r.Origin.VerifyOriginal(p.Cluster) != nil || r.Origin.Change.Action != "prune-node-images" || canonical(r.Origin.Change.Payload, &change) != nil || !change.Valid() || r.Operation != change.Operation || !r.Plan.DeleteReady() || r.Plan.Digest() != change.Plan.Digest() || r.Plan.Cluster != p.Cluster || r.Revision == 0 || r.At < uint64(r.Origin.At) || seen[r.Operation] || len(r.Parts) > len(r.Plan.Images) {
			return out, ErrCatalog
		}
		seen[r.Operation] = true
		failed := false
		for i, part := range r.Parts {
			if !part.Valid() || part.ID != r.Plan.Images[i].ID {
				return out, ErrCatalog
			}
			failed = failed || part.State == "failed" || part.State == "skipped"
		}
		switch r.State {
		case "queued":
			if len(r.Parts) != 0 {
				return out, ErrCatalog
			}
		case "running":
			if len(r.Parts) >= len(r.Plan.Images) {
				return out, ErrCatalog
			}
		case "done", "failed":
			if len(r.Parts) != len(r.Plan.Images) || (r.State == "failed") != failed {
				return out, ErrCatalog
			}
		default:
			return out, ErrCatalog
		}
	}
	return out, nil
}
func (p Policy) currentImageCacheOwner(s state.State, node string, owner [32]byte) error {
	d, err := p.Members(s)
	if err != nil {
		return err
	}
	entry, ok := d.Entry(node)
	key, err := identity.ParseKey(entry.CurrentPeer().Key)
	if !ok || err != nil || key != owner || !d.MemberKey(owner) {
		return access.ErrDenied
	}
	return nil
}
func (p Policy) imageCacheAuthorized(s state.State, session access.Session, at int64, accepted bool) error {
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	if err = c.OperationAllowed(session, "prune-node-images"); err != nil {
		return err
	}
	if accepted {
		return c.AuthorizeAccepted(session, p.Cluster, at, "", access.ManageCluster, "")
	}
	return c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "")
}
func imageCacheFresh(observed uint64, at int64) bool {
	if at <= 0 || uint64(at) > (^uint64(0)-999)/1000 {
		return false
	}
	now := uint64(at)*1000 + 999
	return observed > 0 && observed <= now && now-observed <= 30_000
}
func (p Policy) imageCacheCheckpoint(s state.State, j ImageCacheJobs) (map[string][]byte, state.Code) {
	if j.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	j.Revision++
	raw, err := json.Marshal(j)
	if err != nil || len(raw) > 4<<20 {
		return nil, state.ConditionFailed
	}
	return writeCheckpoint(s, ImageCacheKey, p.Cluster, p.TrustRoot, j.Revision, raw)
}
func (p Policy) reduceImageCache(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind == state.ModuleReport {
		return p.reduceImageCacheReport(s, cmd)
	}
	p, err := p.Current(s)
	if err != nil || cmd.Kind != state.Module || cmd.Key != ImageCacheKey {
		return nil, state.Forbidden
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || op.Change.Action != "prune-node-images" || p.imageCacheAuthorized(s, op.Session, op.At, false) != nil {
		return nil, state.Forbidden
	}
	var change imagecache.Change
	if canonical(op.Change.Payload, &change) != nil || !change.Valid() || change.Plan.Cluster != p.Cluster || op.Change.Expected != 0 {
		return nil, state.Invalid
	}
	plan := change.Plan
	if p.currentImageCacheOwner(s, plan.Node, plan.Owner) != nil || !imageCacheFresh(plan.At, op.At) || plan.Index > s.Index() {
		return nil, state.ConditionFailed
	}
	refs, err := p.imageCacheReferences(s, plan.Node)
	if err != nil {
		return nil, state.Invalid
	}
	for _, image := range plan.Images {
		if cacheReferenceCount(image, refs) > 0 {
			return nil, state.ConditionFailed
		}
	}
	jobs, err := p.ImageCacheJobs(s)
	if err != nil {
		return nil, state.Invalid
	}
	if len(jobs.Records) >= 128 {
		return nil, state.ConditionFailed
	}
	for _, row := range jobs.Records {
		if row.Operation == change.Operation || row.Plan.Owner == plan.Owner && (row.State == "queued" || row.State == "running") {
			return nil, state.ConditionFailed
		}
	}
	jobs.Records = append(jobs.Records, ImageCacheRecord{Origin: op, Operation: change.Operation, Plan: plan, State: "queued", Revision: 1, At: uint64(op.At)})
	raw, budgetErr := json.Marshal(jobs)
	reserved := 0
	for _, row := range jobs.Records {
		if row.State == "queued" || row.State == "running" {
			reserved += (len(row.Plan.Images) - len(row.Parts)) * (4 << 10)
		}
	}
	if budgetErr != nil || len(raw)+reserved > 4<<20 {
		return nil, state.ConditionFailed
	}
	return p.imageCacheCheckpoint(s, jobs)
}

// imageCacheBook is the ImageCacheKey Raft book (see book.go).
var imageCacheBook = Book{
	Key:       ImageCacheKey,
	Actions:   []string{"prune-node-images"},
	Reduce:    Policy.reduceImageCache,
	Authorize: authorizeCluster,
	AdmitReport: func(p Policy, s state.State, cmd state.Command) error {
		_, err := p.imageCacheReport(s, cmd)
		return err
	},
	Events: imageCacheEvents,
}

func imageCacheEvents(p Policy, before, after state.State, emit eventEmitter) error {
	old, err := p.ImageCacheJobs(before)
	if err != nil {
		return err
	}
	next, err := p.ImageCacheJobs(after)
	if err != nil {
		return err
	}
	for _, job := range next.Records {
		previous, _ := old.Record(job.Operation)
		for _, part := range job.Parts {
			existed := false
			for _, p := range previous.Parts {
				if p.ID == part.ID {
					existed = true
					break
				}
			}
			if existed {
				continue
			}
			d := eventlog.Detail{Operation: job.Operation, State: part.State, Code: part.Code}
			eventReason(&d, job.Origin)
			emit("node-cache-cleaned", "cluster", eventlog.Target{Node: job.Plan.Node, Native: part.ID}, d)
		}
	}
	return nil
}
