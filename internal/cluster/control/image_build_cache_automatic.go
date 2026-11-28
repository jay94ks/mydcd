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
)

const ImageBuildCacheAutomaticInterval uint64 = 300

// One current slot per cache, with a new immutable execution intent per
// sequence. Replacing a slot requires the previous real terminal closure.
// The original accepted policy is its user authority, not a fabricated login.
type ImageBuildCacheAutomaticReport struct {
	Schema                                            uint8
	Kind                                              string
	Cluster, Owner, Definition                        [32]byte
	Tenant, Node, Source                              string
	Cache, SourceDigest                               [32]byte
	PolicyRevision, Sequence, RootRevision, Epoch, At uint64
	Signature                                         []byte
}

func ImageBuildCacheAutomaticBytes(r ImageBuildCacheAutomaticReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-imagebuild-cache-automatic-1\x00"), raw...)
}
func (r ImageBuildCacheAutomaticReport) ID() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("sfc-cache-automatic-id-1\x00%x\x00%x\x00%d", r.Cache, r.Definition, r.Sequence)))
	return "auto-cache-" + hex.EncodeToString(hash[:24])
}
func (r ImageBuildCacheAutomaticReport) Change() ImageBuildCachePruneChange {
	return ImageBuildCachePruneChange{Tenant: r.Tenant, ID: r.ID(), Node: r.Node, Cache: r.Cache, Filter: imagebuild.CachePruneFilter{Mode: "policy"}}
}
func cacheAutomaticDefinition(op UserOperation) [32]byte { return sha256.Sum256(OperationBytes(op)) }

func (r ImageBuildCacheAutomaticReport) valid(origin UserOperation, source imagebuild.JobSpec, signature bool) bool {
	if r.Schema != 1 || r.Kind != "cache-automatic" || r.Cluster != source.Cluster || r.Owner != source.Scope.Root.Key || r.Tenant != source.Tenant || r.Node != source.Scope.Root.Node || r.Source != source.ID || r.SourceDigest != source.Digest() || r.Cache != imagebuild.CacheIdentity(source) || r.Definition != cacheAutomaticDefinition(origin) || r.Sequence == 0 || r.PolicyRevision == 0 || r.RootRevision <= origin.RootRevision || r.Epoch < origin.Epoch || r.At == 0 || r.At > math.MaxInt64 || origin.At <= 0 || r.At < uint64(origin.At) || origin.Change.Action != "set-image-build-policy" || origin.Change.Expected == math.MaxUint64 || origin.Change.Expected+1 != r.PolicyRevision {
		return false
	}
	var put ImageBuildPolicyPut
	if canonical(origin.Change.Payload, &put) != nil {
		return false
	}
	spec := imagebuild.NativeCachePruneSpec{Schema: 1, Intent: [32]byte{1}, ID: r.ID(), At: r.At, Source: source, Filter: r.Change().Filter, Automatic: &put.Spec}
	return spec.Valid() && (!signature || ed25519.Verify(r.Owner[:], ImageBuildCacheAutomaticBytes(r), r.Signature))
}

func (r ImageBuildCachePruneRecord) AcceptedAt() uint64 {
	if r.Automatic != nil {
		return r.Automatic.At
	}
	return uint64(r.Origin.At)
}
func (r ImageBuildCachePruneRecord) SubmissionRootRevision() uint64 {
	if r.Automatic != nil {
		return r.Automatic.RootRevision
	}
	return r.Origin.RootRevision
}
func (r ImageBuildCachePruneRecord) SubmissionEpoch() uint64 {
	if r.Automatic != nil {
		return r.Automatic.Epoch
	}
	return r.Origin.Epoch
}
func (r ImageBuildCachePruneRecord) Limits(source imagebuild.JobSpec) (imagebuild.Policy, error) {
	if r.Automatic == nil {
		return source.Policy.Own(), nil
	}
	var put ImageBuildPolicyPut
	if canonical(r.Origin.Change.Payload, &put) != nil {
		return imagebuild.Policy{}, ErrCatalog
	}
	return put.Spec.Own(), nil
}
func (r ImageBuildCachePruneRecord) NativeSpec(source imagebuild.JobSpec) (imagebuild.NativeCachePruneSpec, error) {
	q, err := r.Change()
	if err != nil {
		return imagebuild.NativeCachePruneSpec{}, err
	}
	spec := imagebuild.NativeCachePruneSpec{Schema: 1, Intent: r.Digest(), ID: q.ID, At: r.AcceptedAt(), Source: source.Own(), Filter: q.Filter.Own()}
	if r.Automatic != nil {
		policy, err := r.Limits(source)
		if err != nil {
			return spec, err
		}
		spec.Automatic = &policy
	}
	if !spec.Valid() {
		return spec, ErrCatalog
	}
	return spec, nil
}
func (r ImageBuildCachePruneRecord) recordKey() (string, error) {
	q, err := r.Change()
	if err != nil {
		return "", err
	}
	if r.Automatic != nil {
		return buildRecordKey("cache-automatic", q.Tenant, hex.EncodeToString(q.Cache[:])), nil
	}
	return buildRecordKey("cache-prune", q.Tenant, q.ID), nil
}
func writeCachePruneRecord(writes map[string][]byte, r ImageBuildCachePruneRecord) error {
	key, err := r.recordKey()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 64<<10 {
		return ErrCatalog
	}
	writes[key] = raw
	return nil
}

func (p Policy) currentCacheAutomaticAuthority(s state.State, b ImageBuildCatalog, origin UserOperation, source imagebuild.JobSpec) error {
	policy, ok := b.Policy(source.Tenant)
	if !ok || policy.Deleted || !buildJSONEqual(policy.Definition, origin) || origin.VerifyOriginal(p.Cluster) != nil {
		return access.ErrDenied
	}
	var put ImageBuildPolicyPut
	if canonical(origin.Change.Payload, &put) != nil || !buildJSONEqual(put.Spec, policy.Spec) || origin.Change.Action != "set-image-build-policy" || origin.Change.Expected+1 != policy.Revision {
		return access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	if c.OperationAllowed(origin.Session, "set-image-build-policy") != nil || p.buildRootAccepted(s, c, origin.Session, origin.At, source.Tenant, source.Scope.Root) != nil {
		return access.ErrDenied
	}
	owner, err := p.workNodeOwner(s, source.Scope.Root.Node)
	if err != nil || owner != source.Scope.Root.Key {
		return access.ErrDenied
	}
	if _, err := c.CheckImageRefTrust(source.Tenant, source.Policy.BuilderImage); err != nil {
		return err
	}
	return p.imageCacheAvailable(s, source.Scope.Root.Node, source.Policy.BuilderImage)
}

// The owner may propose only an idle cache already named by a retained source.
// Native existence/pin is checked separately before and during actual work.
func (p Policy) ImageBuildCacheAutomaticPlan(s state.State, caller [32]byte, tenant, node string, cache [32]byte, at int64) (ImageBuildCachePruneRecord, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildCachePruneRecord{}, err
	}
	if at <= 0 || !validID(tenant) || !validID(node) || cache == ([32]byte{}) {
		return ImageBuildCachePruneRecord{}, access.ErrInvalid
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildCachePruneRecord{}, err
	}
	source, found := imageBuildCacheRepresentative(b, tenant, node, cache)
	policy, configured := b.Policy(tenant)
	if !found || !configured || policy.Deleted || source.Run.Spec.Scope.Root.Key != caller {
		return ImageBuildCachePruneRecord{}, access.ErrDenied
	}
	if err := p.currentCacheAutomaticAuthority(s, b, policy.Definition, source.Run.Spec); err != nil {
		return ImageBuildCachePruneRecord{}, err
	}
	sequence := uint64(1)
	for _, row := range b.CachePrunes {
		q, err := row.Change()
		if err != nil {
			return ImageBuildCachePruneRecord{}, err
		}
		if q.Cache != cache {
			continue
		}
		if row.Pending() {
			return ImageBuildCachePruneRecord{}, reconcile.ErrPending
		}
		if row.Automatic != nil {
			if row.Automatic.Sequence == math.MaxUint64 || len(row.Reports) == 0 {
				return ImageBuildCachePruneRecord{}, access.ErrConflict
			}
			last := row.Reports[len(row.Reports)-1]
			if last.Action != "complete" || last.Native == nil || last.ClosedAt == 0 {
				return ImageBuildCachePruneRecord{}, access.ErrConflict
			}
			if uint64(at) < last.ClosedAt || uint64(at)-last.ClosedAt < ImageBuildCacheAutomaticInterval {
				return ImageBuildCachePruneRecord{}, reconcile.ErrPending
			}
			sequence = row.Automatic.Sequence + 1
		}
	}
	for _, job := range b.Jobs {
		if !job.Run.Terminal() && imagebuild.CacheIdentity(job.Run.Spec) == cache {
			return ImageBuildCachePruneRecord{}, reconcile.ErrPending
		}
	}
	r := ImageBuildCacheAutomaticReport{Schema: 1, Kind: "cache-automatic", Cluster: p.Cluster, Owner: caller, Definition: cacheAutomaticDefinition(policy.Definition), Tenant: tenant, Node: node, Source: source.Run.Spec.ID, Cache: cache, SourceDigest: source.Run.Spec.Digest(), PolicyRevision: policy.Revision, Sequence: sequence, RootRevision: s.Object(ImageBuildKey).Revision, Epoch: s.ModuleEpoch(), At: uint64(at)}
	row := ImageBuildCachePruneRecord{Origin: policy.Definition, Source: r.Source, SourceDigest: r.SourceDigest, State: "queued", Revision: 1, At: r.At, Automatic: &r}
	if !r.valid(row.Origin, source.Run.Spec, false) {
		return row, access.ErrDenied
	}
	for _, other := range b.CachePrunes {
		q, _ := other.Change()
		if q.Tenant == tenant && q.ID == r.ID() {
			return row, access.ErrConflict
		}
	}
	return row, nil
}

func (r ImageBuildCacheAutomaticReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Owner[:]), Epoch: r.Epoch, Key: ImageBuildKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) imageBuildCacheAutomaticReport(s state.State, cmd state.Command) (ImageBuildCacheAutomaticReport, ImageBuildCachePruneRecord, error) {
	var report ImageBuildCacheAutomaticReport
	if cmd.Kind != state.ModuleReport || cmd.Key != ImageBuildKey || canonical([]byte(cmd.Value), &report) != nil || report.Kind != "cache-automatic" || report.Epoch != s.ModuleEpoch() || report.At == 0 || report.At > math.MaxInt64 {
		return report, ImageBuildCachePruneRecord{}, access.ErrInvalid
	}
	want, err := report.Command()
	if err != nil || want != cmd {
		return report, ImageBuildCachePruneRecord{}, access.ErrInvalid
	}
	row, err := p.ImageBuildCacheAutomaticPlan(s, report.Owner, report.Tenant, report.Node, report.Cache, int64(report.At))
	if err != nil {
		return report, row, err
	}
	unsigned := report
	unsigned.Signature = nil
	if !buildJSONEqual(*row.Automatic, unsigned) || !ed25519.Verify(report.Owner[:], ImageBuildCacheAutomaticBytes(report), report.Signature) {
		return report, row, access.ErrDenied
	}
	row.Automatic = &report
	return report, row, nil
}
func (p Policy) ResolveImageBuildCacheAutomaticReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r ImageBuildCacheAutomaticReport
	if canonical(raw, &r) != nil || r.Owner != caller || r.Cluster != p.Cluster || !ed25519.Verify(r.Owner[:], ImageBuildCacheAutomaticBytes(r), r.Signature) {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := r.Command()
	if err != nil {
		return cmd, err
	}
	if _, found := s.LookupResult(cmd); found {
		return cmd, nil
	}
	_, _, err = p.imageBuildCacheAutomaticReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceImageBuildCacheAutomatic(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, row, err := p.imageBuildCacheAutomaticReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return nil, state.Invalid
	}
	replaced := false
	for i, old := range b.CachePrunes {
		if old.Automatic != nil && old.Automatic.Cache == r.Cache {
			b.CachePrunes[i] = row
			replaced = true
			break
		}
	}
	if !replaced {
		b.CachePrunes = append(b.CachePrunes, row)
	}
	if err := validateImageBuildCachePrune(b, row, p.Cluster, true); err != nil {
		return nil, state.Invalid
	}
	raw, err := json.Marshal(row)
	if err != nil || len(raw) > 48<<10 {
		return nil, state.ConditionFailed
	}
	root, err := b.root(p.Cluster)
	if err != nil {
		return nil, state.ConditionFailed
	}
	writes := map[string][]byte{ImageBuildKey: root}
	if err := writeCachePruneRecord(writes, row); err != nil {
		return nil, state.ConditionFailed
	}
	return writes, state.Applied
}
