// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"math"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

const RegistryPruneAction = "prune-registry-images"
const RegistryPrunePreviewSeconds = 600

type RegistryPruneFact struct {
	Schema                                      uint8
	Cluster, Owner, Target, Conditions, Preview [32]byte
	Tenant, Registry                            string
	External                                    bool
	Items, Retained                             uint32
	ImageBytes, EstimatedReclaimedBytes         int64
	EstimateKnown, Live                         bool
	At                                          uint64
	Signature                                   []byte
	Public                                      [32]byte
}

func RegistryPruneFactBytes(f RegistryPruneFact) []byte {
	f.Signature = nil
	raw, _ := json.Marshal(f)
	return append([]byte("mydc-registry-prune-fact-1\x00"), raw...)
}
func PruneConditionsDigest(c registryclient.PruneConditions) [32]byte {
	raw, _ := json.Marshal(c)
	return sha256.Sum256(append([]byte("mydc-registry-prune-conditions-1\x00"), raw...))
}
func (q RegistryMaintenanceChange) PruneBase() RegistryMaintenanceChange {
	q.Operation = ""
	q.Prune = nil
	return q
}
func (f RegistryPruneFact) Valid(cluster [32]byte, q RegistryMaintenanceChange, c registryclient.PruneConditions) bool {
	return f.Schema == 1 && f.Cluster == cluster && f.Owner == q.OwnerKey() && f.Owner != ([32]byte{}) && f.Target == q.PruneBase().DigestValue() && f.Conditions == PruneConditionsDigest(c) && f.Preview != ([32]byte{}) && f.Public != ([32]byte{}) && f.Tenant == q.Tenant && f.Registry == q.RegistryID() && f.External == (q.External != nil) && f.Items <= registryclient.MaxCatalogueNames && f.Retained <= 2*registryclient.MaxCatalogueNames && f.ImageBytes >= 0 && f.EstimatedReclaimedBytes >= 0 && (f.EstimateKnown || f.EstimatedReclaimedBytes == 0) && (!f.Live || !f.EstimateKnown) && f.At > 0 && f.At <= math.MaxInt64-RegistryPrunePreviewSeconds && len(f.Signature) == ed25519.SignatureSize && ed25519.Verify(f.Owner[:], RegistryPruneFactBytes(f), f.Signature)
}

type RegistryPruneTarget struct {
	Conditions registryclient.PruneConditions
	Fact       RegistryPruneFact
}

func (t RegistryPruneTarget) Valid(cluster [32]byte, q RegistryMaintenanceChange) bool {
	return t.Conditions.Valid() && !(q.External != nil && t.Conditions.GC) && t.Fact.Valid(cluster, q, t.Conditions)
}

type RegistryPruneQuery struct {
	ID, Operation, Part string
	External            bool                            `json:",omitempty"`
	Conditions          *registryclient.PruneConditions `json:",omitempty"`
	Fact                *RegistryPruneFact              `json:",omitempty"`
}

func (q RegistryPruneQuery) Valid(results bool) bool {
	if results {
		return (RegistryMaintenanceQuery{Operation: q.Operation}).Valid(false) && q.ID == "" && !q.External && q.Conditions == nil && q.Fact == nil && q.Part == "items"
	}
	return validID(q.ID) && q.Operation == "" && (q.Part == "items" || q.Part == "retained") && q.Conditions != nil && q.Conditions.Valid() && !(q.External && q.Conditions.GC)
}

type RegistryPruneRead struct {
	Session access.Session
	Tenant  string
	Query   RegistryPruneQuery
	After   string
	Base    RegistryMaintenancePlan
}

func (p Policy) RegistryPruneRead(s state.State, session access.Session, at int64, tenant string, q RegistryPruneQuery, after string, results bool) (RegistryPruneRead, error) {
	if !q.Valid(results) || !validID(tenant) || len(after) > 512 {
		return RegistryPruneRead{}, access.ErrInvalid
	}
	if _, _, err := registryclient.CatalogueCursor(after); err != nil {
		return RegistryPruneRead{}, access.ErrInvalid
	}
	if results {
		status, err := p.RegistryMaintenanceStatus(s, session, at, tenant, q.Operation)
		if err != nil || status.Change.Prune == nil {
			return RegistryPruneRead{}, access.ErrDenied
		}
		return RegistryPruneRead{Session: session, Tenant: tenant, Query: q, After: after, Base: RegistryMaintenancePlan{Schema: 1, Cluster: p.Cluster, Tenant: tenant, Action: RegistryPruneAction, Expected: status.Change.ExpectedRevision(), RootRevision: status.RootRevision, Epoch: s.ModuleEpoch(), Change: status.Change}}, nil
	}
	base, err := p.PlanRegistryMaintenance(s, session, at, tenant, RegistryMaintenanceQuery{Action: RegistryPruneAction, ID: q.ID, External: q.External})
	if err != nil {
		return RegistryPruneRead{}, err
	}
	if q.Conditions.GC {
		c, err := p.Catalog(s)
		if err != nil || c.OperationAllowed(session, "gc-registry") != nil {
			return RegistryPruneRead{}, access.ErrDenied
		}
	}
	if q.Fact != nil {
		if !q.Fact.Valid(p.Cluster, base.Change, *q.Conditions) || at <= 0 || uint64(at) < q.Fact.At || uint64(at)-q.Fact.At > RegistryPrunePreviewSeconds {
			return RegistryPruneRead{}, access.ErrConflict
		}
	} else if after != "" {
		return RegistryPruneRead{}, access.ErrInvalid
	}
	return RegistryPruneRead{Session: session, Tenant: tenant, Query: q, After: after, Base: base}, nil
}
func (p Policy) CurrentRegistryPruneRead(s state.State, read RegistryPruneRead, at int64, results bool) (RegistryPruneRead, error) {
	current, err := p.RegistryPruneRead(s, read.Session, at, read.Tenant, read.Query, read.After, results)
	if err != nil || current.Base.Change.PruneBase().DigestValue() != read.Base.Change.PruneBase().DigestValue() {
		return RegistryPruneRead{}, access.ErrDenied
	}
	return current, nil
}

type RegistryPruneRow struct {
	ID          string
	Image       registryclient.ImageMetadata
	Aliases     uint32
	AliasDigest string
	Code        string   `json:",omitempty"`
	At          uint64   `json:",omitempty"`
	Native      [32]byte `json:",omitempty"`
}

func PrunePublicItem(item registryclient.PruneItem) RegistryPruneRow {
	return RegistryPruneRow{ID: item.ItemID(), Image: item.Image, Aliases: uint32(len(item.Tags)), AliasDigest: registryclient.PruneAliasDigest(item.Tags)}
}

// The signed public projection lets a CLI assemble bounded wire pages into a
// reviewable file without receiving large private/native alias arrays.
func RegistryPrunePublicDigest(items []RegistryPruneRow, retained []registryclient.PruneRetained) [32]byte {
	raw, _ := json.Marshal(struct {
		Items    []RegistryPruneRow
		Retained []registryclient.PruneRetained
	}{items, retained})
	return sha256.Sum256(append([]byte("mydc-registry-prune-public-1\x00"), raw...))
}
func RegistryPrunePreviewPublicDigest(preview registryclient.PrunePreview) [32]byte {
	items := []RegistryPruneRow{}
	for _, item := range preview.Items {
		items = append(items, PrunePublicItem(item))
	}
	retained := append([]registryclient.PruneRetained{}, preview.Retained...)
	return RegistryPrunePublicDigest(items, retained)
}
func (r RegistryPruneRow) Valid(result bool) bool {
	if !pruneHexString(r.ID) || !r.Image.Valid() || r.Aliases > registryclient.MaxCatalogueNames || !pruneHexString(r.AliasDigest) {
		return false
	}
	if !result {
		return r.Code == "" && r.At == 0 && r.Native == ([32]byte{})
	}
	return (RegistryMaintenanceResult{Code: r.Code, At: r.At, Native: r.Native}).Valid()
}
func pruneHexString(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type RegistryPrunePage struct {
	Schema           uint8
	Root             [32]byte
	Part             string
	Total, Processed uint32
	Rows             []RegistryPruneRow             `json:",omitempty"`
	Retained         []registryclient.PruneRetained `json:",omitempty"`
	Next             string
}
type RegistryPruneView struct {
	Schema uint8
	Tenant string
	Plan   RegistryMaintenancePlan
	Page   RegistryPrunePage
}

func (v RegistryPruneView) Valid(read RegistryPruneRead, results bool) bool {
	if v.Schema != 1 || v.Tenant != read.Tenant || v.Plan.Schema != 1 || v.Plan.Cluster != read.Base.Cluster || v.Plan.Tenant != read.Tenant || v.Plan.Expected == 0 || v.Plan.Expected != v.Plan.Change.ExpectedRevision() || v.Plan.Epoch == 0 || v.Plan.InUse || v.Plan.Change.Prune == nil || v.Plan.Action != RegistryPruneAction || v.Plan.Change.PruneBase().DigestValue() != read.Base.Change.PruneBase().DigestValue() || !v.Plan.Change.Prune.Valid(read.Base.Cluster, v.Plan.Change) || v.Page.Schema != 1 || v.Page.Part != read.Query.Part || v.Page.Root == ([32]byte{}) || len(v.Page.Rows) > 8 || len(v.Page.Retained) > 8 {
		return false
	}
	f := v.Plan.Change.Prune.Fact
	if !results && (v.Plan.Change.Operation != "" || read.Query.Conditions == nil || PruneConditionsDigest(*read.Query.Conditions) != f.Conditions || v.Plan.Change.RegistryID() != read.Query.ID || (v.Plan.Change.External != nil) != read.Query.External || v.Page.Processed != 0) {
		return false
	}
	if !results && (v.Page.Root != f.Preview || v.Page.Part == "items" && v.Page.Total != f.Items || v.Page.Part == "retained" && v.Page.Total != f.Retained) {
		return false
	}
	if read.Query.Fact != nil && !samePruneFact(*read.Query.Fact, f) {
		return false
	}
	if results && (v.Plan.Change.Operation != read.Query.Operation || v.Page.Total > f.Items || v.Page.Processed != v.Page.Total) {
		return false
	}
	for _, row := range v.Page.Rows {
		if !row.Valid(results) {
			return false
		}
	}
	for _, row := range v.Page.Retained {
		if !row.Image.Valid() || !registryclient.ValidPruneRetainedCode(row.Code) {
			return false
		}
	}
	if v.Page.Part == "items" && len(v.Page.Retained) != 0 || v.Page.Part == "retained" && len(v.Page.Rows) != 0 {
		return false
	}
	start, end, next, err := registryclient.PrunePageRange(v.Page.Part, v.Page.Root, v.Page.Total, read.After)
	count := len(v.Page.Rows)
	if v.Page.Part == "retained" {
		count = len(v.Page.Retained)
	}
	if err != nil || count != int(end-start) || next != v.Page.Next {
		return false
	}
	if v.Page.Next != "" {
		root, _, err := registryclient.CatalogueCursor(v.Page.Next)
		if err != nil || root != v.Page.Root {
			return false
		}
	}
	if read.After != "" {
		root, _, err := registryclient.CatalogueCursor(read.After)
		if err != nil || root != v.Page.Root {
			return false
		}
	}
	return true
}
func (v RegistryPruneView) ValidQuery(cluster [32]byte, tenant string, q RegistryPruneQuery, after string, results bool) bool {
	if !q.Valid(results) || v.Plan.Cluster != cluster {
		return false
	}
	base := v.Plan
	base.Change = base.Change.PruneBase()
	return v.Valid(RegistryPruneRead{Tenant: tenant, Query: q, After: after, Base: base}, results)
}
func samePruneFact(a, b RegistryPruneFact) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func (p Policy) pruneChangeAuthorized(c access.Catalog, op UserOperation, q RegistryMaintenanceChange) error {
	if q.Prune == nil || !q.Prune.Valid(p.Cluster, q) || op.At <= 0 || uint64(op.At) < q.Prune.Fact.At || uint64(op.At)-q.Prune.Fact.At > RegistryPrunePreviewSeconds {
		return access.ErrDenied
	}
	if q.Prune.Conditions.GC && c.OperationAllowed(op.Session, "gc-registry") != nil {
		return access.ErrDenied
	}
	return nil
}
func (q RegistryMaintenanceChange) PruneRepository(repo string) bool {
	if q.Prune == nil || len(q.Prune.Conditions.Repositories) > 0 && !slices.Contains(q.Prune.Conditions.Repositories, repo) {
		return false
	}
	if q.External == nil {
		return true
	}
	_, ok := q.External.Spec.Match(access.Image{Registry: q.Authority(), Repository: repo})
	return ok
}
func (p Policy) pruneAdmission(s state.State, q RegistryMaintenanceChange) error {
	jobs, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return err
	}
	for _, row := range jobs.Records {
		if !row.Pending() || row.Change.Authority() != q.Authority() {
			continue
		}
		if row.Change.Prune != nil || row.Origin.Change.Action == "gc-registry" || q.PruneRepository(row.Change.Repository) {
			return access.ErrConflict
		}
	}
	return nil
}

type RegistryPruneSummary struct {
	Processed, Deleted, Skipped, Failed uint32
	GCCode                              string `json:",omitempty"`
	GCAt                                uint64 `json:",omitempty"`
}

func (s RegistryPruneSummary) Valid() bool {
	if uint64(s.Deleted)+uint64(s.Skipped)+uint64(s.Failed) != uint64(s.Processed) || s.Processed > registryclient.MaxCatalogueNames {
		return false
	}
	if (s.GCCode == "OK") != (s.GCAt > 0) {
		return false
	}
	if s.GCCode == "" || s.GCCode == "OK" {
		return true
	}
	return (RegistryMaintenanceResult{Code: s.GCCode, At: 1}).Valid()
}

// Result cursors commit a bounded original progress snapshot, never a native
// liveness claim or a separate synchronization/hash-chain layer.
func RegistryPruneResultRoot(target [32]byte, next uint32, result *RegistryMaintenanceResult) [32]byte {
	raw, _ := json.Marshal(struct {
		Target [32]byte
		Next   uint32
		Result *RegistryMaintenanceResult
	}{target, next, result})
	return sha256.Sum256(append([]byte("mydc-registry-prune-results-1\x00"), raw...))
}

func PruneResultSuccess(code string) bool { return code == "OK" || code == "ALREADY_ABSENT" }
func PruneResultSkipped(code string) bool {
	return code == "IMAGE_IN_USE" || code == "REFERENCE_CHANGED"
}

// A small shared completion must account for every frozen item. Only a missing
// unstarted preview can close without item receipts, with an explicit failure.
func RegistryMaintenanceResultFor(q RegistryMaintenanceChange, r RegistryMaintenanceResult) bool {
	if !r.Valid() {
		return false
	}
	if q.Prune == nil {
		return r.Prune == nil && r.Code != "PARTIAL" && r.Code != "PREVIEW_UNAVAILABLE"
	}
	if r.Prune == nil {
		return false
	}
	s := *r.Prune
	if r.Code == "PREVIEW_UNAVAILABLE" {
		return s.Processed == 0 && s.GCCode == "" && r.ReclaimedBytes == 0 && r.Native == ([32]byte{})
	}
	if r.Code != "OK" && r.Code != "PARTIAL" || s.Processed != q.Prune.Fact.Items || (s.GCCode != "") != q.Prune.Conditions.GC || !q.Prune.Conditions.GC && r.ReclaimedBytes != 0 || s.GCCode != "OK" && r.ReclaimedBytes != 0 {
		return false
	}
	partial := s.Failed > 0 || s.GCCode != "" && s.GCCode != "OK"
	return (r.Code == "PARTIAL") == partial
}
