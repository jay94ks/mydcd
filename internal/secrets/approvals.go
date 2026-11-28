// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/reconcile"
)

const approvalFact = "secret-group-use-approved"

type ApprovalPayload struct {
	ApprovedAt int64  `json:"approved_at"`
	Fact       string `json:"fact"`
	Target     Target `json:"target"`
}
type Approval struct {
	Schema    uint8
	Issuer    [32]byte
	Payload   ApprovalPayload
	Signature []byte
}

func ApprovalBytes(a Approval) []byte {
	b, _ := json.Marshal(a.Payload)
	return append([]byte("sfc-secret-group-approval-1\x00"), b...)
}

type Issuer struct {
	Key     [32]byte
	Policy  uint64
	Enabled bool
}
type Consumer struct {
	ID         string
	Generation uint64
	Use        Use
	Selection  [32]byte
	Lease      reconcile.Lease
}
type approvalRecord struct {
	Approval  Approval
	Revoking  bool
	Leases    reconcile.LeaseJournal
	Consumers []Consumer
}
type Approvals struct {
	cluster   [32]byte
	revision  uint64
	issuers   map[[32]byte]Issuer
	records   map[string]approvalRecord
	usagePins reconcile.LeaseJournal
	usages    map[string]Usage
}
type Pin struct {
	ApprovalID string
	Lease      reconcile.Lease
}
type Grant struct {
	Consumer   string
	Generation uint64
	Use        Use
	Selection  [32]byte
	Pins       []Pin
	Realm      string
	Lifetime   reconcile.Lease
}

func NewApprovals(cluster [32]byte) (Approvals, error) {
	if cluster == ([32]byte{}) {
		return Approvals{}, ErrPolicy
	}
	leases, _ := reconcile.NewLeases(1, maxObjects)
	return Approvals{cluster: cluster, issuers: map[[32]byte]Issuer{}, records: map[string]approvalRecord{}, usagePins: leases.Checkpoint(), usages: map[string]Usage{}}, nil
}
func (a Approvals) Revision() uint64  { return a.revision }
func (a Approvals) Cluster() [32]byte { return a.cluster }
func ownApproval(a Approval) Approval {
	a.Payload.Target = ownTarget(a.Payload.Target)
	a.Signature = slices.Clone(a.Signature)
	return a
}
func ownRecord(r approvalRecord) approvalRecord {
	r.Approval = ownApproval(r.Approval)
	r.Leases.Active = slices.Clone(r.Leases.Active)
	r.Consumers = slices.Clone(r.Consumers)
	for i := range r.Consumers {
		r.Consumers[i].Use = ownUse(r.Consumers[i].Use)
	}
	return r
}
func (a Approvals) clone() (Approvals, error) {
	if a.cluster == ([32]byte{}) || a.issuers == nil || a.records == nil || a.revision == ^uint64(0) {
		return a, ErrPolicy
	}
	n := a
	n.revision++
	n.issuers = map[[32]byte]Issuer{}
	n.records = map[string]approvalRecord{}
	for k, v := range a.issuers {
		n.issuers[k] = v
	}
	for k, v := range a.records {
		n.records[k] = ownRecord(v)
	}
	n.usagePins = a.usagePins
	n.usagePins.Active = slices.Clone(a.usagePins.Active)
	n.usages = map[string]Usage{}
	for k, v := range a.usages {
		n.usages[k] = ownUsage(v)
	}
	return n, nil
}
func (a Approvals) SetIssuer(c access.Catalog, actor string, expected uint64, key [32]byte, enabled bool) (Approvals, error) {
	if !c.SystemAllowed(actor) {
		return a, access.ErrDenied
	}
	if expected != a.revision {
		return a, access.ErrConflict
	}
	if key == ([32]byte{}) {
		return a, ErrPolicy
	}
	if _, exists := a.issuers[key]; !exists && len(a.issuers) >= 256 {
		return a, ErrPolicy
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	n.issuers[key] = Issuer{key, n.revision, enabled}
	return n, nil
}
func (a Approvals) Issuer(key [32]byte) (Issuer, bool) { v, ok := a.issuers[key]; return v, ok }
func validTarget(v Target) bool {
	if !validPurpose(v.Purpose) || v.Cluster == ([32]byte{}) || v.Realm != "" && !identifier(v.Realm) || !identifier(v.Tenant) && !(v.Tenant == "" && v.Realm == "" && v.Purpose == PurposeRegistrySource) || !identifier(v.User) || v.UserPolicy == 0 || v.RequesterKey == ([32]byte{}) || !identifier(v.App) || !identifier(v.Deployment) || !identifier(v.Group) || !identifier(v.ApprovalID) || v.IssuerPolicy == 0 || len(v.Path) < 1 || len(v.Path) > maxDepth || len(v.Services) < 1 || len(v.Nodes) < 1 || len(v.Nodes) > 256 || v.Actions != targetActions(v.Purpose) || v.Scope != namespaceScope {
		return false
	}
	services, err := sortedIDs(v.Services)
	if err != nil || !slices.Equal(services, v.Services) {
		return false
	}
	for i, p := range v.Path {
		if !identifier(p.ID) || p.Generation == 0 || p.PolicyRevision < p.Generation || i > 0 && slices.ContainsFunc(v.Path[:i], func(old PolicyRef) bool { return old.ID == p.ID }) {
			return false
		}
	}
	if v.Path[len(v.Path)-1].ID != v.Group {
		return false
	}
	for i, node := range v.Nodes {
		if !identifier(node.ID) || node.Key == ([32]byte{}) || i > 0 && nodeScopeKey(node) <= nodeScopeKey(v.Nodes[i-1]) {
			return false
		}
	}
	return true
}
func (a Approvals) authentic(v Approval) bool {
	i, ok := a.issuers[v.Issuer]
	return ok && v.Schema == 1 && validTarget(v.Payload.Target) && v.Payload.Target.Cluster == a.cluster && v.Payload.Fact == approvalFact && v.Payload.ApprovedAt >= 0 && i.Policy == v.Payload.Target.IssuerPolicy && ed25519.Verify(ed25519.PublicKey(i.Key[:]), ApprovalBytes(v), v.Signature)
}
func (a Approvals) valid(c access.Catalog, t Tree, v Approval, now int64) bool {
	if !a.authentic(v) || !a.issuers[v.Issuer].Enabled || t.cluster != a.cluster || now < 0 || v.Payload.ApprovedAt > now {
		return false
	}
	return a.currentTarget(c, t, v.Payload.Target, v.Payload.ApprovedAt, now)
}
func (a Approvals) currentTarget(c access.Catalog, t Tree, x Target, approvedAt, now int64) bool {
	if x.Realm != t.tenant {
		return false
	}
	o, ok := t.objects[x.Group]
	if !ok || !o.Protected || o.Status != Active || o.MaxApprovalAge > 0 && now-approvedAt > o.MaxApprovalAge {
		return false
	}
	refs, err := t.policies(x.Group)
	if err != nil || !slices.Equal(refs, x.Path) {
		return false
	}
	path, err := t.path(x.Group)
	if err != nil {
		return false
	}
	u, ok := c.User(x.User)
	m, _ := c.Membership(x.Tenant, x.User)
	if !ok || u.Revision != x.UserPolicy || m.Revision != x.MembershipPolicy {
		return false
	}
	for _, service := range x.Services {
		for _, node := range x.Nodes {
			use := Use{Purpose: x.Purpose, Tenant: x.Tenant, User: x.User, App: x.App, Deployment: x.Deployment, Service: service, Node: node.ID, NodeKey: node.Key, RequesterKey: x.RequesterKey}
			if !t.allowed(c, use, path) {
				return false
			}
		}
	}
	return true
}
func (a Approvals) Commit(c access.Catalog, actor string, t Tree, expected uint64, v Approval, now int64, capacity int) (Approvals, error) {
	if actor != v.Payload.Target.User && !c.SystemAllowed(actor) {
		return a, access.ErrDenied
	}
	if expected != a.revision {
		return a, access.ErrConflict
	}
	if !a.valid(c, t, v, now) || now-v.Payload.ApprovedAt > 300 || capacity < 1 || capacity > 4096 {
		return a, ErrPolicy
	}
	id := v.Payload.Target.ApprovalID
	if old, exists := a.records[id]; exists {
		ob, _ := json.Marshal(old.Approval)
		vb, _ := json.Marshal(v)
		if bytes.Equal(ob, vb) {
			return a, nil
		}
		return a, access.ErrConflict
	}
	if len(a.records) >= maxObjects {
		return a, ErrPolicy
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	leases, err := reconcile.NewLeases(n.revision, capacity)
	if err != nil {
		return a, err
	}
	n.records[id] = approvalRecord{Approval: ownApproval(v), Leases: leases.Checkpoint()}
	return n, nil
}
func covers(have, want Target) bool {
	left, right := ownTarget(have), ownTarget(want)
	left.Services = nil
	right.Services = nil
	left.Nodes = nil
	right.Nodes = nil
	left.ApprovalID = ""
	right.ApprovalID = ""
	left.IssuerPolicy = 0
	right.IssuerPolicy = 0
	if !sameTarget(left, right) {
		return false
	}
	for _, s := range want.Services {
		if !slices.Contains(have.Services, s) {
			return false
		}
	}
	for _, node := range want.Nodes {
		if !slices.Contains(have.Nodes, node) {
			return false
		}
	}
	return true
}
func (a Approvals) matching(c access.Catalog, t Tree, want Target, now int64) (string, bool) {
	ids := make([]string, 0, len(a.records))
	for id := range a.records {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		r := a.records[id]
		if !r.Revoking && covers(r.Approval.Payload.Target, want) && a.valid(c, t, r.Approval, now) {
			return id, true
		}
	}
	return "", false
}
func (a Approvals) Missing(c access.Catalog, t Tree, plan BatchPlan, now int64) []Target {
	var out []Target
	for _, want := range plan.Required {
		if _, ok := a.matching(c, t, want, now); !ok {
			out = append(out, ownTarget(want))
		}
	}
	return out
}
func selectionHash(p UsePlan) [32]byte { b, _ := json.Marshal(p); return sha256.Sum256(b) }

// ErrRevisionChanged is the ReadSet refusal of a consumer whose selection
// differs from the current one only in a secret's value or metadata
// revision. The consumer keeps what it already received; a new value needs
// a new consumer generation (a redeploy).
var ErrRevisionChanged = fmt.Errorf("%w: a secret was updated after this consumer was bound; redeploy to use the new revision", ErrPolicy)

// sameSelectionShape is true when a and b select the same secrets in the
// same order under the same gates and dependencies, whatever revisions they
// name.
func sameSelectionShape(a, b UsePlan) bool {
	if !sameUse(a.Use, b.Use) || !slices.Equal(a.Gates, b.Gates) || !slices.Equal(a.Dependencies, b.Dependencies) || len(a.Leaves) != len(b.Leaves) {
		return false
	}
	for i := range a.Leaves {
		x, y := a.Leaves[i], b.Leaves[i]
		if x.Secret != y.Secret || x.Generation != y.Generation || x.SourcePosition != y.SourcePosition || x.ExpansionPosition != y.ExpansionPosition || x.Reference.Profile != y.Reference.Profile || x.Reference.Object != y.Reference.Object {
			return false
		}
	}
	return true
}
func sameUse(a, b Use) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}

// CommittedUseTime finds one acquisition time for a newly submitted set of
// uses whose immutable operation may precede its Group approvals. It advances
// only to a matching approval's signed ApprovedAt already in this book, never
// to a caller-supplied signature or an invented future time. Every gate is
// rechecked at the common time, including earlier approvals' maximum age.
// This is not a clock: admission and subsequent reads still check current time.
// Existing consumers must retain their original Grants and use ReadSet; this
// helper neither selects replacement Pins nor changes a usage reservation.
func (a Approvals) CommittedUseTime(c access.Catalog, trees map[string]Tree, uses map[string][]Use, notBefore int64) (int64, error) {
	if notBefore < 0 || a.cluster == ([32]byte{}) {
		return 0, ErrPolicy
	}
	type requiredUse struct {
		tree   Tree
		target Target
	}
	var required []requiredUse
	realms := make([]string, 0, len(uses))
	for realm := range uses {
		realms = append(realms, realm)
	}
	slices.Sort(realms)
	for _, realm := range realms {
		tree, ok := trees[realm]
		if !ok || tree.cluster != a.cluster || tree.tenant != realm {
			return 0, ErrPolicy
		}
		plan, err := tree.Plan(c, uses[realm])
		if err != nil {
			return 0, err
		}
		for _, want := range plan.Required {
			required = append(required, requiredUse{tree, want})
		}
	}
	at := notBefore
	for {
		next := at
		for _, use := range required {
			if _, ok := a.matching(c, use.tree, use.target, at); ok {
				continue
			}
			// Missing at this time: find the earliest later committed fact
			// that can satisfy this exact purpose/path/requester/consumer.
			var later int64
			for _, record := range a.records {
				approval := record.Approval
				candidate := approval.Payload.ApprovedAt
				if candidate <= at || record.Revoking || !covers(approval.Payload.Target, use.target) || !a.valid(c, use.tree, approval, candidate) {
					continue
				}
				if later == 0 || candidate < later {
					later = candidate
				}
			}
			if later == 0 {
				return 0, access.ErrDenied
			}
			if later > next {
				next = later
			}
		}
		if next == at {
			return at, nil
		}
		// Each advance consumes an existing, strictly later signed fact. The
		// finite record set bounds this loop even when Group ages do not overlap.
		at = next
	}
}

// Acquire validates EVERY gate before borrowing anything. The caller syncs the
// returned metadata/lease candidate and node journal before reading or mounting
// values. A raw signature or public BatchPlan is never sufficient authority.
func (a Approvals) Acquire(c access.Catalog, t Tree, u Use, consumer string, generation, expected uint64, now int64) (Approvals, Grant, error) {
	if t.cluster != a.cluster || a.cluster == ([32]byte{}) {
		return a, Grant{}, ErrPolicy
	}
	if expected != a.revision {
		return a, Grant{}, access.ErrConflict
	}
	if !identifier(consumer) || generation == 0 {
		return a, Grant{}, ErrPolicy
	}
	plan, err := t.Plan(c, []Use{u})
	if err != nil {
		return a, Grant{}, err
	}
	hash := selectionHash(plan.Uses[0])
	grant := Grant{Consumer: consumer, Generation: generation, Use: ownUse(u), Selection: hash, Realm: t.tenant}
	for _, want := range plan.Required {
		id, ok := a.matching(c, t, want, now)
		if !ok {
			return a, Grant{}, access.ErrDenied
		}
		grant.Pins = append(grant.Pins, Pin{ApprovalID: id})
	}
	if old, exists := a.usages[usageKey(grant)]; exists {
		if old.Grant.Selection != hash || !sameUse(old.Grant.Use, u) {
			return a, Grant{}, access.ErrConflict
		}
		if _, err = a.ReadSet(c, t, old.Grant, now); err != nil {
			return a, Grant{}, err
		}
		return a, ownGrant(old.Grant), nil
	}
	n, err := a.clone()
	if err != nil {
		return a, Grant{}, err
	}
	for i, pin := range grant.Pins {
		r := ownRecord(n.records[pin.ApprovalID])
		found := false
		for _, old := range r.Consumers {
			if old.ID == consumer && old.Generation == generation {
				if !sameUse(old.Use, u) || old.Selection != hash {
					return a, Grant{}, access.ErrConflict
				}
				grant.Pins[i].Lease = old.Lease
				found = true
				break
			}
		}
		if found {
			continue
		}
		leases, err := reconcile.RestoreLeases(r.Leases)
		if err != nil {
			return a, Grant{}, err
		}
		pin.Lease, err = leases.Acquire()
		if err != nil {
			return a, Grant{}, err
		}
		r.Leases = leases.Checkpoint()
		r.Consumers = append(r.Consumers, Consumer{consumer, generation, ownUse(u), hash, pin.Lease})
		slices.SortFunc(r.Consumers, func(a, b Consumer) int {
			if a.Lease.Token < b.Lease.Token {
				return -1
			}
			if a.Lease.Token > b.Lease.Token {
				return 1
			}
			return 0
		})
		n.records[pin.ApprovalID] = r
		grant.Pins[i] = pin
	}
	if err = n.addUsage(grant, plan.Uses[0]); err != nil {
		return a, Grant{}, err
	}
	grant = ownGrant(n.usages[usageKey(grant)].Grant)
	return n, grant, nil
}

// ReadSet rechecks the current catalog/tree/issuer/revoke and exact source
// revisions, before provider reads. Value changes require a new consumer
// generation/staging but may reuse the same namespace approval without prompting.
func (a Approvals) ReadSet(c access.Catalog, t Tree, g Grant, now int64) (UsePlan, error) {
	if t.cluster != a.cluster || a.cluster == ([32]byte{}) {
		return UsePlan{}, ErrPolicy
	}
	plan, err := t.Plan(c, []Use{g.Use})
	if err != nil || !identifier(g.Consumer) || g.Generation == 0 {
		return UsePlan{}, ErrPolicy
	}
	p := plan.Uses[0]
	usage, exists := a.usages[usageKey(g)]
	if !exists || !sameGrant(usage.Grant, g) || g.Realm != t.tenant || len(g.Pins) != len(plan.Required) {
		return UsePlan{}, ErrPolicy
	}
	if selectionHash(p) != g.Selection {
		if selectionHash(usage.Plan) == g.Selection && sameSelectionShape(p, usage.Plan) {
			return UsePlan{}, ErrRevisionChanged
		}
		return UsePlan{}, ErrPolicy
	}
	for i, want := range plan.Required {
		pin := g.Pins[i]
		r, ok := a.records[pin.ApprovalID]
		if !ok || r.Revoking || !covers(r.Approval.Payload.Target, want) || !a.valid(c, t, r.Approval, now) {
			return UsePlan{}, access.ErrDenied
		}
		found := false
		for _, v := range r.Consumers {
			if v.ID == g.Consumer && v.Generation == g.Generation && v.Lease == pin.Lease && v.Selection == g.Selection && sameUse(v.Use, g.Use) {
				found = true
			}
		}
		if !found {
			return UsePlan{}, ErrPolicy
		}
	}
	return p, nil
}
func (a Approvals) Revoke(c access.Catalog, actor, id string, expected uint64) (Approvals, error) {
	r, ok := a.records[id]
	if !ok {
		return a, ErrPolicy
	}
	realm := r.Approval.Payload.Target.Realm
	allowed := c.AuthorizeCleanup(actor, realm, access.ManageSecrets) == nil
	if realm == "" {
		allowed = c.SystemAllowed(actor)
	}
	if !allowed {
		return a, access.ErrDenied
	}
	if expected != a.revision {
		return a, access.ErrConflict
	}
	if r.Revoking {
		return a, nil
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	r = ownRecord(r)
	leases, err := reconcile.RestoreLeases(r.Leases)
	if err != nil {
		return a, err
	}
	leases.Drain()
	r.Revoking = true
	r.Leases = leases.Checkpoint()
	n.records[id] = r
	return n, nil
}

// Realm is the realm of a committed approval (who may revoke it is decided
// in that realm).
func (a Approvals) Realm(id string) (string, bool) {
	r, ok := a.records[id]
	return r.Approval.Payload.Target.Realm, ok
}

func (a Approvals) RevocationPending(id string) bool {
	r, ok := a.records[id]
	return ok && r.Revoking && len(r.Leases.Active) > 0
}

type ConsumerGone struct {
	Cluster              [32]byte
	ApprovalID, Consumer string
	Generation           uint64
	NodeKey              [32]byte
	Lease                reconcile.Lease
	Stopped, MountsGone  bool
	Signature            []byte
}

func ConsumerGoneBytes(p ConsumerGone) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("sfc-secret-consumer-gone-1\x00"), b...)
}
func (a Approvals) Release(p ConsumerGone) (Approvals, error) {
	r, ok := a.records[p.ApprovalID]
	if !ok || p.Cluster != a.cluster || !p.Stopped || !p.MountsGone {
		return a, ErrPolicy
	}
	index := -1
	for i, v := range r.Consumers {
		if v.ID == p.Consumer && v.Generation == p.Generation && v.Lease == p.Lease && v.Use.NodeKey == p.NodeKey {
			index = i
			break
		}
	}
	if index < 0 || !ed25519.Verify(ed25519.PublicKey(p.NodeKey[:]), ConsumerGoneBytes(p), p.Signature) {
		return a, ErrPolicy
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	r = ownRecord(r)
	leases, err := reconcile.RestoreLeases(r.Leases)
	if err != nil {
		return a, err
	}
	if err = leases.Release(p.Lease); err != nil {
		return a, err
	}
	r.Leases = leases.Checkpoint()
	r.Consumers = append(r.Consumers[:index], r.Consumers[index+1:]...)
	n.records[p.ApprovalID] = r
	return n, nil
}

type approvalsRecord struct {
	Schema    uint8
	Cluster   [32]byte
	Revision  uint64
	Issuers   []Issuer
	Records   []approvalRecord
	UsagePins reconcile.LeaseJournal
	Usages    []Usage
}

func (a Approvals) Encode() ([]byte, error) {
	if a.cluster == ([32]byte{}) || a.records == nil || a.issuers == nil {
		return nil, ErrPolicy
	}
	r := approvalsRecord{Schema: 1, Cluster: a.cluster, Revision: a.revision, UsagePins: a.usagePins}
	for _, v := range a.issuers {
		r.Issuers = append(r.Issuers, v)
	}
	slices.SortFunc(r.Issuers, func(a, b Issuer) int { return bytes.Compare(a.Key[:], b.Key[:]) })
	for _, v := range a.records {
		r.Records = append(r.Records, ownRecord(v))
	}
	slices.SortFunc(r.Records, func(a, b approvalRecord) int {
		return strings.Compare(a.Approval.Payload.Target.ApprovalID, b.Approval.Payload.Target.ApprovalID)
	})
	for _, u := range a.usages {
		r.Usages = append(r.Usages, ownUsage(u))
	}
	slices.SortFunc(r.Usages, func(a, b Usage) int {
		if a.Grant.Lifetime.Token < b.Grant.Lifetime.Token {
			return -1
		}
		if a.Grant.Lifetime.Token > b.Grant.Lifetime.Token {
			return 1
		}
		return 0
	})
	return json.Marshal(r)
}
func DecodeApprovals(b []byte) (Approvals, error) {
	var r approvalsRecord
	if json.Unmarshal(b, &r) != nil || r.Schema != 1 || len(r.Issuers) > 256 || len(r.Records) > maxObjects || len(r.Usages) > maxObjects {
		return Approvals{}, ErrPolicy
	}
	a, err := NewApprovals(r.Cluster)
	if err != nil {
		return Approvals{}, err
	}
	a.revision = r.Revision
	for _, v := range r.Issuers {
		if _, dup := a.issuers[v.Key]; dup || v.Key == ([32]byte{}) || v.Policy == 0 || v.Policy > a.revision {
			return Approvals{}, ErrPolicy
		}
		a.issuers[v.Key] = v
	}
	for _, v := range r.Records {
		id := v.Approval.Payload.Target.ApprovalID
		if _, dup := a.records[id]; dup || v.Approval.Schema != 1 || !validTarget(v.Approval.Payload.Target) || v.Approval.Payload.Target.Cluster != a.cluster || v.Approval.Payload.Fact != approvalFact || v.Approval.Payload.ApprovedAt < 0 || !ed25519.Verify(ed25519.PublicKey(v.Approval.Issuer[:]), ApprovalBytes(v.Approval), v.Approval.Signature) {
			return Approvals{}, ErrPolicy
		}
		issuer, ok := a.issuers[v.Approval.Issuer]
		if !ok || v.Approval.Payload.Target.IssuerPolicy > issuer.Policy {
			return Approvals{}, ErrPolicy
		}
		leases, err := reconcile.RestoreLeases(v.Leases)
		if err != nil || v.Leases.Generation > a.revision || v.Leases.Capacity > 4096 || v.Revoking != v.Leases.Draining || len(v.Consumers) != leases.Count() {
			return Approvals{}, ErrPolicy
		}
		for i, c := range v.Consumers {
			if c.Lease != v.Leases.Active[i] || !identifier(c.ID) || c.Generation == 0 || c.Selection == ([32]byte{}) || !sameBase(c.Use, Use{Purpose: v.Approval.Payload.Target.Purpose, Tenant: v.Approval.Payload.Target.Tenant, User: v.Approval.Payload.Target.User, RequesterKey: v.Approval.Payload.Target.RequesterKey, App: v.Approval.Payload.Target.App, Deployment: v.Approval.Payload.Target.Deployment}) || !slices.Contains(v.Approval.Payload.Target.Services, c.Use.Service) || !slices.Contains(v.Approval.Payload.Target.Nodes, NodeScope{c.Use.Node, c.Use.NodeKey}) {
				return Approvals{}, ErrPolicy
			}
			for _, old := range v.Consumers[:i] {
				if old.ID == c.ID && old.Generation == c.Generation {
					return Approvals{}, ErrPolicy
				}
			}
		}
		a.records[id] = ownRecord(v)
	}
	if err = a.restoreUsages(r.UsagePins, r.Usages); err != nil {
		return Approvals{}, err
	}
	canonical, err := a.Encode()
	if err != nil || !bytes.Equal(b, canonical) {
		return Approvals{}, ErrPolicy
	}
	return a, nil
}

// CheckTarget uses the same current policy/path/consumer checks as Commit,
// before an actual verifier read/KDF. It grants no approval and signs nothing.
func (a Approvals) CheckTarget(c access.Catalog, t Tree, issuer [32]byte, target Target, now int64) error {
	i, ok := a.issuers[issuer]
	if !ok || !i.Enabled || i.Policy != target.IssuerPolicy || !validTarget(target) || target.Cluster != a.cluster || t.cluster != a.cluster || now < 0 || !a.currentTarget(c, t, target, now, now) {
		return ErrPolicy
	}
	return nil
}
func (a Approvals) Existing(c access.Catalog, t Tree, want Target, now int64) (Approval, bool) {
	id, ok := a.matching(c, t, want, now)
	if !ok {
		return Approval{}, false
	}
	return ownApproval(a.records[id].Approval), true
}
