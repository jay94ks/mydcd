// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
)

type TenantPhase string

const (
	TenantActive   TenantPhase = "active"
	TenantRetiring TenantPhase = "retiring"
	TenantDeleted  TenantPhase = "deleted"
)

// RetirementTarget is collected by the FSM from all module catalogs and
// accepted/pending operations, including retained data and deauthorized nodes.
// It is not an inventory that an untrusted CLI may supply to skip resources.
type RetirementTarget struct {
	Tenant, Kind, ID, Node string
	// Key preserves the original native journal/source coordinate. Old core
	// records omit it; it is never supplied as an authoritative CLI inventory.
	Key        string `json:",omitempty"`
	Owner      [32]byte
	Generation uint64
	Operation  string
	Retain     bool
}
type RetirementOwner struct {
	Node   string
	Key    [32]byte
	Report *TenantReport
}
type TenantRetirement struct {
	Cluster         [32]byte
	Operation       string
	StartedRevision uint64
	InventoryHash   [32]byte
	OwnersHash      [32]byte
	Targets         []RetirementTarget
	Owners          []RetirementOwner
}
type TenantReport struct {
	Cluster                                                                                      [32]byte
	Tenant, Operation, Node                                                                      string
	Owner                                                                                        [32]byte
	StartedRevision, Sequence                                                                    uint64
	InventoryHash                                                                                [32]byte
	OwnersHash                                                                                   [32]byte
	Quiesced                                                                                     bool
	PendingResources, PendingOperations, PendingWriters, PendingFlows, PendingPins, RetainedData uint64
	Signature                                                                                    []byte
}

func TenantReportBytes(p TenantReport) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("sfc-tenant-retirement-1\x00"), b...)
}
func ownRetirement(r TenantRetirement) TenantRetirement {
	r.Targets = slices.Clone(r.Targets)
	r.Owners = slices.Clone(r.Owners)
	for i := range r.Owners {
		if r.Owners[i].Report != nil {
			p := *r.Owners[i].Report
			p.Signature = slices.Clone(p.Signature)
			r.Owners[i].Report = &p
		}
	}
	return r
}
func targetKey(t RetirementTarget) string {
	b, _ := json.Marshal(t)
	return string(b)
}
func ownerKey(node string, key [32]byte) string { return node + "/" + hex.EncodeToString(key[:]) }
func ownerSetHash(owners []RetirementOwner) [32]byte {
	public := make([]RetirementOwner, len(owners))
	for i, o := range owners {
		public[i] = RetirementOwner{Node: o.Node, Key: o.Key}
	}
	b, _ := json.Marshal(public)
	return sha256.Sum256(append([]byte("sfc-tenant-owners-1\x00"), b...))
}
func canonicalInventory(tenant string, targets []RetirementTarget) ([]RetirementTarget, []RetirementOwner, [32]byte, error) {
	if len(targets) > 16384 {
		return nil, nil, [32]byte{}, ErrInvalid
	}
	targets = slices.Clone(targets)
	if len(targets) == 0 {
		targets = nil
	}
	slices.SortFunc(targets, func(a, b RetirementTarget) int { return strings.Compare(targetKey(a), targetKey(b)) })
	owners := map[string]RetirementOwner{}
	identities := map[string]bool{}
	for _, t := range targets {
		if t.Tenant != tenant || !identifier(t.Kind) || !identifier(t.ID) || !identifier(t.Node) || len(t.Key) > 512 || strings.ContainsAny(t.Key, "\x00\r\n") || t.Owner == ([32]byte{}) || t.Generation == 0 || t.Operation != "" && !identifier(t.Operation) {
			return nil, nil, [32]byte{}, ErrInvalid
		}
		// Retain is policy, not identity: two records cannot hide a different
		// retention flag under the same original resource/operation tuple.
		identity := t
		identity.Retain = false
		k := targetKey(identity)
		if identities[k] {
			return nil, nil, [32]byte{}, ErrInvalid
		}
		identities[k] = true
		owners[ownerKey(t.Node, t.Owner)] = RetirementOwner{Node: t.Node, Key: t.Owner}
	}
	if len(owners) > 1024 {
		return nil, nil, [32]byte{}, ErrInvalid
	}
	list := make([]RetirementOwner, 0, len(owners))
	for _, o := range owners {
		list = append(list, o)
	}
	slices.SortFunc(list, func(a, b RetirementOwner) int {
		return strings.Compare(ownerKey(a.Node, a.Key), ownerKey(b.Node, b.Key))
	})
	// This digest identifies a single immutable inventory, not a replication log
	// or a hash-chain synchronization layer.
	b, _ := json.Marshal(targets)
	h := sha256.Sum256(append([]byte("sfc-tenant-inventory-1\x00"), b...))
	return targets, list, h, nil
}
func reportComplete(p *TenantReport) bool {
	return p != nil && p.Quiesced && p.PendingResources == 0 && p.PendingOperations == 0 && p.PendingWriters == 0 && p.PendingFlows == 0 && p.PendingPins == 0 && p.RetainedData == 0
}

// Complete is closure, not mere receipt of a signed progress report.
func (p TenantReport) Complete() bool { return reportComplete(&p) }

// MatchesInventory validates separately retained original evidence against the
// immutable inventory and owner digests, including after a Deleted tombstone.
func (r TenantRetirement) MatchesInventory(tenant string, targets []RetirementTarget) bool {
	_, owners, digest, err := canonicalInventory(tenant, targets)
	return err == nil && digest == r.InventoryHash && ownerSetHash(owners) == r.OwnersHash
}
func matchesReport(tenant string, r TenantRetirement, o RetirementOwner, p TenantReport) bool {
	return p.Cluster == r.Cluster && p.Tenant == tenant && p.Operation == r.Operation && p.Node == o.Node && p.Owner == o.Key && p.StartedRevision == r.StartedRevision && p.InventoryHash == r.InventoryHash && p.OwnersHash == r.OwnersHash && p.Sequence > 0 && ed25519.Verify(ed25519.PublicKey(o.Key[:]), TenantReportBytes(p), p.Signature)
}

// BeginTenantRetirement must run in the same committed transaction that closes
// new tenant admission and collects the authoritative original inventory. It
// never dispatches deletes, revokes users globally, or destroys retained data.
func (c Catalog) BeginTenantRetirement(actor, tenant, operation string, cluster [32]byte, expected uint64, targets []RetirementTarget) (Catalog, error) {
	if !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	t, ok := c.tenants[tenant]
	if !ok || t.Revision != expected {
		return c, ErrConflict
	}
	if t.Phase != TenantActive || !t.Enabled || !identifier(operation) || cluster == ([32]byte{}) {
		return c, ErrInvalid
	}
	items, owners, digest, err := canonicalInventory(tenant, targets)
	if err != nil {
		return c, err
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	t.Phase = TenantRetiring
	t.Revision = n.revision
	t.Retirement = &TenantRetirement{Cluster: cluster, Operation: operation, StartedRevision: n.revision, InventoryHash: digest, OwnersHash: ownerSetHash(owners), Targets: items, Owners: owners}
	n.tenants[tenant] = ownTenant(t)
	return n, nil
}

// ObserveTenantRetirement records original owner progress after user/grant
// revocation. Missing reports and positive counters remain pending. Permission
// to report settlement is not permission to create new work.
func (c Catalog) ObserveTenantRetirement(p TenantReport) (Catalog, error) {
	t, ok := c.tenants[p.Tenant]
	if !ok || t.Phase != TenantRetiring || t.Retirement == nil {
		return c, ErrConflict
	}
	r := ownRetirement(*t.Retirement)
	index := -1
	for i, o := range r.Owners {
		if o.Node == p.Node && o.Key == p.Owner {
			index = i
			break
		}
	}
	if index < 0 || !matchesReport(t.ID, r, r.Owners[index], p) {
		return c, ErrInvalid
	}
	old := r.Owners[index].Report
	if old != nil {
		if p.Sequence == old.Sequence && bytes.Equal(TenantReportBytes(p), TenantReportBytes(*old)) {
			return c, nil
		}
		if p.Sequence <= old.Sequence || reportComplete(old) {
			return c, ErrConflict
		}
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	p.Signature = slices.Clone(p.Signature)
	r.Owners[index].Report = &p
	t.Retirement = &r
	t.Revision = n.revision
	n.tenants[t.ID] = ownTenant(t)
	return n, nil
}

// FinishTenantRetirement requires BOTH signed owner closure and an empty current
// inventory collected by the FSM under the same transaction. remaining must
// include shared references, retained data and unknown original operations;
// transport payloads are never an authority for this argument.
func (c Catalog) FinishTenantRetirement(actor, tenant, operation string, expected uint64, remaining []RetirementTarget) (Catalog, error) {
	if !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	t, ok := c.tenants[tenant]
	if !ok || t.Revision != expected {
		return c, ErrConflict
	}
	if t.Phase != TenantRetiring || t.Retirement == nil || t.Retirement.Operation != operation || len(remaining) != 0 {
		return c, ErrInvalid
	}
	for _, o := range t.Retirement.Owners {
		if !reportComplete(o.Report) {
			return c, ErrInvalid
		}
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	t = ownTenant(t)
	t.Phase = TenantDeleted
	t.Enabled = false
	t.Revision = n.revision
	t.AllowedNodes = nil
	t.ImageSources = nil
	// Keep the stable ID, original operation/digest and signed closures. Large
	// original inventories live in the operation evidence, not the tombstone.
	t.Retirement.Targets = nil
	n.tenants[tenant] = t
	for k, m := range n.members {
		if m.Tenant == tenant {
			delete(n.members, k)
		}
	}
	return n, nil
}

func validRetirement(t Tenant) bool {
	if t.Phase == TenantActive {
		return t.Retirement == nil
	}
	if t.Phase != TenantRetiring && t.Phase != TenantDeleted || t.Retirement == nil {
		return false
	}
	r := t.Retirement
	if r.Cluster == ([32]byte{}) || !identifier(r.Operation) || r.StartedRevision == 0 || r.StartedRevision > t.Revision || r.InventoryHash == ([32]byte{}) || len(r.Owners) > 1024 || r.OwnersHash != ownerSetHash(r.Owners) {
		return false
	}
	if len(r.Owners) == 0 {
		_, _, empty, err := canonicalInventory(t.ID, nil)
		if err != nil || r.InventoryHash != empty {
			return false
		}
	}
	if t.Phase == TenantRetiring {
		if !t.Enabled {
			return false
		}
		items, owners, digest, err := canonicalInventory(t.ID, r.Targets)
		if err != nil || digest != r.InventoryHash || !slices.Equal(items, r.Targets) || len(owners) != len(r.Owners) {
			return false
		}
		for i, o := range owners {
			if o.Node != r.Owners[i].Node || o.Key != r.Owners[i].Key {
				return false
			}
		}
	} else if t.Enabled || len(t.AllowedNodes) != 0 || len(t.ImageSources) != 0 || r.Targets != nil {
		return false
	}
	for i, o := range r.Owners {
		if !identifier(o.Node) || o.Key == ([32]byte{}) || i > 0 && ownerKey(o.Node, o.Key) <= ownerKey(r.Owners[i-1].Node, r.Owners[i-1].Key) {
			return false
		}
		if o.Report != nil && !matchesReport(t.ID, *r, o, *o.Report) {
			return false
		}
		if t.Phase == TenantDeleted && !reportComplete(o.Report) {
			return false
		}
	}
	return true
}
