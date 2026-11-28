// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// Usage keeps the original metadata dependency set even after a move, ref
// update, policy revoke or consumer's loss of connectivity. This includes
// unprotected Secret/Group sources, not just password approval gates.
type Usage struct {
	Grant Grant
	Plan  UsePlan
}

func ownGrant(g Grant) Grant { g.Use = ownUse(g.Use); g.Pins = slices.Clone(g.Pins); return g }
func ownUsePlan(p UsePlan) UsePlan {
	p.Use = ownUse(p.Use)
	p.Leaves = slices.Clone(p.Leaves)
	for i := range p.Leaves {
		p.Leaves[i] = ownLeaf(p.Leaves[i])
	}
	p.Gates = slices.Clone(p.Gates)
	p.Dependencies = slices.Clone(p.Dependencies)
	return p
}
func ownUsage(u Usage) Usage { return Usage{ownGrant(u.Grant), ownUsePlan(u.Plan)} }

// Usage returns the retained original grant, independently of current read
// authority. Snapshot/reference validation must survive policy revocation.
func (a Approvals) Usage(g Grant) (Usage, bool) {
	u, ok := a.usages[usageKey(g)]
	return ownUsage(u), ok && sameGrant(u.Grant, g)
}
func sameGrant(a, b Grant) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}
func usageKey(g Grant) string {
	key := g.Realm + "/" + g.Use.Tenant + "/" + g.Use.App + "/" + g.Use.Deployment + "/" + g.Consumer + "/" + strconv.FormatUint(g.Generation, 10)
	if g.Use.Purpose != "" {
		key = "@purpose/" + g.Use.Purpose + "/" + key
	}
	return key
}
func (a *Approvals) addUsage(g Grant, p UsePlan) error {
	leases, err := reconcile.RestoreLeases(a.usagePins)
	if err != nil {
		return err
	}
	g.Lifetime, err = leases.Acquire()
	if err != nil {
		return err
	}
	a.usagePins = leases.Checkpoint()
	a.usages[usageKey(g)] = ownUsage(Usage{g, p})
	return nil
}
func (a Approvals) LiveReferences(t Tree, id string, generation uint64) int {
	if a.cluster != t.cluster {
		return -1
	}
	count := 0
	for _, u := range a.usages {
		if u.Grant.Realm != t.tenant {
			continue
		}
		for _, d := range u.Plan.Dependencies {
			if d.ID == id && d.Generation == generation {
				count++
				break
			}
		}
	}
	return count
}

type UseGone struct {
	Purpose                                  string `json:",omitempty"`
	Cluster                                  [32]byte
	Realm, Tenant, App, Deployment, Consumer string
	Generation                               uint64
	NodeKey                                  [32]byte
	Selection                                [32]byte
	Lifetime                                 reconcile.Lease
	Stopped, MountsGone                      bool
	Signature                                []byte
}

func UseGoneBytes(p UseGone) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("sfc-secret-use-gone-1\x00"), b...)
}

// ReleaseUse atomically returns all still-held approval pins and the lifetime
// pin. Receipts are accepted from the exact original node after grant/user
// revocation. Per-approval releases already recorded remain settled.
func (a Approvals) ReleaseUse(p UseGone) (Approvals, error) {
	g := Grant{Realm: p.Realm, Consumer: p.Consumer, Generation: p.Generation, Use: Use{Purpose: p.Purpose, Tenant: p.Tenant, App: p.App, Deployment: p.Deployment}}
	u, ok := a.usages[usageKey(g)]
	if !ok || p.Cluster != a.cluster || p.NodeKey != u.Grant.Use.NodeKey || p.Selection != u.Grant.Selection || p.Lifetime != u.Grant.Lifetime || !p.Stopped || !p.MountsGone || !ed25519.Verify(ed25519.PublicKey(p.NodeKey[:]), UseGoneBytes(p), p.Signature) {
		return a, ErrPolicy
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	for _, pin := range u.Grant.Pins {
		r, ok := n.records[pin.ApprovalID]
		if !ok {
			return a, ErrPolicy
		}
		r = ownRecord(r)
		index := -1
		for i, c := range r.Consumers {
			if c.Lease == pin.Lease {
				if c.ID != u.Grant.Consumer || c.Generation != u.Grant.Generation || !sameUse(c.Use, u.Grant.Use) || c.Selection != u.Grant.Selection {
					return a, ErrPolicy
				}
				index = i
				break
			}
		}
		leases, err := reconcile.RestoreLeases(r.Leases)
		if err != nil {
			return a, err
		}
		if index >= 0 {
			if err = leases.Release(pin.Lease); err != nil {
				return a, err
			}
			r.Consumers = append(r.Consumers[:index], r.Consumers[index+1:]...)
		} else {
			for _, l := range r.Leases.Active {
				if l == pin.Lease {
					return a, ErrPolicy
				}
			}
		}
		r.Leases = leases.Checkpoint()
		n.records[pin.ApprovalID] = r
	}
	leases, err := reconcile.RestoreLeases(n.usagePins)
	if err != nil {
		return a, err
	}
	if err = leases.Release(p.Lifetime); err != nil {
		return a, err
	}
	n.usagePins = leases.Checkpoint()
	delete(n.usages, usageKey(g))
	return n, nil
}
func (a *Approvals) restoreUsages(pins reconcile.LeaseJournal, usages []Usage) error {
	leases, err := reconcile.RestoreLeases(pins)
	if err != nil || pins.Generation != 1 || pins.Capacity != maxObjects || pins.Draining || leases.Count() != len(usages) {
		return ErrPolicy
	}
	a.usagePins = pins
	for i, u := range usages {
		g := u.Grant
		if _, dup := a.usages[usageKey(g)]; dup || !validPurpose(g.Use.Purpose) || g.Lifetime != pins.Active[i] || g.Realm != "" && !identifier(g.Realm) || !identifier(g.Consumer) || g.Generation == 0 || !sameUse(g.Use, u.Plan.Use) || g.Selection != selectionHash(u.Plan) || len(g.Use.Sources) == 0 || len(g.Use.Sources) > 256 || !identifier(g.Use.Tenant) && !(g.Use.ClusterConsumer() && g.Realm == "") || !identifier(g.Use.User) || !identifier(g.Use.App) || !identifier(g.Use.Deployment) || !identifier(g.Use.Service) || !identifier(g.Use.Node) || g.Use.NodeKey == ([32]byte{}) || g.Use.RequesterKey == ([32]byte{}) || len(u.Plan.Dependencies) == 0 || len(u.Plan.Dependencies) > maxObjects || len(u.Plan.Gates) != len(g.Pins) {
			return ErrPolicy
		}
		for _, s := range g.Use.Sources {
			if !identifier(s) {
				return ErrPolicy
			}
		}
		for j, d := range u.Plan.Dependencies {
			if !identifier(d.ID) || d.Generation == 0 || d.PolicyRevision < d.Generation || j > 0 && d.ID <= u.Plan.Dependencies[j-1].ID {
				return ErrPolicy
			}
		}
		for j, pin := range g.Pins {
			r, ok := a.records[pin.ApprovalID]
			if !ok || pin.Lease.Generation != r.Leases.Generation || pin.Lease.Token == 0 || pin.Lease.Token > r.Leases.Next || r.Approval.Payload.Target.Group != u.Plan.Gates[j] {
				return ErrPolicy
			}
			for _, c := range r.Consumers {
				if c.Lease == pin.Lease && (c.ID != g.Consumer || c.Generation != g.Generation || c.Selection != g.Selection || !sameUse(c.Use, g.Use)) {
					return ErrPolicy
				}
			}
		}
		a.usages[usageKey(g)] = ownUsage(u)
	}
	for id, r := range a.records {
		for _, consumer := range r.Consumers {
			found := false
			for _, u := range a.usages {
				if u.Grant.Consumer == consumer.ID && u.Grant.Generation == consumer.Generation && sameUse(u.Grant.Use, consumer.Use) {
					for _, p := range u.Grant.Pins {
						if p.ApprovalID == id && p.Lease == consumer.Lease {
							found = true
						}
					}
				}
			}
			if !found {
				return ErrPolicy
			}
		}
	}
	return nil
}

// Retire only deletes the selectable object. Provider data destruction is a
// separate explicit operation. Its original ref/ID remains in the tombstone.
func (t Tree) Retire(c access.Catalog, actor, id string, expected uint64, a Approvals) (Tree, error) {
	allowed := c.AuthorizeCleanup(actor, t.tenant, access.ManageSecrets) == nil
	if t.tenant == "" {
		allowed = c.SystemAllowed(actor)
	}
	if !allowed {
		return t, access.ErrDenied
	}
	o, ok := t.objects[id]
	if !ok || o.Revision != expected {
		return t, access.ErrConflict
	}
	if o.Status != Revoking || id == t.root || len(o.Entries) > 0 || o.PendingWrite != "" || o.PasswordChange != "" || a.LiveReferences(t, id, o.Generation) != 0 {
		return t, ErrPolicy
	}
	for _, w := range t.writes {
		if w.Request.Object == id && !writeTerminal(w) {
			return t, reconcile.ErrPending
		}
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	o = ownObject(o)
	o.Status = Retired
	o.Revision = n.revision
	o.PolicyRevision = n.revision
	n.objects[id] = o
	parent := ownObject(n.objects[o.Parent])
	index := slices.Index(parent.Entries, id)
	if index < 0 {
		return t, ErrPolicy
	}
	parent.Entries = append(parent.Entries[:index], parent.Entries[index+1:]...)
	parent.Revision = n.revision
	n.objects[parent.ID] = parent
	return n, nil
}
