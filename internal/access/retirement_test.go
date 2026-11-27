// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func retireCatalog(t *testing.T) Catalog {
	t.Helper()
	c := enrolled(t)
	c = put(t, c, "admin", user("alice", false))
	c = put(t, c, "admin", user("viewer", false))
	for _, id := range []string{"first", "second"} {
		c = tenant(t, c, id)
		c = member(t, c, id, "alice", Manager, true)
	}
	return member(t, c, "first", "viewer", Viewer, true)
}
func retireTargets() []RetirementTarget {
	a, _ := signingKey(20)
	b, _ := signingKey(21)
	return []RetirementTarget{{Tenant: "first", Kind: "volume", ID: "mysql", Node: "old-node", Owner: a, Generation: 7, Retain: true}, {Tenant: "first", Kind: "operation", ID: "create", Node: "other-node", Owner: b, Generation: 9, Operation: "original-op"}}
}
func beginRetire(t *testing.T, c Catalog, targets []RetirementTarget) Catalog {
	t.Helper()
	v, _ := c.Tenant("first")
	n, err := c.BeginTenantRetirement("admin", "first", "retire", key(1), v.Revision, targets)
	return must(t, n, err)
}
func progress(c Catalog, node string, sequence uint64) TenantReport {
	v, _ := c.Tenant("first")
	r := v.Retirement
	var owner RetirementOwner
	for _, o := range r.Owners {
		if o.Node == node {
			owner = o
		}
	}
	return TenantReport{Cluster: r.Cluster, Tenant: "first", Operation: r.Operation, Node: owner.Node, Owner: owner.Key, StartedRevision: r.StartedRevision, Sequence: sequence, InventoryHash: r.InventoryHash, OwnersHash: r.OwnersHash, Quiesced: true}
}
func signProgress(p TenantReport) TenantReport {
	_, k := signingKey(20)
	if p.Node == "other-node" {
		_, k = signingKey(21)
	}
	p.Signature = ed25519.Sign(k, TenantReportBytes(p))
	return p
}
func observeProgress(t *testing.T, c Catalog, p TenantReport) Catalog {
	t.Helper()
	n, err := c.ObserveTenantRetirement(signProgress(p))
	return must(t, n, err)
}
func finishRetire(t *testing.T, c Catalog) Catalog {
	t.Helper()
	v, _ := c.Tenant("first")
	n, err := c.FinishTenantRetirement("admin", "first", "retire", v.Revision, nil)
	return must(t, n, err)
}
func catalogBytes(t *testing.T, c Catalog) []byte {
	t.Helper()
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTenantRetirementClosesAdmissionPreservesReadCleanupAndScopes(t *testing.T) {
	c := retireCatalog(t)
	v, _ := c.Tenant("first")
	if _, err := c.BeginTenantRetirement("alice", "first", "retire", key(1), v.Revision, retireTargets()); err != ErrDenied {
		t.Fatal("manager deleted global tenant", err)
	}
	original := catalogBytes(t, c)
	c = beginRetire(t, c, retireTargets())
	if bytes.Equal(original, catalogBytes(t, c)) {
		t.Fatal("retirement did not close admission")
	}
	for _, actor := range []string{"admin", "alice"} {
		for _, a := range []Action{ManageNetwork, Deploy, ManageSecrets, ManageVolumes, ManageRoutes, ManageServices, ManageCD, ManageRegistry, ManageTrust, ManageMembers} {
			if c.Authorize(actor, "first", a, "") == nil {
				t.Fatal("new operation allowed", actor, a)
			}
		}
	}
	if c.Authorize("alice", "first", Read, "") != nil || c.AuthorizeCleanup("alice", "first", ManageVolumes) != nil || c.AuthorizeCleanup("viewer", "first", ManageVolumes) == nil || c.Authorize("alice", "second", Deploy, "") != nil {
		t.Fatal("read/cleanup/tenant scope")
	}
	v, _ = c.Tenant("first")
	if _, err := c.SetNodes("admin", "first", v.Revision, []string{"new-node"}); err != ErrDenied {
		t.Fatal("grant changed while retiring", err)
	}
	if _, err := c.ChangeTrust("admin", "first", v.Revision, nil, v.ImageSources); err != ErrDenied {
		t.Fatal("new trust granted", err)
	}
	if _, err := c.SetMembership("admin", 0, Membership{Tenant: "first", User: "viewer", Role: Manager, Enabled: true}); err != ErrDenied {
		t.Fatal("role elevated during retirement", err)
	}
	s, issuer, _ := signedSession(c, "alice", "key", []Scope{{Tenant: "first", Actions: []Action{Deploy, Read}}, {Tenant: "second", Actions: []Action{Deploy}}})
	if c.AuthorizeSession(s, key(1), issuer, 120, "first", Deploy, "") == nil || c.AuthorizeSessionCleanup(s, key(1), issuer, 120, "first", Deploy) != nil {
		t.Fatal("session cleanup bypass or no cleanup")
	}
	s.Scopes = []Scope{{Tenant: "first", Actions: []Action{Read}}}
	s = resign(s)
	if c.AuthorizeSessionCleanup(s, key(1), issuer, 120, "first", Deploy) == nil {
		t.Fatal("cleanup escaped token scope")
	}
	m, _ := c.Membership("first", "alice")
	expected := m.Revision
	m.Revision = 0
	m.Enabled = false
	n, err := c.SetMembership("admin", expected, m)
	c = must(t, n, err)
	if c.AuthorizeCleanup("alice", "first", ManageVolumes) == nil {
		t.Fatal("revoked manager still cleans")
	}
	c = observeProgress(t, c, progress(c, "old-node", 1))
	if c.tenants["first"].Retirement.Owners[0].Report == nil {
		t.Fatal("owner report needed revoked user")
	}
}

func TestTenantRetirementPositiveCountersAndAbsentOwnersBlockFinish(t *testing.T) {
	c := beginRetire(t, retireCatalog(t), retireTargets())
	mutations := []func(*TenantReport){func(p *TenantReport) { p.PendingResources = 1 }, func(p *TenantReport) { p.PendingOperations = 1 }, func(p *TenantReport) { p.PendingWriters = 1 }, func(p *TenantReport) { p.PendingFlows = 1 }, func(p *TenantReport) { p.PendingPins = 1 }, func(p *TenantReport) { p.RetainedData = 1 }, func(p *TenantReport) { p.Quiesced = false }}
	for i, mutate := range mutations {
		p := progress(c, "old-node", uint64(i+1))
		mutate(&p)
		c = observeProgress(t, c, p)
		v, _ := c.Tenant("first")
		if _, err := c.FinishTenantRetirement("admin", "first", "retire", v.Revision, nil); err == nil {
			t.Fatal("positive/missing evidence finished", i)
		}
	}
	c = observeProgress(t, c, progress(c, "old-node", 8))
	v, _ := c.Tenant("first")
	if _, err := c.FinishTenantRetirement("admin", "first", "retire", v.Revision, nil); err == nil {
		t.Fatal("missing second owner ignored")
	}
	c = observeProgress(t, c, progress(c, "other-node", 1))
	v, _ = c.Tenant("first")
	if _, err := c.FinishTenantRetirement("admin", "first", "retire", v.Revision, retireTargets()[:1]); err == nil {
		t.Fatal("shared control inventory ignored")
	}
	if v.Phase != TenantRetiring || len(v.Retirement.Targets) != 2 || !v.Retirement.Targets[1].Retain && !v.Retirement.Targets[0].Retain {
		t.Fatal("original retained inventory lost")
	}
}

func TestTenantRetirementProofBindingAndMonotonicSequence(t *testing.T) {
	c := beginRetire(t, retireCatalog(t), retireTargets())
	before := catalogBytes(t, c)
	for _, mutate := range []func(*TenantReport){func(p *TenantReport) { p.Cluster = key(8) }, func(p *TenantReport) { p.Tenant = "second" }, func(p *TenantReport) { p.Operation = "other" }, func(p *TenantReport) { p.Node = "unknown" }, func(p *TenantReport) { p.Owner = key(3) }, func(p *TenantReport) { p.StartedRevision-- }, func(p *TenantReport) { p.InventoryHash = key(7) }, func(p *TenantReport) { p.OwnersHash = key(7) }, func(p *TenantReport) { p.Sequence = 0 }} {
		p := progress(c, "old-node", 1)
		mutate(&p)
		p = signProgress(p)
		n, err := c.ObserveTenantRetirement(p)
		if err == nil || !bytes.Equal(before, catalogBytes(t, n)) {
			t.Fatal("invalid report changed original", p)
		}
	}
	p := progress(c, "old-node", 2)
	p.PendingOperations = 1
	c = observeProgress(t, c, p)
	if _, err := c.ObserveTenantRetirement(signProgress(progress(c, "old-node", 1))); err != ErrConflict {
		t.Fatal("old progress rewound state", err)
	}
	p = progress(c, "old-node", 2)
	if _, err := c.ObserveTenantRetirement(signProgress(p)); err != ErrConflict {
		t.Fatal("same sequence changed facts", err)
	}
	p = signProgress(progress(c, "old-node", 3))
	n, err := c.ObserveTenantRetirement(p)
	c = must(t, n, err)
	n, err = c.ObserveTenantRetirement(p)
	if err != nil || n.Revision() != c.Revision() {
		t.Fatal("duplicate receipt not idempotent", err)
	}
	p = progress(c, "old-node", 4)
	p.PendingOperations = 1
	if _, err := c.ObserveTenantRetirement(signProgress(p)); err != ErrConflict {
		t.Fatal("closed dispatcher reopened", err)
	}
}

func TestTenantRetirementTombstoneKeepsOtherTenantSessionsAndRejectsReuse(t *testing.T) {
	c := retireCatalog(t)
	s, issuer, _ := signedSession(c, "alice", "key", []Scope{{Tenant: "first", Actions: []Action{Read, Deploy}}, {Tenant: "second", Actions: []Action{Read, Deploy}}})
	c = beginRetire(t, c, retireTargets())
	for _, node := range []string{"old-node", "other-node"} {
		c = observeProgress(t, c, progress(c, node, 1))
	}
	c = finishRetire(t, c)
	v, _ := c.Tenant("first")
	if v.Phase != TenantDeleted || v.Enabled || v.Retirement.Targets != nil || len(v.Retirement.Owners) != 2 || len(v.AllowedNodes)+len(v.ImageSources) != 0 {
		t.Fatal("invalid tombstone")
	}
	if _, exists := c.Membership("first", "alice"); exists {
		t.Fatal("old membership survived")
	}
	if _, exists := c.Membership("second", "alice"); !exists {
		t.Fatal("other membership deleted")
	}
	if c.AuthorizeSession(s, key(1), issuer, 120, "first", Read, "") == nil || c.AuthorizeSession(s, key(1), issuer, 120, "second", Deploy, "") != nil {
		t.Fatal("session tenant isolation")
	}
	if _, err := c.CreateTenant("admin", "first", 0); err != ErrConflict {
		t.Fatal("stable ID reused", err)
	}
	n, err := c.CreateTenant("admin", "first-new", 0)
	c = must(t, n, err)
	fresh, _ := c.Tenant("first-new")
	if len(fresh.ImageSources) != 1 || fresh.ImageSources[0].Registry != "docker.io" || c.Authorize("alice", "first-new", Read, "") == nil {
		t.Fatal("new tenant inherited policy")
	}
	restored, err := Decode(catalogBytes(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restored.ObserveTenantRetirement(signProgress(progress(c, "old-node", 2))); err != ErrConflict {
		t.Fatal("deleted tenant accepted report", err)
	}
}

func TestTenantRetirementSnapshotOwnsAndRejectsForgedCompletion(t *testing.T) {
	c := beginRetire(t, retireCatalog(t), retireTargets())
	p := progress(c, "old-node", 1)
	p.RetainedData = 1
	c = observeProgress(t, c, p)
	b := catalogBytes(t, c)
	restored, err := Decode(b)
	if err != nil || !bytes.Equal(b, catalogBytes(t, restored)) {
		t.Fatal("pending snapshot", err)
	}
	v, _ := c.Tenant("first")
	v.Retirement.Targets[0].Operation = "evil"
	v.Retirement.Owners[0].Report.Signature[0] ^= 1
	if !bytes.Equal(b, catalogBytes(t, c)) {
		t.Fatal("getter alias")
	}
	for _, mutate := range []func(*Tenant){func(v *Tenant) { v.Retirement.Targets[0].Generation++ }, func(v *Tenant) { v.Retirement.Owners[0].Report.Signature[0] ^= 1 }, func(v *Tenant) {
		v.Phase = TenantDeleted
		v.Enabled = false
		v.ImageSources = nil
		v.AllowedNodes = nil
		v.Retirement.Targets = nil
	}} {
		var s catalogRecord
		json.Unmarshal(b, &s)
		for i := range s.Tenants {
			if s.Tenants[i].ID == "first" {
				mutate(&s.Tenants[i])
			}
		}
		bad, _ := json.Marshal(s)
		if _, err = Decode(bad); err == nil {
			t.Fatal("forged retirement snapshot")
		}
	}
	c = observeProgress(t, c, progress(c, "old-node", 2))
	c = observeProgress(t, c, progress(c, "other-node", 1))
	c = finishRetire(t, c)
	var s catalogRecord
	json.Unmarshal(catalogBytes(t, c), &s)
	for i := range s.Tenants {
		if s.Tenants[i].ID == "first" {
			r := s.Tenants[i].Retirement
			r.Owners = r.Owners[:1]
			r.OwnersHash = ownerSetHash(r.Owners)
		}
	}
	bad, _ := json.Marshal(s)
	if _, err = Decode(bad); err == nil {
		t.Fatal("removed required owner from tombstone")
	}
}

func TestTenantRetirementCanonicalInventoryAndEmptyTenant(t *testing.T) {
	c := retireCatalog(t)
	targets := retireTargets()
	a := beginRetire(t, c, targets)
	targets[0], targets[1] = targets[1], targets[0]
	b := beginRetire(t, c, targets)
	if !bytes.Equal(catalogBytes(t, a), catalogBytes(t, b)) {
		t.Fatal("inventory order changed state")
	}
	v, _ := c.Tenant("first")
	bad := retireTargets()
	bad = append(bad, bad[0])
	bad[2].Retain = !bad[0].Retain
	if _, err := c.BeginTenantRetirement("admin", "first", "retire", key(1), v.Revision, bad); err != ErrInvalid {
		t.Fatal("duplicate target identity", err)
	}
	bad = retireTargets()
	bad[0].Tenant = "second"
	if _, err := c.BeginTenantRetirement("admin", "first", "retire", key(1), v.Revision, bad); err != ErrInvalid {
		t.Fatal("foreign target accepted", err)
	}
	empty := beginRetire(t, c, nil)
	empty = finishRetire(t, empty)
	if _, err := Decode(catalogBytes(t, empty)); err != nil {
		t.Fatal("empty tenant closure", err)
	}
}
