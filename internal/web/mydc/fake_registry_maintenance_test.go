// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

// REQ-18 in mydcd's real shape: registry-catalog pages, delete/GC through
// maintenance plan → signed action → status, prune preview → action →
// results. Every answer passes the same checks userauth.Client makes.
func TestRegistryMaintenanceReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	cluster := f.w.cluster

	catalogue := func(c Conn, q control.RegistryCatalogueQuery) []control.RegistryCatalogueResult {
		t.Helper()
		var pages []control.RegistryCatalogueResult
		after := ""
		for {
			r, err := c.RegistryCatalogue(ctx, "shop", q, after)
			if err != nil {
				t.Fatalf("catalogue %+v: %v", q, err)
			}
			if !r.ValidQuery(q, after) {
				t.Fatalf("catalogue %+v: invalid %+v", q, r)
			}
			pages = append(pages, r)
			if r.Page.Next == "" {
				return pages
			}
			after = r.Page.Next
		}
	}
	images := func(repo string) map[string]registryclient.ImageMetadata {
		t.Helper()
		out := map[string]registryclient.ImageMetadata{}
		for _, p := range catalogue(bob, control.RegistryCatalogueQuery{Kind: "managed", ID: "builtin", Repository: repo}) {
			for _, im := range p.Page.Images {
				out[im.Reference] = im
			}
		}
		return out
	}
	plan := func(q control.RegistryMaintenanceQuery) control.RegistryMaintenancePlan {
		t.Helper()
		p, err := alice.PlanRegistryMaintenance(ctx, "shop", q)
		if err != nil {
			t.Fatalf("plan %+v: %v", q, err)
		}
		change := p.Change
		change.Operation = "validation"
		if p.Schema != 1 || p.Cluster != cluster || p.Expected == 0 || p.Expected != p.Change.ExpectedRevision() || p.Epoch == 0 || p.Change.Query(q.Action) != q || p.Change.Operation != "" || !change.Valid(cluster, q.Action) {
			t.Fatalf("plan %+v: invalid %+v", q, p)
		}
		return p
	}
	run := func(action, id string, p control.RegistryMaintenancePlan) control.RegistryMaintenanceStatus {
		t.Helper()
		ch := p.Change
		ch.Operation = id
		if _, res := submit(t, alice, action, p.Expected, ch, p.RootRevision); res.Code != ResultApplied {
			t.Fatalf("%s %s: %v", action, id, res.Code)
		}
		s, err := bob.RegistryMaintenanceStatus(ctx, "shop", id)
		if err != nil || s.State != "queued" || s.Result != nil || s.Action != action || s.User != "u-alice" {
			t.Fatalf("status %s %+v %v", id, s, err)
		}
		f.FinishRegistryMaintenance()
		s, _ = bob.RegistryMaintenanceStatus(ctx, "shop", id)
		if s.Result == nil || !control.RegistryMaintenanceResultFor(s.Change, *s.Result) || (s.State == "done") != (s.Result.Code == "OK" || s.Result.Code == "ALREADY_ABSENT") {
			t.Fatalf("status %s %+v", id, s)
		}
		return s
	}

	// Catalogue: repositories, then 10 reference rows of php-shop on two pages.
	repos := catalogue(bob, control.RegistryCatalogueQuery{Kind: "managed", ID: "builtin"})
	if len(repos) != 1 || strings.Join(repos[0].Page.Repositories, ",") != "shop/php-shop,shop/worker" || !repos[0].Page.UntaggedComplete || repos[0].Page.Authority != "registry.mydc.local" {
		t.Fatalf("repositories %+v", repos)
	}
	if pages := catalogue(bob, control.RegistryCatalogueQuery{Kind: "managed", ID: "builtin", Repository: "shop/php-shop"}); len(pages) != 2 || len(pages[0].Page.Images)+len(pages[1].Page.Images) != 10 {
		t.Fatalf("php-shop pages %+v", pages)
	}
	ext := catalogue(bob, control.RegistryCatalogueQuery{Kind: "external", ID: "example"})
	if strings.Join(ext[0].Page.Repositories, ",") != "shop/cron" || !ext[0].Page.Live {
		t.Fatalf("external %+v", ext)
	}
	if _, err := bob.RegistryCatalogue(ctx, "payments", control.RegistryCatalogueQuery{Kind: "managed", ID: "builtin"}, ""); err == nil {
		t.Fatal("bob read payments")
	}

	// Delete an unused digest: accepted, queued, then done; gone from the list.
	shop := images("shop/php-shop")
	old := shop["1.4.0"]
	q := control.RegistryMaintenanceQuery{Action: "delete-registry-image", ID: "builtin", Repository: "shop/php-shop", Reference: old.Digest, Digest: old.Digest}
	if p := plan(q); p.InUse {
		t.Fatal("1.4.0 in use")
	}
	if _, err := bob.PlanRegistryMaintenance(ctx, "shop", q); err == nil {
		t.Fatal("viewer planned a delete")
	}
	if s := run("delete-registry-image", "del-old", plan(q)); s.Result.Code != "OK" || s.Result.Native == ([32]byte{}) {
		t.Fatalf("delete %+v", s.Result)
	}
	if _, ok := images("shop/php-shop")["1.4.0"]; ok {
		t.Fatal("1.4.0 still listed")
	}
	// The running digest (1.4.2 / stable) is in use; the job fails with IMAGE_IN_USE.
	live := shop["1.4.2"]
	q = control.RegistryMaintenanceQuery{Action: "delete-registry-image", ID: "builtin", Repository: "shop/php-shop", Reference: live.Digest, Digest: live.Digest}
	if p := plan(q); !p.InUse {
		t.Fatal("running digest not in use")
	}
	if s := run("delete-registry-image", "del-live", plan(q)); s.State != "failed" || s.Result.Code != "IMAGE_IN_USE" {
		t.Fatalf("delete live %+v", s)
	}

	// GC: one job per registry; a second plan while it is pending is a conflict.
	f.HoldRegistryMaintenance(true)
	gc := plan(control.RegistryMaintenanceQuery{Action: "gc-registry", ID: "builtin"})
	ch := gc.Change
	ch.Operation = "gc-1"
	if _, res := submit(t, alice, "gc-registry", gc.Expected, ch, root(t, alice)); res.Code != ResultApplied {
		t.Fatalf("gc %v", res.Code)
	}
	_, err := alice.PlanRegistryMaintenance(ctx, "shop", control.RegistryMaintenanceQuery{Action: "gc-registry", ID: "builtin"})
	wantCode(t, err, CodeConflict)
	regs, _ := bob.Registries(ctx, "shop", "")
	if m := regs.Items[0].Maintenance; m == nil || m.PendingOperation != "gc-1" {
		t.Fatalf("summary while pending %+v", m)
	}
	f.FinishRegistryMaintenance()
	s, _ := bob.RegistryMaintenanceStatus(ctx, "shop", "gc-1")
	if s.State != "done" || s.Result.ReclaimedBytes == 0 {
		t.Fatalf("gc %+v", s)
	}
	regs, _ = bob.Registries(ctx, "shop", "")
	if m := regs.Items[0].Maintenance; m == nil || m.LastGCOperation != "gc-1" || m.ReclaimedBytes != s.Result.ReclaimedBytes {
		t.Fatalf("summary after gc %+v", m)
	}

	// Prune: keep the newest tag, the running digest is retained IMAGE_IN_USE.
	cond := registryclient.PruneConditions{Repositories: []string{"shop/php-shop"}, KeepRecentPerRepository: 1, IncludeUntagged: true}
	pq := control.RegistryPruneQuery{ID: "builtin", Part: "items", Conditions: &cond}
	v, err := alice.RegistryPrune(ctx, "shop", pq, "", false)
	if err != nil || !v.ValidQuery(cluster, "shop", pq, "", false) || v.Page.Total == 0 {
		t.Fatalf("preview %+v %v", v, err)
	}
	fact := v.Plan.Change.Prune.Fact
	rq := control.RegistryPruneQuery{ID: "builtin", Part: "retained", Conditions: &cond, Fact: &fact}
	r, err := alice.RegistryPrune(ctx, "shop", rq, "", false)
	if err != nil || !r.ValidQuery(cluster, "shop", rq, "", false) {
		t.Fatalf("retained %+v %v", r, err)
	}
	inUse := false
	for _, x := range r.Page.Retained {
		inUse = inUse || x.Code == "IMAGE_IN_USE" && x.Image.Digest == live.Digest
	}
	if !inUse {
		t.Fatalf("running digest not retained: %+v", r.Page.Retained)
	}
	if _, err := bob.RegistryPrune(ctx, "shop", pq, "", false); err == nil {
		t.Fatal("viewer previewed a prune")
	}
	ch = v.Plan.Change
	ch.Operation = "prune-1"
	if _, res := submit(t, alice, ActionPruneRegistryImages, v.Plan.Expected, ch, rootFor(t, alice, ActionPruneRegistryImages)); res.Code != ResultApplied {
		t.Fatalf("prune %v", res.Code)
	}
	f.FinishRegistryMaintenance()
	s, _ = bob.RegistryMaintenanceStatus(ctx, "shop", "prune-1")
	if s.State != "done" || s.Result.Prune == nil || s.Result.Prune.Processed != fact.Items || s.Result.Prune.Deleted == 0 {
		t.Fatalf("prune status %+v %+v", s, s.Result)
	}
	resq := control.RegistryPruneQuery{Operation: "prune-1", Part: "items"}
	res, err := bob.RegistryPrune(ctx, "shop", resq, "", true)
	if err != nil || !res.ValidQuery(cluster, "shop", resq, "", true) || res.Page.Total != fact.Items {
		t.Fatalf("results %+v %v", res, err)
	}

	// External: a tag-only delete is UNSUPPORTED.
	eq := control.RegistryMaintenanceQuery{Action: "delete-registry-image", ID: "example", Repository: "shop/cron", Reference: "1.4", External: true}
	img := catalogue(bob, control.RegistryCatalogueQuery{Kind: "external", ID: "example", Repository: "shop/cron"})[0].Page.Images[0]
	eq.Digest = img.Digest
	p, err := alice.PlanRegistryMaintenance(ctx, "shop", eq)
	if err != nil || !p.InUse {
		t.Fatalf("external plan %+v %v", p, err)
	}
	ch = p.Change
	ch.Operation = "ext-1"
	if _, res := submit(t, alice, "delete-registry-image", p.Expected, ch, root(t, alice)); res.Code != ResultApplied {
		t.Fatalf("external delete %v", res.Code)
	}
	f.FinishRegistryMaintenance()
	if s, _ := bob.RegistryMaintenanceStatus(ctx, "shop", "ext-1"); s.Result == nil || s.Result.Code != "UNSUPPORTED" {
		t.Fatalf("external tag delete %+v", s)
	}
}
