// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// an incident-response account with a key from the admin, an
// action allow list, key-only, and reason metadata.
func TestAccountScope(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	cred := Credential{ID: "key-1", Method: MethodPrivateKey, PublicKey: pub32(key), Enabled: true}
	if _, res := submit(t, admin, ActionPutUser, 0, User{ID: "u-autofix", Username: "mydc-autofix", Enabled: true, Credentials: []Credential{cred}}, rootFor(t, admin, ActionPutUser)); res.Code != ResultApplied {
		t.Fatalf("put-user %+v", res)
	}
	tr, _ := fc(admin).imageTrust(ctx, "shop")
	if _, res := submit(t, admin, ActionSetMembership, tr.Revision, access.Membership{Tenant: "shop", User: "u-autofix", Role: RoleManager, Enabled: true}, rootFor(t, admin, ActionSetMembership)); res.Code != ResultApplied {
		t.Fatalf("membership %+v", res)
	}
	before, _ := admin.AccountScope(ctx, "u-autofix")
	if _, res := submit(t, admin, ActionSetAccountScope, before.Revision, AccountScopeChange{User: "u-autofix", Operations: []string{ActionRestartTask}, KeyOnly: true}, rootFor(t, admin, ActionSetAccountScope)); res.Code != ResultApplied {
		t.Fatalf("scope %+v", res)
	}
	sc, err := admin.AccountScope(ctx, "u-autofix")
	if err != nil || !sc.KeyOnly || !slices.Equal(sc.Actions, []string{ActionRestartTask}) || sc.Revision == 0 {
		t.Fatalf("scope read %+v %v", sc, err)
	}

	bot, err := keyLogin(t, f, "mydc-autofix", key)
	if err != nil {
		t.Fatal(err)
	}
	worker := ContainerSelection{App: "shop-worker", Service: "worker", Instance: "1"}
	rs, rev := restartChange(t, bot, "shop", worker, "fix-1")
	ch := Change{Action: ActionRestartTask, Expected: rev, Payload: mustPayload(t, rs)}
	op, err := bot.PrepareReason(ctx, ch, rootFor(t, bot, ActionRestartTask), OperationReason{Reason: "autofix", Incident: "inc-7"})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := bot.Submit(ctx, op); err != nil || res.Code != ResultApplied {
		t.Fatalf("restart %+v %v", res, err)
	}
	j := f.Journal()
	last := j[len(j)-1]
	if last.Reason == nil || last.Reason.Incident != "inc-7" {
		t.Fatalf("journal %+v", last)
	}
	if r, ok, err := SignedReason(op); err != nil || !ok || r.Reason != "autofix" {
		t.Fatalf("reason %+v %v %v", r, ok, err)
	}
	// Outside the allow list: forbidden although the role allows it.
	if _, res := submit(t, bot, ActionDownApp, rev+1, map[string]string{"Tenant": "shop", "App": "shop-worker"}, rootFor(t, bot, ActionDownApp)); res.Code != ResultForbidden {
		t.Fatalf("down-app %+v", res)
	}
	// Key-only: no password login, none can be added or issued.
	conn, _ := f.Dial(ctx)
	if _, err := conn.CredentialChallenge(ctx, "mydc-autofix", MethodPassword, ""); err == nil {
		t.Fatal("password challenge")
	}
	rec, _ := admin.UserCredentials(ctx, "mydc-autofix")
	pw := append(slices.Clone(rec.Credentials), Credential{ID: "password", Method: MethodPassword, VerifierRef: "vault:users/u-autofix", Enabled: true})
	// put-user replaces the whole record, so the edit starts from the current
	// one (AutomationOnly and Operations included), as in mydcd.
	withPW := rec
	withPW.Revision, withPW.Credentials = 0, pw
	if _, res := submit(t, admin, ActionPutUser, rec.Revision, withPW, rootFor(t, admin, ActionPutUser)); res.Code != ResultInvalid {
		t.Fatalf("password on key-only %+v", res)
	}
	// The admin turns the key off: every request is refused.
	off := slices.Clone(rec.Credentials)
	off[0].Enabled = false
	keyOff := rec
	keyOff.Revision, keyOff.Credentials = 0, off
	if _, res := submit(t, admin, ActionPutUser, rec.Revision, keyOff, rootFor(t, admin, ActionPutUser)); res.Code != ResultApplied {
		t.Fatalf("disable key %+v", res)
	}
	if _, err := keyLogin(t, f, "mydc-autofix", key); err == nil {
		t.Fatal("login after disable")
	}
	var e *Error
	if _, err := bot.PrepareReason(ctx, ch, 0, OperationReason{Reason: strings.Repeat("x", 513)}); !errors.As(err, &e) || e.Code != CodeInvalid {
		t.Fatalf("long reason %v", err)
	}
}

// cordon, tunnel reconnect, node image prune, CD version kind.
func TestIncidentNodeActions(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	member := func(id string) liveMember { return liveMemberOf(t, admin, id) }

	// Cordon node-a: php-shop web stays; a new service there is refused.
	if _, res := submit(t, alice, ActionCordonNode, member("node-a").Revision, NodeCordon{ID: "node-a"}, rootFor(t, alice, ActionCordonNode)); res.Code != ResultForbidden {
		t.Fatalf("cordon by manager %+v", res)
	}
	if _, res := submit(t, admin, ActionCordonNode, member("node-a").Revision, NodeCordon{ID: "node-a", Reason: "디스크 경보"}, rootFor(t, admin, ActionCordonNode)); res.Code != ResultApplied {
		t.Fatalf("cordon %+v", res)
	}
	if m := member("node-a"); !m.Scheduling.Enabled || m.Scheduling.Revision != m.Revision || m.Scheduling.CordonedBy != "admin" || m.Scheduling.CordonedAt == "" || m.Scheduling.Reason != "디스크 경보" {
		t.Fatalf("member %+v", m)
	}
	if ns, _ := admin.NodeSummary(ctx, "", "", ""); !slices.ContainsFunc(ns.Nodes, func(s NodeSummaryView) bool {
		return s.Node == "node-a" && s.CordonedBy == "admin" && s.CordonedAt != "" && s.Scheduling.Enabled
	}) {
		t.Fatalf("node-summary %+v", ns)
	}
	plan := func(doc string) error {
		_, err := alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: []byte(doc), Project: "php-shop"})
		return err
	}
	if err := plan(phpShopYAML); err != nil {
		t.Fatalf("existing placement %v", err)
	}
	var e *Error
	if err := plan(strings.Replace(phpShopYAML, "      node: node-b\n", "      node: node-a\n", 1)); !errors.As(err, &e) || e.InputCode != InputNodeCordoned {
		t.Fatalf("new placement %v", err)
	}
	tasks, _ := alice.Tasks(ctx, TaskFilter{Tenant: "shop", Node: "node-a"}, "")
	if len(tasks.Items) == 0 {
		t.Fatal("tasks on node-a were touched")
	}
	if _, res := submit(t, admin, ActionUncordonNode, member("node-a").Revision, control.NodeSelection{ID: "node-a"}, rootFor(t, admin, ActionUncordonNode)); res.Code != ResultApplied {
		t.Fatalf("uncordon %+v", res)
	}
	if err := plan(strings.Replace(phpShopYAML, "      node: node-b\n", "      node: node-a\n", 1)); err != nil {
		t.Fatalf("after uncordon %v", err)
	}
	if m := member("node-a"); m.Scheduling.Enabled || m.Scheduling.CordonedBy != "" || m.Scheduling.CordonedAt != "" || m.Scheduling.Reason != "" {
		t.Fatalf("uncordoned member %+v", m)
	}

	// Image prune: plan first, a changed cache fails the old plan.
	if _, err := alice.ImageCachePlan(ctx, ImageCacheQuery{Node: "node-a"}); err == nil {
		t.Fatal("image cache plan by manager")
	}
	f.AddNodeImage("node-a", "registry.mydc.local/shop/php-shop:1.4.2", 30<<20) // web runs it on node-a
	p, err := admin.ImageCachePlan(ctx, ImageCacheQuery{Node: "node-a"})
	if err != nil || len(p.Images) != 3 || !p.Valid() {
		t.Fatalf("plan %+v %v", p, err)
	}
	var unused []string
	for _, img := range p.Images {
		inUse := slices.ContainsFunc(img.Aliases, func(a string) bool { return strings.Contains(a, "php-shop:1.4.2") })
		if inUse != (img.Containers > 0) {
			t.Fatalf("containers %+v", img)
		}
		if img.Unused() {
			unused = append(unused, img.ID)
		}
	}
	if len(unused) != 2 {
		t.Fatalf("unused %v in %+v", unused, p.Images)
	}
	sel, err := admin.ImageCachePlan(ctx, ImageCacheQuery{Node: "node-a", Images: unused})
	if err != nil || !sel.DeleteReady() {
		t.Fatalf("selection %+v %v", sel, err)
	}
	if _, res := submit(t, admin, ActionPruneNodeImages, 0, ImageCacheChange{Operation: "cache-1", Plan: sel}, rootFor(t, admin, ActionPruneNodeImages)); res.Code != ResultApplied {
		t.Fatalf("prune %+v", res)
	}
	if st, err := admin.ImageCacheStatus(ctx, "cache-1"); err != nil || st.State != "done" || len(st.Parts) != 2 || st.Parts[0].State != "removed" {
		t.Fatalf("status %+v %v", st, err)
	}
	// The same operation again, or a selection whose images are gone, fails.
	if _, res := submit(t, admin, ActionPruneNodeImages, 0, ImageCacheChange{Operation: "cache-2", Plan: sel}, rootFor(t, admin, ActionPruneNodeImages)); res.Code != ResultConditionFailed {
		t.Fatalf("stale selection %+v", res)
	}
	if _, err := admin.ImageCacheStatus(ctx, "cache-2"); err == nil {
		t.Fatal("status of a refused prune")
	}
	if p, _ := admin.ImageCachePlan(ctx, ImageCacheQuery{Node: "node-a"}); len(p.Images) != 1 {
		t.Fatalf("after prune %+v", p)
	}

	// A CD sync is an app version of Kind "cd".
	apps, _ := alice.Apps(ctx, "shop", "")
	for _, a := range apps.Items {
		if a.App != "php-shop" {
			continue
		}
		c := a.CD
		_, res := submit(t, alice, ActionSyncApp, c.Revision, map[string]any{"Tenant": "shop", "App": "php-shop", "Target": c.Target,
			"Choice": map[string]any{"Operation": "cd-1", "Candidate": c.CandidateDigest, "Registration": c.Registration}}, root(t, alice))
		if res.Code != ResultApplied {
			t.Fatalf("sync %+v", res)
		}
	}
	revs, err := alice.AppRevisions(ctx, "shop", "php-shop", "")
	if err != nil {
		t.Fatal(err)
	}
	if last := revs.Items[len(revs.Items)-1]; last.Kind != "cd" || last.Operation != "cd-1" || last.AcceptedAt == 0 {
		t.Fatalf("revisions %+v", revs.Items)
	}
}
