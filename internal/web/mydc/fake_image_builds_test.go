// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func TestImageBuildsRealContract(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	cluster := f.w.cluster
	part := func(c Conn, q control.ImageBuildQuery) control.ImageBuildPage {
		t.Helper()
		p, err := c.ImageBuilds(ctx, "shop", q, "")
		if err != nil {
			t.Fatalf("image-builds %+v: %v", q, err)
		}
		return p
	}
	contextOf := func(id string) control.ImageBuildContextView {
		t.Helper()
		p := part(bob, control.ImageBuildQuery{Part: "contexts", ID: id})
		if len(p.Contexts) != 1 {
			t.Fatalf("context %s: %+v", id, p.Contexts)
		}
		return p.Contexts[0]
	}
	versionOf := func(ctxID string, n uint64) [32]byte {
		t.Helper()
		for _, v := range part(bob, control.ImageBuildQuery{Part: "versions", ID: ctxID}).Versions {
			if v.Number == n {
				return v.ID
			}
		}
		t.Fatalf("no version %s/%d", ctxID, n)
		return [32]byte{}
	}
	jobOf := func(id string) control.ImageBuildJobView {
		t.Helper()
		p := part(bob, control.ImageBuildQuery{Part: "jobs", Job: id})
		if len(p.Jobs) != 1 {
			t.Fatalf("job %s: %+v", id, p.Jobs)
		}
		return p.Jobs[0]
	}
	begin := func(ctxID string, n uint64, id string) (control.ImageBuildJobPlan, ResultCode) {
		t.Helper()
		plan, err := alice.PlanImageBuildJob(ctx, "shop", control.ImageBuildJobQuery{ID: id, Context: ctxID, Version: versionOf(ctxID, n)})
		if err != nil {
			t.Fatalf("plan %s: %v", id, err)
		}
		_, res := submit(t, alice, ActionBeginImageBuild, 0, plan.Change, rootFor(t, alice, ActionBeginImageBuild))
		return plan, res.Code
	}

	// Policy and contexts read in the real shape and pass mydcd's checks.
	pol := part(bob, control.ImageBuildQuery{Part: "policy"})
	if len(pol.Policies) != 1 || pol.Policies[0].Spec.Validate(cluster) != nil || pol.Policies[0].Revision != 34 || pol.Policies[0].Spec.Nodes[0].Node != "node-a" {
		t.Fatalf("policy %+v", pol.Policies)
	}
	policy := pol.Policies[0].Spec
	if got := part(bob, control.ImageBuildQuery{Part: "contexts"}); len(got.Contexts) != 3 {
		t.Fatalf("contexts %+v", got.Contexts)
	}
	worker := contextOf("worker")
	if !worker.Spec.Under(policy) || worker.Spec.Arguments["APP_ENV"] != "production" || worker.Spec.Secrets[0].Secret != "mysql" || worker.NextVersion != 3 {
		t.Fatalf("worker %+v", worker)
	}
	if _, ok := worker.Spec.Arguments["NPM_TOKEN"]; ok {
		t.Fatal("a secret ARG has no place in the real spec")
	}
	if cron := contextOf("cron"); cron.Spec.Kind != "draft" {
		t.Fatalf("cron kind %q", cron.Spec.Kind)
	}
	if _, err := bob.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "versions"}, ""); err == nil {
		t.Fatal("versions without a context")
	}

	// Content: a version's tree (8 a page) and Dockerfile; ids are stable.
	v2 := versionOf("worker", 2)
	if v2 != versionOf("worker", 2) || v2 == versionOf("worker", 1) {
		t.Fatal("version ids")
	}
	tree, err := bob.BuildContextContent(ctx, "shop", imagebuild.ContentQuery{Version: v2, Part: "tree"}, "")
	if err != nil || tree.Page.Total != 3 || tree.Page.Entries[0].Path != "Dockerfile" || !tree.Page.Entries[1].Directory || tree.Next != "" {
		t.Fatalf("tree %+v %v", tree, err)
	}
	df, err := bob.BuildContextContent(ctx, "shop", imagebuild.ContentQuery{Version: v2, Part: "dockerfile"}, "")
	if err != nil || !strings.HasPrefix(string(df.Page.Data), "FROM docker.io/library/busybox") {
		t.Fatalf("dockerfile %+v %v", df, err)
	}

	// Git check.
	chk, err := bob.CheckBuildContext(ctx, "shop", control.ImageBuildSourceQuery{ID: "web"})
	if err != nil || chk.Code != "OK" || len(chk.Commit) != 40 || chk.BaseSources != 1 {
		t.Fatalf("check %+v %v", chk, err)
	}

	// Plan → begin: the spec passes JobSpec.Validate, the job finishes.
	plan, code := begin("worker", 2, "b-real")
	if code != ResultApplied {
		t.Fatalf("begin %v", code)
	}
	if err := plan.Spec.Validate(); err != nil {
		t.Fatalf("job spec: %v", err)
	}
	j := jobOf("b-real")
	if j.Phase != ImageBuildSucceeded || j.Result == nil || j.Result.Code != "OK" || j.Version != v2 || j.Number != 2 || j.Revision != 2 {
		t.Fatalf("job %+v", j)
	}
	if _, err := bob.PlanImageBuildJob(ctx, "shop", control.ImageBuildJobQuery{ID: "b-bob", Context: "worker", Version: v2}); err == nil {
		t.Fatal("bob planned a build")
	}
	// The same ID again, or a plan made stale by a context change, is refused.
	if _, res := submit(t, alice, ActionBeginImageBuild, 0, plan.Change, rootFor(t, alice, ActionBeginImageBuild)); res.Code != ResultConditionFailed {
		t.Fatalf("job id reused: %v", res.Code)
	}
	stale, err := alice.PlanImageBuildJob(ctx, "shop", control.ImageBuildJobQuery{ID: "b-stale", Context: "worker", Version: v2})
	if err != nil {
		t.Fatal(err)
	}
	put := control.ImageBuildContextPut{Spec: worker.Spec}
	put.Spec.Tags = []string{"{version}", "latest"}
	if _, res := submit(t, alice, ActionPutBuildContext, worker.Revision, put, rootFor(t, alice, ActionPutBuildContext)); res.Code != ResultApplied {
		t.Fatalf("put context %v", res.Code)
	}
	if _, res := submit(t, alice, ActionBeginImageBuild, 0, stale.Change, rootFor(t, alice, ActionBeginImageBuild)); res.Code != ResultConditionFailed {
		t.Fatalf("stale plan: %v", res.Code)
	}
	if got := contextOf("worker"); !slices.Equal(got.Spec.Tags, put.Spec.Tags) {
		t.Fatalf("put kept %+v", got.Spec)
	}

	// Logs: byte pages with the real cursor.
	var text []byte
	after := ""
	for i := 0; ; i++ {
		p, err := bob.ImageBuildLogs(ctx, "shop", imagebuild.LogQuery{Job: "b-real", MaxBytes: 16}, after)
		if err != nil || !p.ValidQuery(cluster, "shop", imagebuild.LogQuery{Job: "b-real", MaxBytes: 16}, after) || p.Page.Unclosed || p.Phase != ImageBuildSucceeded {
			t.Fatalf("logs page %d: %+v %v", i, p, err)
		}
		text = append(text, p.Page.Data...)
		if p.Page.Next == p.Page.Total {
			break
		}
		after = p.Next
	}
	if !bytes.Contains(text, []byte("pushed registry.mydc.local/shop/worker")) {
		t.Fatalf("log text %q", text)
	}
	if _, err := bob.ImageBuildLogs(ctx, "shop", imagebuild.LogQuery{Job: "b-real", MaxBytes: imagebuild.MaxLogPageBytes + 1}, ""); err == nil {
		t.Fatal("page over 24 KiB")
	}
	// Tail reads the last page in one call (no After); its Next
	// reads on without Tail.
	tq := imagebuild.LogQuery{Job: "b-real", MaxBytes: 16, Tail: true}
	tail, err := bob.ImageBuildLogs(ctx, "shop", tq, "")
	if err != nil || tail.Page.Offset != uint32(len(text))-16 || tail.Page.Next != tail.Page.Total || !bytes.Equal(tail.Page.Data, text[len(text)-16:]) || !tail.ValidQuery(cluster, "shop", tq, "") {
		t.Fatalf("tail %+v %v", tail.Page, err)
	}
	if _, err := bob.ImageBuildLogs(ctx, "shop", tq, tail.Next); err == nil {
		t.Fatal("Tail with After")
	}
	if next, err := bob.ImageBuildLogs(ctx, "shop", imagebuild.LogQuery{Job: "b-real", MaxBytes: 16}, tail.Next); err != nil || len(next.Page.Data) != 0 || next.Page.Offset != tail.Page.Total {
		t.Fatalf("after tail %+v %v", next.Page, err)
	}
	if whole, _ := bob.ImageBuildLogs(ctx, "shop", imagebuild.LogQuery{Job: "b-real", MaxBytes: imagebuild.MaxLogPageBytes, Tail: true}, ""); whole.Page.Offset != 0 || !bytes.Equal(whole.Page.Data, text) {
		t.Fatalf("short log tail %+v", whole.Page)
	}
	if _, err := bob.ImageBuildLogs(ctx, "payments", tq, ""); err == nil {
		t.Fatal("tail of another tenant")
	}

	// Held build: cancel (Expected = Revision), then delete the ended job.
	f.SetBuildHold("shop", true)
	if _, code := begin("cron", 1, "b-held"); code != ResultApplied {
		t.Fatalf("begin held %v", code)
	}
	held := jobOf("b-held")
	if held.Phase != ImageBuildRunning || held.Revision != 1 {
		t.Fatalf("held %+v", held)
	}
	if p, err := bob.ImageBuildLogs(ctx, "shop", imagebuild.LogQuery{Job: "b-held", MaxBytes: 1024}, ""); err != nil || !p.Page.Unclosed {
		t.Fatalf("running log %+v %v", p, err)
	}
	sel := control.ImageBuildSelection{Tenant: "shop", ID: "b-held"}
	if _, res := submit(t, alice, ActionDeleteImageBuildJob, held.Revision, sel, rootFor(t, alice, ActionDeleteImageBuildJob)); res.Code != ResultConditionFailed {
		t.Fatalf("delete running job: %v", res.Code)
	}
	if _, res := submit(t, alice, ActionCancelImageBuild, held.Revision, sel, rootFor(t, alice, ActionCancelImageBuild)); res.Code != ResultApplied {
		t.Fatalf("cancel %v", res.Code)
	}
	held = jobOf("b-held")
	if held.Phase != ImageBuildCancelled || !held.Cancel || held.Result.Code != "CANCELLED" {
		t.Fatalf("cancelled %+v", held)
	}
	if _, res := submit(t, alice, ActionDeleteImageBuildJob, held.Revision, sel, rootFor(t, alice, ActionDeleteImageBuildJob)); res.Code != ResultApplied {
		t.Fatalf("delete job %v", res.Code)
	}
	if !jobOf("b-held").Deleted {
		t.Fatal("deleted job row")
	}
	if _, err := bob.ImageBuildLogs(ctx, "shop", imagebuild.LogQuery{Job: "b-held", MaxBytes: 1024}, ""); err == nil {
		t.Fatal("logs of a deleted job")
	}

	// Caches: inventory rows, usage pages, prune accepted then finished.
	caches := part(bob, control.ImageBuildQuery{Part: "caches"})
	if len(caches.Caches) == 0 || caches.InventoryRoot == nil {
		t.Fatalf("caches %+v", caches)
	}
	row := caches.Caches[0]
	if !row.Valid(control.ImageBuildQuery{Part: "caches"}, true) {
		t.Fatalf("cache row %+v", row)
	}
	use, err := bob.ImageBuildCacheUsage(ctx, "shop", imagebuild.CacheQuery{Cache: &row.Cache, Node: row.Node}, "")
	if err != nil || len(use.Page.Entries) == 0 || !use.ValidQuery("shop", imagebuild.CacheQuery{Cache: &row.Cache, Node: row.Node}, "") {
		t.Fatalf("cache usage %+v %v", use, err)
	}
	if byJob, err := bob.ImageBuildCacheUsage(ctx, "shop", imagebuild.CacheQuery{Job: row.RepresentativeJob}, ""); err != nil || byJob.Page.Cache != row.Cache {
		t.Fatalf("cache by job %+v %v", byJob, err)
	}
	prune := control.ImageBuildCachePruneChange{Tenant: "shop", ID: "p-1", Node: row.Node, Cache: row.Cache, Filter: imagebuild.CachePruneFilter{Mode: "all"}}
	if _, res := submit(t, bob, ActionPruneBuildCache, 0, prune, rootFor(t, bob, ActionPruneBuildCache)); res.Code != ResultForbidden {
		t.Fatalf("bob prune %v", res.Code)
	}
	if _, res := submit(t, alice, ActionPruneBuildCache, 0, prune, rootFor(t, alice, ActionPruneBuildCache)); res.Code != ResultApplied {
		t.Fatalf("prune %v", res.Code)
	}
	pr := part(bob, control.ImageBuildQuery{Part: "cache-prunes", ID: "p-1"}).CachePrunes
	if len(pr) != 1 || pr[0].State != ImageBuildQueued || !pr[0].Valid() {
		t.Fatalf("held prune %+v", pr)
	}
	f.FinishCachePrune("shop", "p-1", "")
	pr = part(bob, control.ImageBuildQuery{Part: "cache-prunes", ID: "p-1"}).CachePrunes
	if pr[0].State != ImageBuildSucceeded || pr[0].RemovedCount == 0 || pr[0].ReportedBytes == 0 || !pr[0].Valid() {
		t.Fatalf("prune done %+v", pr)
	}

	// Policy put; a root the node does not have is refused.
	cur := part(bob, control.ImageBuildQuery{Part: "policy"}).Policies[0]
	next := control.ImageBuildPolicyPut{Spec: cur.Spec}
	next.Spec.Concurrency = 3
	if _, res := submit(t, alice, ActionSetImageBuildPolicy, cur.Revision, next, rootFor(t, alice, ActionSetImageBuildPolicy)); res.Code != ResultApplied {
		t.Fatalf("set policy %v", res.Code)
	}
	bad := control.ImageBuildPolicyPut{Spec: next.Spec.Own()}
	bad.Spec.Nodes[0].Root.Path = "/elsewhere"
	got := part(bob, control.ImageBuildQuery{Part: "policy"}).Policies[0]
	if _, res := submit(t, alice, ActionSetImageBuildPolicy, got.Revision, bad, rootFor(t, alice, ActionSetImageBuildPolicy)); res.Code != ResultInvalid {
		t.Fatalf("bad root %v", res.Code)
	}

	// A new draft context is an inline one in the fake's model.
	spec := imagebuild.ContextSpec{Tenant: "shop", ID: "api", Kind: "draft", Root: got.Spec.Nodes[0].Root, Dockerfile: "Dockerfile", Repository: "shop/api",
		Tags: []string{"{version}"}, Platforms: []string{"linux/amd64"}}
	if _, res := submit(t, alice, ActionPutBuildContext, 0, control.ImageBuildContextPut{Spec: spec}, rootFor(t, alice, ActionPutBuildContext)); res.Code != ResultApplied {
		t.Fatalf("put api %v", res.Code)
	}
	if x := f.w.build.find("shop", "api"); x == nil || x.row.Kind != BuildInline || contextOf("api").Spec.Kind != "draft" {
		t.Fatalf("api context %+v", x)
	}

	// delete-build-version: Expected = the Number; the current one stays.
	v1 := versionOf("worker", 1)
	if _, res := submit(t, alice, ActionDeleteBuildVersion, 2, control.ImageBuildVersionSelection{Tenant: "shop", ID: v2}, rootFor(t, alice, ActionDeleteBuildVersion)); res.Code != ResultConditionFailed {
		t.Fatalf("delete current version %v", res.Code)
	}
	if _, res := submit(t, alice, ActionDeleteBuildVersion, 1, control.ImageBuildVersionSelection{Tenant: "shop", ID: v1}, rootFor(t, alice, ActionDeleteBuildVersion)); res.Code != ResultApplied {
		t.Fatalf("delete version %v", res.Code)
	}
	if vs := part(bob, control.ImageBuildQuery{Part: "versions", ID: "worker"}).Versions; len(vs) != 1 || vs[0].ID != v2 {
		t.Fatalf("versions %+v", vs)
	}

	// delete-build-context (ImageBuildSelection, Expected = Revision):
	// refused while versions remain, as in mydcd.
	w := contextOf("worker")
	if _, res := submit(t, alice, ActionDeleteBuildContext, w.Revision, control.ImageBuildSelection{Tenant: "shop", ID: "worker"}, rootFor(t, alice, ActionDeleteBuildContext)); res.Code != ResultConditionFailed {
		t.Fatalf("delete context with versions %v", res.Code)
	}
	api := contextOf("api")
	if _, res := submit(t, bob, ActionDeleteBuildContext, api.Revision, control.ImageBuildSelection{Tenant: "shop", ID: "api"}, rootFor(t, bob, ActionDeleteBuildContext)); res.Code != ResultForbidden {
		t.Fatalf("bob delete context %v", res.Code)
	}
	if _, res := submit(t, alice, ActionDeleteBuildContext, api.Revision, control.ImageBuildSelection{Tenant: "shop", ID: "api"}, rootFor(t, alice, ActionDeleteBuildContext)); res.Code != ResultApplied {
		t.Fatalf("delete context %v", res.Code)
	}
	if p := part(bob, control.ImageBuildQuery{Part: "contexts", ID: "api"}); len(p.Contexts) != 0 {
		t.Fatalf("deleted context %+v", p.Contexts)
	}
}
