// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
)

// REQ-29 parts in mydcd's shape: the management Target, pin/remove with
// control.StandaloneChange, stop/start/restart through task-restart-plan.
func TestStandaloneReal(t *testing.T) {
	f, clk := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	get := func(name string) StandaloneView {
		t.Helper()
		v, err := alice.Standalone(ctx, "shop", name)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	// The Target does not move with connection samples or time.
	v := get("alice-debug")
	if v.Target == ([32]byte{}) {
		t.Fatal("no Target")
	}
	clk.add(10 * time.Second)
	if get("alice-debug").Target != v.Target {
		t.Fatal("Target moved without a change")
	}

	// pin with an old Target is ConditionFailed; with the current one it applies.
	old := [32]byte{1}
	pin := control.StandaloneChange{Tenant: "shop", Name: "alice-debug", NewName: "maint", Restart: "on-failure", Operation: "keep-debug", Target: &old}
	if _, res := submit(t, alice, ActionStandalonePin, v.Revision, pin, rootFor(t, alice, ActionStandalonePin)); res.Code != ResultConditionFailed {
		t.Fatalf("old Target %v", res.Code)
	}
	pin.Target = &v.Target
	if _, res := submit(t, alice, ActionStandalonePin, v.Revision, pin, rootFor(t, alice, ActionStandalonePin)); res.Code != ResultApplied {
		t.Fatalf("pin %v", res.Code)
	}
	m := get("maint")
	if m.Lifetime != LifetimeFixed || m.Target == v.Target {
		t.Fatalf("after pin %+v", m)
	}

	// stop/start/restart through the plan.
	control_ := func(action, operation string) Result {
		t.Helper()
		p, err := alice.TaskRestartPlan(ctx, "shop", control.TaskRestartQuery{Action: action, Selection: containerops.Selection{Standalone: "maint"}})
		if err != nil {
			t.Fatalf("plan %s %v", action, err)
		}
		if p.ManagementTarget == nil || *p.ManagementTarget != get("maint").Target || p.StandaloneRevision != get("maint").Revision || p.Container.Standalone != "maint" {
			t.Fatalf("plan %+v", p)
		}
		ch := control.TaskRestartChange{Tenant: "shop", Standalone: "maint", Operation: operation, Target: p.Target, ManagementTarget: p.ManagementTarget}
		ch.Selection.Service, ch.Selection.Instance = p.Container.Service, p.Container.Instance
		_, res := submit(t, alice, action, p.StandaloneRevision, ch, rootFor(t, alice, action))
		return res
	}
	_, err := alice.TaskRestartPlan(ctx, "shop", control.TaskRestartQuery{Action: ActionStandaloneStart, Selection: containerops.Selection{Standalone: "maint"}})
	wantCode(t, err, CodeInvalid) // already running
	if res := control_(ActionStandaloneStop, "stop-maint"); res.Code != ResultApplied {
		t.Fatalf("stop %v", res.Code)
	}
	if s := get("maint"); s.State != "exited" {
		t.Fatalf("after stop %+v", s)
	}
	st, err := alice.TaskRestartStatus(ctx, "shop", control.TaskRestartQuery{Selection: containerops.Selection{Standalone: "maint"}, Operation: "stop-maint"})
	if err != nil || st.Status != "completed" || st.User != "u-alice" || st.Plan.Action != "stop" {
		t.Fatalf("status %+v %v", st, err)
	}
	if res := control_(ActionStandaloneStart, "start-maint"); res.Code != ResultApplied || get("maint").State != "running" {
		t.Fatalf("start %v", res.Code)
	}
	// A plan read before another change no longer matches.
	p, _ := alice.TaskRestartPlan(ctx, "shop", control.TaskRestartQuery{Action: ActionStandaloneRestart, Selection: containerops.Selection{Standalone: "maint"}})
	if res := control_(ActionStandaloneRestart, "restart-1"); res.Code != ResultApplied {
		t.Fatalf("restart %v", res.Code)
	}
	stale := control.TaskRestartChange{Tenant: "shop", Standalone: "maint", Operation: "restart-2", Target: p.Target, ManagementTarget: p.ManagementTarget}
	if _, res := submit(t, alice, ActionStandaloneRestart, get("maint").Revision, stale, rootFor(t, alice, ActionStandaloneRestart)); res.Code != ResultConditionFailed {
		t.Fatalf("stale plan %v", res.Code)
	}
	_, err = alice.TaskRestartStatus(ctx, "shop", control.TaskRestartQuery{Selection: containerops.Selection{Standalone: "maint"}, Operation: "none"})
	wantCode(t, err, CodeMissing)

	// remove with the current Target.
	m = get("maint")
	rm := control.StandaloneChange{Tenant: "shop", Name: "maint", Operation: "remove-maint", Target: &m.Target}
	if _, res := submit(t, alice, ActionStandaloneRemove, m.Revision, rm, rootFor(t, alice, ActionStandaloneRemove)); res.Code != ResultApplied || get("maint").State != "removed" {
		t.Fatalf("remove %v", res.Code)
	}
}

// The plan reports VOLUME_WRITER_CONFLICT: writing beside another task, or
// reading beside another writer; readers share.
func TestStandaloneVolumeWriterConflict(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	writer := "name: w1\nlifetime: fixed\nmode: entrypoint\nimage: busybox:1.36\nnetworks: [shop-net]\nvolumes: [\"uploads:/data\"]\nx-mydc: {node: node-a}\n"
	if res := standaloneUp(t, alice, "shop", writer, 0); res.Code != ResultApplied {
		t.Fatalf("w1 %v", res.Code)
	}
	code := func(doc string) string {
		t.Helper()
		p, err := standalonePlan(t, alice, "shop", doc)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range p.Impact {
			if im.Kind == "volume" {
				return im.Code
			}
		}
		return "-"
	}
	reader := "name: r1\nlifetime: fixed\nmode: entrypoint\nimage: busybox:1.36\nnetworks: [shop-net]\nvolumes: [\"uploads:/data:ro\"]\nx-mydc: {node: node-a}\n"
	if c := code(reader); c != VolumeWriterConflict {
		t.Fatalf("reader beside a writer %q", c)
	}
	if c := code(writer); c != "" {
		t.Fatalf("w1 again (itself) %q", c)
	}
	if c := code("name: w2\nlifetime: fixed\nmode: entrypoint\nimage: busybox:1.36\nnetworks: [shop-net]\nvolumes: [\"uploads:/data\"]\nx-mydc: {node: node-a}\n"); c != VolumeWriterConflict {
		t.Fatalf("second writer %q", c)
	}
}

// restart-task of an app Task through the same plan/status.
func TestRestartTaskReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	sel := containerops.Selection{App: "shop-worker", Service: "worker", Instance: "1"}
	p, err := alice.TaskRestartPlan(ctx, "shop", control.TaskRestartQuery{Selection: sel})
	if err != nil || p.App != "shop-worker" || p.Container.Service != "worker" || p.InventoryRevision == 0 {
		t.Fatalf("plan %+v %v", p, err)
	}
	ch := control.TaskRestartChange{Tenant: "shop", App: "shop-worker", Operation: "restart-w1", Target: p.Target}
	ch.Selection.Service, ch.Selection.Instance = "worker", "1"
	bad := ch
	bad.Target = [32]byte{9}
	if _, res := submit(t, alice, ActionRestartTask, p.InventoryRevision, bad, rootFor(t, alice, ActionRestartTask)); res.Code != ResultConditionFailed {
		t.Fatalf("wrong Target %v", res.Code)
	}
	if _, res := submit(t, alice, ActionRestartTask, p.InventoryRevision, ch, rootFor(t, alice, ActionRestartTask)); res.Code != ResultApplied {
		t.Fatalf("restart %v", res.Code)
	}
	st, err := alice.TaskRestartStatus(ctx, "shop", control.TaskRestartQuery{Selection: containerops.Selection{App: "shop-worker"}, Operation: "restart-w1"})
	if err != nil || st.Status != "completed" || st.Plan.Target != p.Target {
		t.Fatalf("status %+v %v", st, err)
	}
	if op, err := alice.AppOperation(ctx, "shop", "shop-worker", "restart-w1"); err != nil || op.Status != "succeeded" {
		t.Fatalf("app operation %+v %v", op, err)
	}
	// The old plan no longer matches after the restart.
	ch.Operation = "restart-w2"
	if _, res := submit(t, alice, ActionRestartTask, p.InventoryRevision, ch, rootFor(t, alice, ActionRestartTask)); res.Code != ResultConditionFailed {
		t.Fatalf("stale plan %v", res.Code)
	}
}

// extendChange signs a standalone-extend from the row, as the CLI does.
func extendChange(v StandaloneView, op string, ttl int64) control.StandaloneExtendChange {
	return control.StandaloneExtendChange{Tenant: v.Tenant, Name: v.Name, Scope: v.Scope, Operation: op, CreatedAt: v.CreatedAt, PreviousExpiresAt: v.ExpiresAt, TTLSeconds: ttl, Target: v.Target}
}

// REQ-61 in mydcd's shape: signed At + TTLSeconds, within 24 h of creation,
// a running temp whose Target and coordinates still match.
func TestStandaloneExtendREQ61(t *testing.T) {
	f, clk := newTestFake(t)
	clk.t = time.Now() // the fixture rows are aged from the wall clock
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	v, _ := alice.Standalone(ctx, "shop", "alice-debug")
	if v.Scope != standaloneScope("shop", "alice-debug") {
		t.Fatalf("scope %q", v.Scope)
	}
	extend := func(v StandaloneView, id string, ttl int64) (SignedOp, Result) {
		t.Helper()
		return submit(t, alice, ActionStandaloneExtend, v.Revision, extendChange(v, id, ttl), rootFor(t, alice, ActionStandaloneExtend))
	}
	op, res := extend(v, "ext-1", 10*3600)
	if res.Code != ResultApplied {
		t.Fatalf("extend %v", res.Code)
	}
	if u, _ := DecodeOperation(op); !control.StandaloneCASAllowed(u.Change) {
		t.Fatal("not a management-target CAS change")
	}
	n, _ := alice.Standalone(ctx, "shop", "alice-debug")
	if n.ExpiresAt != clk.now().Unix()+10*3600 || n.GraceSeconds != v.GraceSeconds || n.Target == v.Target || n.Generation != v.Generation {
		t.Fatalf("extended %+v", n)
	}
	if o, err := StandaloneExtension(op, res); err != nil || !o.Applied || o.Code != "" || o.Extension.ProposedExpiresAt != n.ExpiresAt || o.Extension.PreviousExpiresAt != v.ExpiresAt || o.Extension.MaximumExpiresAt != v.CreatedAt+86400 {
		t.Fatalf("outcome %+v %v", o, err)
	}
	// The old row's Target and coordinates no longer match.
	if _, res := extend(v, "ext-stale", 11*3600); res.Code != ResultConditionFailed {
		t.Fatalf("stale Target %v", res.Code)
	}
	// Over the 24 h limit, or not later than now: refused with the numbers.
	op, res = extend(n, "ext-long", 30*86400)
	if o, _ := StandaloneExtension(op, res); res.Code != ResultConditionFailed || o.Applied || o.Code != "STANDALONE_TTL_LIMIT" || o.Extension.AllowedTTLSeconds <= 0 {
		t.Fatalf("past 24 h %v %+v", res.Code, o)
	}
	op, res = extend(n, "ext-short", 1)
	if o, _ := StandaloneExtension(op, res); res.Code != ResultConditionFailed || o.Code != "STANDALONE_TTL_NOT_INCREASED" {
		t.Fatalf("not increased %v %+v", res.Code, o)
	}
	cron, _ := alice.Standalone(ctx, "shop", "shop-cron")
	if _, res := extend(cron, "ext-fixed", 60); res.Code == ResultApplied {
		t.Fatalf("fixed %v", res.Code)
	}
	n, _ = alice.Standalone(ctx, "shop", "alice-debug")
	// An Operation must be a lifecycle ID: a UUID starting with a digit is not.
	rm := control.StandaloneChange{Tenant: "shop", Name: "alice-debug", Operation: "3f2a9c1e-0000-4000-8000-000000000001", Target: &n.Target}
	if _, res := submit(t, alice, ActionStandaloneRemove, n.Revision, rm, rootFor(t, alice, ActionStandaloneRemove)); res.Code != ResultInvalid {
		t.Fatalf("digit-first Operation %v", res.Code)
	}
	rm.Operation = "op-3f2a9c1e-0000-4000-8000-000000000001"
	if _, res := submit(t, alice, ActionStandaloneRemove, n.Revision, rm, rootFor(t, alice, ActionStandaloneRemove)); res.Code != ResultApplied {
		t.Fatalf("op- prefixed Operation %v", res.Code)
	}
}

// a new extension after the current expiry is refused before commit.
func TestStandaloneExtendExpired(t *testing.T) {
	f, clk := newTestFake(t)
	f.SetIdleTimeout(0)
	clk.t = time.Now() // the fixture rows are aged from the wall clock
	n, _ := passwordLogin(t, f, "alice", "alice").Standalone(ctx, "shop", "alice-debug")
	clk.add(time.Duration(n.ExpiresAt-clk.now().Unix()-10) * time.Second)
	alice := passwordLogin(t, f, "alice", "alice")
	late, err := alice.Prepare(ctx, Change{Action: ActionStandaloneExtend, Expected: n.Revision, Payload: mustPayload(t, extendChange(n, "ext-late", 600))}, rootFor(t, alice, ActionStandaloneExtend))
	if err != nil {
		t.Fatal(err)
	}
	clk.add(20 * time.Second)
	_, err = alice.Submit(ctx, late)
	wantCode(t, err, CodeConflict)
	if _, found, _ := alice.Result(ctx, late); found {
		t.Fatal("expired extension has a result")
	}
}

// standalone-up in mydcd's shape: plan one compose service, upload under
// the internal scope, standalone-up control.AppBegin with the Target.
func TestStandaloneUpReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	def := control.StandaloneDefinition{Name: "dbg", Lifetime: "temp", Mode: "shell", TTLSeconds: 1800}
	doc := []byte("services:\n  dbg:\n    image: busybox:1.36\n    networks: [shop-net]\n    x-mydc: {node: node-a}\n")
	up := func(def control.StandaloneDefinition, doc []byte, id string, target [32]byte, expected uint64) Result {
		t.Helper()
		p, err := alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: doc, Standalone: &def})
		if err != nil {
			t.Fatalf("plan %v", err)
		}
		if p.App != standaloneScope("shop", def.Name) || p.Standalone == nil || len(p.Services) != 1 {
			t.Fatalf("plan %+v", p)
		}
		if target == ([32]byte{}) {
			target = control.AppCreateTarget(clusterOf(t, alice), "shop", p.App, "dep-"+p.App)
		}
		uploadApp(t, alice, "shop", p.App, id, p.Data)
		b := control.AppBegin{Standalone: &def, Target: &target, Tenant: "shop", App: p.App, Deployment: "dep-" + p.App, Upload: id, Operation: id}
		_, res := submit(t, alice, ActionStandaloneUp, expected, b, rootFor(t, alice, ActionStandaloneUp))
		return res
	}
	// Two services, or a depends_on, are refused by the plan.
	_, err := alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: []byte("services:\n  a: {image: x}\n  b: {image: y}\n"), Standalone: &def})
	if e, ok := err.(*Error); !ok || e.InputCode != "STANDALONE_SINGLE_SERVICE_REQUIRED" {
		t.Fatalf("two services %v", err)
	}
	// A wrong create Target is ConditionFailed; the right one applies.
	if res := up(def, doc, "up-bad", [32]byte{7}, 0); res.Code != ResultConditionFailed {
		t.Fatalf("bad Target %v", res.Code)
	}
	if res := up(def, doc, "up-dbg", [32]byte{}, 0); res.Code != ResultApplied {
		t.Fatalf("up %v", res.Code)
	}
	v, err := alice.Standalone(ctx, "shop", "dbg")
	if err != nil || v.Lifetime != LifetimeTemp || v.Mode != ModeShell || v.State != "running" || v.ExpiresAt == 0 {
		t.Fatalf("row %+v %v", v, err)
	}
	if op, err := alice.StandaloneOperation(ctx, "shop", "dbg", "up-dbg"); err != nil || op.Status != "succeeded" {
		t.Fatalf("operation %+v %v", op, err)
	}
	// A change signs the row's Target and Revision.
	doc2 := []byte("services:\n  dbg:\n    image: busybox:1.37\n    networks: [shop-net]\n    x-mydc: {node: node-a}\n")
	if res := up(def, doc2, "up-dbg-2", v.Target, v.Revision); res.Code != ResultApplied {
		t.Fatalf("change %v", res.Code)
	}
	if n, _ := alice.Standalone(ctx, "shop", "dbg"); n.Image != "busybox:1.37" || n.Target == v.Target {
		t.Fatalf("after change %+v", n)
	}
	// A protected Group needs its approval on this original first.
	f.SetGroupPassword("shop", "shop-db", "open-sesame")
	sec := control.StandaloneDefinition{Name: "dbg-sec", Lifetime: "fixed"}
	secDoc := []byte("services:\n  dbg-sec:\n    image: busybox:1.36\n    networks: [shop-net]\n    x-mydc:\n      node: node-a\n      secrets_from: [group/shop-db]\n")
	if res := up(sec, secDoc, "up-sec", [32]byte{}, 0); res.Code != ResultInvalid {
		t.Fatalf("without approval %v", res.Code)
	}
}

func clusterOf(t *testing.T, c Conn) [32]byte {
	t.Helper()
	w, err := c.Whoami(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return w.Session.Cluster
}

// restartChange plans a restart-task and returns mydcd's change and its Expected.
func restartChange(t *testing.T, c Conn, tenant string, sel ContainerSelection, op string) (control.TaskRestartChange, uint64) {
	t.Helper()
	p, err := c.TaskRestartPlan(ctx, tenant, control.TaskRestartQuery{Selection: containerops.Selection{App: sel.App, Service: sel.Service, Instance: sel.Instance}})
	if err != nil {
		t.Fatalf("restart plan %+v %v", sel, err)
	}
	ch := control.TaskRestartChange{Tenant: tenant, App: sel.App, Operation: op, Target: p.Target}
	ch.Selection.Service, ch.Selection.Instance = sel.Service, sel.Instance
	return ch, p.InventoryRevision
}

// mydcd's limit refusals: the plan of a new name fails with the limit's
// InputCode, and an up that crosses a limit after its plan is ConditionFailed.
func TestStandaloneLimitsReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	def := control.StandaloneDefinition{Name: "dbg", Lifetime: "temp", Mode: "shell"}
	doc := []byte("services:\n  dbg:\n    image: busybox:1.36\n    networks: [shop-net]\n    x-mydc: {node: node-a}\n")
	plan := func() (AppPlan, error) {
		return alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: doc, Standalone: &def})
	}
	p, err := plan()
	if err != nil || p.Standalone.Limits.MineMax != control.StandaloneTempLimitUser || p.Standalone.Limits.TenantMax != control.StandaloneLimitTenant ||
		p.Standalone.Limits.NodeMax != control.StandaloneLimitNode || p.Standalone.Limits.Mine != 1 || p.Standalone.Limits.Node != 1 {
		t.Fatalf("limits %+v %v", p.Standalone, err)
	}
	for _, c := range []struct {
		set  func()
		code string
	}{
		{func() { f.SetStandaloneLimits(1, 0) }, StandaloneUserLimit},
		{func() { f.SetStandaloneLimits(0, 2) }, StandaloneTenantLimit},
		{func() { f.SetStandaloneLimits(0, 0); f.SetStandaloneNodeLimit(1) }, StandaloneNodeLimit},
	} {
		c.set()
		_, err := plan()
		if e, ok := err.(*Error); !ok || e.Code != CodeInvalid || e.InputCode != c.code || LimitInputCode(e.InputCode) == "" {
			t.Fatalf("%s: %v", c.code, err)
		}
	}
	// Planned under the limit, submitted over it.
	f.SetStandaloneNodeLimit(0)
	p, err = plan()
	if err != nil {
		t.Fatal(err)
	}
	f.SetStandaloneLimits(1, 0)
	target := control.AppCreateTarget(clusterOf(t, alice), "shop", p.App, "dep-"+p.App)
	uploadApp(t, alice, "shop", p.App, "up-lim", p.Data)
	b := control.AppBegin{Standalone: &def, Target: &target, Tenant: "shop", App: p.App, Deployment: "dep-" + p.App, Upload: "up-lim", Operation: "up-lim"}
	if _, res := submit(t, alice, ActionStandaloneUp, 0, b, rootFor(t, alice, ActionStandaloneUp)); res.Code != ResultConditionFailed {
		t.Fatalf("over limit %+v", res)
	}
}

// Streams select a standalone container by mydcd's Selection{Standalone};
// the target carries the name and the internal scope as App.
func TestStandaloneStreamSelection(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	sel := ContainerSelection{Standalone: "alice-debug"}
	if o := sel.Ops(); o != (containerops.Selection{Standalone: "alice-debug"}) || !o.Valid() {
		t.Fatalf("ops %+v", o)
	}
	tg, err := alice.ResolveStream(ctx, "shop", sel, LogsFollowSpec(sel, 1, true, false))
	if err != nil || tg.Standalone != "alice-debug" || tg.App != standaloneScope("shop", "alice-debug") || !sel.Ops().Matches(tg) {
		t.Fatalf("target %+v %v", tg, err)
	}
	in, err := alice.PrepareStream(ctx, tg, LogsFollowSpec(sel, 1, true, false), "")
	if err != nil {
		t.Fatal(err)
	}
	s, err := alice.OpenStream(ctx, "shop", in)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f.EmitStandaloneLog("shop", "alice-debug", "stdout", "hello")
	for range 30 {
		r, err := s.Recv(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if r.Kind == "stdout" && strings.Contains(string(r.Data), "hello") {
			return
		}
	}
	t.Fatal("no standalone log line")
}

func TestStandaloneViewOf(t *testing.T) {
	restarts, exit := uint64(2), int64(0)
	v := control.StandaloneView{Target: [32]byte{1}, RemainingSeconds: 900,
		Metadata: control.StandaloneMetadata{Name: "dbg", Scope: "standalone-x", Creator: "u-alice", Node: "node-a", Lifetime: "temp", Mode: "shell", Restart: "no",
			Desired: "running", Connections: 1, Revision: 3, CreatedAt: 100, ExpiresAt: 3700, GraceSeconds: 600},
		Tasks: []control.TaskView{{Image: "busybox:1.36", Generation: 4, Observed: "running", RestartCount: &restarts, ExitCode: &exit, ObservedAt: 200}}}
	r := StandaloneViewOf("shop", v, []byte("x"))
	if r.Name != "dbg" || r.Tenant != "shop" || r.State != "running" || r.Image != "busybox:1.36" || r.Generation != 4 || r.Restarts != 2 || r.ExitCode == nil ||
		r.ExpiresAt != 3700 || r.GraceSeconds != 600 || r.RemainingSeconds != 900 || r.RestartPolicy != "" || r.Owner != "u-alice" || r.Scope != "standalone-x" ||
		r.Target != v.Target || r.Selection.Standalone != "dbg" || r.Connections != 1 || string(r.Document) != "x" {
		t.Fatalf("temp %+v", r)
	}
	v.Metadata.Lifetime, v.Metadata.Restart, v.Metadata.Desired, v.Tasks = "fixed", "always", "stopped", nil
	if r := StandaloneViewOf("shop", v, nil); r.State != "exited" || r.RestartPolicy != "always" || r.ExpiresAt != 0 || r.RemainingSeconds != 0 {
		t.Fatalf("fixed %+v", r)
	}
}

// The fixture's protected Group shop/shop-ops (password "ops-pass"): a
// standalone up that takes it waits for an approval bound to its original.
func TestStandaloneUpApprovalFixture(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	def := control.StandaloneDefinition{Name: "ops-dbg", Lifetime: "fixed"}
	doc := []byte("services:\n  ops-dbg:\n    image: busybox:1.36\n    networks: [shop-net]\n    x-mydc:\n      node: node-a\n      secrets_from: [group/shop-ops]\n")
	p, err := alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: doc, Standalone: &def})
	if err != nil {
		t.Fatal(err)
	}
	target := control.AppCreateTarget(clusterOf(t, alice), "shop", p.App, "dep-"+p.App)
	uploadApp(t, alice, "shop", p.App, "up-ops", p.Data)
	b := control.AppBegin{Standalone: &def, Target: &target, Tenant: "shop", App: p.App, Deployment: "dep-" + p.App, Upload: "up-ops", Operation: "up-ops"}
	signed, err := alice.Prepare(ctx, Change{Action: ActionStandaloneUp, Payload: mustPayload(t, b)}, rootFor(t, alice, ActionStandaloneUp))
	if err != nil {
		t.Fatal(err)
	}
	origin, err := DecodeOperation(signed)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := alice.PlanVaultApprovals(ctx, "shop", VaultApprovalPlanRequest{Realm: "shop", ID: "compose/" + origin.RequestID, Origin: &origin})
	if err != nil || len(plan.Targets) != 1 || plan.Targets[0].Target.Group != "shop-ops" || plan.Targets[0].Existing != nil {
		t.Fatalf("plan %+v %v", plan, err)
	}
	tg := plan.Targets[0].Target
	if code, err := alice.ApproveVault(ctx, "shop", *plan.Targets[0].Approver, VaultApprove{Target: tg, Password: []byte("ops-pass"), Origin: &origin}); err != nil || code != "ok" {
		t.Fatalf("approve %s %v", code, err)
	}
	if res, err := alice.Submit(ctx, signed); err != nil || res.Code != ResultApplied {
		t.Fatalf("approved %v %v", res.Code, err)
	}
}
