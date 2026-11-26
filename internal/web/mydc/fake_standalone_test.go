// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
)

func standaloneNames(t *testing.T, c Conn, tenant string) string {
	t.Helper()
	p, err := c.Standalones(ctx, tenant, "")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, v := range p.Items {
		names = append(names, v.Name)
	}
	return strings.Join(names, ",")
}

// flatStandalone splits a flat definition (name, lifetime, mode, restart,
// ttl, grace, then the service's fields) into mydcd's StandaloneDefinition
// and a one-service compose document.
func flatStandalone(t *testing.T, flat string) (control.StandaloneDefinition, []byte) {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(flat), &m); err != nil {
		t.Fatal(err)
	}
	str := func(k string) string { s, _ := m[k].(string); delete(m, k); return s }
	secs := func(k string) int64 {
		s := str(k)
		if s == "" {
			return 0
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			t.Fatal(err)
		}
		return int64(d / time.Second)
	}
	def := control.StandaloneDefinition{Name: str("name"), Lifetime: str("lifetime"), Mode: str("mode"), Restart: str("restart")}
	def.TTLSeconds, def.GraceSeconds = secs("ttl"), secs("grace")
	doc, err := yaml.Marshal(map[string]any{"services": map[string]any{def.Name: m}})
	if err != nil {
		t.Fatal(err)
	}
	return def, doc
}

// standalonePlan: the StandalonePlan summary of mydcd's AppPlan.
func standalonePlan(t *testing.T, c Conn, tenant, flat string) (StandalonePlan, error) {
	t.Helper()
	def, doc := flatStandalone(t, flat)
	p, err := c.AppPlan(ctx, AppPlanRequest{Tenant: tenant, Document: doc, Standalone: &def})
	if err != nil {
		return StandalonePlan{}, err
	}
	return *p.Standalone, nil
}

var upSeq atomic.Int64

// standaloneUp runs mydcd's up order: AppPlan, upload, standalone-up
// control.AppBegin with the create Target (or the row's) and expected.
func standaloneUp(t *testing.T, c Conn, tenant, flat string, expected uint64) Result {
	t.Helper()
	def, doc := flatStandalone(t, flat)
	p, err := c.AppPlan(ctx, AppPlanRequest{Tenant: tenant, Document: doc, Standalone: &def})
	if err != nil {
		t.Fatalf("plan %v", err)
	}
	target := control.AppCreateTarget(clusterOf(t, c), tenant, p.App, "dep-"+p.App)
	if v, err := c.Standalone(ctx, tenant, def.Name); err == nil && v.State != "removed" {
		target = v.Target
	}
	id := fmt.Sprintf("op-up-%d", upSeq.Add(1))
	uploadApp(t, c, tenant, p.App, id, p.Data)
	b := control.AppBegin{Standalone: &def, Target: &target, Tenant: tenant, App: p.App, Deployment: "dep-" + p.App, Upload: id, Operation: id}
	_, res := submit(t, c, ActionStandaloneUp, expected, b, rootFor(t, c, ActionStandaloneUp))
	return res
}

// standaloneControl: stop/start/restart through task-restart-plan.
func standaloneControl(t *testing.T, c Conn, tenant, name, action, operation string) Result {
	t.Helper()
	p, err := c.TaskRestartPlan(ctx, tenant, control.TaskRestartQuery{Action: action, Selection: containerops.Selection{Standalone: name}})
	if err != nil {
		t.Fatalf("plan %s %v", action, err)
	}
	ch := control.TaskRestartChange{Tenant: tenant, Standalone: name, Operation: operation, Target: p.Target, ManagementTarget: p.ManagementTarget}
	ch.Selection.Service, ch.Selection.Instance = p.Container.Service, p.Container.Instance
	_, res := submit(t, c, action, p.StandaloneRevision, ch, rootFor(t, c, action))
	return res
}

const tmpDoc = `name: tmp-a
lifetime: temp
ttl: 30m
grace: 5m
mode: shell
image: busybox:1.36
networks: [shop-net]
x-mydc: {node: node-a}
`

func TestStandaloneLifecycle(t *testing.T) {
	f, clk := newTestFake(t)
	f.SetIdleTimeout(0)
	f.SetStreamTick(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, err := keyLogin(t, f, "bob", FixtureKey("bob"))
	if err != nil {
		t.Fatal(err)
	}

	// Seeds and visibility: another user's temp container is manager-only.
	if got := standaloneNames(t, admin, "shop"); got != "alice-debug,shop-cron" {
		t.Fatalf("admin sees %q", got)
	}
	if got := standaloneNames(t, bob, "shop"); got != "shop-cron" {
		t.Fatalf("viewer sees %q", got)
	}
	_, err = bob.Standalone(ctx, "shop", "alice-debug")
	wantCode(t, err, CodeMissing)
	_, err = bob.Standalones(ctx, "payments", "")
	wantCode(t, err, CodeDenied)
	_, err = standalonePlan(t, bob, "shop", tmpDoc)
	wantCode(t, err, CodeDenied)

	// Plan, then create a temp shell container.
	p, err := standalonePlan(t, alice, "shop", tmpDoc)
	if err != nil || !p.Create || p.Revision != 0 || p.Limits.Mine != 1 || p.Limits.MineMax != 8 || len(p.Impact) != 1 || p.Impact[0].Blocking {
		t.Fatalf("plan %+v %v", p, err)
	}
	if res := standaloneUp(t, alice, "shop", tmpDoc, 0); res.Code != ResultApplied {
		t.Fatalf("up %+v", res)
	}
	v, err := alice.Standalone(ctx, "shop", "tmp-a")
	now := clk.now().Unix()
	if err != nil || v.Lifetime != LifetimeTemp || v.Mode != ModeShell || v.State != "running" || v.Owner != "u-alice" ||
		v.ExpiresAt != now+1800 || v.GraceSeconds != 300 || v.Selection.Standalone != "tmp-a" || !strings.Contains(string(v.Document), "name: tmp-a") {
		t.Fatalf("view %+v %v", v, err)
	}
	// Same name again with Expected 0 is a CAS failure; a viewer is forbidden.
	if res := standaloneUp(t, alice, "shop", tmpDoc, 0); res.Code != ResultConditionFailed {
		t.Fatalf("cas %+v", res)
	}
	if _, res := submit(t, bob, ActionStandaloneRestart, v.Revision, control.TaskRestartChange{Tenant: "shop", Standalone: "tmp-a", Operation: "op-bob"}, rootFor(t, bob, ActionStandaloneRestart)); res.Code != ResultForbidden {
		t.Fatalf("viewer %+v", res)
	}

	// Attach an interactive shell exactly like an app task.
	sel := v.Selection
	s, _ := openStream(t, alice, "shop", sel, ExecStreamSpec([]string{"/bin/sh"}, true, true, 24, 80), "exec-tmp-a-1")
	if tg := s.Target(); tg.Tenant != "shop" || tg.Node != "node-a" {
		t.Fatalf("target %+v", tg)
	}
	if v, _ = alice.Standalone(ctx, "shop", "tmp-a"); v.Connections != 1 || v.DisconnectedAt != 0 {
		t.Fatalf("attached %+v", v)
	}
	logs, err := alice.ContainerObserve(ctx, "shop", ContainerQuery{Selection: sel, Kind: "logs", Tail: 5, Stdout: true, Stderr: true})
	if err != nil || logs.Selection.Standalone != "tmp-a" || len(logs.Logs) == 0 {
		t.Fatalf("observe %+v %v", logs, err)
	}
	s.Close()
	clk.add(time.Minute)
	if v, _ = alice.Standalone(ctx, "shop", "tmp-a"); v.Connections != 0 || v.DisconnectedAt == 0 {
		t.Fatalf("detached %+v", v)
	}

	// Pin: temp → fixed, same container (generation kept), no TTL.
	gen := v.Generation
	if _, res := submit(t, alice, ActionStandaloneExtend, v.Revision, extendChange(v, "ext-a", 7200), rootFor(t, alice, ActionStandaloneExtend)); res.Code != ResultApplied {
		t.Fatalf("extend %+v", res)
	}
	v, _ = alice.Standalone(ctx, "shop", "tmp-a")
	if v.ExpiresAt != clk.now().Unix()+7200 {
		t.Fatalf("extended %+v", v)
	}
	if _, res := submit(t, alice, ActionStandalonePin, v.Revision, control.StandaloneChange{Tenant: "shop", Name: "tmp-a", NewName: "keep-a", Restart: "always", Operation: "op-keep-a", Target: &v.Target}, rootFor(t, alice, ActionStandalonePin)); res.Code != ResultApplied {
		t.Fatalf("pin %+v", res)
	}
	_, err = alice.Standalone(ctx, "shop", "tmp-a")
	wantCode(t, err, CodeMissing)
	v, _ = alice.Standalone(ctx, "shop", "keep-a")
	doc := string(v.Document)
	if v.Lifetime != LifetimeFixed || v.RestartPolicy != "always" || v.ExpiresAt != 0 || v.Generation != gen || v.Selection.Standalone != "keep-a" ||
		!strings.Contains(doc, "name: keep-a") || !strings.Contains(doc, "lifetime: fixed") || !strings.Contains(doc, `restart: "always"`) || strings.Contains(doc, "ttl:") {
		t.Fatalf("pinned %+v\n%s", v, doc)
	}
	sel = v.Selection
	clk.add(45 * time.Minute) // past the old TTL: a fixed container does not expire
	f.ExitStandalone("shop", "keep-a", 0)
	if v, _ = alice.Standalone(ctx, "shop", "keep-a"); v.State != "running" || v.Restarts != 1 {
		t.Fatalf("restart policy %+v", v)
	}

	// Stop / start / remove.
	if res := standaloneControl(t, alice, "shop", "keep-a", ActionStandaloneStop, "op-stop-a"); res.Code != ResultApplied {
		t.Fatalf("stop %+v", res)
	}
	v, _ = alice.Standalone(ctx, "shop", "keep-a")
	_, err = alice.ResolveStream(ctx, "shop", sel, LogsFollowSpec(sel, 1, true, false))
	wantCode(t, err, CodeUnavailable)
	if res := standaloneControl(t, alice, "shop", "keep-a", ActionStandaloneStart, "op-start-a"); res.Code != ResultApplied {
		t.Fatalf("start %+v", res)
	}
	v, _ = alice.Standalone(ctx, "shop", "keep-a")
	if _, res := submit(t, alice, ActionStandaloneRemove, v.Revision, control.StandaloneChange{Tenant: "shop", Name: "keep-a", Operation: "op-rm-a", Target: &v.Target}, rootFor(t, alice, ActionStandaloneRemove)); res.Code != ResultApplied {
		t.Fatalf("remove %+v", res)
	}
	if v, _ = alice.Standalone(ctx, "shop", "keep-a"); v.State != "removed" || v.EndedAt != clk.now().Unix() {
		t.Fatalf("removed %+v", v)
	}

	// An unattached temp container ends after its grace period; the row
	// stays as removed for an hour, then disappears.
	doc = strings.ReplaceAll(tmpDoc, "tmp-a", "tmp-b")
	if res := standaloneUp(t, alice, "shop", doc, 0); res.Code != ResultApplied {
		t.Fatalf("up b %+v", res)
	}
	clk.add(6 * time.Minute)
	if v, _ = alice.Standalone(ctx, "shop", "tmp-b"); v.State != "removed" || v.EndedAt == 0 {
		t.Fatalf("grace %+v", v)
	}
	// Re-creating a removed name starts from Expected 0.
	if res := standaloneUp(t, alice, "shop", doc, 0); res.Code != ResultApplied {
		t.Fatalf("re-up b %+v", res)
	}
	f.ExitStandalone("shop", "tmp-b", 0)

	// Limits refuse the plan of a new name (TestStandaloneLimitsReal).
	f.SetStandaloneLimits(1, 10)
	_, err = standalonePlan(t, alice, "shop", strings.ReplaceAll(tmpDoc, "tmp-a", "tmp-d"))
	if e, ok := err.(*Error); !ok || e.InputCode != StandaloneUserLimit {
		t.Fatalf("limit %v", err)
	}

	// Blocking impacts are invalid; a bad definition fails the plan.
	bad := strings.ReplaceAll(strings.ReplaceAll(tmpDoc, "tmp-a", "tmp-c"), "shop-net", "nope-net")
	f.SetStandaloneLimits(0, 0)
	if p, _ = standalonePlan(t, alice, "shop", bad); !p.Impact[0].Blocking {
		t.Fatalf("network impact %+v", p)
	}
	if res := standaloneUp(t, alice, "shop", bad, 0); res.Code != ResultInvalid {
		t.Fatalf("blocked %+v", res)
	}
	_, err = standalonePlan(t, alice, "shop", "name: x\nlifetime: forever\nimage: a\n")
	wantCode(t, err, CodeInvalid)

	// An exited fixed container cannot be attached.
	_, err = admin.ContainerObserve(ctx, "payments", ContainerQuery{Selection: ContainerSelection{Standalone: "ledger-migrate"}, Kind: "logs", Tail: 1, Stdout: true})
	wantCode(t, err, CodeMissing)
}
