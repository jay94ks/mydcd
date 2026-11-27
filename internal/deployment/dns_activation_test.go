// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

func dnsActivationFixture(t *testing.T) *executionFixture {
	t.Helper()
	f := makeFixture(t)
	ctx := contextFor(t, f)
	ctx.Features["network-services"] = true
	c := smallCompose(t)
	n := c.Networks["app"]
	n.Sfc.DNS = &DNSDeclaration{Enabled: true, Zone: "app.sfc.test", TTL: 30, NegativeTTL: 5, Transports: []string{"tcp", "udp"}}
	n.Sfc.DNS.Limits.Cache, n.Sfc.DNS.Limits.Inflight, n.Sfc.DNS.Limits.TCP, n.Sfc.DNS.Limits.Timeout = 4, 8, 4, 1000
	c.Networks["app"] = n
	b, err := Compile(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewExecution(b, f.c, ctx, "operation", "submitter", 1)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := state.New("submitter")
	if err != nil {
		t.Fatal(err)
	}
	return &executionFixture{f, b, e, shared, 100}
}

func TestDNSCommitAllowsExactTaskAddressBeforeNativeActivation(t *testing.T) {
	x := dnsActivationFixture(t)
	db := ResourceKey("task", "tenant", "php-mysql", "db")
	dns := ResourceKey("dns", "tenant", "php-mysql", "app/node-b")
	commit := func(key string) {
		t.Helper()
		x.prepare(key)
		cmd := x.send(key)
		x.save(x.e.Commit(x.e.Revision(), key, cmd, x.apply(cmd)))
	}
	for _, step := range x.b.Steps() {
		if step.Key == db {
			break
		}
		commit(step.Key)
		if step.Node != "" && step.Kind != "dns" {
			x.observe(step.Key, true, false)
		}
	}
	stage, _ := x.e.Stage(dns)
	if stage.Result == nil || stage.Observation != nil {
		t.Fatal("fixture needs committed, unserved DNS")
	}
	commit(db)
	task, _ := x.e.Stage(db)
	var goal GoalCommand
	if json.Unmarshal([]byte(task.Command.Value), &goal) != nil || x.shared.Object(db).Generation == 0 || task.Result.Generation != x.shared.Object(db).Generation {
		t.Fatal("no exact authoritative address generation")
	}
	if len(goal.Activation) == 0 || x.e.ActivationReady(db) || x.e.ActivationReady("missing") {
		t.Fatal("DNS desired commit allowed native execution")
	}
	input := ResourceKey("inputs", "tenant", "php-mysql", "db")
	commit(input)
	x.observe(input, true, false)
	if x.e.ActivationReady(db) {
		t.Fatal("input readiness bypassed DNS")
	}
	if _, err := x.e.Observe(x.e.Revision(), x.observation(db, true, false), x.now); err == nil {
		t.Fatal("fabricated Applied before DNS activation")
	}
	if x.e.CanRelease(dns) {
		t.Fatal("unserved DNS lost original committed consumer")
	}
	// save() crosses the product codec on every transition. Unknown/native
	// absence never changes the exact original Task command/result into a retry.
	original, result := *task.Command, *task.Result
	x.observe(dns, true, false)
	if !x.e.ActivationReady(db) {
		t.Fatal("exact original task cannot activate after DNS")
	}
	x.observe(db, true, false)
	task, _ = x.e.Stage(db)
	if *task.Command != original || *task.Result != result || x.e.CanRelease(dns) {
		t.Fatal("activation replaced task or returned DNS dependency")
	}
	x.save(x.e.Pause(x.f.c, "alice", x.e.Revision(), true))
	if x.e.ActivationReady(db) {
		t.Fatal("paused execution authorized new native activation")
	}
}
