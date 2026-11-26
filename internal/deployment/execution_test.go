// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload"
)

type executionFixture struct {
	f      *fixture
	b      Blueprint
	e      Execution
	shared state.State
	now    uint64
}

func runFixture(t *testing.T) *executionFixture {
	t.Helper()
	f := makeFixture(t)
	ctx := contextFor(t, f)
	b, err := Compile(smallCompose(t), f.c, ctx)
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
func (x *executionFixture) save(e Execution, err error) {
	x.f.t.Helper()
	if err != nil {
		x.f.t.Fatal(err)
	}
	raw, err := e.Encode()
	if err != nil {
		x.f.t.Fatal("candidate", err)
	}
	x.e, err = DecodeExecution(raw)
	if err != nil {
		x.f.t.Fatal("restore", err)
	}
}
func (x *executionFixture) prepare(key string) state.Command {
	x.f.t.Helper()
	e, cmd, err := x.e.Prepare(x.f.c, x.e.Revision(), key, x.shared.Object(key), x.now)
	x.save(e, err)
	return cmd
}
func (x *executionFixture) send(key string) state.Command {
	x.f.t.Helper()
	e, cmd, err := x.e.Send(x.f.c, x.e.Revision(), key, x.now)
	x.save(e, err)
	return cmd
}
func (x *executionFixture) apply(cmd state.Command) state.Result {
	x.f.t.Helper()
	s, r, err := state.Apply(x.shared, x.shared.Index()+1, cmd)
	if err != nil {
		x.f.t.Fatal(err)
	}
	x.shared = s
	return r
}
func (x *executionFixture) observation(key string, healthy, released bool) Observation {
	s, _ := x.e.Stage(key)
	step := stepMap(x.b)[key]
	sequence := uint64(1)
	if s.Observation != nil {
		sequence = s.Observation.Sequence + 1
	}
	o := Observation{Cluster: x.f.cluster, Plan: x.b.Digest(), Operation: x.e.d.Operation, Key: key, Native: "native-" + requestID("object", key), Owner: step.Owner, Command: state.Digest(*s.Command), Generation: s.Result.Generation, Revision: s.Result.Revision, Sequence: sequence, At: x.now, Applied: !released, Healthy: healthy, Released: released}
	if step.Kind == "ingress" && x.e.d.Replacement == nil && healthy && !released {
		// Explicit fake serving observations for initial setup. Replacement
		// tests must supply the new backend receipts separately from Task health.
		for _, taskKey := range step.Identity {
			if task, exists := x.e.Stage(taskKey); exists && task.Result != nil {
				o.IngressBackends = append(o.IngressBackends, ObjectRef{Key: taskKey, Generation: task.Result.Generation, Revision: task.Result.Revision})
			}
		}
	}
	if released {
		o.Stopped = true
		o.Retained = step.Retain
		o.Gone = !step.Retain
	}
	k := x.f.na
	if step.Owner == public(x.f.nb) {
		k = x.f.nb
	}
	o.Signature = ed25519.Sign(k, ObservationBytes(o))
	return o
}
func (x *executionFixture) observe(key string, healthy, released bool) {
	x.f.t.Helper()
	x.save(x.e.Observe(x.e.Revision(), x.observation(key, healthy, released), x.now))
}
func (x *executionFixture) completeStep(key string) {
	x.f.t.Helper()
	x.prepare(key)
	s, _ := x.e.Stage(key)
	if !s.Noop {
		cmd := x.send(key)
		r := x.apply(cmd)
		x.save(x.e.Commit(x.e.Revision(), key, cmd, r))
	}
	x.flushReady()
}
func (x *executionFixture) flushReady() {
	for changed := true; changed; {
		changed = false
		for _, step := range x.b.Steps() {
			s, _ := x.e.Stage(step.Key)
			i := x.e.index(step.Key)
			if step.Node != "" && s.Result != nil && s.Result.Code == state.Applied && s.Observation == nil && x.e.activationReady(i) {
				x.observe(step.Key, true, false)
				changed = true
			}
		}
	}
}
func (x *executionFixture) before(key string) {
	x.f.t.Helper()
	for _, s := range x.b.Steps() {
		if s.Key == key {
			return
		}
		x.completeStep(s.Key)
	}
	x.f.t.Fatal("unknown key")
}

func TestExecutionFreezesCommandsAndSeparatesCommitFromDatabaseReadiness(t *testing.T) {
	x := runFixture(t)
	db := ResourceKey("task", "tenant", "php-mysql", "db")
	web := ResourceKey("task", "tenant", "php-mysql", "web")
	x.before(db)
	_, _, err := x.e.Prepare(x.f.c, x.e.Revision(), web, state.Object{}, 100)
	deny(t, err)
	cmd := x.prepare(db)
	rev := x.e.Revision()
	again, copy, err := x.e.Prepare(x.f.c, rev, db, state.Object{Revision: 999}, 100)
	if err != nil || copy != cmd || again.Revision() != rev {
		t.Fatal("prepare rewrote original command/CAS")
	}
	x.save(x.e.Pause(x.f.c, "alice", x.e.Revision(), true))
	_, _, err = x.e.Send(x.f.c, x.e.Revision(), db, 100)
	deny(t, err)
	x.save(x.e.Pause(x.f.c, "alice", x.e.Revision(), false))
	sent := x.send(db)
	if sent != cmd {
		t.Fatal("send changed frozen bytes")
	}
	result := x.apply(sent)
	x.save(x.e.Commit(x.e.Revision(), db, sent, result))
	_, _, err = x.e.Prepare(x.f.c, x.e.Revision(), web, state.Object{}, 100)
	deny(t, err)
	_, err = x.e.Observe(x.e.Revision(), x.observation(db, true, false), x.now)
	deny(t, err)
	inputKey := ResourceKey("inputs", "tenant", "php-mysql", "db")
	x.prepare(inputKey)
	inputCmd := x.send(inputKey)
	x.save(x.e.Commit(x.e.Revision(), inputKey, inputCmd, x.apply(inputCmd)))
	x.observe(inputKey, true, false)
	x.observe(db, false, false)
	_, _, err = x.e.Prepare(x.f.c, x.e.Revision(), web, state.Object{}, 100)
	deny(t, err)
	x.observe(db, true, false)
	webCmd := x.prepare(web)
	var value GoalCommand
	if json.Unmarshal([]byte(webCmd.Value), &value) != nil {
		t.Fatal("goal encoding")
	}
	var found bool
	for _, r := range value.Dependencies {
		if r.Key == db {
			found = true
			if r.Generation != result.Generation || r.Revision != result.Revision {
				t.Fatal("assumed dependency generation")
			}
		}
	}
	if !found || x.e.Status() == "Succeeded" {
		t.Fatal("native gate not preserved")
	}
	// A formerly healthy dependency expires while the next command is Prepared.
	_, _, err = expired(x.e).Send(x.f.c, x.e.Revision(), web, 200)
	deny(t, err)
}

func TestExecutionUnknownRestoresOriginalRequestAndSettlesOnlyExactLookup(t *testing.T) {
	x := runFixture(t)
	key := x.b.Steps()[0].Key
	cmd := x.prepare(key)
	x.send(key)
	r := x.apply(cmd)
	x.save(x.e.Unknown(x.e.Revision(), key))
	if x.e.Status() != "Unknown" {
		t.Fatal("lost transport uncertainty")
	}
	_, _, err := x.e.Send(x.f.c, x.e.Revision(), key, 100)
	deny(t, err)
	restored, original, err := x.e.Prepare(x.f.c, x.e.Revision(), key, state.Object{Revision: 900}, 100)
	if err != nil || original != cmd || restored.Revision() != x.e.Revision() {
		t.Fatal("resume changed command")
	}
	wrong := cmd
	wrong.RequestID = "replacement"
	_, err = x.e.Commit(x.e.Revision(), key, wrong, r)
	deny(t, err)
	lookedUp, ok := x.shared.LookupResult(cmd)
	if !ok || lookedUp != r {
		t.Fatal("fixture did not recover original result")
	}
	x.save(x.e.Commit(x.e.Revision(), key, cmd, lookedUp))
	if x.e.Status() == "Succeeded" {
		t.Fatal("commit was treated as native success")
	}
	valid := x.observation(key, true, false)
	for _, change := range []func(*Observation){func(o *Observation) { o.Generation++ }, func(o *Observation) { o.Revision++ }, func(o *Observation) { o.Operation = "other" }, func(o *Observation) { o.Command[0]++ }, func(o *Observation) { o.Plan[0]++ }, func(o *Observation) { o.Sequence = 0 }} {
		o := valid
		change(&o)
		o.Signature = ed25519.Sign(x.f.na, ObservationBytes(o))
		_, err = x.e.Observe(x.e.Revision(), o, 100)
		deny(t, err)
	}
	x.save(x.e.Observe(x.e.Revision(), valid, 100))
	rev := x.e.Revision()
	x.save(x.e.Observe(x.e.Revision(), valid, 100))
	if x.e.Revision() != rev {
		t.Fatal("duplicate observation changed revision")
	}
}

func TestExecutionCASRejectionCannotReplanOrReissueOriginalStep(t *testing.T) {
	early := runFixture(t)
	earlyKey := early.b.Steps()[0].Key
	early.apply(state.Command{Actor: "submitter", Epoch: 1, RequestID: "before-prepare", Key: earlyKey, Value: "competing"})
	_, _, earlyErr := early.e.Prepare(early.f.c, early.e.Revision(), earlyKey, early.shared.Object(earlyKey), 100)
	deny(t, earlyErr)
	x := runFixture(t)
	key := x.b.Steps()[0].Key
	cmd := x.prepare(key)
	x.send(key)
	x.apply(state.Command{Actor: "submitter", Epoch: 1, RequestID: "competing", Key: key, Value: "competing"})
	r := x.apply(cmd)
	if r.Code != state.ConditionFailed {
		t.Fatal("fixture lost CAS race")
	}
	x.save(x.e.Commit(x.e.Revision(), key, cmd, r))
	if x.e.Status() != "Failed" {
		t.Fatal("CAS rejection hidden")
	}
	_, again, err := x.e.Prepare(x.f.c, x.e.Revision(), key, x.shared.Object(key), 100)
	if err != nil || again.Expected != 0 || again.RequestID != cmd.RequestID {
		t.Fatal("CAS conflict was rebound")
	}
	_, _, err = x.e.Send(x.f.c, x.e.Revision(), key, 100)
	deny(t, err)
	_, err = x.e.Finish(x.e.Revision(), 100)
	deny(t, err)
}

func TestExecutionSameGoalsNoopUsesRealObjectsAndFreshProofs(t *testing.T) {
	x := runFixture(t)
	for _, s := range x.b.Steps() {
		x.completeStep(s.Key)
	}
	x.save(x.e.Finish(x.e.Revision(), 100))
	if x.e.Status() != "Succeeded" || x.e.Health(100) != "Healthy" {
		t.Fatal("operation did not verify")
	}
	completedRaw, _ := x.e.Encode()
	for _, change := range []func(*executionRecord){func(d *executionRecord) { d.CompletionWitness = nil }, func(d *executionRecord) { d.CompletionWitness[0].Signature[0] ^= 1 }} {
		var corrupt executionRecord
		_ = json.Unmarshal(completedRaw, &corrupt)
		change(&corrupt)
		raw, _ := json.Marshal(corrupt)
		_, err := DecodeExecution(raw)
		deny(t, err)
	}
	old := x.e
	ctx := contextFor(t, x.f)
	ctx.Current = x.shared.Objects("")
	ctx.Reserved = map[string]workload.Resources{}
	for _, step := range x.b.Steps() {
		if step.Kind == "task" {
			var service ComposeService
			_ = json.Unmarshal(step.Goal, &service)
			cpu, _ := nanoCPU(service.CPUs)
			memory, _ := byteSize(service.Memory)
			ctx.Reserved[step.Key] = workload.Resources{CPU: cpu, Memory: memory}
		}
	}
	for id, node := range ctx.Nodes {
		node.Used = node.Capacity
		ctx.Nodes[id] = node
	}
	oldBlueprint := x.b
	currentBlueprint, err := Compile(x.b.d.Input, x.f.c, ctx)
	x.b = currentBlueprint
	if err != nil {
		t.Fatal("unchanged goal double-counted a full node", err)
	}
	if x.b.Digest() == oldBlueprint.Digest() {
		t.Fatal("plan did not bind current per-resource base revisions")
	}
	next, err := NewExecution(x.b, x.f.c, ctx, "next-operation", "submitter", 1)
	if err != nil {
		t.Fatal(err)
	}
	x.e = next
	x.now = 200
	originalIndex := x.shared.Index()
	for _, step := range x.b.Steps() {
		x.prepare(step.Key)
		record, _ := x.e.Stage(step.Key)
		if !record.Noop || record.Result.Generation != x.shared.Object(step.Key).Generation {
			t.Fatal("same goal recreated native generation")
		}
		_, _, err = x.e.Send(x.f.c, x.e.Revision(), step.Key, 200)
		deny(t, err)
		prior, _ := old.Stage(step.Key)
		if prior.Observation != nil {
			_, err = x.e.Observe(x.e.Revision(), *prior.Observation, 200)
			deny(t, err)
		}
		x.flushReady()
	}
	if x.shared.Index() != originalIndex {
		t.Fatal("noop wrote new management command")
	}
	x.save(x.e.Finish(x.e.Revision(), 200))
	if x.e.Status() != "Succeeded" {
		t.Fatal("noop verification incomplete")
	}
	key := ResourceKey("task", "tenant", "php-mysql", "db")
	x.now = 210
	x.observe(key, false, false)
	if x.e.Status() != "Succeeded" || x.e.Health(210) != "Degraded" || expired(x.e).Health(300) != "Unknown" {
		t.Fatal("operation completion confused with current health")
	}
}

func TestExecutionStopSettlesUnknownAndClosesInReverseWithoutDeletingRetain(t *testing.T) {
	x := runFixture(t)
	key := x.b.Steps()[0].Key
	cmd := x.prepare(key)
	x.send(key)
	r := x.apply(cmd)
	x.save(x.e.Unknown(x.e.Revision(), key))
	x.save(x.e.Stop(x.f.c, "admin", x.e.Revision()))
	if x.e.CanRelease(key) {
		t.Fatal("unknown submission allowed cleanup")
	}
	_, err := x.e.Close(x.e.Revision())
	deny(t, err)
	x.save(x.e.Commit(x.e.Revision(), key, cmd, r))
	if !x.e.CanRelease(key) {
		t.Fatal("settled leaf blocked")
	}
	x.observe(key, false, true)
	x.save(x.e.Close(x.e.Revision()))
	if x.e.Status() != "Closed" {
		t.Fatal("original cleanup incomplete")
	}
	x = runFixture(t)
	for _, s := range x.b.Steps() {
		x.completeStep(s.Key)
	}
	x.save(x.e.Stop(x.f.c, "admin", x.e.Revision()))
	volume := ResourceKey("volume", "tenant", "php-mysql", "mysql-data")
	if x.e.CanRelease(volume) {
		t.Fatal("live consumer allowed volume closure")
	}
	for _, s := range x.b.ReleaseOrder() {
		if s.Node == "" {
			continue
		}
		if !x.e.CanRelease(s.Key) {
			t.Fatal("reverse order cannot release", s.Kind)
		}
		x.now++
		x.observe(s.Key, false, true)
	}
	x.save(x.e.Close(x.e.Revision()))
	v, _ := x.e.Stage(volume)
	if v.Observation.Gone || !v.Observation.Retained {
		t.Fatal("retained data erased on down")
	}
}

func TestExecutionCurrentPolicyBlocksSendAndAdminStillSettlesOriginal(t *testing.T) {
	x := runFixture(t)
	key := x.b.Steps()[0].Key
	cmd := x.prepare(key)
	x.send(key)
	r := x.apply(cmd)
	u, _ := x.f.c.User("alice")
	revision := u.Revision
	u.Revision = 0
	u.Enabled = false
	var err error
	x.f.c, err = x.f.c.PutUser("admin", revision, u)
	if err != nil {
		t.Fatal(err)
	}
	x.save(x.e.Commit(x.e.Revision(), key, cmd, r))
	x.observe(key, true, false)
	other := x.b.Steps()[1].Key
	_, _, err = x.e.Prepare(x.f.c, x.e.Revision(), other, state.Object{}, 100)
	deny(t, err)
	x.save(x.e.Stop(x.f.c, "admin", x.e.Revision()))
	x.observe(key, false, true)
	x.save(x.e.Close(x.e.Revision()))
}

func TestExecutionSnapshotRejectsErasedUnknownOrChangedCommand(t *testing.T) {
	x := runFixture(t)
	key := x.b.Steps()[0].Key
	x.prepare(key)
	x.send(key)
	x.save(x.e.Unknown(x.e.Revision(), key))
	raw, err := x.e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*executionRecord){
		func(d *executionRecord) { d.Stages[0].Journal.Pending = nil }, func(d *executionRecord) { d.Stages[0].Command.RequestID = "fresh" }, func(d *executionRecord) { d.Stages[0].Command.Value = "changed" }, func(d *executionRecord) { d.Epoch++ }, func(d *executionRecord) { d.Stages = nil }, func(d *executionRecord) { d.CompletedAt = 100 }, func(d *executionRecord) {
			d.Stages[0].Result = &state.Result{Code: state.Applied, Index: 8, Revision: 8, Generation: 8}
		},
	} {
		var d executionRecord
		_ = json.Unmarshal(raw, &d)
		change(&d)
		bad, _ := json.Marshal(d)
		_, err = DecodeExecution(bad)
		deny(t, err)
	}
	before, _ := x.e.Encode()
	candidate, err := x.e.Pause(x.f.c, "admin", x.e.Revision(), true)
	if err != nil {
		t.Fatal(err)
	}
	if after, _ := x.e.Encode(); !bytes.Equal(before, after) || candidate.Revision() == x.e.Revision() {
		t.Fatal("failed fake sync would mutate published state")
	}
	stage, _ := x.e.Stage(key)
	if !strings.Contains(stage.Journal.Pending.Target.Spec, stage.Command.RequestID) {
		t.Fatal("original bytes not journaled")
	}
}

func TestExecutionValidationBindsEveryObservationAndWitnessToCanonicalPlan(t *testing.T) {
	x := restartingExecution(t)
	for _, step := range x.b.Steps() {
		x.completeStep(step.Key)
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	raw, err := x.e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(x.e.d.Plan)
	if err != nil || sha256.Sum256(plan) != x.b.Digest() {
		t.Fatal("canonical digest changed", err)
	}
	if decoded, err := DecodeExecution(raw); err != nil {
		t.Fatal(err)
	} else if encoded, err := decoded.Encode(); err != nil || !bytes.Equal(raw, encoded) {
		t.Fatal("schema1 canonical bytes changed", err)
	}
	for _, witness := range []bool{false, true} {
		count := len(x.e.d.Stages)
		if witness {
			count = len(x.e.d.CompletionWitness)
		}
		checked := 0
		for i := 0; i < count; i++ {
			for _, signature := range []bool{false, true} {
				var d executionRecord
				if err := json.Unmarshal(raw, &d); err != nil {
					t.Fatal(err)
				}
				var o *Observation
				if witness {
					o = &d.CompletionWitness[i]
				} else {
					o = d.Stages[i].Observation
				}
				if o == nil {
					continue
				}
				checked++
				if signature {
					o.Signature[0] ^= 1
				} else {
					o.Plan[0] ^= 1
					*o = signCompletion(x, *o) // valid owner signature, wrong plan
				}
				bad, _ := json.Marshal(d)
				if _, err := DecodeExecution(bad); err == nil {
					t.Fatalf("unchecked observation: witness=%v index=%d signature=%v", witness, i, signature)
				}
			}
		}
		if checked < 4 {
			t.Fatal("fixture must check multiple observations/witnesses", witness, checked)
		}
	}
	var forged executionRecord
	if json.Unmarshal(raw, &forged) != nil || forged.Plan.Checkers == nil {
		t.Fatal("frozen lifecycle plan missing")
	}
	forged.Plan.Checkers.Program.Services["web"][0].ID = "substituted"
	bad, _ := json.Marshal(forged)
	if _, err := DecodeExecution(bad); err == nil {
		t.Fatal("validated-plan digest bypassed frozen metadata validation")
	}
}
