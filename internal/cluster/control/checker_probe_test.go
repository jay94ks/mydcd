// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Two installed member keys, actual planner/FSM/Binding/signature validation;
// acceptance and native facts are injected, not real transport/native success.
func checkerProbePermitFixture(t *testing.T) (*backupCoreFixture, CheckerProbeRequest, checker.ProbeCall, [32]byte, [32]byte) {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	a := f.node
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{125}, 32))
	consumer, provider := [32]byte(a.Public().(ed25519.PublicKey)), [32]byte(b.Public().(ed25519.PublicKey))
	for _, scope := range []string{"", "tenant"} {
		resources, _ := f.p.Resources(f.s)
		limit, ok := resources.Quotas.Limit(scope, "node-b")
		if !ok {
			t.Fatal("missing installed target quota")
		}
		expected := limit.Revision
		limit.Revision = 0
		limit.Capacity = workload.Resources{CPU: 4e9, Memory: 256 << 20}
		managedDNSChange(t, f, "probe-target-quota-"+scope, "set-node-quota", expected, limit, state.Applied)
	}
	managedDNSChange(t, f, "probe-policy", "set-lifecycle-policy", 0, checkerPolicy(), state.Applied)
	managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first", func(input *deployment.Compose, ctx *deployment.PlanningContext) {
		alpha := input.Services["web"]
		delete(input.Services, "web")
		beta := alpha
		beta.MyDC.Node = "node-b"
		beta.Networks = map[string]deployment.Attachment{"lan": {IPv4: "10.80.2.10", Aliases: []string{"second"}}}
		input.Services["alpha"], input.Services["beta"] = alpha, beta
		input.MyDC.Lifecycle = &deployment.LifecycleDeclaration{Checks: []deployment.LifecycleCheck{{ID: "inspect", Phase: contract.Liveness, LifecycleTemplate: deployment.LifecycleTemplate{Builtin: "file", Parameters: deployment.LifecycleParameters(`{"service":"beta","path":"/ready","kind":"regular"}`)}}}}
		ctx.Features["lifecycle"] = true // core planning input, not advertised live support
	})
	for _, node := range []string{"node-a", "node-b"} {
		f.node = a
		if node == "node-b" {
			f.node = b
		}
		managedDNSTaskCoreSubmit(t, f, "first", deployment.ResourceKey("network-ref", "tenant", "first", "lan/"+node), true, state.Applied)
	}
	f.node = a
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, a), state.Applied)
	for _, name := range []string{"alpha", "beta"} {
		f.node = a
		if name == "beta" {
			f.node = b
		}
		key := deployment.ResourceKey("task", "tenant", "first", name)
		managedDNSTaskCoreSubmit(t, f, "first", key, true, state.Applied)
		managedDNSTaskCoreProgress(t, f, "first", "bind-inputs", key, nil)
		apps, _ := f.p.Apps(f.s)
		execution, _ := apps.Execution("tenant", "first")
		stage, _ := execution.Stage(key)
		observed := *stage.Observation
		observed.Sequence++
		observed.StartedAt = int64(time.Second)
		boot := sha256.Sum256([]byte(name + "-boot"))
		observed.OwnerBoot = hex.EncodeToString(boot[:])
		observed.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(observed))
		managedDNSTaskCoreProgress(t, f, "first", "observe", key, &observed)
	}
	f.node = a
	apps, _ := f.p.Apps(f.s)
	taskKey := deployment.ResourceKey("task", "tenant", "first", "alpha")
	o := f.s.Object(taskKey)
	task := deployment.ObjectRef{Key: taskKey, Generation: o.Generation, Revision: o.Revision}
	binding, ok := apps.Binding(task)
	if !ok {
		t.Fatal("missing coordinator binding")
	}
	goal, err := schema.Decode[deployment.GoalCommand]([]byte(o.Value))
	if err != nil {
		t.Fatal(err)
	}
	service, err := schema.Decode[deployment.ComposeService](goal.Config)
	if err != nil {
		t.Fatal(err)
	}
	p := service.LifecycleProgram
	check := p.AppChecks[0]
	source, err := p.CheckSourceDigest(check)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.Request{Schema: 1, Cluster: hex.EncodeToString(f.p.Cluster[:]), Tenant: "tenant", App: "first", Checker: check.ID, SourceDigest: hex.EncodeToString(source[:]), Phase: check.Phase, Parameters: check.Parameters}
	for _, name := range []string{"alpha", "beta"} {
		key := deployment.ResourceKey("task", "tenant", "first", name)
		obj := f.s.Object(key)
		claim, ok := apps.Claim("tenant", "first", deployment.ObjectRef{Key: key, Generation: obj.Generation, Revision: obj.Revision})
		if !ok || claim.Observation == nil {
			t.Fatal("missing signed native fact")
		}
		obs := claim.Observation
		request.Targets = append(request.Targets, contract.Target{Service: name, TaskKey: key, NativeID: obs.Native, Owner: hex.EncodeToString(obs.Owner[:]), OwnerBoot: obs.OwnerBoot, StartedAt: time.Unix(0, obs.StartedAt).UTC().Format(time.RFC3339Nano), Generation: obj.Generation, Revision: obj.Revision})
	}
	d := checker.Definition{ProgramDigest: hex.EncodeToString(p.Program[:]), PolicyRevision: p.Policy.Revision, Timing: check.Timing, Request: request}
	m, err := checker.New(d, 10000)
	if err != nil {
		t.Fatal(err)
	}
	m, run, err := m.Plan(10000)
	if err != nil {
		t.Fatal(err)
	}
	m, err = m.Dispatch(run.Request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	run = *m.Checkpoint().Active
	call := checker.ProbeCall{Schema: 1, Binding: checker.ProbeBinding(run.Request), Sequence: 1, DeadlineUnixMilli: run.Request.DeadlineUnixMilli, Kind: "file", File: &contract.FileProbe{Service: "beta", Path: "/ready", Kind: "regular"}}
	q := CheckerProbeRequest{Schema: 1, Task: task, Binding: binding.Digest(), Run: run, PolicyRevision: p.Policy.Revision, Sequence: call.Sequence, Kind: call.Kind, Service: "beta", Payload: call.Digest(), DeadlineUnixMilli: call.DeadlineUnixMilli, At: 10000}
	return f, q, call, consumer, provider
}

func TestCheckerProbePermitRequiresExactTwoOwnerAppRunAndFreshFacts(t *testing.T) {
	f, q, call, consumer, provider := checkerProbePermitFixture(t)
	for _, caller := range [][32]byte{consumer, provider} {
		permit, err := f.p.CheckerProbePermit(f.s, caller, q)
		if err != nil || !permit.Matches(q, call) || permit.Consumer != consumer || permit.Provider != provider || permit.Target.Service != "beta" {
			t.Fatal("original two-owner delegation denied", permit, err)
		}
		changed := call
		query := *call.File
		query.Path = "/private"
		changed.File = &query
		if permit.Matches(q, changed) {
			t.Fatal("call payload substituted after grant")
		}
	}
	// A permit binds the payload hash, but its selected service must also
	// match the typed payload itself before a provider touches its lease.
	wrongCall := call
	query := *call.File
	query.Service = "alpha"
	wrongCall.File = &query
	wrongHeader := q
	wrongHeader.Payload = wrongCall.Digest()
	if grant, err := f.p.CheckerProbePermit(f.s, consumer, wrongHeader); err != nil || grant.Matches(wrongHeader, wrongCall) {
		t.Fatal("header/payload service mismatch reached native authorization", err)
	}
	for label, mutate := range map[string]func(*CheckerProbeRequest){
		"run": func(q *CheckerProbeRequest) { q.Run.Sequence++ }, "prepared": func(q *CheckerProbeRequest) { q.Run.Phase = checker.Prepared },
		"digest": func(q *CheckerProbeRequest) { q.Run.RequestDigest[0]++ }, "binding": func(q *CheckerProbeRequest) { q.Binding[0]++ },
		"service": func(q *CheckerProbeRequest) { q.Service = "alpha" }, "kind": func(q *CheckerProbeRequest) { q.Kind = "exec" },
		"policy": func(q *CheckerProbeRequest) { q.PolicyRevision++ }, "deadline": func(q *CheckerProbeRequest) { q.At = q.DeadlineUnixMilli },
		"stop": func(q *CheckerProbeRequest) { q.Stop = &checker.ShutdownScope{Operation: "invented", Revision: 1} },
	} {
		raw, _ := json.Marshal(q)
		var changed CheckerProbeRequest
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture copy")
		}
		mutate(&changed)
		if _, err := f.p.CheckerProbePermit(f.s, consumer, changed); err == nil {
			t.Fatal("changed remote authority accepted", label)
		}
	}
	foreign := [32]byte(f.admin.Public().(ed25519.PublicKey))
	if foreign == consumer || foreign == provider {
		foreign = [32]byte{45}
	}
	if _, err := f.p.CheckerProbePermit(f.s, foreign, q); err == nil {
		t.Fatal("foreign caller used delegated probe")
	}
	advanced := q
	advanced.At++
	if advanced.HeaderDigest() != q.HeaderDigest() {
		t.Fatal("fresh observation time changed original call identity")
	}
	var owner contract.Target
	for _, target := range q.Run.Request.Targets {
		if target.Service == "beta" {
			owner = target
		}
	}
	if parsed, err := identity.ParseKey(owner.Owner); err != nil || parsed != provider {
		t.Fatal("fixture is not a foreign owner")
	}
	goal, err := schema.Decode[deployment.GoalCommand]([]byte(f.s.Object(q.Task.Key).Value))
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := schema.Decode[deployment.ComposeService](goal.Config)
	if err != nil || declaration.LifecycleProgram == nil {
		t.Fatal("missing original program", err)
	}
	program := declaration.LifecycleProgram
	definition, _, err := program.AppProbeDefinition(q.Run, nil)
	if err != nil {
		t.Fatal(err)
	}
	for label, mutate := range map[string]func(*CheckerProbeRequest){
		"namespace": func(q *CheckerProbeRequest) {
			q.Run.Request.Targets[1].TaskKey = deployment.ResourceKey("task", "foreign", "first", "beta")
		},
		"native": func(q *CheckerProbeRequest) { q.Run.Request.Targets[1].NativeID = "foreign-native" },
		"epoch": func(q *CheckerProbeRequest) {
			hash := sha256.Sum256([]byte("other-boot"))
			q.Run.Request.Targets[1].OwnerBoot = hex.EncodeToString(hash[:])
		},
		"instance": func(q *CheckerProbeRequest) {
			q.Run.Request.Targets[1].StartedAt = time.Unix(0, 2*int64(time.Second)).UTC().Format(time.RFC3339Nano)
		},
		"owner":               func(q *CheckerProbeRequest) { q.Run.Request.Targets[1].Owner = hex.EncodeToString(consumer[:]) },
		"coordinator-native":  func(q *CheckerProbeRequest) { q.Run.Request.Targets[0].NativeID = "invented-coordinator" },
		"expired-observation": func(q *CheckerProbeRequest) { q.At += (int64(AppObservationMaxAge) + 1) * 1000 },
	} {
		raw, _ := json.Marshal(q)
		var changed CheckerProbeRequest
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("copy header")
		}
		mutate(&changed)
		def := definition
		def.Request = changed.Run.Request
		def.Request.RunID = ""
		def.Request.DeadlineUnixMilli = 0
		m, err := checker.New(def, changed.At)
		if err != nil {
			t.Fatal(label, err)
		}
		m, run, err := m.Plan(changed.At)
		if err != nil {
			t.Fatal(label, err)
		}
		m, err = m.Dispatch(run.Request.RunID)
		if err != nil {
			t.Fatal(label, err)
		}
		changed.Run = *m.Checkpoint().Active
		changed.DeadlineUnixMilli = changed.Run.Request.DeadlineUnixMilli
		rebound := call
		rebound.Binding = checker.ProbeBinding(changed.Run.Request)
		rebound.DeadlineUnixMilli = changed.DeadlineUnixMilli
		changed.Payload = rebound.Digest()
		// Rebind with the real Machine: these counterexamples must fail the
		// namespace/binding/signed-native checks, not merely a stale run hash.
		if _, _, err = program.AppProbeDefinition(changed.Run, nil); err != nil {
			t.Fatal("counterexample is not a valid run", label, err)
		}
		current := f.s
		if label == "expired-observation" {
			current = expireAll(t, f.p, f.s, f.node, uint64(changed.At/1000))
		}
		if _, err = f.p.CheckerProbePermit(current, consumer, changed); err == nil {
			t.Fatal("valid run widened current native facts", label)
		}
	}
}

func TestCheckerProbePermitDoesNotReuseAuthorityAfterTargetNodeRevocation(t *testing.T) {
	f, q, _, consumer, provider := checkerProbePermitFixture(t)
	original := f.s
	if _, err := f.p.CheckerProbePermit(original, consumer, q); err != nil {
		t.Fatal("original delegation", err)
	}
	users, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, ok := users.Tenant("tenant")
	if !ok {
		t.Fatal("original tenant missing")
	}
	managedDNSChange(t, f, "revoke-probe-target-node", "set-nodes", tenant.Revision, NodeAssignment{Tenant: "tenant", Nodes: []string{"node-a"}}, state.Applied)
	for _, caller := range [][32]byte{consumer, provider} {
		if _, err := f.p.CheckerProbePermit(f.s, caller, q); err == nil {
			t.Fatal("target authority reused across state reads")
		}
	}
	// This is an explicit old immutable input to the pure policy, not a live
	// quorum permit. Evaluating a newer view must not mutate the old one.
	if _, err := f.p.CheckerProbePermit(original, consumer, q); err != nil {
		t.Fatal("new read mutated original immutable view", err)
	}
}
