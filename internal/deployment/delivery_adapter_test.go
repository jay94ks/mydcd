// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func acceptedDeliveryAdapterFixture(t *testing.T) (*fixture, PlanningContext, Blueprint, Delivery) {
	t.Helper()
	f, input, ctx, _ := externalFixture(t)
	input.MyDC.Delivery = &DeliveryDeclaration{}
	input.MyDC.Delivery.Enabled = true
	input.MyDC.Delivery.Source.Kind = "git"
	input.MyDC.Delivery.Source.Repository = "https://git.mydc.test/team/app.git"
	input.MyDC.Delivery.Source.Ref = "refs/heads/main"
	input.MyDC.Delivery.Source.Path = "app.yaml"
	if err := input.normalize(); err != nil {
		t.Fatal(err)
	}
	ctx.Features["git-cd"] = true
	b, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	i, err := NewInventory(ctx.Cluster, b.Scope().Tenant, b.Scope().App, b.Scope().Deployment)
	if err == nil {
		i, err = i.Begin(i.Revision(), f.c, ctx, b, "original", "user/original", 1, false)
	}
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewAcceptedDelivery(b, i, f.c)
	if err != nil {
		t.Fatal(err)
	}
	return f, ctx, b, d
}

func TestDeliveryIntentRebasePreservesOnlyCASAndUsageDifferences(t *testing.T) {
	_, _, b, _ := acceptedDeliveryAdapterFixture(t)
	clone := func() Blueprint {
		raw, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		next, err := DecodeBlueprint(raw)
		if err != nil {
			t.Fatal(err)
		}
		return next
	}
	rebased := clone()
	rebased.d.CatalogRevision++
	rebased.d.NetworkRevision++
	for index := range rebased.d.Steps {
		s := &rebased.d.Steps[index]
		s.Base, s.BasePresent = ObjectRef{s.Key, 55, 12}, true
		s.StableDNS = []ObjectRef{{"network/dns/current", 6, 3}}
	}
	for id, n := range rebased.d.Nodes {
		n.Used.CPU++
		n.Used.Memory += 4096
		rebased.d.Nodes[id] = n
	}
	if b.IntentDigest() == ([32]byte{}) || b.IntentDigest() != rebased.IntentDigest() || b.Digest() == rebased.Digest() {
		t.Fatal("CAS/readiness rebasing changed semantic selection or lost plan CAS")
	}
	for name, mutate := range map[string]func(*Blueprint){
		"tenant": func(n *Blueprint) { n.d.Tenant = "another" },
		"input": func(n *Blueprint) {
			service := n.d.Input.Services["web"]
			args := Arguments{"changed"}
			service.Command = &args
			n.d.Input.Services["web"] = service
		},
		"goal":   func(n *Blueprint) { n.d.Steps[0].Goal = goal(map[string]string{"changed": "goal"}) },
		"owner":  func(n *Blueprint) { n.d.Steps[0].Owner[0] ^= 1 },
		"retain": func(n *Blueprint) { n.d.Steps[0].Retain = !n.d.Steps[0].Retain },
		"generation": func(n *Blueprint) {
			for id, node := range n.d.Nodes {
				node.Generation++
				n.d.Nodes[id] = node
				break
			}
		},
		"capacity": func(n *Blueprint) {
			for id, node := range n.d.Nodes {
				node.Capacity.Memory++
				n.d.Nodes[id] = node
				break
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := clone()
			mutate(&n)
			if b.IntentDigest() == n.IntentDigest() {
				t.Fatal("changed semantic target accepted as the original choice")
			}
		})
	}
}

func TestDeliveryDefaultPlacementIsFrozenOnlyForRegisteredAppSources(t *testing.T) {
	f, ctx, b, _ := acceptedDeliveryAdapterFixture(t)
	ctx.DefaultNode = "node-a"
	frozen, err := CompileApp(b.d.Input, f.c, ctx)
	if err != nil || frozen.CDDefaultNode() != "node-a" {
		t.Fatal("source lost original default placement", err)
	}
	raw, err := frozen.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeBlueprint(raw)
	if err != nil || restored.CDDefaultNode() != "node-a" {
		t.Fatal("snapshot changed default placement", err)
	}
	input := b.d.Input
	input.MyDC.Delivery = nil
	ordinary, err := CompileApp(input, f.c, ctx)
	if err != nil || ordinary.CDDefaultNode() != "" {
		t.Fatal("non-CD format acquired a source default field", err)
	}
	ordinary.d.DefaultNode = "node-a"
	raw, _ = ordinary.Encode()
	if _, err := DecodeBlueprint(raw); err == nil {
		t.Fatal("non-CD checkpoint accepted a source default")
	}
	ctx.DefaultNode = "../node-a"
	if _, err := CompileApp(b.d.Input, f.c, ctx); err == nil {
		t.Fatal("invalid source placement frozen")
	}
}

func TestDeliverySyncUsesOriginalCoreAndPauseCollectsExactUnknown(t *testing.T) {
	f, ctx, b, _ := acceptedDeliveryAdapterFixture(t)
	body, err := marshalApp(b.d.Input)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDelivery(f.c, ctx, body)
	if err == nil {
		d, err = d.Sync(d.Revision(), f.c, ctx, "alice", "manual-sync", "user/original", 1, false)
	}
	if err != nil {
		t.Fatal(err)
	}
	selection, exists := d.Selection()
	e, active := d.Inventory().Execution()
	if !exists || !active || selection.Operation != "manual-sync" || e.d.Operation != selection.Operation || e.Blueprint().Digest() != selection.Plan || e.Blueprint().IntentDigest() != selection.Intent {
		t.Fatal("sync did not use the selected original Inventory/Execution")
	}
	key := e.Blueprint().Steps()[0].Key
	shared, _ := state.New("user/original")
	e, command, err := e.Prepare(f.c, e.Revision(), key, shared.Object(key), 100)
	if err != nil {
		t.Fatal(err)
	}
	e, sent, err := e.Send(f.c, e.Revision(), key, 100)
	if err != nil || command != sent {
		t.Fatal("original send", err)
	}
	e, err = e.Unknown(e.Revision(), key)
	if err == nil {
		d, err = d.AdvanceExecution(d.Revision(), e, shared)
	}
	if err == nil {
		d, err = d.Pause(d.Revision(), f.c, "alice", true, shared)
	}
	if err != nil {
		t.Fatal(err)
	}
	raw, err := d.Encode()
	if err == nil {
		d, err = DecodeDelivery(raw)
	}
	if err != nil {
		t.Fatal(err)
	}
	before, _ := d.Encode()
	if _, err = d.Sync(d.Revision(), f.c, ctx, "alice", "replacement", "user/original", 1, false); err == nil {
		t.Fatal("paused Unknown was replaced")
	}
	after, _ := d.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("failed selection mutated original")
	}
	var result state.Result
	shared, result, err = state.Apply(shared, shared.Index()+1, command)
	if err != nil || result.Code != state.Applied {
		t.Fatal("late original result", result, err)
	}
	e, _ = d.Inventory().Execution()
	e, err = e.Commit(e.Revision(), key, command, result)
	if err == nil {
		d, err = d.AdvanceExecution(d.Revision(), e, shared)
	}
	if err != nil {
		t.Fatal("paused original result could not settle", err)
	}
	e, _ = d.Inventory().Execution()
	stage, _ := e.Stage(key)
	if !d.Paused() || stage.Command == nil || *stage.Command != command || stage.Result == nil || *stage.Result != result {
		t.Fatal("late original settlement changed identity or resumed dispatch")
	}
}

func TestAutomaticSyncDoesNotManufactureManualDriftApproval(t *testing.T) {
	f, ctx, b, _ := acceptedDeliveryAdapterFixture(t)
	input := b.d.Input
	input.MyDC.Delivery.Sync.Mode = "automatic"
	input.MyDC.Delivery.Sync.Drift = "report"
	body, err := marshalApp(input)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDelivery(f.c, ctx, body)
	if err == nil {
		d, err = d.SyncAutomatic(d.Revision(), f.c, ctx, "first", "original", 1)
	}
	if err != nil {
		t.Fatal(err)
	}
	e, _ := d.Inventory().Execution()
	shared, _ := state.New("original")
	x := &executionFixture{f: f, b: e.Blueprint(), e: e, shared: shared, now: 100}
	for _, step := range x.b.Steps() {
		x.completeStep(step.Key)
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	inventory := d.Inventory()
	inventory, err = inventory.Advance(inventory.Revision(), x.e, x.shared)
	if err != nil {
		t.Fatal(err)
	}
	bridged, err := d.FollowInventory(d.Revision(), inventory)
	if err != nil {
		t.Fatal(err)
	}
	d, err = d.AdvanceExecution(d.Revision(), x.e, x.shared)
	if err != nil {
		t.Fatal(err)
	}
	direct, _ := d.Encode()
	stored, _ := bridged.Encode()
	if !bytes.Equal(direct, stored) {
		t.Fatal("checkpoint bridge published a different execution outcome")
	}
	for key, object := range x.shared.Objects("") {
		ctx.Current[key] = object
	}
	task := ResourceKey("task", "tenant", b.Scope().App, "web")
	object := ctx.Current[task]
	var desired GoalCommand
	if !object.Present || json.Unmarshal([]byte(object.Value), &desired) != nil {
		t.Fatal("missing original desired task")
	}
	var service ComposeService
	if json.Unmarshal(desired.Config, &service) != nil {
		t.Fatal("task config")
	}
	args := Arguments{"drifted"}
	service.Command = &args
	desired.Config = goal(service)
	object.Value = string(goal(desired))
	ctx.Current[task] = object
	d, err = d.Replan(d.Revision(), f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := d.Encode()
	_, err = d.SyncAutomatic(d.Revision(), f.c, ctx, "automatic-drift", "original", 1)
	var denied *InputError
	if !errors.As(err, &denied) || denied.Code != "CD_DRIFT_REPORT_ONLY" {
		t.Fatal("poll silently approved report-only drift", err)
	}
	after, _ := d.Encode()
	if !bytes.Equal(before, after) || d.d.Approval != nil {
		t.Fatal("denied poll manufactured approval")
	}
	manual, err := d.Sync(d.Revision(), f.c, ctx, "alice", "explicit-drift", "original", 1, false)
	if err != nil {
		t.Fatal("explicit operator could not choose the existing replacement transition", err)
	}
	transition, exists := manual.Transition()
	if !exists || transition.Mode != DeliveryUpdate || transition.Selection.Operation != "explicit-drift" {
		t.Fatal("manual drift bypassed the original retirement")
	}
}

func TestAcceptedDeliveryKeepsOneOriginalInventoryAndRejectsForeignExecutionAdoption(t *testing.T) {
	f, ctx, b, d := acceptedDeliveryAdapterFixture(t)
	i := d.Inventory()
	before, err := i.Encode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeDelivery(raw)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := restored.Inventory().Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("source attachment replaced original inventory/execution bytes")
	}
	foreign, err := NewInventory(ctx.Cluster, b.Scope().Tenant, b.Scope().App, b.Scope().Deployment)
	if err == nil {
		foreign, err = foreign.Begin(foreign.Revision(), f.c, ctx, b, "replacement", "user/other", 1, false)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.FollowInventory(d.Revision(), foreign); err == nil {
		t.Fatal("storage bridge adopted another execution")
	}
	if next, err := d.FollowInventory(d.Revision(), i); err != nil || next.Revision() != d.Revision() {
		t.Fatal("unchanged inventory created another source revision", err)
	}
	policy := d.Policy()
	policy.Source.Repository = "https://other.invalid/repo.git"
	if d.Policy().Source.Repository == policy.Source.Repository {
		t.Fatal("caller changed original source policy")
	}
}

func TestDeliveryIdenticalAuthenticatedPollPreservesManualApprovalAndOriginalRun(t *testing.T) {
	f, ctx, b, d := acceptedDeliveryAdapterFixture(t)
	body, err := marshalApp(b.d.Input)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(goal(d.d.Running))
	var ticket DeliveryFetch
	d, ticket, err = d.Fetch(d.Revision(), f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	input, err := RestoreFetchedDeliveryInput(ticket, strings.Repeat("1", 40), "app.yaml", body, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	d, err = d.Received(d.Revision(), f.c, ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := d.Candidate()
	d, err = d.Approve(d.Revision(), f.c, ctx, "alice", id)
	if err != nil {
		t.Fatal(err)
	}
	approval := bytes.Clone(goal(d.d.Approval))
	d, ticket, err = d.Fetch(d.Revision(), f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	input, err = RestoreFetchedDeliveryInput(ticket, strings.Repeat("1", 40), "app.yaml", body, 4<<20)
	if err == nil {
		d, err = d.Received(d.Revision(), f.c, ctx, input)
	}
	if err != nil {
		t.Fatal(err)
	}
	if next, _ := d.Candidate(); next != id || !bytes.Equal(approval, goal(d.d.Approval)) || !bytes.Equal(original, goal(d.d.Running)) {
		t.Fatal("unchanged poll rewrote approval or original running operation")
	}
	d, ticket, err = d.Fetch(d.Revision(), f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	changed := append(bytes.Clone(body), []byte("\n# changed immutable commit\n")...)
	input, err = RestoreFetchedDeliveryInput(ticket, strings.Repeat("2", 40), "app.yaml", changed, 4<<20)
	if err == nil {
		d, err = d.Received(d.Revision(), f.c, ctx, input)
	}
	if err != nil {
		t.Fatal(err)
	}
	if d.d.Approval != nil || !bytes.Equal(original, goal(d.d.Running)) {
		t.Fatal("new source kept old approval or replaced original run")
	}
}

// This captures the legacy two-pass controller's liveness counterexample.
// A valid health heartbeat changes bookkeeping, not the pending source intent.
// Passing this test proves the counterexample, not automatic CD completion.
func TestDeliveryHealthReportsInvalidateLegacyReplanWithoutChangingIntent(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("original")
	f.completeDelivery()
	input, err := ParseCompose(f.body)
	if err != nil {
		t.Fatal(err)
	}
	web := input.Services["web"]
	web.Environment = map[string]string{"NEXT": "1"}
	input.Services["web"] = web
	raw, err := marshalApp(input)
	if err != nil {
		t.Fatal(err)
	}
	f.receive(raw)
	selected, _ := f.d.CandidateSelection()
	originalExecution, _ := f.d.Inventory().Execution()
	key := ResourceKey("task", f.ctx.Tenant, f.ctx.Project, "web")
	current := f.ctx.Current[key]
	for tick := 0; tick < 3; tick++ {
		f.now++
		f.observe(key, true, false)
		f.syncDelivery()
		before := f.d.Revision()
		f.saveDelivery(f.d.Replan(before, f.f.c, f.ctx))
		next, _ := f.d.CandidateSelection()
		if f.d.Revision() == before || next.Candidate == selected.Candidate {
			t.Fatal("legacy heartbeat/replan counterexample was not exercised")
		}
		if next.Intent != selected.Intent {
			t.Fatal("heartbeat changed pending source intent")
		}
		active, _ := f.d.Inventory().Execution()
		if active.ActiveOperation() != originalExecution.ActiveOperation() || f.ctx.Current[key] != current {
			t.Fatal("read-only replan changed original execution/native goal")
		}
		selected = next
	}
	t.Log("three healthy observation/replan passes changed candidate coordinates while retaining the same pending intent and original execution; no new app/native operation")
	// A current-intent rebase can instead be consumed in the same state change.
	f.now++
	f.observe(key, true, false)
	f.syncDelivery()
	rebased, err := f.d.RebaseCandidate(f.d.Revision(), f.f.c, f.ctx)
	if err != nil {
		t.Fatal("same intent rebase", err)
	}
	accepted, err := rebased.SyncAutomatic(rebased.Revision(), f.f.c, f.ctx, "atomic-next", "submitter", 1)
	if err != nil {
		t.Fatal("same-view automatic acceptance", err)
	}
	if _, pending := accepted.Transition(); !pending {
		t.Fatal("changed native goal skipped its original retirement transition")
	}
	changed := f.ctx
	changed.Nodes = map[string]PlanningNode{}
	for id, node := range f.ctx.Nodes {
		node.Capacity.Memory++
		changed.Nodes[id] = node
	}
	if _, err = f.d.RebaseCandidate(f.d.Revision(), f.f.c, changed); err == nil {
		t.Fatal("changed admission was rebased as the original intent")
	}

}
