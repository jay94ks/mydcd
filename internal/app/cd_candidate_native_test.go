// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/tests/gitfixture"
	"github.com/moby/moby/client"
	"testing"
)

func TestRQ4CDCandidateDecisionsAndEventsNative(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppCDDecision, true)
}

// Only public dependency/dispatch coordinates, never Goal/command bodies or
// credential material. Preserve the exact blocker before fixture cleanup.
func cdNativeRetirementGraph(i deployment.Inventory, retirement deployment.RetirementView) map[string]any {
	stages := make([]map[string]any, 0)
	status := ""
	if e, ok := i.Execution(); ok {
		status = e.Status()
		for _, step := range e.Steps() {
			s, _ := e.Stage(step.Key)
			phase := uint8(0)
			if s.Journal.Pending != nil {
				phase = uint8(s.Journal.Pending.Phase)
			}
			stages = append(stages, map[string]any{"key": step.Key, "pending": phase, "result": s.Result})
		}
	}
	claims := make([]map[string]any, 0)
	for _, claim := range i.Claims() {
		claims = append(claims, map[string]any{"key": claim.Step.Key, "kind": claim.Step.Kind, "generation": claim.Result.Generation, "revision": claim.Result.Revision, "removed": claim.Removed, "retained": claim.Retained, "dependencies": claim.Step.Dependencies})
	}
	targets := make([]map[string]any, 0)
	for _, target := range retirement.Targets {
		phases := map[string]any{}
		for name, m := range map[string]*deployment.Mutation{"drain": target.Drain, "proof": target.Proof, "delete": target.Delete} {
			if m == nil {
				continue
			}
			phase := uint8(0)
			if m.Journal.Pending != nil {
				phase = uint8(m.Journal.Pending.Phase)
			}
			phases[name] = map[string]any{"request": m.Command.RequestID, "expected": m.Command.Expected, "pending": phase, "result": m.Result}
		}
		c := target.Original
		targets = append(targets, map[string]any{"key": c.Step.Key, "kind": c.Step.Kind, "owner": c.Step.Node, "closed": target.Closed, "can_retire": i.CanRetire(c.Step.Key), "phases": phases})
	}
	return map[string]any{"id": retirement.ID, "claims": claims, "targets": targets, "execution": status, "stages": stages}
}

// Shares the ordinary app fixture and the existing decision assertions. SQL,
// cross-node TUN and generic field override regressions are separate evidence.
func verifyManagedCDDecisions(t *testing.T, ctx context.Context, r *Runtime, root string, user userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), source *gitfixture.Fixture, original []byte, first string) []*Runtime {
	t.Helper()
	remote := prepareManagedHandoffControl(t, ctx, root, r, user, peer, session, p, read, change)
	owners := [2]*Runtime{r, remote}
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	cli := func(args ...string) []byte {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
		if err != nil {
			var receipt struct {
				Result    *state.Result
				Code      string
				InputCode string
			}
			_ = json.Unmarshal(out, &receipt)
			t.Fatal("actual CD CLI", args, err, string(diagnostic), receipt.Code, receipt.InputCode, receipt.Result)
		}
		return out
	}
	delivery := func() (control.Apps, deployment.Delivery) {
		t.Helper()
		apps, err := p.ReadApps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		d, ok := apps.Delivery("tenant", "app")
		if !ok {
			t.Fatal("original app lacks registered CD source")
		}
		return apps, d
	}
	candidate := func(commit string) bool {
		_, d := delivery()
		choice, ok := d.CandidateSelection()
		return ok && choice.Commit == commit && d.SourceError() == ""
	}
	running := func(commit, revision string) bool {
		apps, d := delivery()
		selection, ok := d.Selection()
		e, active := apps.Execution("tenant", "app")
		if !ok || !active || selection.Commit != commit || selection.Operation != e.ActiveOperation() || e.Status() != "Succeeded" {
			return false
		}
		status, err := r.workload.Status(ctx, key)
		if err != nil || !status.Ready {
			return false
		}
		native, err := r.docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
		return err == nil && native.Container.Config != nil && slices.Contains(native.Container.Config.Env, "REVISION="+revision)
	}
	wait("actual HTTPS Git initial candidate", func() bool { return candidate(first) })
	_, d := delivery()
	verifyCDCandidateDecisionNative(t, ctx, &owners, source, original, d.Policy(), key, cli, wait, delivery, candidate, running, root, user, peer, change, "app", "web")
	return []*Runtime{remote}
}

// Runs as a bounded branch of the existing two-owner fixture, sharing its real
// HTTPS/credential/CLI/DB/Docker setup and rollback. It does not repeat the
// unrelated R1 handoff/field-override/source-isolation sequence.
func verifyCDCandidateDecisionNative(t *testing.T, ctx context.Context, owners *[2]*Runtime, source *gitfixture.Fixture, original []byte, policy deployment.DeliveryDeclaration, key string, cli func(...string) []byte, wait func(string, func() bool), delivery func() (control.Apps, deployment.Delivery), candidate func(string) bool, running func(string, string) bool, root string, admin userauth.Client, peer mydcp.Peer, change func(string, string, uint64, any), names ...string) map[string]any {
	t.Helper()
	appName, serviceName := "next", "endpoint"
	if len(names) == 2 {
		appName, serviceName = names[0], names[1]
	} else if len(names) != 0 {
		t.Fatal("explicit app/service names must be supplied together")
	}

	// cd pause/resume have no preview: pause, check the CD record, repeat
	// with the same operation ID (it finishes the same change), then resume.
	// The CD record revision is read just before sending; a source poll or
	// observation between the read and the send is a correct CAS rejection,
	// so the command is run again under a new ID that reads the record again.
	toggle := func(verb string) string {
		t.Helper()
		for attempt := 1; ; attempt++ {
			id := fmt.Sprintf("rq4-cd-%s-%d", verb, attempt)
			out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), []string{"cd", verb, appName, "--tenant", "tenant", "--id", id}, nil)
			if err == nil {
				return id
			}
			if attempt == 3 || !strings.Contains(string(diagnostic), "the record changed") {
				t.Fatal("actual CD CLI", verb, id, err, string(diagnostic), string(out))
			}
		}
	}
	pause := toggle("pause")
	cli("cd", "pause", appName, "--tenant", "tenant", "--id", pause)
	if _, d := delivery(); !d.Paused() {
		t.Fatal("actual CD pause")
	}
	resume := toggle("resume")
	cli("cd", "resume", appName, "--tenant", "tenant", "--id", resume)
	if _, d := delivery(); d.Paused() {
		t.Fatal("actual CD resume")
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	gate, err := (access.User{ID: "cd-gate", Username: "cd-gate", Enabled: true, AutomationOnly: true}).WithPrivateKeyOperations("release-gate", [32]byte(pub), []string{"cd-approve", "cd-reject"})
	if err != nil {
		t.Fatal(err)
	}
	change("rq4-create-cd-gate", "put-user", 0, gate)
	change("rq4-cd-gate-membership", "set-membership", 0, access.Membership{Tenant: "tenant", User: gate.ID, Role: access.Manager, Enabled: true})
	gateClient := admin
	gateClient.OperationReason = &control.OperationReason{Text: "release gate decision", IncidentID: "release-42"}
	gateSession, err := gateClient.Login(ctx, peer, gate.Username, private)
	if err != nil {
		t.Fatal("actual restricted credential login", err)
	}
	home := filepath.Join(root, "rq4-gate-home")
	if err = os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	send := func(id, action string, expected uint64, payload any) control.UserOperation {
		t.Helper()
		raw, _ := json.Marshal(payload)
		op, err := gateClient.Prepare(ctx, peer, gateSession, id, control.Change{Schema: 1, Principal: gateSession.User, Action: action, Expected: expected, Payload: raw})
		if err != nil {
			t.Fatal("actual gate preparation", err)
		}
		if _, err = userauth.StageOperation(home, gateClient, op); err != nil {
			t.Fatal("durable original gate intent", err)
		}
		reply, err := gateClient.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal("actual restricted gate operation", action, err)
		}
		if err = userauth.RecordOperationResult(home, gateClient, gateSession, op, *reply.Result); err != nil {
			t.Fatal(err)
		}
		return op
	}
	decision := func(action, id string) control.UserOperation {
		t.Helper()
		row, ok, err := composeCDNativeView(ctx, gateClient, peer, gateSession, appName)
		if err != nil || !ok || row.CD == nil || row.CD.Candidate == nil {
			t.Fatal("current public decision target", err)
		}
		return send(id, action, row.CD.Revision, control.AppCDDecisionChange{Tenant: "tenant", App: appName, Candidate: row.CD.Candidate.Candidate, Target: row.CD.Target})
	}
	before, err := (*owners)[0].workload.Status(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	second := source.Commit(nativeGitServiceRevision(t, original, "2", &policy, serviceName))
	wait("RQ4 manual candidate from actual HTTPS Git", func() bool { return candidate(second) })
	_, d := delivery()
	_, ok := d.CandidateSelection()
	if !ok {
		t.Fatal("missing candidate")
	}
	decision("cd-reject", "rq4-candidate-reject")
	wait("RQ4 durable rejected candidate", func() bool { _, d := delivery(); return d.Rejected() })
	ads := source.Stats().Advertisements
	wait("RQ4 same source fetched twice without resurrection", func() bool {
		_, d := delivery()
		return source.Stats().Advertisements >= ads+2 && candidate(second) && d.Rejected()
	})
	held, err := (*owners)[0].workload.Status(ctx, key)
	if err != nil || held.NativeID != before.NativeID || held.StartedAt != before.StartedAt {
		t.Fatal("rejected candidate changed native", err)
	}
	cli("cd", "replan", appName, "--tenant", "tenant", "--id", "rq4-reconsider-candidate")
	_, d = delivery()
	_, ok = d.CandidateSelection()
	if !ok || d.Rejected() {
		t.Fatal("explicit reconsider failed")
	}
	approved := decision("cd-approve", "rq4-candidate-approve")
	wait("RQ4 approved manual candidate executes through actual SDK", func() bool { return running(second, "2") })
	after, err := (*owners)[0].workload.Status(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := gateClient.Operation(ctx, peer, approved, false)
	if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
		t.Fatal("actual original gate replay", err)
	}
	replay, err := (*owners)[0].workload.Status(ctx, key)
	if err != nil || replay.NativeID != after.NativeID || replay.StartedAt != after.StartedAt {
		t.Fatal("original candidate approval executed twice", err)
	}
	// The credential has no permission for a new non-CD management change.
	view, err := gateClient.Query(ctx, peer, gateSession, "apps", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	var selected *control.AppView
	for _, row := range view.Apps {
		if row.App == appName {
			selected = &row
		}
	}
	if selected == nil || selected.DownTarget == nil {
		t.Fatal("missing current original app target for denial")
	}
	payload, _ := json.Marshal(control.AppDown{Tenant: "tenant", App: appName, Operation: "forbidden-gate-down", Target: selected.DownTarget})
	denied, err := gateClient.Prepare(ctx, peer, gateSession, "rq4-denied-gate-down", control.Change{Schema: 1, Principal: gateSession.User, Action: "down-app", Expected: selected.Revision, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = userauth.StageOperation(home, gateClient, denied); err != nil {
		t.Fatal(err)
	}
	deniedReply, deniedErr := gateClient.Operation(ctx, peer, denied, false)
	var deniedCode *userauth.Error
	rejected := deniedReply.Result != nil && deniedReply.Result.Code == state.Forbidden
	if errors.As(deniedErr, &deniedCode) && deniedCode.Code == "denied" {
		rejected = true
	}
	if !rejected {
		t.Fatal("expected explicit CD-only credential denial", deniedErr, deniedReply.Code, deniedReply.Result)
	}
	third := source.Commit(nativeGitServiceRevision(t, original, "3", &policy, serviceName))
	wait("RQ4 fresh candidate does not inherit old approval", func() bool {
		if !candidate(third) {
			return false
		}
		view, err := (*owners)[0].Engine().Read(ctx, false)
		if err != nil {
			return false
		}
		users, err := (*owners)[0].controlPolicy.Catalog(view.State)
		if err != nil {
			return false
		}
		_, d := delivery()
		return !d.ExplicitApprovalReady(users)
	})
	_, d = delivery()
	selection, ok := d.CandidateSelection()
	if !ok {
		t.Fatal("fresh CLI candidate absent")
	}
	args := []string{"cd", "approve", appName, hex.EncodeToString(selection.Candidate[:]), "--tenant", "tenant", "--id", "rq4-cli-candidate-approve"}
	cli(args...)
	wait("RQ4 actual candidate approval CLI executes", func() bool { return running(third, "3") })
	cli(args...)
	apps, _ := delivery()
	rows := apps.Records()
	found := false
	for _, row := range rows {
		if row.Tenant == "tenant" && row.App == appName {
			found = true
		}
	}
	if !found {
		t.Fatal("ordinary app inventory disappeared")
	}
	cli("cd", "show", appName, "--tenant", "tenant")
	wait("RQ4 durable CD event transitions through the real user API", func() bool {
		q := eventlog.Query{Tenant: "tenant", App: appName, Limit: 100}
		seen := map[string]bool{}
		position := map[string]int{}
		ordinal := 0
		for {
			page, err := gateClient.EventsPage(ctx, peer, gateSession, q)
			if err != nil {
				t.Fatal("actual CD event read", err)
			}
			for _, event := range page.Items {
				seen[event.Kind] = true
				if event.Detail.Commit == second {
					if _, found := position[event.Kind]; !found {
						position[event.Kind] = ordinal
					}
					if (event.Kind == "cd-approved" || event.Kind == "cd-rejected") && (event.Detail.Reason != "release gate decision" || event.Detail.IncidentID != "release-42" || event.Detail.Actor != gate.ID) {
						t.Fatal("CD event lost original decision metadata")
					}
				}
				ordinal++
			}
			if !page.More {
				break
			}
			q.After = page.Cursor
		}
		for _, kind := range []string{"cd-paused", "cd-resumed", "cd-candidate-created", "cd-approval-required", "cd-rejected", "cd-approved", "cd-sync-started", "cd-sync-succeeded"} {
			if !seen[kind] {
				return false
			}
		}
		previous := -1
		for _, kind := range []string{"cd-candidate-created", "cd-approval-required", "cd-rejected", "cd-approved", "cd-sync-started", "cd-sync-succeeded"} {
			at, found := position[kind]
			if !found {
				return false
			}
			if at <= previous {
				t.Fatal("CD events do not preserve the accepted transition order", kind)
			}
			previous = at
		}
		return true
	})
	return map[string]any{"rejected_and_approved_commit": second, "cli_approved_commit": third, "same_source_refetch": true, "retained_native_while_rejected": held.NativeID, "approved_native": after.NativeID, "original_replay_without_new_start": true, "restricted_gate_user": gate.ID, "scope": "actual HTTPS Git, two owners, restricted user login/decisions/replay/down denial, CLI replan/status, ordinary app inventory and Docker"}
}

func composeCDNativeView(ctx context.Context, c userauth.Client, peer mydcp.Peer, session access.Session, appName string) (control.AppView, bool, error) {
	after := ""
	for {
		reply, err := c.AppPage(ctx, peer, session, "tenant", after)
		if err != nil {
			return control.AppView{}, false, err
		}
		for _, row := range reply.Apps {
			if row.App == appName {
				return row, true, nil
			}
		}
		if reply.AppsNext == "" {
			return control.AppView{}, false, nil
		}
		after = reply.AppsNext
	}
}
