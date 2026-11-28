// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/moby/moby/client"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Uses only the fixture's registered Task. The existing fixture owns baseline,
// down/unknown settlement, Docker cleanup and leadership rollback. Restart is
// intentionally not reversed by another restart, which would lose its history.
func verifyUserTaskRestartNative(t *testing.T, ctx context.Context, r *Runtime, root string, c userauth.Client, peer sfcp.Peer, session access.Session) {
	t.Helper()
	selection := containerops.Selection{App: "app", Service: "web"}
	planned, err := c.QueryTaskRestart(ctx, peer, session, "tenant", true, control.TaskRestartQuery{Selection: selection})
	if err != nil || planned.TaskRestartPlan == nil {
		t.Fatal("real restart plan", err)
	}
	plan := *planned.TaskRestartPlan
	before, err := r.docker.API.ContainerInspect(ctx, plan.Container.NativeID, client.ContainerInspectOptions{})
	if err != nil || before.Container.State == nil {
		t.Fatal("original native baseline", err)
	}
	owned, err := r.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner="+r.docker.Owner)})
	if err != nil {
		t.Fatal(err)
	}
	other := map[string]string{}
	for _, item := range owned.Items {
		if item.ID != plan.Container.NativeID {
			v, err := r.docker.API.ContainerInspect(ctx, item.ID, client.ContainerInspectOptions{})
			if err != nil || v.Container.State == nil {
				t.Fatal(err)
			}
			other[item.ID] = v.Container.State.StartedAt
		}
	}
	run := func(args []string) []byte {
		t.Helper()
		if len(args) != 0 && args[0] == "compose" {
			args = append([]string{"--tenant", "tenant"}, args...)
		}
		out, diag, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
		if err != nil {
			t.Fatal("actual Task restart CLI", args, err, string(diag))
		}
		return out
	}
	node := plan.Container.Node
	var shown struct {
		Lifecycle *membership.NodeView `json:"lifecycle"`
	}
	if json.Unmarshal(run([]string{"node", "show", node}), &shown) != nil || shown.Lifecycle == nil || shown.Lifecycle.Scheduling.Enabled {
		t.Fatal("unexpected fixture scheduling baseline")
	}
	baseline := shown.Lifecycle.Scheduling.Revision
	run([]string{"-y", "node", "cordon", node, "--if-revision", strconv.FormatUint(baseline, 10), "--id", "native-cordon"})
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, diag, err := runManagedCLICommand(clean, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), []string{"-y", "node", "uncordon", node, "--if-revision", strconv.FormatUint(baseline+1, 10), "--id", "native-uncordon"}, nil)
		if err != nil {
			t.Error("restore scheduling baseline", err, string(diag))
		}
	}()
	// The accepted Task's read/Secret/Volume/native Start authority survives a
	// scheduling-only exclusion. This restart must still reach the real SDK.
	preview := run([]string{"compose", "restart", "-p", "app", "web", "--preview"})
	var actualPlan control.TaskRestartPlan
	if json.Unmarshal(preview, &actualPlan) != nil || actualPlan.Target != plan.Target {
		t.Fatal("CLI preview reselected original")
	}
	args := []string{"compose", "restart", "-p", "app", "web", "--operation", "native-restart-web"}
	run(args)
	var status *control.TaskRestartStatus
	for {
		reply, e := c.QueryTaskRestart(ctx, peer, session, "tenant", false, control.TaskRestartQuery{Selection: containerops.Selection{App: "app"}, Operation: "native-restart-web"})
		if e != nil {
			t.Fatal("accepted original status", e)
		}
		status = reply.TaskRestartStatus
		if status != nil && status.Control != nil && status.Control.Terminal() {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("original restart did not settle", ctx.Err())
		case <-time.After(40 * time.Millisecond):
		}
	}
	if status.Status != "completed" || status.Plan.Target != plan.Target || status.Control.Target.NativeID != plan.Container.NativeID {
		t.Fatal("same original restart did not complete", status)
	}
	after, err := r.docker.API.ContainerInspect(ctx, plan.Container.NativeID, client.ContainerInspectOptions{})
	if err != nil || after.Container.State == nil || after.Container.State.StartedAt == before.Container.State.StartedAt || after.Container.Config.Image != before.Container.Config.Image {
		t.Fatal("same native was not restarted", err)
	}
	for {
		view, err := r.Engine().Read(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		apps, err := r.controlPolicy.ReadApps(view.State)
		if err != nil {
			t.Fatal(err)
		}
		claim, ok := apps.Claim("tenant", "app", deployment.ObjectRef{Key: plan.Container.Instance, Generation: plan.Container.Generation, Revision: plan.Container.Revision})
		if ok && claim.Observation != nil && claim.Observation.Restart != nil && claim.Observation.Restart.User != nil && claim.Observation.Restart.User.Operation == "native-restart-web" {
			stamp, err := parseAppInstance(after.Container.State.StartedAt)
			if err != nil || claim.Observation.StartedAt != stamp {
				t.Fatal("wrong shared instance proof", err)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("completed private action not published to original Task", ctx.Err())
		case <-time.After(40 * time.Millisecond):
		}
	}
	started := after.Container.State.StartedAt
	run(args) // original operation journal/result, never replans today's lifetime
	replay, err := r.docker.API.ContainerInspect(ctx, plan.Container.NativeID, client.ContainerInspectOptions{})
	if err != nil || replay.Container.State == nil || replay.Container.State.StartedAt != started {
		t.Fatal("replay performed another restart", err)
	}
	if os.Getenv("SFC_TEST_RQ4_AUTOMATION") == "1" {
		verifyRestrictedTaskRestartNative(t, ctx, root, c, peer, session, selection)
	}
	if os.Getenv("SFC_TEST_RQ4_EVENTS") == "1" {
		verifyThreeRestartEventsNative(t, ctx, r, c, peer, session, plan.Container, run)
	}
	for id, stamp := range other {
		v, err := r.docker.API.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil || v.Container.State == nil || v.Container.State.StartedAt != stamp {
			t.Fatal("unselected container changed", id, err)
		}
	}
	run([]string{"compose", "restart-status", "-p", "app", "--operation", "native-restart-web"})
}

func verifyRestrictedTaskRestartNative(t *testing.T, ctx context.Context, root string, admin userauth.Client, peer sfcp.Peer, session access.Session, selection containerops.Selection) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	account, err := (access.User{ID: "autofix", Username: "autofix", Enabled: true, AutomationOnly: true}).WithPrivateKeyOperations("autofix-key", [32]byte(public), []string{"restart-task"})
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the last-credential guard: this fixture's unused recovery key
	// lets an administrator disable the selected key while the account exists.
	account, err = account.WithPrivateKeyOperations("recovery", admin.Self.Public, []string{"restart-task"})
	if err != nil {
		t.Fatal(err)
	}
	send := func(c userauth.Client, s access.Session, id, action string, expected uint64, payload any) control.UserOperation {
		t.Helper()
		raw, err := control.ChangeBytes(action, s.User, expected, payload)
		if err != nil {
			t.Fatal(err)
		}
		var change control.Change
		if json.Unmarshal(raw, &change) != nil {
			t.Fatal("automation test change")
		}
		op, err := c.Prepare(ctx, peer, s, id, change)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = userauth.StageOperation(root, c, op); err != nil {
			t.Fatal(err)
		}
		reply, err := c.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal("restricted actual operation", action, err)
		}
		if err = userauth.RecordOperationResult(root, c, s, op, *reply.Result); err != nil {
			t.Fatal(err)
		}
		return op
	}
	send(admin, session, "native-autofix-create", "put-user", 0, account)
	send(admin, session, "native-autofix-membership", "set-membership", 0, access.Membership{Tenant: "tenant", User: account.ID, Role: access.Manager, Enabled: true})
	client := admin
	client.OperationReason = &control.OperationReason{Text: "autofix", IncidentID: "native-task-incident", ApprovedBy: "display-only"}
	actor, err := client.Login(ctx, peer, account.Username, private)
	if err != nil {
		t.Fatal("actual automation key login", err)
	}
	planned, err := client.QueryTaskRestart(ctx, peer, actor, "tenant", true, control.TaskRestartQuery{Selection: selection})
	if err != nil || planned.TaskRestartPlan == nil {
		t.Fatal("restricted restart plan", err)
	}
	plan := planned.TaskRestartPlan
	change := control.TaskRestartChange{Tenant: "tenant", App: selection.App, Operation: "native-autofix-restart", Target: plan.Target}
	change.Selection.Service, change.Selection.Instance = selection.Service, selection.Instance
	original := send(client, actor, "native-autofix-restart", "restart-task", plan.InventoryRevision, change)
	for {
		reply, err := client.QueryTaskRestart(ctx, peer, actor, "tenant", false, control.TaskRestartQuery{Selection: containerops.Selection{App: selection.App}, Operation: "native-autofix-restart"})
		if err != nil {
			t.Fatal(err)
		}
		status := reply.TaskRestartStatus
		if status != nil && status.Control != nil && status.Control.Terminal() {
			if status.Status != "completed" || status.Plan.Container.NativeID != plan.Container.NativeID || status.Reason == nil || status.Reason.Text != "autofix" || status.Reason.IncidentID != "native-task-incident" || status.Reason.ApprovedBy != "display-only" {
				t.Fatal("automation action/result lost scope, identity or original labels")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("restricted original restart not terminal", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	replayed, err := client.Operation(ctx, peer, original, false)
	if err != nil || replayed.OperationReason == nil || replayed.OperationReason.IncidentID != "native-task-incident" {
		t.Fatal("original result omitted signed operation reason", err)
	}
	apps, err := client.Query(ctx, peer, actor, "apps", "tenant")
	if err != nil {
		t.Fatal("restricted account current app target", err)
	}
	var currentApp *control.AppView
	for i := range apps.Apps {
		if apps.Apps[i].App == selection.App {
			currentApp = &apps.Apps[i]
			break
		}
	}
	if currentApp == nil || currentApp.DownTarget == nil {
		t.Fatal("missing original down target")
	}
	payload, _ := json.Marshal(control.AppDown{Tenant: "tenant", App: selection.App, Operation: "autofix-forbidden-down", Target: currentApp.DownTarget})
	denied, err := client.Prepare(ctx, peer, actor, "native-autofix-denied", control.Change{Schema: 1, Principal: actor.User, Action: "down-app", Expected: currentApp.Revision, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = userauth.StageOperation(root, client, denied); err != nil {
		t.Fatal(err)
	}
	reply, err := client.Operation(ctx, peer, denied, false)
	var code *userauth.Error
	if !(reply.Result != nil && reply.Result.Code == state.Forbidden) && !(errors.As(err, &code) && code.Code == "denied") {
		t.Fatal("restart-only credential did not return authorization refusal", err, reply.Code, reply.Result)
	}
	current, err := admin.UserCredentials(ctx, peer, session, account.Username)
	if err != nil {
		t.Fatal(err)
	}
	revision := current.Revision
	disabled, err := current.WithPrivateKeyDisabled("autofix-key")
	if err != nil {
		t.Fatal(err)
	}
	disabled.Revision = 0 // CAS is carried by Change.Expected, not the new record.
	send(admin, session, "native-autofix-disable", "put-user", revision, disabled)
	if _, err = client.Whoami(ctx, peer, actor); err == nil {
		t.Fatal("revoked automation key retained its session")
	}
	if _, err = client.Login(ctx, peer, account.Username, private); err == nil {
		t.Fatal("disabled automation key logged in again")
	}
}
