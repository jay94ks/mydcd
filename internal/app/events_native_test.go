// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/moby/moby/client"
)

// Reuses the owned container fixture, wallet, quorum and teardown. The only
// additional effects are three explicit restarts of the selected original
// native. It does not recreate the app or restart unselected containers.
func verifyThreeRestartEventsNative(t *testing.T, ctx context.Context, r *Runtime, c userauth.Client, peer mydcp.Peer, session access.Session, target containerops.Target, run func([]string) []byte) {
	t.Helper()
	q := eventlog.Query{Tenant: target.Tenant, App: target.App, Kind: "task-restarted", Limit: 1}
	for {
		page, err := c.EventsPage(ctx, peer, session, q)
		if err != nil {
			t.Fatal("event baseline", err)
		}
		q.After = page.Cursor
		if !page.More {
			break
		}
	}
	originalCursor := q.After
	baseline := uint64(time.Now().UnixMilli())
	for i := range 3 {
		operation := fmt.Sprintf("native-event-restart-%d", i+1)
		run([]string{"compose", "restart", "-p", target.App, target.Service, "--operation", operation})
		for {
			reply, err := c.QueryTaskRestart(ctx, peer, session, target.Tenant, false, control.TaskRestartQuery{Selection: containerops.Selection{App: target.App}, Operation: operation})
			if err != nil {
				t.Fatal("event restart original status", err)
			}
			status := reply.TaskRestartStatus
			if status != nil && status.Control != nil && status.Control.Terminal() {
				if status.Status != "completed" || status.Plan.Container.NativeID != target.NativeID {
					t.Fatal("event restart did not complete on original native")
				}
				// The next action must use the new shared instance proof, rather
				// than race the old accepted Start witness.
				native, err := r.docker.API.ContainerInspect(ctx, target.NativeID, client.ContainerInspectOptions{})
				if err != nil || native.Container.State == nil {
					t.Fatal("restarted native", err)
				}
				view, err := r.Engine().Read(ctx, false)
				if err != nil {
					t.Fatal(err)
				}
				apps, err := r.controlPolicy.ReadApps(view.State)
				if err != nil {
					t.Fatal(err)
				}
				claim, found := apps.Claim(target.Tenant, target.App, deployment.ObjectRef{Key: target.Instance, Generation: target.Generation, Revision: target.Revision})
				stamp, err := parseAppInstance(native.Container.State.StartedAt)
				if err == nil && found && claim.Observation != nil && claim.Observation.Restart != nil && claim.Observation.Restart.User != nil && claim.Observation.Restart.User.Operation == operation && claim.Observation.StartedAt == stamp {
					break
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("original event restart not settled", ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	var items []eventlog.Item
	for len(items) < 3 {
		page, err := c.EventsPage(ctx, peer, session, q)
		if err != nil {
			t.Fatal("actual event continuation", err)
		}
		for _, row := range page.Items {
			if row.Target.Native == target.NativeID && row.At >= baseline {
				items = append(items, row)
			}
		}
		q.After = page.Cursor
		if len(items) >= 3 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("three short native restarts were not retained", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if len(items) != 3 || items[2].At-items[0].At > 600000 {
		t.Fatal("restart event count/time range")
	}
	ids := map[string]bool{}
	for i, row := range items {
		if ids[row.ID] || row.Target.Task != target.Instance || row.Target.Generation != target.Generation || i > 0 && row.At < items[i-1].At {
			t.Fatal("restart events lost ordering or original identity")
		}
		ids[row.ID] = true
	}
	var cliPage eventlog.Page
	if json.Unmarshal(run([]string{"events", "--tenant", target.Tenant, "--app", target.App, "--kind", "task-restarted", "--since", originalCursor, "--limit", "100"}), &cliPage) != nil {
		t.Fatal("actual event CLI format")
	}
	for _, row := range cliPage.Items {
		delete(ids, row.ID)
	}
	if len(ids) != 0 {
		t.Fatal("CLI cursor did not return the same native facts")
	}
	result, err := c.ObserveContainer(ctx, peer, session, target.Tenant, containerops.Query{Schema: 1, Selection: containerops.Selection{App: target.App, Service: target.Service}, Kind: "inspect", HistoryLimit: 20, MaxBytes: 16384})
	if err != nil || result.Container == nil || result.Container.Detail == nil {
		t.Fatal("actual event detail history", err)
	}
	for _, row := range items {
		found := false
		for _, historical := range result.Container.Detail.History {
			found = found || historical.ID == row.ID && historical.NativeID == target.NativeID
		}
		if !found {
			t.Fatal("detail and events did not share original event identity")
		}
	}
	// Exact owned native only. The parent fixture's original app down/Wait
	// cleans up this stopped container; do not create a new deployment or
	// fabricate exit137 from a diagnostic model.
	api, err := r.docker.StreamingAPI()
	if err != nil {
		t.Fatal(err)
	}
	killedAt := uint64(time.Now().UnixMilli())
	if _, err = api.ContainerKill(ctx, target.NativeID, client.ContainerKillOptions{Signal: "SIGKILL"}); err != nil {
		t.Fatal("owned native forced exit", err)
	}
	for {
		exits, err := c.EventsPage(ctx, peer, session, eventlog.Query{Tenant: target.Tenant, App: target.App, Kind: "task-exited", Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range exits.Items {
			if row.Target.Native == target.NativeID && row.At >= killedAt && row.Detail.ExitCode != nil && *row.Detail.ExitCode == 137 {
				if row.Detail.Reason != "exit" {
					t.Fatal("SIGKILL invented an OOM/user/health cause", row.Detail.Reason)
				}
				found = true
			}
		}
		if found {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("native exit137 was not retained", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
