// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
)

func verifyComposeDownCLI(t *testing.T, ctx context.Context, home string, call func(int, ...string) []byte, login func(), c *userauth.Client, session access.Session, peer sfcp.Peer, p control.Policy, view func() state.State, runtime **app.Runtime, cfg config.Node) {
	t.Helper()
	a, err := p.Apps(view())
	if err != nil {
		t.Fatal(err)
	}
	rows := a.Records()
	if len(rows) != 1 {
		t.Fatal("expected original accepted app")
	}
	sources := view().Objects(tenancy.ManagedNetworkSourcePrefix)
	if len(sources) == 0 {
		t.Fatal("expected separately provisioned management network")
	}
	preserveSources := func() {
		t.Helper()
		current := view()
		for key, original := range sources {
			if !original.Present || current.Object(key) != original {
				t.Fatal("app retirement/resume changed borrowed management source", key)
			}
		}
	}
	raw, err := control.ChangeBytes("down-app", session.User, rows[0].Revision, control.AppDown{Tenant: "tenant", App: "app", Operation: "stop-app"})
	if err != nil {
		t.Fatal(err)
	}
	var change control.Change
	_ = json.Unmarshal(raw, &change)
	original, err := c.Prepare(ctx, peer, session, "compose-down/stop-app", change)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = userauth.StageOperation(home, *c, original); err != nil {
		t.Fatal(err)
	}
	before := view().Index()
	call(4, "compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "stop-app")
	if view().Index() != before {
		t.Fatal("default down retransmitted original uncertain request")
	}
	login()
	call(0, "compose", "resume", "--tenant", "tenant", "--operation", "stop-app")
	for {
		a, err = p.Apps(view())
		if err != nil {
			t.Fatal(err)
		}
		rows = a.Records()
		if len(rows) == 1 && rows[0].Retirement != nil && rows[0].Retirement.ID == "stop-app" && rows[0].Retirement.Status == "Retired" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	record, err := userauth.LoadOperation(home, *c, session, original.RequestID)
	if err != nil || record.Result == nil || record.Result.Code != state.Applied || !bytes.Equal(control.OperationBytes(record.Operation), control.OperationBytes(original)) || !bytes.Equal(record.Operation.Signature, original.Signature) {
		t.Fatal("down resume replaced original intent", err)
	}
	preserveSources()
	before = view().Index()
	call(0, "compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "stop-app")
	if view().Index() != before {
		t.Fatal("repeated down changed original retirement")
	}
	call(2, "compose", "down", "--tenant", "tenant", "-p", "another-app", "--operation", "stop-app")
	call(2, "compose", "up", "--tenant", "tenant", "--operation", "stop-app")
	if err = (*runtime).Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = (*runtime).Close(); err != nil {
		t.Fatal(err)
	}
	*runtime = nil
	*runtime, err = app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (*runtime).InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		_, err = (*runtime).Engine().Read(ctx, true)
		if err == nil {
			break
		}
		if !errors.Is(err, raft.ErrNotLeader) && !errors.Is(err, raft.ErrLeadershipLost) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	before = view().Index()
	call(0, "compose", "resume", "--tenant", "tenant", "--operation", "stop-app")
	if view().Index() != before {
		t.Fatal("retired same DB resume repeated an effect")
	}
	preserveSources()
	t.Log("real CLI down private original CAS -> Unknown/no auto-submit -> new login -> explicit original resume -> same daemon Inventory.Retire/FinishRetirement -> stable Retired receipt -> repeated down/no writes -> scope/ID rebinding deny -> Snapshot/same DB/result-only resume; native modules disabled, separate actual owner retirement covers kernel/container cleanup")
}
