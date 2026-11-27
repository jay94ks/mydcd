// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func TestRealComposeHistoryCLICommittedEpochAndSameDB(t *testing.T) {
	testRealComposeAppBoundary(t, true, true, "history")
}

func verifyComposeHistoryCLI(t *testing.T, ctx context.Context, root string, call func(int, ...string) []byte, c *userauth.Client, session access.Session, peer sfcp.Peer, p control.Policy, view func() state.State, runtime **app.Runtime, cfg config.Node) {
	t.Helper()
	apply := func(want int, id, action string, expected uint64, payload any) {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := json.Marshal(control.ChangeDocument{Schema: 1, Action: action, Expected: expected, Payload: raw})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, id+".json")
		if err = os.WriteFile(path, doc, 0600); err != nil {
			t.Fatal(err)
		}
		call(want, "manage", "apply", "--request-id", id, "--change", path)
	}
	a, err := p.Apps(view())
	if err != nil {
		t.Fatal(err)
	}
	before, ok := a.Inventory("tenant", "app")
	if !ok {
		t.Fatal("missing original inventory")
	}
	origin, ok := a.Origin("tenant", "app")
	if !ok {
		t.Fatal("missing signed original")
	}
	original, err := c.AppOperation(ctx, peer, session, "tenant", control.AppOperationRequest{App: "app", ID: "rollout"})
	if err != nil || original.AppOperation == nil || !original.AppOperation.Found {
		t.Fatal("original query", err)
	}
	q := control.AppHistorySelection{Tenant: "tenant", App: "app"}
	// No native modules ran: this original app was cancelled while Planned.
	// The real automatic retirement controller has positively settled it.
	apply(3, "history-before-floor", "rotate-app-history", before.Revision(), q)
	apply(0, "history-window", "rotate-ledger", 1, control.LedgerWindow{NextEpoch: 2})
	apply(3, "history-stale", "rotate-app-history", before.Revision()-1, q)
	apply(0, "history-collect", "rotate-app-history", before.Revision(), q)
	collected := view()
	a, err = p.Apps(collected)
	if err != nil {
		t.Fatal(err)
	}
	after, ok := a.Inventory("tenant", "app")
	cmd, _ := origin.Command()
	if !ok || !after.OperationExpired(cmd.Actor, cmd.Epoch) || after.Revision() != before.Revision()+1 || !reflect.DeepEqual(before.Claims(), after.Claims()) {
		t.Fatal("floor/claims/identity changed")
	}
	check := func() {
		t.Helper()
		out, err := c.AppOperation(ctx, peer, session, "tenant", control.AppOperationRequest{App: "app", ID: "rollout"})
		if err != nil || out.AppOperation == nil || !out.AppOperation.Found || out.AppOperation.Current || !reflect.DeepEqual(out.AppOperation.Operation, original.AppOperation.Operation) {
			t.Fatal("lost/changed original result", err)
		}
	}
	check()
	call(0, "manage", "result", "--request-id", "history-collect")
	call(0, "manage", "resume", "--request-id", "history-collect")
	if view().Index() != collected.Index() {
		t.Fatal("original result/resume caused new effect")
	}
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
	check()
	read, err := p.Apps(view())
	if err != nil || !reflect.DeepEqual(a, read) {
		t.Fatal("same DB changed anchor/claims/floor", err)
	}
	t.Log("actual CLI/user SFCP/Raft/bbolt automatic cancellation closure -> committed global epoch -> app history CAS -> original Retired result/claims/floor -> result-only resume/Snapshot/same DB; no native modules or native cleanup claimed")
}
