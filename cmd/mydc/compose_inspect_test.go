// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func TestComposeInspectOptions(t *testing.T) {
	for _, args := range [][]string{{"diff", "-f", "app.yaml"}, {"wait", "-p", "app", "--operation", "up-app"}, {"wait", "-p", "app", "--operation", "down-app", "--condition", "retired"}} {
		if _, err := parseComposeOptions(args, io.Discard); err != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{{"wait", "-p", "app"}, {"wait", "--operation", "x"}, {"wait", "-p", "app", "--operation", "x", "-f", "app.yaml"}, {"wait", "-p", "app", "--operation", "x", "--condition", "accepted"}, {"diff", "--operation", "x"}, {"ps", "--condition", "healthy"}, {"diff", "--plan", "plan.json"}} {
		if _, err := parseComposeOptions(args, io.Discard); err == nil {
			t.Fatal("accepted", args)
		}
	}
}

func TestRealComposeDiffAndWaitReadOnlyBoundary(t *testing.T) {
	testRealComposeAppBoundary(t, false, false, "inspect")
}

func verifyComposeInspectCLI(t *testing.T, ctx context.Context, root string, call func(int, ...string) []byte, c *userauth.Client, session access.Session, peer mydcp.Peer, issuer ed25519.PrivateKey, view func() state.State) {
	t.Helper()
	document := appComposeDocument(1)
	path := filepath.Join(root, "compose.yaml")
	if err := os.WriteFile(path, document, 0600); err != nil {
		t.Fatal(err)
	}
	before := view().Index()
	raw := call(0, "compose", "diff", "-f", path, "--tenant", "tenant")
	diff, err := control.DecodeAppDiff(bytes.TrimSpace(raw))
	if err != nil || diff.InventoryRevision != 0 || len(diff.Changes) != 2 {
		t.Fatal("new app diff", err, diff)
	}
	for _, change := range diff.Changes {
		if change.Action != "Create" {
			t.Fatal(change)
		}
	}
	if view().Index() != before {
		t.Fatal("diff wrote state")
	}
	limited := session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	// The actual issuer signature keeps this a valid, narrowly scoped session.
	// It must not acquire Deploy by calling the diff variant of PlanApp.
	limited.Signature = ed25519.Sign(issuer, access.SessionBytes(limited))
	if _, err := c.PlanApp(ctx, peer, limited, "tenant", control.AppPlanRequest{Document: document, Diff: true}); err == nil {
		t.Fatal("Read acquired Deploy through diff")
	}
	if _, err := c.PlanApp(ctx, peer, session, "foreign", control.AppPlanRequest{Document: document, Diff: true}); err == nil {
		t.Fatal("foreign file tenant accepted")
	}
	call(0, "compose", "up", "-f", path, "--tenant", "tenant", "--operation", "inspect-up")
	before = view().Index()
	call(4, "--timeout", "300ms", "compose", "wait", "-p", "app", "--tenant", "tenant", "--operation", "inspect-up")
	call(4, "compose", "wait", "-p", "app", "--tenant", "tenant", "--operation", "other")
	call(4, "compose", "wait", "-p", "app", "--tenant", "tenant", "--operation", "inspect-up", "--condition", "retired")
	status := call(0, "compose", "status", "-p", "app", "--tenant", "tenant")
	var reply struct{ Apps []control.AppView }
	if json.Unmarshal(status, &reply) != nil || len(reply.Apps) != 1 || reply.Apps[0].Health != "Unknown" || reply.Apps[0].ObservedAt == 0 || reply.Apps[0].Operation.Status != "Planned" {
		t.Fatal("acceptance is not health", string(status))
	}
	if view().Index() != before {
		t.Fatal("wait/status wrote state or resumed original operation")
	}
	call(0, "compose", "down", "-p", "app", "--tenant", "tenant", "--operation", "inspect-down")
	result := call(0, "compose", "wait", "-p", "app", "--tenant", "tenant", "--operation", "inspect-down", "--condition", "retired")
	var waited struct {
		Complete bool
		Observed control.AppView
	}
	if json.Unmarshal(result, &waited) != nil || !waited.Complete || waited.Observed.Health != "Unknown" {
		t.Fatal("retirement falsely healthy", string(result))
	}
	before = view().Index()
	call(4, "compose", "wait", "-p", "app", "--tenant", "tenant", "--operation", "inspect-up")
	if view().Index() != before {
		t.Fatal("retired healthy wait resubmitted effects")
	}
	t.Log("actual CLI/MYDCP/auth/Raft/bbolt read-only diff Create, tenant denial, Planned != Healthy, deadline/original-ID guard, original retirement wait; native disabled, no claim of Docker readiness")
}
