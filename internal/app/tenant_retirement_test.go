// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"testing"
	"time"
)

func TestTenantRetirementCensusKeepsForeignAndOriginalCoordinatesSeparate(t *testing.T) {
	original := map[string]bool{"legacy/original-native": true}
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"workload/task/red/app/web", true},
		{"workload/task/red-other/app/web", false},
		{"workload/task/blue/app/web", false},
		{"network/bridge/red/app/main", true},
		{"volume/red/app/data/local", true},
		{"fixed-volume/red/data/1", true},
		{"ingress/app/blue/app/main", false},
		{"legacy/original-native", true},
		{"legacy/unmapped", false},
		{"image-build/red/build-one", true},
		{"image-build/blue/build-one", false},
		{"image-build-cache-prune/red/cleanup-one", true},
		{"image-build-cache-prune/red-other/cleanup-one", false},
	} {
		if got := tenantResourceKey(tc.key, "red", original); got != tc.want {
			t.Fatalf("tenant census %q=%v want %v", tc.key, got, tc.want)
		}
	}
}

func TestRealControlOnlyTenantRetirementRetriesBusyCensus(t *testing.T) {
	testRealManagedJoin(t, false, "tenant-retirement")
}

func verifyControlOnlyTenantRetirement(t *testing.T, ctx context.Context, r *Runtime, c userauth.Client, peer sfcp.Peer, session access.Session, _ control.Policy, submit func(string, string, uint64, any), wait func(string, func() bool)) {
	t.Helper()
	if r.network != nil || r.workload != nil || r.ingress != nil {
		t.Fatal("control-only boundary has native adapters")
	}
	tenantID := "retirement-control"
	submit("retirement-empty-tenant", "create-tenant", 0, control.TenantID{ID: tenantID})
	read := func() control.TenantRetirementStatus {
		t.Helper()
		reply, err := c.TenantRetirement(ctx, peer, session, tenantID, "")
		if err != nil {
			t.Fatal("actual retirement status", err)
		}
		return reply
	}
	selected := read()
	r.inputLife.Lock()
	locked := true
	defer func() {
		if locked {
			r.inputLife.Unlock()
		}
	}()
	selection := control.TenantRetirementSelection{Tenant: tenantID, Operation: "retire-empty"}
	submit("retirement-empty-begin", "begin-tenant-retirement", selected.Tenant.Revision, selection)
	// Let the existing two-second loop observe begin while the IO barrier is
	// held. No native adapters or new user command can wake a later pass.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(2200 * time.Millisecond):
	}
	selected = read()
	view, err := r.Engine().Read(ctx, true)
	if err != nil || !r.tenantRetirementPending(view.State) || selected.ClosedOwners != 0 || selected.RemainingCount != 0 {
		t.Fatal("busy original census bypassed", err, selected.ClosedOwners)
	}
	r.inputLife.Unlock()
	locked = false
	wait("actual control-only owner closure after IO barrier", func() bool {
		selected = read()
		return selected.OwnerCount == 1 && selected.ClosedOwners == 1
	})
	submit("retirement-empty-finish", "finish-tenant-retirement", selected.Tenant.Revision, selection)
	selected = read()
	if selected.Tenant.Phase != access.TenantDeleted {
		t.Fatal("missing actual tenant tombstone")
	}
	view, err = r.Engine().Read(ctx, true)
	if err != nil || r.tenantRetirementPending(view.State) {
		t.Fatal("terminal tenant still requests periodic reports", err)
	}
	if err = r.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("actual N1 Runtime/SFCP/Raft/bbolt owner report after temporary census barrier, no native adapters/new user submission; explicit finish and snapshot")
}
