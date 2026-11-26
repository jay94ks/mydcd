// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"testing"
	"time"

	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func TestCheckerProbeAuthoritySeparatesLocalReadsFromEffectsAndForeignTargets(t *testing.T) {
	target := contract.Target{Service: "web", TaskKey: "task/web", NativeID: "original", Owner: "owner", OwnerBoot: "boot", StartedAt: "original-start", Generation: 3, Revision: 7}
	for _, scenario := range []struct {
		name, kind             string
		app, shutdown, foreign bool
		local                  bool
	}{
		{name: "http", kind: "healthz", local: true},
		{name: "tcp", kind: "connect", local: true},
		{name: "file", kind: "file", local: true},
		{name: "exec", kind: "exec"},
		{name: "dependency", kind: "dependency"},
		{name: "app-coordinator", kind: "healthz", app: true},
		{name: "shutdown", kind: "healthz", shutdown: true},
		{name: "foreign-owner", kind: "healthz", foreign: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			own := target
			if scenario.foreign {
				own.Owner = "other"
			}
			request := contract.Request{Phase: contract.Readiness, Targets: []contract.Target{own}}
			if scenario.shutdown {
				request.Phase = contract.Shutdown
			}
			fresh, local := 0, 0
			denied := errors.New("current authority revoked")
			authorize := checkerProbeAuthorizer(request, scenario.app, "owner", func(context.Context, string) error { fresh++; return denied }, func(context.Context, string) error { local++; return denied })
			// A local denial is final; no quorum/fallback can revive that read.
			if err := authorize(context.Background(), scenario.kind, own); !errors.Is(err, denied) {
				t.Fatal(err)
			}
			if scenario.local && (local != 1 || fresh != 0) || !scenario.local && (local != 0 || fresh != 1) {
				t.Fatal("wrong authority edge", fresh, local)
			}
		})
	}
}

func TestCheckerProbeAuthorityPinsOriginalTargetAndDeadline(t *testing.T) {
	target := contract.Target{Service: "web", TaskKey: "task/web", NativeID: "original", Owner: "owner", OwnerBoot: "boot", StartedAt: "original-start", Generation: 3, Revision: 7}
	request := contract.Request{Phase: contract.Readiness, Targets: []contract.Target{target}}
	calls := 0
	check := func(context.Context, string) error { calls++; return nil }
	authorize := checkerProbeAuthorizer(request, false, "owner", check, check)
	request.Targets[0].NativeID = "replacement"
	for _, mutate := range []func(*contract.Target){
		func(t *contract.Target) { t.NativeID = "replacement" },
		func(t *contract.Target) { t.StartedAt = "new-start" },
		func(t *contract.Target) { t.Generation++ },
		func(t *contract.Target) { t.Revision++ },
		func(t *contract.Target) { t.Owner = "other" },
		func(t *contract.Target) { t.OwnerBoot = "new-boot" },
	} {
		changed := target
		mutate(&changed)
		if err := authorize(context.Background(), "healthz", changed); !errors.Is(err, checker.ErrContract) {
			t.Fatal("substituted target accepted", err)
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := authorize(ctx, "healthz", target); err == nil || calls != 0 {
		t.Fatal("expired or substituted request reached authority", err, calls)
	}
	if err := authorize(context.Background(), "healthz", target); err != nil || calls != 1 {
		t.Fatal("original immutable target lost", err, calls)
	}
}
