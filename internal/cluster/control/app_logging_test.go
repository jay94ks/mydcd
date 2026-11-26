// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/workload"
)

func logClearPlanFixture(t *testing.T, driver string) (*backupCoreFixture, deployment.Observation, containerops.Selection) {
	t.Helper()
	f, _ := fieldCASFixture(t)
	managedDNSTaskCoreProgress(t, f, "source-app", "bind-inputs", deployment.ResourceKey("task", "tenant", "source-app", "web"), nil)
	apps, _ := f.p.Apps(f.s)
	e, _ := apps.Execution("tenant", "source-app")
	key := deployment.ResourceKey("task", "tenant", "source-app", "web")
	stage, found := e.Stage(key)
	if !found || stage.Observation == nil {
		t.Fatal("missing original task observation")
	}
	o := *stage.Observation
	o.LogDriver, o.StartedAt = driver, int64(time.Second)
	o.Sequence++
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	managedDNSTaskCoreProgress(t, f, "source-app", "observe", key, &o)
	return f, o, containerops.Selection{App: "source-app", Service: "web"}
}

func TestAppLogClearPlanPinsNativeLifetimeAndShowsOnlyOwnedImpact(t *testing.T) {
	f, o, selection := logClearPlanFixture(t, "local")
	plan, err := f.p.PlanAppLogClear(f.s, f.session, 10, "tenant", selection)
	if err != nil || plan.Target == ([32]byte{}) || plan.LogDriver != "local" || plan.Container.NativeID != o.Native || len(plan.Impact) == 0 {
		t.Fatal("current owner plan unavailable", err)
	}
	encoded, _ := json.Marshal(plan)
	for _, secret := range [][]byte{[]byte("Signature"), []byte("Credentials"), []byte("Command"), []byte("VerifierRef")} {
		if bytes.Contains(encoded, secret) {
			t.Fatal("impact plan exposed private command/grant material")
		}
	}
	for _, impact := range plan.Impact {
		if impact.Kind == "volume" || impact.Kind == "network-ref" {
			t.Fatal("log clearing selected borrowed data/network")
		}
	}
	o.Sequence++ // Same native and goal, newer signed health heartbeat.
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	managedDNSTaskCoreProgress(t, f, "source-app", "observe", o.Key, &o)
	newer, err := f.p.PlanAppLogClear(f.s, f.session, 10, "tenant", selection)
	if err != nil || newer.Target != plan.Target || newer.InventoryRevision <= plan.InventoryRevision {
		t.Fatal("health heartbeat changed the destruction target", err)
	}
	stale := expireAll(t, f.p, f.s, f.node, 10+AppObservationMaxAge+1)
	if _, err := f.p.PlanAppLogClear(stale, f.session, 10+int64(AppObservationMaxAge)+1, "tenant", selection); !errors.Is(err, containerops.ErrTarget) {
		t.Fatal("expired owner fact inferred current destruction target", err)
	}
	readOnly := f.session
	readOnly.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	readOnly.Signature = ed25519.Sign(f.node, access.SessionBytes(readOnly))
	if _, err := f.p.PlanAppLogClear(f.s, readOnly, 10, "tenant", selection); !errors.Is(err, access.ErrDenied) {
		t.Fatal("read-only session gained recreation authority", err)
	}
}

func TestAppLogClearPlanRejectsUnobservedOrExternalLogStorage(t *testing.T) {
	for _, driver := range []string{"", "syslog", "none"} {
		t.Run(driver, func(t *testing.T) {
			f, _, selection := logClearPlanFixture(t, driver)
			_, err := f.p.PlanAppLogClear(f.s, f.session, 10, "tenant", selection)
			if driver == "" && !errors.Is(err, containerops.ErrTarget) || driver != "" && !errors.Is(err, workload.ErrLogPolicy) {
				t.Fatal("unknown/external storage became locally deletable", err)
			}
		})
	}
}
