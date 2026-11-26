// SPDX-License-Identifier: Apache-2.0

package workload_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Reuse the existing owned real-Engine fixture and its rollback. Check results
// and authority here are injected; this is the SDK control/storage boundary,
// not an actual script or managed-cluster/quorum success claim.
func exerciseContainerCheckControls(t *testing.T, ctx context.Context, manager *workload.Manager, key, root string, cluster, node [32]byte) {
	t.Helper()
	db, err := storage.Open(filepath.Join(root, "checker-controls.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	observation := func(id string, status workload.ContainerStatus, result contract.Status) checker.Observation {
		t.Helper()
		record, err := manager.View(key)
		if err != nil {
			t.Fatal(err)
		}
		d := checker.Definition{Scope: "web", PolicyRevision: 1, Timing: checker.Timing{IntervalMS: 100, TimeoutMS: 10000, FreshForMS: 30000, Retries: 1}, Request: contract.Request{Schema: 1, Cluster: hex.EncodeToString(cluster[:]), Tenant: "tenant", App: "app", Checker: id, SourceDigest: hash("fixture-result"), Phase: contract.Liveness, Targets: []contract.Target{{Service: "web", TaskKey: key, NativeID: status.NativeID, Owner: hex.EncodeToString(node[:]), OwnerBoot: hash("credential"), Generation: record.State.Applied.Generation, Revision: record.State.Desired.Revision, StartedAt: status.StartedAt}}}}
		now := time.Now().UnixMilli()
		m, err := checker.New(d, now)
		if err != nil {
			t.Fatal(err)
		}
		m, run, err := m.Plan(now)
		if err != nil {
			t.Fatal(err)
		}
		m, err = m.Dispatch(run.Request.RunID)
		if err != nil {
			t.Fatal(err)
		}
		_, o, err := m.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: result, Reason: "fixture-observation"}, At: time.Now().UnixMilli(), HelperExited: true, ProbesClosed: true})
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	for _, scenario := range []string{"start", "restart", "stop"} {
		before, err := manager.Status(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		result, policy := contract.Fail, checker.ActionPolicy{OnDead: checker.RestartContainer}
		if scenario == "stop" {
			result, policy = contract.Pass, checker.ActionPolicy{OnAlive: checker.StopContainer}
		}
		o := observation(scenario, before, result)
		control, err := checker.NewContainerControl(o, policy, result, before.Running)
		if err != nil || control == nil {
			t.Fatal(control, err)
		}
		save := func(c checker.ContainerControl) error {
			raw, err := json.Marshal(c)
			if err != nil {
				return err
			}
			if err = db.Write(map[string][]byte{"control/" + c.RunID: raw}); err != nil {
				return err
			}
			*control = c
			return nil
		}
		if err = save(*control); err != nil {
			t.Fatal(err)
		}
		if scenario == "restart" {
			injected := errors.New("control marker sync failed")
			if err = manager.ControlContainer(ctx, o, *control, true, func(checker.ContainerControl) error { return injected }, func(context.Context) error { return nil }); !errors.Is(err, injected) {
				t.Fatal(err)
			}
			unchanged, err := manager.Status(ctx, key)
			if err != nil || !unchanged.Running || unchanged.StartedAt != before.StartedAt {
				t.Fatal("SDK Stop before marker sync", unchanged, err)
			}
		}
		for {
			err = manager.ControlContainer(ctx, o, *control, true, save, func(context.Context) error { return nil })
			if err == nil {
				break
			}
			if !errors.Is(err, reconcile.ErrPending) {
				t.Fatal("actual SDK control", scenario, err)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		if !control.Terminal() {
			t.Fatal("control returned before settlement", control)
		}
		if err = manager.Step(ctx, key); err != nil {
			t.Fatal(err)
		}
		after, err := manager.Status(ctx, key)
		if err != nil || after.NativeID != before.NativeID || after.Running != (scenario != "stop") {
			t.Fatal("wrong original native effect", scenario, after, err)
		}
		if scenario != "stop" && after.StartedAt == before.StartedAt {
			t.Fatal("Start did not produce new execution")
		}
		if err = manager.ControlContainer(ctx, o, *control, true, save, func(context.Context) error { return nil }); err != nil {
			t.Fatal("terminal replay", err)
		}
		duplicate, err := manager.Status(ctx, key)
		if err != nil || duplicate.StartedAt != after.StartedAt || duplicate.Running != after.Running {
			t.Fatal("same result repeated effect", duplicate, err)
		}
	}
}
