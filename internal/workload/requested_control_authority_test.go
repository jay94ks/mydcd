// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
	"github.com/moby/moby/api/types/container"
)

// The original journal and SDK control path are real; native facts are the
// existing HTTP fixture. Actual managed authority/effects remain a native test.
func TestRequestedStopUsesControlAuthorityAndStartKeepsActivationFence(t *testing.T) {
	for _, mode := range []string{"stop", "start", "restart", "denied-stop", "unsynced-stop"} {
		t.Run(mode, func(t *testing.T) {
			f := makeStartFixture(t)
			owner := strings.Repeat("a", 64)
			f.engine.Owner = "cluster/" + owner
			f.spec.Node = f.engine.Owner
			raw, _ := json.Marshal(f.spec)
			f.op.Target.Spec = string(raw)
			id, err := f.engine.Identity("container", "task", f.op.Target)
			if err != nil {
				t.Fatal(err)
			}
			f.native.Name, f.native.Config.Labels = "/"+id.Name, id.Labels
			started := "2026-11-24T00:00:00Z"
			f.native.State = &container.State{Running: mode != "start", Status: container.StateRunning, StartedAt: started}
			if mode == "start" {
				f.native.State.Status = container.StateExited
			}
			f.onStop = func(*http.Request) error {
				f.native.State.Running = false
				f.native.State.Status = container.StateExited
				f.native.State.FinishedAt = "2026-11-24T00:00:01Z"
				return nil
			}
			m, err := OpenManager(filepath.Join(t.TempDir(), "workload.db"), f.engine, f.bridge)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Close() })
			if err = m.Desired("task", 1, 1, &f.spec, 8); err != nil {
				t.Fatal(err)
			}
			if err = m.journal.Step(context.Background(), "task", readProbeAppliedFixture{}); err != nil {
				t.Fatal(err)
			}
			activationCalls, controlCalls := 0, 0
			denied := errors.New("activation denied by current desired policy")
			m.driver.Authority = func(context.Context, string, reconcile.Operation) error { activationCalls++; return denied }
			action := checker.StopContainer
			if mode == "start" {
				action = checker.StartContainer
			}
			if mode == "restart" {
				action = checker.RestartContainer
			}
			digest := sha256.Sum256([]byte(mode))
			target := contract.Target{Service: "debug", TaskKey: "task", NativeID: f.native.ID, Owner: owner, OwnerBoot: strings.Repeat("b", 64), Generation: 1, Revision: 1, StartedAt: started}
			control, err := checker.NewRequestedContainerControl(strings.Repeat("c", 64), digest, target, action)
			if err != nil {
				t.Fatal(err)
			}
			persist := func(next checker.ContainerControl) error {
				if mode == "unsynced-stop" {
					return errors.New("receipt sync failed")
				}
				if !control.CanAdvanceTo(next) {
					t.Fatal("changed original control")
				}
				control = next
				return nil
			}
			err = m.ControlContainerAction(context.Background(), control, true, persist, func(context.Context) error {
				controlCalls++
				if mode == "denied-stop" {
					return denied
				}
				return nil
			})
			if mode == "stop" {
				if err != nil || control.Phase != checker.ControlCompleted || activationCalls != 0 || controlCalls == 0 || f.stops != 1 || f.starts != 0 {
					t.Fatal("authorized Stop incorrectly required activation or lost exact settlement", control.Phase, activationCalls, controlCalls, f.stops, f.starts, err)
				}
			} else if mode == "start" || mode == "restart" {
				stops := 0
				if mode == "restart" {
					stops = 1
				}
				if !errors.Is(err, denied) || control.Phase != checker.ControlCanceled || activationCalls != 1 || f.starts != 0 || f.stops != stops {
					t.Fatal("Start escaped current activation fence or restart did not settle Stop", control.Phase, activationCalls, f.stops, f.starts, err)
				}
			} else if err == nil || f.stops != 0 || f.starts != 0 || activationCalls != 0 || controlCalls == 0 || mode == "denied-stop" && !errors.Is(err, denied) {
				t.Fatal("Stop escaped current authorization/receipt sync", f.stops, f.starts, err)
			}
		})
	}
}
