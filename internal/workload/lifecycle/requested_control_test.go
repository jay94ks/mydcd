// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/json"
	"testing"
)

func TestRequestedControlKeepsOriginalNativeAndUnknownStopStartWithoutFakeCheck(t *testing.T) {
	target := testDefinition().Request.Targets[0]
	target.StartedAt = "2026-11-21T00:00:00Z"
	control, err := NewRequestedContainerControl(hashText("original-user-operation"), [32]byte{9}, target, RestartContainer)
	if err != nil {
		t.Fatal(err)
	}
	view := ControlView{NativeID: target.NativeID, StartedAt: target.StartedAt, Running: true}
	if control.Next(view) != StopContainer {
		t.Fatal("requested restart skipped original Stop")
	}
	control, err = control.Dispatch(StopContainer)
	if err != nil {
		t.Fatal(err)
	}
	control, err = control.Observe(view)
	if err != nil || control.Phase != ControlStopSent || control.Next(view) != KeepContainer {
		t.Fatal("unknown Stop was resubmitted", err)
	}
	raw, _ := json.Marshal(control)
	if json.Unmarshal(raw, &control) != nil || control.Validate() != nil {
		t.Fatal("original requested receipt lost in storage")
	}
	view.Running = false
	view.Startable = true
	control, err = control.Observe(view)
	if err != nil || control.Next(view) != StartContainer {
		t.Fatal("positive original exit did not permit Start", err)
	}
	control, err = control.Dispatch(StartContainer)
	if err != nil {
		t.Fatal(err)
	}
	control, err = control.Observe(view)
	if err != nil || control.Phase != ControlStartSent || control.Next(view) != KeepContainer {
		t.Fatal("unknown Start was retried or settled by old exit", err)
	}
	view.StartedAt = "2026-11-21T00:00:01Z"
	control, err = control.Observe(view)
	if err != nil || control.Phase != ControlCompleted || control.Target != target || control.RunID != hashText("original-user-operation") || control.Validate() != nil {
		t.Fatal("requested original control did not settle", err)
	}
}

func TestRequestedControlRejectsInvalidIdentityAndCannotBecomeCheckerEvidence(t *testing.T) {
	target := testDefinition().Request.Targets[0]
	target.StartedAt = "2026-11-21T00:00:00Z"
	valid, err := NewRequestedContainerControl(hashText("user"), [32]byte{1}, target, RestartContainer)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ContainerControl){func(c *ContainerControl) { c.RunID = "new" }, func(c *ContainerControl) { c.RequestDigest = [32]byte{} }, func(c *ContainerControl) { c.Target.NativeID = "" }, func(c *ContainerControl) { c.Target.Owner = "unknown" }, func(c *ContainerControl) { c.Target.OwnerBoot = "" }, func(c *ContainerControl) { c.Target.StartedAt = "" }, func(c *ContainerControl) { c.Target.Generation = 0 }, func(c *ContainerControl) { c.Phase = "new" }} {
		bad := valid
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid requested control admitted")
		}
	}
	observation := controlObservation(t, "fail")
	if valid.ValidateFor(observation) == nil {
		t.Fatal("explicit user intent was treated as a checker pass/fail")
	}
}
