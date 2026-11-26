// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"encoding/json"
	"testing"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func controlObservation(t *testing.T, status contract.Status) Observation {
	t.Helper()
	d := testDefinition()
	d.Request.Phase = contract.Liveness
	d.Request.Targets[0].StartedAt = "2026-11-15T01:00:00Z"
	m, run := beginRun(t, newMachine(t, d), 100)
	_, o := completeRun(t, m, run, 101, status)
	return o
}

func TestContainerControlUsesSameRunAndNeverRedispatchesUnknownEffect(t *testing.T) {
	o := controlObservation(t, contract.Fail)
	c, err := NewContainerControl(o, ActionPolicy{OnDead: RestartContainer}, contract.Fail, true)
	if err != nil || c == nil {
		t.Fatal(c, err)
	}
	v := ControlView{NativeID: c.Target.NativeID, StartedAt: c.Target.StartedAt, Running: true}
	if c.Next(v) != StopContainer {
		t.Fatal("restart did not begin with stop")
	}
	sent, err := c.Dispatch(StopContainer)
	if err != nil {
		t.Fatal(err)
	}
	// A lost Stop reply with an unchanged running observation is unresolved.
	sent, err = sent.Observe(v)
	if err != nil || sent.Phase != ControlStopSent || sent.Next(v) != KeepContainer {
		t.Fatal("lost Stop was retransmitted", sent, err)
	}
	v.Running, v.Startable = false, true
	stopped, err := sent.Observe(v)
	if err != nil || stopped.Next(v) != StartContainer {
		t.Fatal(stopped, err)
	}
	started, err := stopped.Dispatch(StartContainer)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := started.Observe(v)
	if err != nil || unchanged.Phase != ControlStartSent || unchanged.Next(v) != KeepContainer {
		t.Fatal("old exit settled/repeated new Start", unchanged, err)
	}
	v.StartedAt = "2026-11-15T01:01:00Z" // even a fast exit is a new execution
	done, err := started.Observe(v)
	if err != nil || !done.Terminal() || done.RunID != o.Run.Request.RunID || done.ValidateFor(o) != nil {
		t.Fatal(done, err)
	}
	if _, err = done.Dispatch(StartContainer); err == nil {
		t.Fatal("terminal receipt dispatched again")
	}
	other := v
	other.NativeID = "foreign"
	if _, err = started.Observe(other); err == nil {
		t.Fatal("foreign native settled original")
	}
}

func TestContainerControlHonorsPublishedResultAndInstance(t *testing.T) {
	o := controlObservation(t, contract.Fail)
	for _, published := range []contract.Status{contract.Unknown, contract.Pass} {
		if c, err := NewContainerControl(o, ActionPolicy{OnDead: RestartContainer, OnAlive: StopContainer}, published, true); err != nil || c != nil {
			t.Fatal("grace/retry/unknown gained an action", c, err)
		}
	}
	c, err := NewContainerControl(o, ActionPolicy{OnDead: RestartContainer}, contract.Fail, false)
	if err != nil || c.Action != StartContainer {
		t.Fatal("stopped restart not normalized", c, err)
	}
	v := ControlView{NativeID: c.Target.NativeID, StartedAt: "2026-11-15T01:02:00Z", Running: true}
	changed, err := c.Observe(v)
	if err != nil || changed.Phase != ControlCanceled || changed.Next(v) != KeepContainer {
		t.Fatal("old result controlled new execution", changed, err)
	}
	unknown := controlObservation(t, contract.Unknown)
	if c, err := NewContainerControl(unknown, ActionPolicy{OnDead: RestartContainer}, contract.Unknown, true); err != nil || c != nil {
		t.Fatal("unknown treated as death", c, err)
	}
	legacy := testDefinition().Request
	raw, _ := json.Marshal(legacy)
	if bytes.Contains(raw, []byte("StartedAt")) {
		t.Fatal("optional instance changed old request bytes")
	}
	legacy.Targets[0].StartedAt = "invalid"
	if validateRequestFields(legacy) == nil {
		t.Fatal("invalid Docker timestamp accepted")
	}
}
