// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/api/types/container"
)

// Native/Bridge are fixtures; Manager, original A2 Start/Remove checkpoint and
// actual DB recovery are reused. This does not assert real Docker closure.
func TestNormalRemoveRetainsOriginalStopDispatchAcrossReplyLossAndSameDB(t *testing.T) {
	f := makeStartFixture(t)
	f.onStart = func() error {
		f.native.State = &container.State{Running: true, Status: container.StateRunning}
		return nil
	}
	f.onStop = func(r *http.Request) error {
		if r.URL.Query().Get("t") != "10" || r.URL.Query().Get("signal") != "SIGTERM" {
			t.Fatal("lost original default/inherited Stop policy")
		}
		return io.ErrUnexpectedEOF // The original stays Running until a later observation.
	}
	path := filepath.Join(t.TempDir(), "workload.db")
	m, err := OpenManager(path, f.engine, f.bridge)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err = m.Desired("task", 1, 1, &f.spec, 4); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(context.Background(), "task"); err != nil {
		t.Fatal(err)
	}
	if err = m.Desired("task", 2, 1, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(context.Background(), "task"); err == nil {
		t.Fatal("Stop response loss became successful Remove")
	}
	r, err := m.View("task")
	var receipt containerRetirement
	if err != nil || json.Unmarshal(r.Retirement, &receipt) != nil || !receipt.StopSent || receipt.NativeID != f.native.ID || r.Checkpoint == nil || !r.State.Applied.Present || r.State.Pending == nil || r.State.Pending.ID != 2 {
		t.Fatal("original Stop receipt/Start checkpoint/lifetime lost", err)
	}
	_ = m.Close()
	m, err = OpenManager(path, f.engine, f.bridge)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(context.Background(), "task"); !errors.Is(err, reconcile.ErrPending) || f.stops != 1 || f.removes != 0 {
		t.Fatal("Running original resent Stop or removed resources", err)
	}
	f.native.State = &container.State{Status: container.StateExited, StartedAt: "2026-11-14T01:00:00Z", FinishedAt: "2026-11-14T01:00:01Z"}
	if err = m.Step(context.Background(), "task"); err != nil || f.stops != 1 || f.removes != 1 {
		t.Fatal("late original exit did not settle same Remove", err)
	}
	r, err = m.View("task")
	if err != nil || r.State.Pending != nil || r.State.Applied.Present || r.Checkpoint != nil || len(r.Retirement) != 0 || r.State.LastID != 2 {
		t.Fatal("closure did not settle original operation", err)
	}
}

func TestRetirementUsesOriginalStartNativeWhenAlreadyGoneAndGuardsLegacyRename(t *testing.T) {
	f := makeStartFixture(t)
	d := &DockerDriver{Engine: f.engine, Network: f.bridge}
	op := f.op
	op.Kind, op.ID = reconcile.Remove, 2
	f.gone = true // The original name is absent, but an owned native can be renamed.
	f.listItems = []container.Summary{{ID: f.native.ID, Names: []string{"renamed-original"}}}
	if out, err := d.RemoveCheckpoint(context.Background(), "task", op, nil, func([]byte) error { return nil }); out != reconcile.EffectUnknown || !errors.Is(err, reconcile.ErrPending) || f.lists != 1 {
		t.Fatal("legacy name absence hid a still-owned original", err)
	}
	start, _ := json.Marshal(containerStart{Schema: 1, Native: f.native.ID})
	f.listItems = nil // Later the exact original has actually disappeared too.
	d.startCheckpoint = &reconcile.EffectCheckpoint{Operation: 1, Target: op.Target, Data: start}
	var proof []byte
	op.Kind, op.ID, op.Phase = reconcile.Apply, 1, reconcile.Retiring
	closed, err := d.Retire(context.Background(), "task", op, nil, func(raw []byte) error { proof = append([]byte(nil), raw...); return nil })
	var receipt containerRetirement
	if err != nil || !closed || json.Unmarshal(proof, &receipt) != nil || receipt.NativeID != f.native.ID || f.stops != 0 || f.removes != 0 || f.lists != 1 {
		t.Fatal("positive original Start ID was lost before retirement/absence", err)
	}
}
