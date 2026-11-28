// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/storage"
)

func TestParkedKeyRoundTrip(t *testing.T) {
	key := "workload/task/t/a/web"
	parked := ParkedKey(key, 7)
	if got, gen, ok := ParkedTask(parked); !ok || got != key || gen != 7 {
		t.Fatal("parked key", got, gen, ok)
	}
	for _, bad := range []string{key, key + "#surge/0", key + "#surge/x", "#surge/3", key + "#surge/07"} {
		if _, _, ok := ParkedTask(bad); ok {
			t.Fatal("accepted", bad)
		}
	}
}

func TestParkMovesOnlyTheAppliedGeneration(t *testing.T) {
	f := makeStartFixture(t)
	m, err := OpenManager(filepath.Join(t.TempDir(), "workload.db"), f.engine, f.bridge)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.Desired("task", 1, 1, &f.spec, 8); err != nil {
		t.Fatal(err)
	}
	if err = m.Park("task", 1); err == nil {
		t.Fatal("parked a generation that is not applied yet")
	}
	if err = m.journal.Step(context.Background(), "task", readProbeAppliedFixture{}); err != nil {
		t.Fatal(err)
	}
	if err = m.Park("task", 2); err == nil {
		t.Fatal("parked another generation")
	}
	if err = m.Park("task", 1); err != nil {
		t.Fatal(err)
	}
	if _, err = m.View("task"); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("original stayed under the Task key", err)
	}
	parked, err := m.Parked("task", 1)
	if err != nil || parked.State.Applied.Generation != 1 {
		t.Fatal("parked record", err)
	}
	if err = m.Desired("task", 2, 2, &f.spec, 8); err != nil {
		t.Fatal("successor could not start under the Task key", err)
	}
	if err = m.Park(ParkedKey("task", 1), 1); err == nil {
		t.Fatal("parked a parked record")
	}
}
