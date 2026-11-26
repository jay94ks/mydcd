// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type absentLocalFile struct {
	*fileDriver
	probeErr error
	probes   int
}

func (d *absentLocalFile) AppliedAbsent(_ context.Context, _ string, _ Resource) (bool, error) {
	d.probes++
	if d.probeErr != nil {
		return false, d.probeErr
	}
	_, err := os.Stat(d.path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	return false, err
}

func TestRestoreAppliedRetainsPinsAndNeverReplacesUnknown(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "journal.db")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	d := &absentLocalFile{fileDriver: &fileDriver{j: j, t: t, path: filepath.Join(root, "native")}}
	desired := Desired{Revision: 4, Resource: Resource{Generation: 3, Present: true, Spec: "original"}}
	if err = j.Desired("tun", desired, 4); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(ctx, "tun", d); err != nil {
		t.Fatal(err)
	}
	pin, err := j.Borrow("tun", "packet-plane", 3)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := j.Read("tun")
	if err = j.RestoreApplied(ctx, "tun", d); err != nil {
		t.Fatal(err)
	}
	same, _ := j.Read("tun")
	if !reflect.DeepEqual(before, same) {
		t.Fatal("existing native caused a new operation")
	}
	if err = os.Remove(d.path); err != nil {
		t.Fatal(err)
	}
	d.probeErr = errors.New("readback unavailable")
	if err = j.RestoreApplied(ctx, "tun", d); !errors.Is(err, d.probeErr) {
		t.Fatal("unknown observation allowed repair", err)
	}
	same, _ = j.Read("tun")
	if !reflect.DeepEqual(before, same) {
		t.Fatal("failed probe changed original state")
	}
	d.probeErr = nil
	if err = j.RestoreApplied(ctx, "tun", d); err != nil {
		t.Fatal(err)
	}
	prepared, _ := j.Read("tun")
	if prepared.State.Pending == nil || prepared.State.Pending.Phase != Prepared || prepared.State.LastID != before.State.LastID+1 || prepared.State.Applied != before.State.Applied || !reflect.DeepEqual(prepared.Consumers, before.Consumers) || !reflect.DeepEqual(prepared.Pins, before.Pins) {
		t.Fatal("repair lost confirmed target/pins", prepared)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	d.j = j
	d.loseReply = true
	if err = j.Step(ctx, "tun", d); err == nil {
		t.Fatal("uncertain repair falsely settled")
	}
	unknown, _ := j.Read("tun")
	if unknown.State.Pending == nil || unknown.State.Pending.Phase != RecoveryRequired {
		t.Fatal(unknown)
	}
	if err = os.Remove(d.path); err != nil {
		t.Fatal(err)
	}
	probes, executions := d.probes, d.executions
	if err = j.RestoreApplied(ctx, "tun", d); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(ctx, "tun", d); !errors.Is(err, ErrPending) {
		t.Fatal("unresolved repair lost uncertainty", err)
	}
	retained, _ := j.Read("tun")
	if retained.State.Pending.ID != unknown.State.Pending.ID || d.probes != probes || d.executions != executions || !reflect.DeepEqual(retained.Consumers, before.Consumers) || retained.Consumers["packet-plane"] != pin {
		t.Fatal("Unknown was reprobed/reexecuted or lost pins")
	}
	if err = os.WriteFile(d.path, []byte(desired.Spec), 0600); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(ctx, "tun", d); err != nil {
		t.Fatal(err)
	}
	restored, _ := j.Read("tun")
	if restored.State.Pending != nil || restored.State.Applied != desired.Resource || restored.Consumers["packet-plane"] != pin {
		t.Fatal(restored)
	}
}

func TestPlanRestoreRejectsChangedStoppedAndUnresolvedTargets(t *testing.T) {
	r := Resource{Present: true, Generation: 7, Spec: "original"}
	base := State{Desired: Desired{Revision: 9, Resource: r}, Applied: r, LastID: 3, GenerationFloor: 7}
	cases := []State{Stop(base), func() State { s := base; s.Desired.Spec = "changed"; return s }(), func() State {
		s := base
		s.Pending = &Operation{ID: 3, Kind: Apply, Phase: RecoveryRequired, Target: r}
		return s
	}()}
	for _, s := range cases {
		before := copyState(s)
		if _, err := PlanRestore(s); err == nil {
			t.Fatal("accepted invalid restoration", s)
		}
		if !reflect.DeepEqual(s, before) {
			t.Fatal("changed rejected input")
		}
	}
}
