// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type checkpointFileDriver struct {
	*fileDriver
	checkpoint  []byte
	after       func([]byte) error
	invalidSave bool
	canRetire   bool
}

func (d *checkpointFileDriver) ExecuteCheckpoint(ctx context.Context, key string, op Operation, save func([]byte) error) (Outcome, error) {
	d.after = save
	if d.invalidSave {
		_ = save(nil)
		return EffectApplied, nil
	}
	input := []byte("positively-observed-private-object")
	if err := save(input); err != nil {
		return EffectUnknown, err
	}
	if err := save(input); err != nil {
		return EffectUnknown, err
	}
	input[0] = 'X'
	raw, err := d.j.db.Get("resource/" + key)
	var durable Record
	if err != nil || json.Unmarshal(raw, &durable) != nil || durable.Checkpoint == nil || string(durable.Checkpoint.Data) != "positively-observed-private-object" || durable.Checkpoint.Operation != op.ID || durable.Checkpoint.Target != op.Target {
		d.t.Fatal("effect preceded original checkpoint sync", err)
	}
	return d.fileDriver.Execute(ctx, key, op)
}
func (d *checkpointFileDriver) Retire(_ context.Context, key string, op Operation, _ []byte, _ func([]byte) error) (bool, error) {
	raw, err := d.j.db.Get("resource/" + key)
	var r Record
	if err != nil || json.Unmarshal(raw, &r) != nil || r.Checkpoint == nil || r.Checkpoint.Operation != op.ID || r.Checkpoint.Target != op.Target {
		d.t.Fatal("retirement lost original checkpoint", err)
	}
	if !d.canRetire {
		return false, nil
	}
	if err = os.Remove(d.path); err != nil {
		return false, err
	}
	return true, nil
}
func TestJournalEffectCheckpointOwnedRestartAndOriginalRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "module.db")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	d := &checkpointFileDriver{fileDriver: &fileDriver{path: filepath.Join(t.TempDir(), "effect"), j: j, t: t, loseReply: true}}
	if err = j.Desired("original", Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "original"}}, 1); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(context.Background(), "original", d); err == nil {
		t.Fatal("lost effect reply accepted")
	}
	if err = d.after([]byte("late")); !errors.Is(err, ErrOperation) {
		t.Fatal("callback usable after Execute", err)
	}
	r, _ := j.Read("original")
	if r.Checkpoint == nil || r.State.Pending == nil || r.State.LastID != 1 {
		t.Fatal("original checkpoint missing")
	}
	r.Checkpoint.Data[0] = 'X'
	own, _ := j.Read("original")
	if string(own.Checkpoint.Data) != "positively-observed-private-object" {
		t.Fatal("Read aliases checkpoint bytes")
	}
	_ = j.Close()
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	d.j = j
	d.loseReply = false
	if err = j.Step(context.Background(), "original", d); err != nil {
		t.Fatal(err)
	}
	r, _ = j.Read("original")
	if r.Checkpoint == nil || r.State.LastID != 1 || r.State.Pending != nil || d.executions != 1 {
		t.Fatal("restart recopied or lost original checkpoint")
	}
	if err = j.Desired("original", Desired{Revision: 2, Retiring: 1}, 1); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(context.Background(), "original", d); err != nil {
		t.Fatal(err)
	}
	r, _ = j.Read("original")
	if r.Checkpoint != nil || r.State.Applied.Present || r.State.LastID != 2 {
		t.Fatal("positive Remove did not return original identity")
	}
}
func TestJournalEffectCheckpointRemainsThroughUnprovenRetirement(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "module.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	d := &checkpointFileDriver{fileDriver: &fileDriver{path: filepath.Join(t.TempDir(), "effect"), j: j, t: t, loseReply: true}}
	_ = j.Desired("original", Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "original"}}, 1)
	if err = j.Step(context.Background(), "original", d); err == nil {
		t.Fatal("lost reply accepted")
	}
	_ = j.Desired("original", Desired{Revision: 2, Retiring: 1}, 1)
	if err = j.Step(context.Background(), "original", d); !errors.Is(err, ErrPending) {
		t.Fatal("unproven retirement accepted", err)
	}
	r, _ := j.Read("original")
	if r.Checkpoint == nil || r.State.Pending == nil || r.State.Pending.Phase != Retiring || r.State.Pending.ID != 1 {
		t.Fatal("retirement discarded original checkpoint")
	}
	d.canRetire = true
	if err = j.Step(context.Background(), "original", d); err != nil {
		t.Fatal(err)
	}
	r, _ = j.Read("original")
	if r.Checkpoint != nil || r.State.Pending != nil || r.State.LastID != 1 || r.State.Applied.Present {
		t.Fatal("closure changed original ID or retained proof")
	}
}
func TestJournalEffectCheckpointCannotIgnoreFailedOrChangedSave(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "replacement", true: "empty"}[invalid], func(t *testing.T) {
			j, err := OpenJournal(filepath.Join(t.TempDir(), "module.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			d := &invalidCheckpointDriver{invalid: invalid}
			_ = j.Desired("resource", Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "original"}}, 1)
			if err = j.Step(context.Background(), "resource", d); !errors.Is(err, ErrOperation) {
				t.Fatal("ignored save failure settled Apply", err)
			}
			r, _ := j.Read("resource")
			if r.State.Applied.Present || r.State.Pending == nil || r.State.Pending.ID != 1 || r.State.Pending.Phase != RecoveryRequired {
				t.Fatal("invalid checkpoint lost original Unknown")
			}
			if !invalid && (r.Checkpoint == nil || string(r.Checkpoint.Data) != "original") {
				t.Fatal("checkpoint overwritten")
			}
		})
	}
}

type invalidCheckpointDriver struct{ invalid bool }

func (d *invalidCheckpointDriver) Execute(context.Context, string, Operation) (Outcome, error) {
	return EffectApplied, nil
}
func (d *invalidCheckpointDriver) Recover(context.Context, string, Operation) (Outcome, error) {
	return EffectUnknown, nil
}
func (d *invalidCheckpointDriver) ExecuteCheckpoint(_ context.Context, _ string, _ Operation, save func([]byte) error) (Outcome, error) {
	if !d.invalid {
		_ = save([]byte("original"))
		_ = save([]byte("replacement"))
	} else {
		_ = save(nil)
	}
	return EffectApplied, nil
}

type failedCheckpointDBDriver struct {
	j          *Journal
	saves      int
	recoveries int
	saveError  error
}

func (d *failedCheckpointDBDriver) Execute(context.Context, string, Operation) (Outcome, error) {
	return EffectUnknown, ErrOperation
}
func (d *failedCheckpointDBDriver) Recover(context.Context, string, Operation) (Outcome, error) {
	d.recoveries++
	return EffectUnknown, nil
}
func (d *failedCheckpointDBDriver) ExecuteCheckpoint(_ context.Context, _ string, _ Operation, save func([]byte) error) (Outcome, error) {
	d.saves++
	if err := d.j.db.Close(); err != nil {
		return EffectUnknown, err
	}
	d.saveError = save([]byte("observed-but-not-synced"))
	// An incorrect consumer cannot turn a failed durable write into Applied.
	return EffectApplied, nil
}
func TestJournalEffectCheckpointRealDBFailureKeepsOriginalDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "module.db")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	d := &failedCheckpointDBDriver{j: j}
	_ = j.Desired("original", Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "original"}}, 1)
	if err = j.Step(context.Background(), "original", d); err == nil || d.saveError == nil {
		t.Fatal("DB failure accepted")
	}
	if _, err = j.Read("original"); !errors.Is(err, ErrJournalUncertain) {
		t.Fatal("uncertain journal remained readable", err)
	}
	_ = j.Close()
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	row, err := j.Read("original")
	if err != nil || row.Checkpoint != nil || row.State.Applied.Present || row.State.Pending == nil || row.State.Pending.ID != 1 || row.State.Pending.Phase != Dispatched {
		t.Fatal("failed save published ownership or lost dispatch", err)
	}
	d.j = j
	if err = j.Step(context.Background(), "original", d); !errors.Is(err, ErrPending) || d.recoveries != 1 || d.saves != 1 {
		t.Fatal("DB restart repeated effect or invented proof", err)
	}
	row, err = j.Read("original")
	if err != nil || row.Checkpoint != nil || row.State.LastID != 1 || row.State.Pending == nil || row.State.Pending.Phase != RecoveryRequired {
		t.Fatal("original unknown/proof absence lost", err)
	}
}
