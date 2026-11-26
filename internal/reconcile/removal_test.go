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

type removalFileDriver struct {
	*checkpointFileDriver
	requests   int
	hold       bool
	after      func([]byte) error
	ignoreSave bool
}

func (d *removalFileDriver) RemoveCheckpoint(_ context.Context, key string, op Operation, receipt []byte, save func([]byte) error) (Outcome, error) {
	d.after = save
	if len(receipt) == 0 {
		if d.ignoreSave {
			_ = save(nil)
			return EffectApplied, nil
		}
		if err := save([]byte("original-stop-sent")); err != nil {
			return EffectUnknown, err
		}
		raw, err := d.j.db.Get("resource/" + key)
		var record Record
		if err != nil || json.Unmarshal(raw, &record) != nil || string(record.Retirement) != "original-stop-sent" || record.Checkpoint == nil || record.Checkpoint.Operation != 1 || record.State.Pending == nil || *record.State.Pending != op {
			d.t.Fatal("normal Remove effect preceded original receipt sync", err)
		}
		d.requests++
		if !d.hold {
			if err := os.Remove(d.path); err != nil {
				return EffectUnknown, err
			}
		}
		return EffectUnknown, errors.New("original Stop response lost")
	}
	if string(receipt) != "original-stop-sent" {
		return EffectUnknown, ErrOperation
	}
	if _, err := os.Stat(d.path); errors.Is(err, os.ErrNotExist) {
		return EffectApplied, nil
	}
	return EffectUnknown, ErrPending
}

func TestNormalRemovalReceiptAndOriginalStartCheckpointSurviveSameDB(t *testing.T) {
	for _, hold := range []bool{false, true} {
		root := t.TempDir()
		path := filepath.Join(root, "journal.db")
		j, err := OpenJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = j.Close() }()
		base := &fileDriver{path: filepath.Join(root, "native"), j: j, t: t}
		d := &removalFileDriver{checkpointFileDriver: &checkpointFileDriver{fileDriver: base}, hold: hold}
		if err = j.Desired("task", Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "original"}}, 2); err != nil {
			t.Fatal(err)
		}
		if err = j.Step(context.Background(), "task", d); err != nil {
			t.Fatal(err)
		}
		if err = j.Desired("task", Desired{Revision: 2, Retiring: 1}, 2); err != nil {
			t.Fatal(err)
		}
		if err = j.Step(context.Background(), "task", d); err == nil {
			t.Fatal("lost original Stop became closed")
		}
		if err = d.after([]byte("late callback")); !errors.Is(err, ErrOperation) {
			t.Fatal("receipt callback outlived its locked call", err)
		}
		before, err := j.Read("task")
		if err != nil || before.State.Pending == nil || before.State.Pending.Kind != Remove || before.State.Pending.ID != 2 || before.Checkpoint == nil || len(before.Retirement) == 0 || !before.State.Applied.Present {
			t.Fatal("original lifetime/Remove receipt lost", err)
		}
		_ = j.Close()
		j, err = OpenJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		base.j = j
		if err = j.Step(context.Background(), "task", base); !errors.Is(err, ErrOperation) {
			t.Fatal("driver without receipt support bypassed original proof", err)
		}
		if hold {
			if err = j.Step(context.Background(), "task", d); !errors.Is(err, ErrPending) || d.requests != 1 {
				t.Fatal("Running original was removed or resent", err)
			}
			if err = os.Remove(base.path); err != nil {
				t.Fatal(err)
			} // Simulated late native completion, not a second dispatch.
		}
		if err = j.Step(context.Background(), "task", d); err != nil || d.requests != 1 {
			t.Fatal("same original closure not recovered", err)
		}
		after, err := j.Read("task")
		if err != nil || after.State.Pending != nil || after.State.Applied.Present || len(after.Retirement) != 0 || after.Checkpoint != nil || after.State.LastID != 2 {
			t.Fatal("closure did not settle original receipt/checkpoint", err)
		}
	}
}

func TestIgnoredRemovalReceiptFailureCannotPublishClosure(t *testing.T) {
	root := t.TempDir()
	j, err := OpenJournal(filepath.Join(root, "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	base := &fileDriver{path: filepath.Join(root, "native"), j: j, t: t}
	d := &removalFileDriver{checkpointFileDriver: &checkpointFileDriver{fileDriver: base}, ignoreSave: true}
	if err = j.Desired("task", Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "original"}}, 2); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(context.Background(), "task", d); err != nil {
		t.Fatal(err)
	}
	if err = j.Desired("task", Desired{Revision: 2, Retiring: 1}, 2); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(context.Background(), "task", d); !errors.Is(err, ErrOperation) {
		t.Fatal("ignored receipt error became successful closure", err)
	}
	r, err := j.Read("task")
	if err != nil || r.State.Pending == nil || !r.State.Applied.Present || r.Checkpoint == nil || d.requests != 0 {
		t.Fatal("failed receipt forgot original lifetime", err)
	}
}
