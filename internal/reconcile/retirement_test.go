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

func TestRetirementPreservesOriginalAndRequiresPositiveClosure(t *testing.T) {
	s := desired(t, State{}, 1, 1, "original")
	s, op := dispatched(t, s)
	if _, e := BeginRetirement(s, op.ID); e == nil {
		t.Fatal("live desired retired")
	}
	s = desired(t, s, 2, 2, "replacement")
	n, e := BeginRetirement(s, op.ID)
	if e != nil || n.Pending.ID != op.ID || n.Pending.Target != op.Target || n.LastID != op.ID || n.Pending.Kind != Apply || n.Pending.Phase != Retiring {
		t.Fatal("original operation replaced", e)
	}
	for _, outcome := range []Outcome{EffectApplied, EffectNotApplied, EffectUnknown} {
		if _, e = Settle(n, op.ID, outcome); e == nil {
			t.Fatal("retirement disguised as ordinary outcome")
		}
	}
	if _, e = FinishRetirement(n, op.ID+1, true); e == nil {
		t.Fatal("other operation closure")
	}
	wait, e := FinishRetirement(n, op.ID, false)
	if e != nil || wait.Pending == nil {
		t.Fatal("unproven closure cleared original", e)
	}
	if _, _, e = Plan(wait); !errors.Is(e, ErrPending) {
		t.Fatal("replacement overlapped uncertain original")
	}
	closed, e := FinishRetirement(wait, op.ID, true)
	if e != nil || closed.Pending != nil || closed.Applied.Present || closed.LastID != op.ID || closed.GenerationFloor != 2 {
		t.Fatal("positive closure lost floor/identity", e)
	}
	_, next, e := Plan(closed)
	if e != nil || next == nil || next.ID != op.ID+1 || next.Target.Generation != 2 {
		t.Fatal("replacement not enabled after closure", e)
	}
	if _, e = SetDesired(closed, Desired{Revision: 3, Resource: op.Target}); e == nil {
		t.Fatal("retired generation reused")
	}
}

type retiringFileDriver struct {
	*fileDriver
	loseRetire  bool
	retirements int
}

func (d *retiringFileDriver) Retire(_ context.Context, key string, op Operation, receipt []byte, save func([]byte) error) (bool, error) {
	d.retirements++
	if op.Phase != Retiring || op.Kind != Apply {
		d.t.Fatal("retirement changed original operation")
	}
	if len(receipt) == 0 {
		data, e := os.ReadFile(d.path)
		if errors.Is(e, os.ErrNotExist) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		if string(data) != op.Target.Spec {
			return false, ErrOperation
		}
		receipt = []byte("positively-observed-original-file")
		if e = save(receipt); e != nil {
			return false, e
		}
	}
	raw, e := d.j.db.Get("resource/" + key)
	var record Record
	if e != nil || json.Unmarshal(raw, &record) != nil || record.State.Pending == nil || record.State.Pending.Phase != Retiring || string(record.Retirement) != string(receipt) {
		d.t.Fatal("external retirement before durable original receipt", e)
	}
	if e = os.Remove(d.path); e != nil && !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	if d.loseRetire {
		d.loseRetire = false
		return true, errors.New("removed original; closure ACK lost")
	}
	return true, nil
}
func TestRealJournalRetirementReceiptAndLostClosureSameDB(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := filepath.Join(root, "journal.db")
	j, e := OpenJournal(db)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = j.Close() }()
	d := &retiringFileDriver{fileDriver: &fileDriver{path: filepath.Join(root, "native"), j: j, t: t, loseReply: true}, loseRetire: true}
	if e = j.Desired("task", Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "original"}}, 2); e != nil {
		t.Fatal(e)
	}
	if e = j.Step(ctx, "task", d); e == nil {
		t.Fatal("lost original effect ACK accepted")
	}
	if e = j.Desired("task", Desired{Revision: 2, Retiring: 1}, 2); e != nil {
		t.Fatal(e)
	}
	if e = j.Step(ctx, "task", d); e == nil {
		t.Fatal("lost retirement ACK accepted")
	}
	r, e := j.Read("task")
	if e != nil || r.State.Pending == nil || r.State.Pending.ID != 1 || r.State.Pending.Phase != Retiring || len(r.Retirement) == 0 || r.State.Applied.Present {
		t.Fatal("original retirement lost", e)
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	j, e = OpenJournal(db)
	if e != nil {
		t.Fatal(e)
	}
	d.j = j
	if e = j.Step(ctx, "task", d.fileDriver); !errors.Is(e, ErrOperation) {
		t.Fatal("driver without retirement resumed creation", e)
	}
	if e = j.Step(ctx, "task", d); e != nil {
		t.Fatal(e)
	}
	r, e = j.Read("task")
	if e != nil || r.State.Pending != nil || r.State.Applied.Present || r.State.LastID != 1 || len(r.Retirement) != 0 || d.executions != 1 || d.retirements != 2 {
		t.Fatal("retirement substituted create/success", e)
	}
	if e = j.Desired("task", Desired{Revision: 3, Resource: Resource{Present: true, Generation: 1, Spec: "again"}}, 2); e == nil {
		t.Fatal("deleted generation reused")
	}
}
func TestRealJournalRetirementMissingAndReceiptSyncFailure(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	j, e := OpenJournal(filepath.Join(root, "journal.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	d := &retiringFileDriver{fileDriver: &fileDriver{path: filepath.Join(root, "native"), j: j, t: t, loseReply: true}}
	if e = j.Desired("task", Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "original"}}, 2); e != nil {
		t.Fatal(e)
	}
	_ = j.Step(ctx, "task", d)
	if e = os.Remove(d.path); e != nil {
		t.Fatal(e)
	}
	if e = j.Desired("task", Desired{Revision: 2, Retiring: 1}, 2); e != nil {
		t.Fatal(e)
	}
	if e = j.Step(ctx, "task", d); !errors.Is(e, ErrPending) {
		t.Fatal("unobserved missing original closed", e)
	}
	if e = os.WriteFile(d.path, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	// A closed DB prevents persisting retirement before the driver can remove.
	_ = j.db.Close()
	if e = j.Step(ctx, "task", d); e == nil {
		t.Fatal("unsynced retirement dispatched")
	}
	if _, e = os.Stat(d.path); e != nil {
		t.Fatal("original removed without durable receipt", e)
	}
}

func TestRealJournalPreparedDrainDoesNotDispatch(t *testing.T) {
	root := t.TempDir()
	j, e := OpenJournal(filepath.Join(root, "journal.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	d := &retiringFileDriver{fileDriver: &fileDriver{path: filepath.Join(root, "native"), j: j, t: t}}
	if e = j.Desired("task", Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "never-dispatched"}}, 2); e != nil {
		t.Fatal(e)
	}
	entry, e := j.entry("task", false)
	if e != nil {
		t.Fatal(e)
	}
	entry.mu.Lock()
	r := cloneRecord(entry.r)
	r.State, _, e = Plan(r.State)
	if e == nil {
		e = j.save("task", entry, r)
	}
	entry.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Desired("task", Desired{Revision: 2, Retiring: 1}, 2); e != nil {
		t.Fatal(e)
	}
	if e = j.Step(context.Background(), "task", d); e != nil {
		t.Fatal(e)
	}
	r, e = j.Read("task")
	if e != nil || r.State.Pending != nil || r.State.Applied.Present || r.State.LastID != 1 || r.State.GenerationFloor != 1 || d.executions != 0 || d.retirements != 0 {
		t.Fatal("stale Prepared was dispatched", e)
	}
	if _, e = os.Stat(d.path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("native work started after Drain", e)
	}
}
