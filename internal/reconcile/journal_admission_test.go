// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

// Actual bbolt + the existing file effect adapter, without claiming native
// network/quorum coverage. The admission tests exercise the product journal.
func admissionJournal(t *testing.T, capacity int) (*Journal, string, Desired, *fileDriver) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "network.db")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	d := Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "original-bridge"}}
	if err = j.Desired("bridge", d, capacity); err != nil {
		t.Fatal(err)
	}
	driver := &fileDriver{path: filepath.Join(root, "effect"), j: j, t: t}
	if err = j.Step(t.Context(), "bridge", driver); err != nil {
		t.Fatal(err)
	}
	return j, path, d, driver
}

func TestJournalCurrentConsumerLimitIsAtomicForTheLastSlot(t *testing.T) {
	j, _, d, _ := admissionJournal(t, 8)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, consumer := range []string{"dhcp/client-a", "workload/task-b"} {
		go func() {
			<-start
			_, err := j.BorrowLimited("bridge", consumer, 1, d.Revision, 1)
			results <- err
		}()
	}
	close(start)
	success := 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if !errors.Is(err, ErrLease) {
			t.Fatal(err)
		}
	}
	r, err := j.Read("bridge")
	if err != nil || success != 1 || r.Capacity != 1 || len(r.Consumers) != 1 || r.Pins.Next != 1 {
		t.Fatal("last-slot competition bypassed current cap", success, r, err)
	}
}

func TestJournalCurrentLimitShrinkRetainsPinsFloorAndSameDBRecovery(t *testing.T) {
	j, path, d, _ := admissionJournal(t, 4)
	a, err := j.Borrow("bridge", "old-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := j.Borrow("bridge", "old-b", 1)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := j.Read("bridge")
	if _, err = j.BorrowLimited("bridge", "new", 1, d.Revision, 1); !errors.Is(err, ErrLease) {
		t.Fatal("shrink evicted an old user or admitted a new one", err)
	}
	r, err := j.Read("bridge")
	if err != nil || r.Capacity != 1 || len(r.Consumers) != 2 || r.Pins.Next != before.Pins.Next || !reflect.DeepEqual(r.State, before.State) {
		t.Fatal("rejected shrink lost pins/floor/original operation", r, err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if pin, err := reopened.BorrowLimited("bridge", "old-a", 1, 0, 0); err != nil || pin != a {
		t.Fatal("existing pin recovery became new admission", pin, err)
	}
	if err := reopened.Return("bridge", "old-a", a); err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.BorrowLimited("bridge", "new", 1, d.Revision, 1); !errors.Is(err, ErrLease) {
		t.Fatal("one remaining old user still fills the limit", err)
	}
	if err := reopened.Return("bridge", "old-b", b); err != nil {
		t.Fatal(err)
	}
	// A delayed staging path may still carry the previous capacity. Fresh
	// admission must use its own current limit inside the actual pin lock.
	if err := reopened.Desired("bridge", d, 8); err != nil {
		t.Fatal(err)
	}
	next, err := reopened.BorrowLimited("bridge", "new", 1, d.Revision, 1)
	if err != nil || next.Token <= b.Token || next.Generation != a.Generation {
		t.Fatal("same DB reset the original token floor", next, err)
	}
	if _, err = reopened.BorrowLimited("bridge", "excess", 1, d.Revision, 1); !errors.Is(err, ErrLease) {
		t.Fatal("stale staged capacity bypassed fresh admission", err)
	}
}

func TestJournalDelayedConsumerPermitCannotEnterAnotherSourceRevision(t *testing.T) {
	j, _, d, _ := admissionJournal(t, 4)
	d.Revision++
	if err := j.Desired("bridge", d, 4); err != nil {
		t.Fatal(err)
	}
	before, _ := j.Read("bridge")
	if _, err := j.BorrowLimited("bridge", "late", 1, d.Revision-1, 1); !errors.Is(err, ErrLease) {
		t.Fatal("old source permit admitted into changed source", err)
	}
	if _, err := j.BorrowLimited("bridge", "zero", 1, d.Revision, 0); !errors.Is(err, ErrLease) {
		t.Fatal("zero capacity issued a pin", err)
	}
	after, _ := j.Read("bridge")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rejected source/cap changed original record")
	}
}

func TestJournalConsumerWriteFailureFencesAllFurtherEntryEffects(t *testing.T) {
	j, path, d, driver := admissionJournal(t, 4)
	original, err := j.Borrow("bridge", "original", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.BorrowLimited("bridge", "uncertain", 1, d.Revision, 2); !errors.Is(err, ErrJournalUncertain) {
		t.Fatal("failed pin write was not fenced", err)
	}
	if _, err := j.Read("bridge"); !errors.Is(err, ErrJournalUncertain) {
		t.Fatal("stale in-memory record was presented as current", err)
	}
	if err := j.Desired("bridge", d, 4); !errors.Is(err, ErrJournalUncertain) {
		t.Fatal("same Desired bypassed uncertain-write fence", err)
	}
	if err := j.Return("bridge", "original", original); !errors.Is(err, ErrJournalUncertain) {
		t.Fatal("return overwrote an uncertain pin write", err)
	}
	if _, err := j.Borrow("bridge", "original", 1); !errors.Is(err, ErrJournalUncertain) {
		t.Fatal("existing lookup bypassed an uncertain write", err)
	}
	executions, inspections := driver.executions, driver.inspections
	if err := j.Step(context.Background(), "bridge", driver); !errors.Is(err, ErrJournalUncertain) || driver.executions != executions || driver.inspections != inspections {
		t.Fatal("uncertain record dispatched/recovered native work", err)
	}
	reopened, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	r, err := reopened.Read("bridge")
	if err != nil || len(r.Consumers) != 1 || r.Consumers["original"] != original || r.Pins.Next != original.Token {
		t.Fatal("closed-DB failure invented a committed pin or lost original", r, err)
	}
}
