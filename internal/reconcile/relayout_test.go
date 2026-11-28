// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type unknownDriver struct{ recovered []string }

func (d *unknownDriver) Execute(context.Context, string, Operation) (Outcome, error) {
	return EffectUnknown, errors.New("route held by another device")
}
func (d *unknownDriver) Recover(_ context.Context, _ string, op Operation) (Outcome, error) {
	d.recovered = append(d.recovered, op.Target.Spec)
	return EffectApplied, nil
}

// A server upgraded onto a new local layout of the same committed input
// moves its recorded Desired and the stuck Apply of that generation, so the
// same revision is accepted and recovery runs the new layout.
func TestRelayoutMovesDesiredAndPendingApply(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	old := Desired{Revision: 74, Resource: Resource{Generation: 74, Present: true, Spec: "old"}}
	if err = j.Desired("tun/a", old, 2); err != nil {
		t.Fatal(err)
	}
	d := &unknownDriver{}
	if err = j.Step(context.Background(), "tun/a", d); err == nil {
		t.Fatal("unknown apply settled")
	}
	next := old
	next.Spec = "new"
	if err = j.Desired("tun/a", next, 2); !errors.Is(err, ErrDesired) {
		t.Fatal("same revision with a new layout must still be refused by Desired", err)
	}
	never := func(string, string) bool { return false }
	if changed, err := j.Relayout("tun/a", 74, 74, "new", never); err != nil || changed {
		t.Fatal("relayout ignored the driver's verdict", changed, err)
	}
	same := func(a, b string) bool { return a == "old" && b == "new" }
	for _, wrong := range [][2]uint64{{75, 74}, {74, 73}} {
		if changed, err := j.Relayout("tun/a", wrong[0], wrong[1], "new", same); err != nil || changed {
			t.Fatal("relayout of another revision or generation", wrong, changed, err)
		}
	}
	if changed, err := j.Relayout("tun/a", 74, 74, "new", same); err != nil || !changed {
		t.Fatal("relayout", changed, err)
	}
	r, _ := j.Read("tun/a")
	if r.State.Desired.Spec != "new" || r.State.Pending == nil || r.State.Pending.Target.Spec != "new" {
		t.Fatal("desired or pending apply kept the old layout", r.State)
	}
	if err = j.Desired("tun/a", next, 2); err != nil {
		t.Fatal("same revision refused after relayout", err)
	}
	if err = j.Step(context.Background(), "tun/a", d); err != nil || len(d.recovered) != 1 || d.recovered[0] != "new" {
		t.Fatal("recovery did not run the new layout", d.recovered, err)
	}
}
