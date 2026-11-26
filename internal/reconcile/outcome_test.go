// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type rejectedCreate struct {
	j       *Journal
	failDB  bool
	recover bool
}

var errCreatePrerequisite = errors.New("create was never called: prerequisite unavailable")

func (d *rejectedCreate) Execute(context.Context, string, Operation) (Outcome, error) {
	if d.failDB {
		_ = d.j.db.Close()
	}
	return EffectNotApplied, errCreatePrerequisite
}
func (d *rejectedCreate) Recover(context.Context, string, Operation) (Outcome, error) {
	d.recover = true
	return EffectUnknown, nil
}

func TestRealBoundaryNotAppliedErrorAndFailedSettlement(t *testing.T) {
	for _, failDB := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal-rejection", true: "settlement-write-fails"}[failDB], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "module.db")
			j, err := OpenJournal(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = j.Close() }()
			desired := Desired{Revision: 1, Resource: Resource{Generation: 1, Spec: "original", Present: true}}
			if err = j.Desired("container", desired, 1); err != nil {
				t.Fatal(err)
			}
			driver := &rejectedCreate{j: j, failDB: failDB}
			err = j.Step(context.Background(), "container", driver)
			if err == nil || !failDB && !errors.Is(err, errCreatePrerequisite) {
				t.Fatal("failure cause was hidden", err)
			}
			_ = j.Close()
			j, err = OpenJournal(path)
			if err != nil {
				t.Fatal(err)
			}
			r, err := j.Read("container")
			if err != nil || r.State.Desired != desired || r.State.Applied.Present || r.State.LastID != 1 {
				t.Fatal("rejected operation changed authority/target", r, err)
			}
			if !failDB {
				if r.State.Pending != nil {
					t.Fatal("positive no-create evidence was converted to unknown", r.State.Pending)
				}
				// A later scheduler turn may prepare a new attempt only after the
				// original rejection is durable; no automatic retry in this call.
				n, op, err := Plan(r.State)
				if err != nil || op == nil || op.ID != 2 || n.Desired != desired || driver.recover {
					t.Fatal("terminal rejection did not permit later preparation", op, err)
				}
				return
			}
			if r.State.Pending == nil || r.State.Pending.ID != 1 || r.State.Pending.Phase != Dispatched {
				t.Fatal("failed settlement forgot durable original", r.State.Pending)
			}
			driver.j, driver.failDB = j, false
			if err = j.Step(context.Background(), "container", driver); !errors.Is(err, ErrPending) || !driver.recover {
				t.Fatal("unpersisted rejection was trusted after restart", err)
			}
			r, _ = j.Read("container")
			if r.State.Pending == nil || r.State.Pending.ID != 1 || r.State.LastID != 1 {
				t.Fatal("unknown original was resubmitted", r.State)
			}
		})
	}
}
