// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type inPlaceDriver struct {
	fileDriver
	allow bool
}

func (d *inPlaceDriver) InPlace(applied, target Resource) bool { return d.allow }

func TestInPlaceApplyRunsUnderLiveConsumersOnlyWhenTheDriverSaysSo(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	j, err := OpenJournal(filepath.Join(root, "j.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	d := &inPlaceDriver{fileDriver: fileDriver{path: filepath.Join(root, "effect"), j: j, t: t}}
	desire := func(revision uint64, spec string) {
		t.Helper()
		if err := j.Desired("k", Desired{Revision: revision, Resource: Resource{Present: true, Generation: 1, Spec: spec}}, 2); err != nil {
			t.Fatal(err)
		}
	}
	desire(1, "a")
	if err = j.Step(ctx, "k", d); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Borrow("k", "plane", 1); err != nil {
		t.Fatal(err)
	}
	desire(2, "b")
	if err = j.Step(ctx, "k", d); !errors.Is(err, ErrLease) {
		t.Fatal("an ordinary change ran under a live consumer", err)
	}
	d.allow = true
	if err = j.Step(ctx, "k", d); err != nil {
		t.Fatal("an in-place change waited for consumers", err)
	}
	if r, _ := j.Read("k"); r.State.Applied.Spec != "b" || len(r.Consumers) != 1 {
		t.Fatal("in-place change lost its consumer or result", r)
	}
}

type inPlaceCheckpointDriver struct {
	inPlaceDriver
}

func (d *inPlaceCheckpointDriver) ExecuteCheckpoint(ctx context.Context, key string, op Operation, save func([]byte) error) (Outcome, error) {
	if op.ID == 1 {
		if err := save([]byte("start-witness")); err != nil {
			return EffectUnknown, err
		}
	}
	return d.fileDriver.Execute(ctx, key, op)
}

// A same-generation in-place Apply keeps the original start witness, bound to
// the new Applied target, so the record stays valid across a reopen.
func TestInPlaceApplyCarriesTheStartCheckpoint(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "j.db")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	d := &inPlaceCheckpointDriver{inPlaceDriver{fileDriver: fileDriver{path: filepath.Join(root, "effect"), j: j, t: t}, allow: true}}
	for revision, spec := range []string{"a", "b"} {
		if err = j.Desired("k", Desired{Revision: uint64(revision + 1), Resource: Resource{Present: true, Generation: 1, Spec: spec}}, 2); err != nil {
			t.Fatal(err)
		}
		if err = j.Step(ctx, "k", d); err != nil {
			t.Fatal(spec, err)
		}
	}
	r, _ := j.Read("k")
	if c := r.Checkpoint; c == nil || c.Operation != r.State.LastID || c.Target != r.State.Applied || string(c.Data) != "start-witness" {
		t.Fatal("in-place Apply lost or kept a stale start witness", r.Checkpoint)
	}
	_ = j.Close()
	if j, err = OpenJournal(path); err != nil {
		t.Fatal("record invalid after in-place Apply", err)
	}
	_ = j.Close()
}
