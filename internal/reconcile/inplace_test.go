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
