// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/storage"
)

func TestMoveKeepsRecordUnderOneKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.db")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Desired("task", Desired{Revision: 1, Resource: Resource{Generation: 1, Spec: "a", Present: true}}, 1); err != nil {
		t.Fatal(err)
	}
	before, _ := j.Read("task")
	if err = j.Move("task", "task#old", func(r Record) bool { return false }); !errors.Is(err, ErrMove) {
		t.Fatal("refused move went ahead", err)
	}
	if err = j.Move("task", "task#old", func(r Record) bool { return r.State.Desired.Generation == 1 }); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Read("task"); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("source kept its record", err)
	}
	if err = j.Desired("task", Desired{Revision: 2, Resource: Resource{Generation: 2, Spec: "b", Present: true}}, 1); err != nil {
		t.Fatal("new generation could not start under the source key", err)
	}
	if err = j.Move("task", "task#old", nil); !errors.Is(err, ErrMove) {
		t.Fatal("move overwrote a taken key", err)
	}
	_ = j.Close()
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	moved, err := j.Read("task#old")
	if err != nil || moved.State.Desired != before.State.Desired {
		t.Fatal("moved record lost on reopen", err)
	}
	next, err := j.Read("task")
	if err != nil || next.State.Desired.Generation != 2 {
		t.Fatal("new record lost on reopen", err)
	}
	if keys := j.Keys(); len(keys) != 2 {
		t.Fatal("keys", keys)
	}
}
