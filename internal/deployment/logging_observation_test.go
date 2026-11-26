// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestTaskLogDriverIsAnOptionalSignedOwnerFact(t *testing.T) {
	x := runFixture(t)
	for _, step := range x.b.Steps() {
		x.completeStep(step.Key)
	}
	key := ResourceKey("task", "tenant", "php-mysql", "db")
	original := x.observation(key, true, false)
	raw, _ := json.Marshal(original)
	if bytes.Contains(raw, []byte("LogDriver")) {
		t.Fatal("absent metadata changed the old observation format")
	}
	o := original
	o.LogDriver = "local"
	o = signCompletion(x, o)
	updated, err := x.e.Observe(x.e.Revision(), o, x.now)
	if err != nil {
		t.Fatal("owner driver fact rejected", err)
	}
	x.save(updated, nil)
	changed := o
	changed.Sequence++
	changed.LogDriver = "json-file"
	if _, err := x.e.Observe(x.e.Revision(), changed, x.now); err == nil {
		t.Fatal("unsigned driver rewrite accepted")
	}
	changed = signCompletion(x, changed)
	if _, err := x.e.Observe(x.e.Revision(), changed, x.now); err == nil {
		t.Fatal("same native lifetime changed its fixed Engine driver")
	}
	changed.LogDriver = "local\n"
	changed = signCompletion(x, changed)
	if _, err := x.e.Observe(x.e.Revision(), changed, x.now); err == nil {
		t.Fatal("owner signed malformed driver metadata")
	}
	for _, step := range x.b.Steps() {
		if step.Kind == "task" || step.Owner == ([32]byte{}) {
			continue
		}
		foreign := x.observation(step.Key, true, false)
		foreign.LogDriver = "local"
		foreign = signCompletion(x, foreign)
		if _, err := x.e.Observe(x.e.Revision(), foreign, x.now); err == nil {
			t.Fatal("non-container resource supplied a log driver")
		}
		return
	}
	t.Fatal("fixture has no non-container owner fact")
}
