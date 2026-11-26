// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"errors"
	"testing"
)

func TestAdvanceNamesItsRefusal(t *testing.T) {
	x := newInventoryFixture(t)
	view, _ := x.a.Execution()
	key := x.b.Steps()[0].Key
	prepared, _, err := view.Prepare(x.f.c, view.Revision(), key, x.shared.Object(key), x.now)
	if err != nil {
		t.Fatal(err)
	}
	var input *InputError
	if _, err = x.a.Advance(x.a.Revision()+1, prepared, x.shared); !errors.As(err, &input) || input.Code != "ADVANCE_REVISION" {
		t.Fatal(err)
	}
}

// An unchanged fact is renewed over MyDCP, so its stored At ages while it
// stays live. Finishing long after it, with no Expired marker, must still
// produce an execution that the inventory accepts.
func TestFinishAcceptsALiveObservationOlderThanMaxAge(t *testing.T) {
	x := newInventoryFixture(t)
	for _, s := range x.b.Steps() {
		x.completeStep(s.Key)
	}
	later := x.now + 1000 // far beyond maxAge 50
	x.save(x.e.Finish(x.e.Revision(), later))
	if _, err := x.a.Advance(x.a.Revision(), x.e, x.shared); err != nil {
		t.Fatal("a finish over renewed facts was refused:", err)
	}
}
