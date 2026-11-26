// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestManagedDNSCandidateRetainsOriginalViewButRejectsNewPolicyAndDrain(t *testing.T) {
	f, definition, registrations := managedDNSFixture(t)
	before, err := definition.Plans(f.c, f.n, f.a, "admin", 77, 4, registrations)
	if err != nil {
		t.Fatal(err)
	}
	original, ok := f.n.NamedNetwork("first", "shared", "node-a")
	if !ok {
		t.Fatal("original member")
	}
	target := original
	target.Generation, target.Revision = 0, 0
	f.n, err = f.n.PlanChange(f.c, "admin", "first", original.ID, "change-cidr", original.Revision, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := definition.Plans(f.c, f.n, f.a, "admin", 77, 4, registrations); err == nil {
		t.Fatal("fresh DNS configuration accepted while a member is changing")
	}
	after, err := definition.RetainedPlans(f.c, f.n, f.a, "admin", 77, 4, registrations)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("candidate changed the committed DNS projection", err)
	}
	f.n, err = f.n.Drain(f.c, "admin", "first", original.ID, original.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := definition.RetainedPlans(f.c, f.n, f.a, "admin", 77, 4, registrations); err == nil {
		t.Fatal("retained projection admitted a drained member")
	}
}
