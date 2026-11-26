// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"bytes"
	"testing"
)

func TestOwnerRotationChargesHistoricalReservationsAndAdmitsOnlyNewFutureOwner(t *testing.T) {
	f, q := quotaFixture(t)
	old := public(f.a)
	next := public(f.b)
	original := request("first", "old-task", old, 1, 10)
	var err error
	q, err = q.Reserve(f.c, "admin", q.Revision(), original)
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := q.Reservation(original.Key)
	before, _ := q.Encode()
	q, err = q.RotateOwner(OwnerRotation{Node: "node-a", Operation: "replace-a", Old: old, New: next, Proof: [32]byte{1}, Index: 12})
	if err != nil {
		t.Fatal(err)
	}
	preserved, _ := q.Reservation(original.Key)
	if preserved != saved {
		t.Fatal("rotation rewrote original reservation")
	}
	limit, _ := q.Limit("first", "node-a")
	usage, err := q.Usage("first", "node-a")
	if err != nil || limit.Owner != next || usage.CPU != 1 || usage.Memory != 10 || !q.SameOwner("node-a", next, old) || q.SameOwner("node-b", next, old) {
		t.Fatal("logical owner quota lineage is not node scoped", limit, usage, err)
	}
	stale := request("first", "new-old-task", old, 1, 10)
	if _, err = q.Reserve(f.c, "admin", q.Revision(), stale); err == nil {
		t.Fatal("historical key minted a future reservation")
	}
	future := request("first", "new-task", next, 1, 10)
	q, err = q.Reserve(f.c, "admin", q.Revision(), future)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := q.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeQuotas(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.SameOwner("node-a", old, next) {
		t.Fatal("lineage lost across restart")
	}
	legacy, err := DecodeQuotas(before)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip, _ := legacy.Encode()
	if !bytes.Equal(roundtrip, before) {
		t.Fatal("old snapshot changed bytes without a rotation")
	}
}
