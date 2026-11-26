// SPDX-License-Identifier: Apache-2.0

package state

import (
	"reflect"
	"testing"
)

func TestRangeObjectsPreservesPrefixTombstonesAndOriginalSnapshot(t *testing.T) {
	s := initial()
	apply := func(c Command) {
		t.Helper()
		if result := mustApply(t, &s, c); result.Code != Applied {
			t.Fatal("range fixture mutation", result)
		}
	}
	apply(command("range-a", "group/a", "original", 0))
	apply(command("range-b", "group/b", "deleted", 0))
	remove := command("range-remove-b", "group/b", "", s.Object("workload/group/b").Revision)
	remove.Delete = true
	apply(remove)
	apply(command("range-other", "group-other/c", "outside prefix", 0))

	original := s
	prefix := "workload/group/"
	sequence := original.RangeObjects(prefix)
	want := original.Objects(prefix)
	if len(want) != 2 || want["workload/group/b"].Present {
		t.Fatal("range fixture lost its tombstone")
	}
	// Publish another immutable candidate both before and during the range.
	apply(command("range-update-a", "group/a", "updated", s.Object("workload/group/a").Revision))
	got := map[string]Object{}
	for key, object := range sequence {
		if len(got) == 0 {
			apply(command("range-add-c", "group/c", "new candidate", 0))
		}
		got[key] = object
		object.Value = "caller-owned value"
	}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(original.Objects(prefix), want) {
		t.Fatal("range changed the captured snapshot, prefix or tombstone values")
	}
	if s.Object("workload/group/a").Value != "updated" || !s.Object("workload/group/c").Present {
		t.Fatal("subsequent state candidate was not independently published")
	}
	// The sequence is reusable, and the original owned Objects API is unchanged.
	delete(got, "workload/group/a")
	delete(want, "workload/group/a")
	got = map[string]Object{}
	for key, object := range sequence {
		got[key] = object
	}
	if !reflect.DeepEqual(got, original.Objects(prefix)) || len(got) != 2 {
		t.Fatal("repeated range borrowed a caller-owned map")
	}
	all := map[string]Object{}
	for key, object := range original.RangeObjects("") {
		all[key] = object
	}
	if !reflect.DeepEqual(all, original.Objects("")) {
		t.Fatal("empty prefix changed Objects semantics")
	}
	for range original.RangeObjects("workload/absent/") {
		t.Fatal("unmatched prefix returned a row")
	}
	for range (State{}).RangeObjects("") {
		t.Fatal("zero state returned a row")
	}
	visits := 0
	original.RangeObjects("")(func(string, Object) bool {
		visits++
		return false
	})
	if visits != 1 {
		t.Fatal("range ignored early termination", visits)
	}
}
