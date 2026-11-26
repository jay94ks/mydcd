// SPDX-License-Identifier: Apache-2.0

package imagebuild

import "testing"

func TestCachePruneFilterHasOneBoundedExplicitIntent(t *testing.T) {
	for _, f := range []CachePruneFilter{{Mode: "all"}, {Mode: "unused", UnusedDays: 7}, {Mode: "entries", IDs: []string{"a", "b"}}} {
		if !f.Valid() {
			t.Fatal(f)
		}
	}
	for _, f := range []CachePruneFilter{{}, {Mode: "all", UnusedDays: 7}, {Mode: "unused"}, {Mode: "entries"}, {Mode: "entries", IDs: []string{"b", "a"}}, {Mode: "entries", IDs: []string{"a", "a"}}, {Mode: "entries", IDs: []string{"../escape"}}, {Mode: "unknown"}} {
		if f.Valid() {
			t.Fatal("mixed/invalid filter accepted", f)
		}
	}
	original := CachePruneFilter{Mode: "entries", IDs: []string{"a"}}
	copy := original.Own()
	copy.IDs[0] = "changed"
	if original.IDs[0] != "a" {
		t.Fatal("public view aliases original signed IDs")
	}
}
