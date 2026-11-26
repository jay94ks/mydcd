// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"slices"
	"testing"
)

func TestLogClearDependents(t *testing.T) {
	doc := []byte("services:\n  db: {image: a}\n  api: {image: b, depends_on: [db]}\n  web: {image: c, depends_on: {api: {condition: service_started}}}\n  cron: {image: d}\n")
	got := dependents(doc, "db")
	slices.Sort(got)
	if !slices.Equal(got, []string{"api", "db", "web"}) {
		t.Fatalf("dependents %v", got)
	}
}
