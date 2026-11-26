// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// A latest read with Engine().Read(ctx, true) works only on the leader. Owner
// paths run on any member, so they read through currentView. The only direct
// latest reads left sit behind IsLeader or run once at bootstrap.
func TestLatestReadsGoThroughCurrentView(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	latest := regexp.MustCompile(`Engine\(\)\.Read\([^,()]+, true\)`)
	var found []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for range latest.FindAll(raw, -1) {
			found = append(found, file)
		}
	}
	slices.Sort(found)
	if want := []string{"applications.go", "bootstrap.go", "checker_remote_provider.go"}; !slices.Equal(found, want) {
		t.Fatalf("direct latest reads in %v, want only the leader/bootstrap ones %v; use r.currentView", found, want)
	}
}
