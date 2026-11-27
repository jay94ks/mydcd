// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

func TestGitObservationSchedulerDoesNotStarveContextsBehindSlowFetches(t *testing.T) {
	eligible := map[string]control.ImageBuildContextRecord{}
	for _, id := range []string{"a", "b", "c"} {
		eligible["tenant/"+id] = control.ImageBuildContextRecord{Spec: imagebuild.ContextSpec{Tenant: "tenant", ID: id}}
	}
	next := map[string]time.Time{}
	now := time.Unix(100, 0)
	for _, want := range []string{"tenant/a", "tenant/b", "tenant/c"} {
		key, row := imageBuildGitWatchCandidate(eligible, next, now)
		if key != want || "tenant/"+row.Spec.ID != want {
			t.Fatal("slow fetch starved an unobserved context", key, want)
		}
		// Each fetch lasts longer than the configured recheck interval. A
		// first-ready/lexicographic scan would revisit a before reaching c.
		now = now.Add(2 * time.Minute)
		next[key] = now.Add(time.Minute)
	}
	key, _ := imageBuildGitWatchCandidate(eligible, next, now)
	if key != "tenant/a" {
		t.Fatal("oldest due context not revisited", key)
	}
	for key := range eligible {
		next[key] = now.Add(time.Minute)
	}
	if key, _ := imageBuildGitWatchCandidate(eligible, next, now); key != "" {
		t.Fatal("not-yet-due source launched", key)
	}
	delete(eligible, "tenant/a")
	if key, _ := imageBuildGitWatchCandidate(eligible, next, now.Add(time.Minute)); key != "tenant/b" {
		t.Fatal("removed context selected or equal-due ordering unstable", key)
	}
}
