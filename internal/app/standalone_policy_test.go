// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
)

func TestStandalonePolicyOrdersEffectsAndOldestSamplesBeforeIdleRefresh(t *testing.T) {
	const now int64 = 1000
	work := []control.StandaloneWork{
		{App: "first-idle", Metadata: control.StandaloneMetadata{Lifetime: "fixed", ConnectionAt: 999}},
		{App: "old-sample", Metadata: control.StandaloneMetadata{Lifetime: "fixed", ConnectionAt: 100}},
		{App: "ttl", Metadata: control.StandaloneMetadata{Lifetime: "temp", ExpiresAt: 1000, ConnectionAt: 998}},
		{App: "new-sample", Metadata: control.StandaloneMetadata{Lifetime: "fixed", ConnectionAt: 0}},
		{App: "restart", Metadata: control.StandaloneMetadata{Lifetime: "fixed", Desired: "running", Restart: "on-failure", ConnectionAt: 997}, Target: &containerops.Target{}, Exited: true, ExitCode: 7},
		{App: "grace", Metadata: control.StandaloneMetadata{Lifetime: "temp", ExpiresAt: 2000, DisconnectedAt: 900, GraceSeconds: 10, ConnectionAt: 996}},
	}
	sortStandalonePolicyWork(work, now)
	for i, want := range []string{"grace", "restart", "ttl", "new-sample", "old-sample", "first-idle"} {
		if work[i].App != want {
			t.Fatal("idle sample outranked effect or older observation", i, work[i].App, want)
		}
	}
	// With more jobs than fit in the refresh period, oldest-first selection
	// still visits each original job. This calls the product ordering function.
	work = nil
	for i := range 16 {
		work = append(work, control.StandaloneWork{App: string(rune('a' + i)), Metadata: control.StandaloneMetadata{Lifetime: "fixed"}})
	}
	visited := map[string]bool{}
	for i := range 16 {
		sortStandalonePolicyWork(work, now+int64(i)*2)
		if visited[work[0].App] {
			t.Fatal("newer sample starved an unvisited job", work[0].App)
		}
		visited[work[0].App] = true
		work[0].Metadata.ConnectionAt = now + int64(i)*2
	}
}
