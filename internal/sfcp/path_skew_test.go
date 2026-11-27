// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"testing"
	"time"
)

func TestPathSampleToleratesSmallClockSkew(t *testing.T) {
	scope := []byte("scope")
	var cluster [32]byte
	from, to := Identity{1}, Identity{2}
	sample := func(ahead time.Duration) PathSample {
		return PathSample{Schema: 1, Cluster: cluster, From: from, To: to, Scope: scope, MTU: 1400, At: time.Now().Add(ahead).UnixMilli()}
	}
	// NTP-synced KVM servers differed by about 20ms, more than the LAN RTT.
	if got := sampleProblem(sample(50*time.Millisecond), cluster, from, to, scope, 1400, [32]byte{}); got == "future" {
		t.Fatal("a sample 50ms ahead was refused as future")
	}
	if got := sampleProblem(sample(5*time.Second), cluster, from, to, scope, 1400, [32]byte{}); got != "future" {
		t.Fatalf("a sample 5s ahead gave %q, want future", got)
	}
}
