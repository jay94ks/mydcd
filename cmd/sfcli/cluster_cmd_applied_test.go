// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/jay94ks/seafield/internal/userauth"
)

func TestAppliedTextShowsReportAge(t *testing.T) {
	applied := uint64(65)
	n := userauth.RaftNodeStatus{AppliedIndex: &applied, ObservedAt: 100_000}
	if got := appliedText(n, 102_000); got != "65" {
		t.Fatal("fresh report shows an age:", got)
	}
	if got := appliedText(n, 130_500); got != "65 (30s ago)" {
		t.Fatal("old report hides its age:", got)
	}
	n.ObservedAt = 0
	if got := appliedText(n, 130_500); got != "65" {
		t.Fatal("own row shows an age:", got)
	}
}
