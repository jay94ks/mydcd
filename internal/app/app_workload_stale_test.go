// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
)

func TestStaleAppInputsStayBoundedByOwnedSteps(t *testing.T) {
	r := &Runtime{}
	app := control.AppView{Tenant: "t", App: "a"}
	r.noteStaleAppInputs(app, "inputs/a", [32]byte{1})
	r.noteStaleAppInputs(app, "inputs/b", [32]byte{2})
	// A redeploy gives the same step a new binding: it replaces the old one.
	r.noteStaleAppInputs(app, "inputs/a", [32]byte{3})
	if len(r.staleInputs) != 2 || r.staleInputs["inputs/a"] != [32]byte{3} {
		t.Fatalf("stale inputs = %v", r.staleInputs)
	}
	r.forgetStaleAppInputs([]appWorkload{{step: deployment.Step{Key: "inputs/a"}}})
	if _, ok := r.staleInputs["inputs/b"]; ok || len(r.staleInputs) != 1 {
		t.Fatalf("removed step kept: %v", r.staleInputs)
	}
	r.clearStaleAppInputs("inputs/a")
	if len(r.staleInputs) != 0 {
		t.Fatalf("current step kept: %v", r.staleInputs)
	}
}
