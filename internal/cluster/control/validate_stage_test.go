// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestValidateStageNamesTheRefusingInvariant(t *testing.T) {
	f := newBackupCore(t)
	if stage, err := f.p.ValidateManagedStage(f.s, f.s, state.Command{}); stage != "" || err != nil {
		t.Fatal("valid state refused", stage, err)
	}
	// A native goal that no app step or claim binds.
	stray := state.Command{Kind: state.Mutate, Actor: "anchor", Epoch: 1, RequestID: "stray", Key: "workload/stray", Value: `{"Kind":"task"}`}
	after, r, err := state.Apply(f.s, f.s.Index()+1, stray)
	if err != nil || r.Code != state.Applied {
		t.Fatal(r, err)
	}
	// The resource projection sees the stray goal first.
	if stage, _ := f.p.ValidateManagedStage(f.s, after, stray); stage != "resource-projection" {
		t.Fatal(stage)
	}
	apps, err := f.p.readOnlyApps(after)
	if err != nil {
		t.Fatal(err)
	}
	err = f.p.validateAppCommands(after, apps, stray)
	var reason invariantFailure
	if !errors.As(err, &reason) || reason != "unbound-goal" || !errors.Is(err, ErrCatalog) {
		t.Fatal(err)
	}
	if f.p.ValidateManaged(f.s, after, stray) == nil {
		t.Fatal("stage split changed the verdict")
	}
}
