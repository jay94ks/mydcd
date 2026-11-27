// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"gopkg.in/yaml.v3"
)

// Only the pure retirement/floor contract is tested here. Admission and live
// reference collection in the actual control reducer have separate tests.
func TestInventoryAndDeliveryConsumeModuleFloorWithoutPrincipal(t *testing.T) {
	// This floor-only test still enters Delivery through today's app.yaml
	// contract: management networks are predeclared, not inline app fields.
	f, input, ctx, _ := externalFixture(t)
	ctx.Features["git-cd"] = true
	document, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := NewDelivery(f.c, ctx, document)
	if err != nil {
		t.Fatal(err)
	}
	actor := "user/retired-session"
	a := delivery.Inventory()
	a.d.History = []OperationSummary{{ID: "settled", Status: "Closed", Plan: [32]byte{1}, CompletedAt: 10, Submitter: actor, Epoch: 1}}
	raw, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	a, err = DecodeInventory(raw)
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := state.New("legacy-admin")
	if _, err := a.RotateWindow(a.Revision(), f.c, "alice", shared); err == nil {
		t.Fatal("unadvanced global floor allowed compaction")
	}
	delivery.d.Transitions = []deliveryTransitionSummary{{ID: "abandoned", Mode: DeliveryUpdate, Outcome: "abandoned", Artifact: [32]byte{2}, Plan: [32]byte{3}, Closure: [32]byte{4}, Submitter: actor, Epoch: 1}}
	if _, err := delivery.RotateWindow(delivery.Revision(), f.c, "alice", shared); err == nil {
		t.Fatal("CD invented a global epoch")
	}
	command := state.Command{Kind: state.ModuleWindow, Actor: "user/admin", RequestID: "window", Key: "control/storage", Epoch: 1, Value: "fixed-proof"}
	shared, result, err := state.ApplyAdmitted(shared, 1, command, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
		return map[string][]byte{command.Key: []byte("fixed-window")}, state.Applied
	}, func(state.State, state.Command) bool { return true })
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	if _, _, _, known := shared.Principal(actor); known {
		t.Fatal("fixture manufactured actor authority")
	}
	if epoch, known := shared.LedgerEpoch(actor); !known || epoch != 2 {
		t.Fatal("reclaimed actor lost global fence")
	}
	next, err := a.RotateWindow(a.Revision(), f.c, "alice", shared)
	if err != nil || len(next.d.History) != 0 || next.d.MinEpoch[actor] != 2 {
		t.Fatal("inventory required obsolete principal row", err)
	}
	if _, err := DecodeInventory(mustInventoryBytes(t, next)); err != nil {
		t.Fatal(err)
	}
	d, err := delivery.RotateWindow(delivery.Revision(), f.c, "alice", shared)
	if err != nil || len(d.d.Transitions) != 0 || d.d.Inventory.MinEpoch[actor] != 2 {
		t.Fatal("CD required obsolete principal row", err)
	}
	if _, err := DecodeDelivery(deliveryRaw(t, d)); err != nil {
		t.Fatal(err)
	}
	if epoch, known := shared.LedgerEpoch("legacy-admin"); !known || epoch != 1 {
		t.Fatal("global maintenance changed legacy epoch")
	}
	if _, known := shared.LedgerEpoch("unknown-legacy"); known {
		t.Fatal("unknown legacy actor gained a fence")
	}
}

func mustInventoryBytes(t *testing.T, a Inventory) []byte {
	t.Helper()
	b, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
