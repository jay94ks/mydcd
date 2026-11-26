// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// The product planner/FSM creates the canonical original Task and Binding.
// The selective view is injected to isolate the finish ownership filter; this
// is not a signed whole-CD transition or a native termination claim.
func TestPartialRetirementPreservesOnlyOriginalUnselectedBinding(t *testing.T) {
	f := deliveryControlFixture(t)
	const app = "source-app"
	managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("network-ref", "tenant", app, "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	task := deployment.ResourceKey("task", "tenant", app, "web")
	managedDNSTaskCoreSubmit(t, f, app, task, true, state.Applied)
	managedDNSTaskCoreProgress(t, f, app, "bind-inputs", task, nil)
	a, err := f.p.Apps(f.s)
	if err != nil || len(a.bindings.Live()) != 1 {
		t.Fatal("original live binding", err)
	}
	b := a.bindings.Live()[0]
	entry := a.entries[appKey("tenant", app)]
	entry.PendingSync = &AppDeliverySync{} // structural filter only, not admission
	source, exists := a.BindingSource(b.Digest())
	if !exists {
		t.Fatal("original accepted source missing")
	}
	retirement := deployment.RetirementView{ID: "selective", Targets: []deployment.RetirementTarget{{Original: deployment.Claim{Step: deployment.Step{Key: "another-task"}}, Closed: true}}}
	before, err := a.bindings.Encode()
	if err != nil || !preserveRetirementBinding(f.s, a, entry, retirement, b) {
		t.Fatal("unrelated selected closure rejected original live Task", err)
	}
	rolling, wave := entry, retirement
	rolling.PendingSync, rolling.Delivery = nil, nil
	wave.KeepExecution = true
	if !preserveRetirementBinding(f.s, a, rolling, wave, b) {
		t.Fatal("ordinary app wave released an unselected original Binding")
	}
	wave.Targets = []deployment.RetirementTarget{{Original: deployment.Claim{Step: deployment.Step{Key: source.Task.Key}}}}
	if preserveRetirementBinding(f.s, a, rolling, wave, b) {
		t.Fatal("wave retained the selected Task's old Binding")
	}
	for _, label := range []string{"full-down", "app-down", "no-sync", "no-delivery", "selected-task", "unknown-source", "changed-task", "unverified-input", "missing-current", "foreign-app"} {
		t.Run(label, func(t *testing.T) {
			current, apps, original, selection := f.s, a, entry, retirement
			apps.sources = append([]AppBindingSource(nil), a.sources...)
			switch label {
			case "full-down":
				selection.Down = true
			case "app-down":
				original.Down = &UserOperation{}
			case "no-sync":
				original.PendingSync = nil
			case "no-delivery":
				original.Delivery = nil
			case "selected-task":
				selection.Targets = []deployment.RetirementTarget{{Original: deployment.Claim{Step: deployment.Step{Key: source.Task.Key}}, Closed: true}}
			case "unknown-source":
				apps.sources = nil
			case "changed-task":
				apps.sources[0].Task.Generation++
			case "unverified-input":
				apps.sources[0].Inputs = deployment.ObjectRef{Key: deployment.ResourceKey("inputs", "tenant", app, "web"), Generation: 1, Revision: 1}
			case "missing-current":
				current, err = state.New("other-state")
				if err != nil {
					t.Fatal(err)
				}
			case "foreign-app":
				original.Inventory, err = deployment.NewInventory(f.p.Cluster, "tenant", "other-app", "deploy")
				if err != nil {
					t.Fatal(err)
				}
			}
			if preserveRetirementBinding(current, apps, original, selection, b) {
				t.Fatal("retired, unknown or foreign Binding bypassed finish", label)
			}
		})
	}
	after, err := a.bindings.Encode()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("finish filtering released or rewrote original references", err)
	}
}
