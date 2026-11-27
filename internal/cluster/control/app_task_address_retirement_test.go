// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/schema"
)

// Native Gone/owner facts are injected; every planner, retirement journal,
// signed report, FSM transition and address authority is the product core.
func TestClosedTaskReturnsOnlyItsOwnAddressesBeforeSharedBorrowRetires(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	first := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first-alias")
	second := managedDNSTaskCoreBegin(t, f, "second", "10.80.1.11", "second-alias")
	for _, app := range []string{"first", "second"} {
		managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("network-ref", "tenant", app, "lan/node-a"), true, state.Applied)
		managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("task", "tenant", app, "web"), true, state.Applied)
	}
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, err := f.p.Apps(f.s)
	if err != nil || apps.network == nil {
		t.Fatal(err)
	}
	i, _ := apps.Inventory("tenant", "first")
	other := f.s.Object(second)
	otherAllocation, held := apps.network.Authority.AddressBook().Allocation(second + "/lan/0")
	if !held {
		t.Fatal("other original allocation missing")
	}
	managedDNSChange(t, f, "stop-first-task-address", "down-app", i.Revision(), AppDown{Tenant: "tenant", App: "first", Operation: "stop-first"}, state.Applied)
	view := func() (Apps, deployment.Inventory, deployment.RetirementView) {
		t.Helper()
		a, err := f.p.Apps(f.s)
		if err != nil {
			t.Fatal(err)
		}
		i, ok := a.Inventory("tenant", "first")
		r, retiring := i.Retirement()
		if !ok || !retiring {
			t.Fatal("original retirement disappeared")
		}
		return a, i, r
	}
	explain := func(key string, detail AppRetirementProgress) string {
		t.Helper()
		_, i, retirement := view()
		return f.p.ExplainAddressRetirement(f.s, AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "first", Operation: retirement.ID, Action: "retire-addresses", Key: key, Expected: i.Revision(), At: 11, Retire: &detail})
	}
	report := func(action, key string, detail AppRetirementProgress, want state.Code) {
		t.Helper()
		_, i, retirement := view()
		r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "first", Operation: retirement.ID, Action: action, Key: key, Expected: i.Revision(), RootRevision: f.s.Object(AppsKey).Revision, Epoch: f.s.ModuleEpoch(), At: 11, RequestID: "original-task-address", Retire: &detail}
		r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
		cmd, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		var result state.Result
		f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != want {
			t.Fatal(action, key, result, want, err)
		}
	}
	applyRemoval := func(phase string) {
		t.Helper()
		report("retire-send", first, AppRetirementProgress{Phase: phase}, state.Applied)
		_, i, _ := view()
		m, ok := i.Removal(first, phase)
		if !ok {
			t.Fatal("original mutation missing", phase)
		}
		var result state.Result
		f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, m.Command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != state.Applied {
			t.Fatal("original mutation", phase, result, err)
		}
		report("retire-collect", first, AppRetirementProgress{Phase: phase}, state.Applied)
	}
	applyRemoval("drain")
	_, i, retirement := view()
	var original deployment.RetirementTarget
	for _, target := range retirement.Targets {
		if target.Original.Step.Key == first {
			original = target
		}
	}
	if original.Drain == nil || original.Drain.Result == nil {
		t.Fatal("original drain was not committed")
	}
	signature := ed25519.Sign(f.node, schema.GoneBytes(f.p.Cluster, first, original.Original.Result.Generation, []byte(original.Drain.Command.Value)))
	report("retire-gone", first, AppRetirementProgress{Gone: signature}, state.Applied)
	applyRemoval("proof")
	applyRemoval("delete")
	apps, _, _ = view()
	allocations, err := apps.NetworkRetirementAllocations("tenant", "first", first)
	if err != nil || len(allocations) != 1 || allocations[0].Endpoint != first+"/lan/0" || allocations[0].Address.String() != "10.80.1.10" || f.s.Object(first).Present {
		t.Fatal("closed Task did not retain exactly its original address", allocations, err)
	}
	if _, err := apps.NetworkRetirementAllocations("tenant", "second", first); err == nil {
		t.Fatal("foreign app obtained the closed Task scope")
	}
	report("retire-finish", "", AppRetirementProgress{}, state.ConditionFailed)
	if why := explain(first, AppRetirementProgress{Phase: "fence"}); why != "" {
		t.Fatal("applicable fence explained as rejected:", why)
	}
	report("retire-addresses", first, AppRetirementProgress{Phase: "fence"}, state.Applied)
	if why := explain(first, AppRetirementProgress{Phase: "fence"}); why != "fence changed nothing (1 allocations, 1 already fenced)" {
		t.Fatal("repeated fence reason:", why)
	}
	apps, _, _ = view()
	fence, exists := apps.network.Authority.AddressRetirement(allocations[0])
	if !exists {
		t.Fatal("original address fence missing")
	}
	bad := services.AddressOwnerClose{Cluster: f.p.Cluster, Target: fence.ID, Epoch: fence.Epoch, Owner: [32]byte(f.node.Public().(ed25519.PublicKey)), Boot: [32]byte{1}, At: 11, Native: "foreign-native", Fenced: true, Stopped: true}
	bad.Signature = ed25519.Sign(f.node, services.AddressOwnerCloseBytes(bad))
	if why := explain(first, AppRetirementProgress{Phase: "release", Addresses: []services.AddressOwnerClose{bad}}); !strings.HasPrefix(why, "release proof native or owner differs") {
		t.Fatal("forged release reason:", why)
	}
	report("retire-addresses", first, AppRetirementProgress{Phase: "release", Addresses: []services.AddressOwnerClose{bad}}, state.ConditionFailed)
	apps, _, _ = view()
	if current, ok := apps.network.Authority.AddressBook().Allocation(second + "/lan/0"); !ok || current != otherAllocation || f.s.Object(second) != other {
		t.Fatal("one closed Task disturbed another app's Task/address")
	}
	if _, held := apps.network.Authority.AddressBook().Allocation(first + "/lan/0"); !held {
		t.Fatal("fence or forged closure released the original slot")
	}
}
