// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
)

// No stage is sent in this fixture. The empty retirement proves that planned
// work was stopped before effects, not that an unobserved native object ended.
func stopUnsentDeliveryForHistory(t *testing.T, f *backupCoreFixture) {
	t.Helper()
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := a.entries[appKey("tenant", "source-app")]
	active, ok := entry.Inventory.Active()
	if !ok || len(entry.Inventory.Claims()) != 0 {
		t.Fatal("fixture is not an unsent original app")
	}
	f.apply("down-"+active.ID, "down-app", entry.Inventory.Revision(), AppDown{Tenant: "tenant", App: "source-app", Operation: "stop-" + active.ID}, state.Applied)
	a, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry = a.entries[appKey("tenant", "source-app")]
	retirement, ok := entry.Inventory.Retirement()
	if !ok || len(retirement.Targets) != 0 {
		t.Fatal("planned work acquired native targets")
	}
	r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "source-app", Operation: retirement.ID, Action: "retire-finish", Expected: entry.Inventory.Revision(), At: 10, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "finish-" + active.ID, Retire: &AppRetirementProgress{}}
	r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
	command, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	var result state.Result
	f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("empty original closure", result, err)
	}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "continue"}, state.Applied)
}

func TestCDSourceTicketPinsSharedLedgerWithoutNativeOrUpload(t *testing.T) {
	f := deliveryControlFixture(t)
	stopUnsentDeliveryForHistory(t, f)
	a, _ := f.p.Apps(f.s)
	entry := a.entries[appKey("tenant", "source-app")]
	f.apply("resume-idle-source", "resume-app-cd", entry.Delivery.Revision(), AppCDChange{Tenant: "tenant", App: "source-app"}, state.Applied)
	a, _ = f.p.Apps(f.s)
	if !a.Quiescent() || !f.p.storageQuiescent(f.s) {
		t.Fatal("idle source retained an unresolved reference")
	}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	a, _ = f.p.Apps(f.s)
	entry = a.entries[appKey("tenant", "source-app")]
	ticket, pending := entry.Delivery.FetchTicket()
	if !pending || len(a.uploads) != 0 || !entry.Inventory.Quiescent() || a.Quiescent() {
		t.Fatal("source-only pending ticket omitted from shared expiry guard")
	}
	f.apply("deny-source-request-expiry", "rotate-ledger", 1, LedgerWindow{NextEpoch: 2}, state.ConditionFailed)
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil || f.p.storageQuiescent(f.s) {
		t.Fatal("Snapshot/restore lost source receipt protection", err)
	}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "source-error", Ticket: &ticket, Error: "policy"}, state.Applied)
	f.apply("explicit-expiry-after-source-closure", "rotate-ledger", 1, LedgerWindow{NextEpoch: 2}, state.Applied)
	a, err = f.p.Apps(f.s)
	entry = a.entries[appKey("tenant", "source-app")]
	if err != nil || f.s.ModuleEpoch() != 2 || entry.Delivery.SourceError() != "policy" {
		t.Fatal("expiry replaced original source outcome", err)
	}
}

func TestCDHistoryConsumesCommittedFloorAndPreservesCurrentSelection(t *testing.T) {
	for _, successor := range []bool{false, true} {
		name := "registration"
		if successor {
			name = "successor"
		}
		t.Run(name, func(t *testing.T) {
			f := deliveryControlFixture(t)
			stopUnsentDeliveryForHistory(t, f)
			if successor {
				a, _ := f.p.Apps(f.s)
				d, _ := a.Delivery("tenant", "source-app")
				q := AppCDChange{Tenant: "tenant", App: "source-app"}
				f.apply("resume-source", "resume-app-cd", d.Revision(), q, state.Applied)
				a, _ = f.p.Apps(f.s)
				d, _ = a.Delivery("tenant", "source-app")
				f.apply("replan-successor", "replan-app", d.Revision(), q, state.Applied)
				a, _ = f.p.Apps(f.s)
				entry := a.entries[appKey("tenant", "source-app")]
				selected, _ := entry.Delivery.CandidateSelection()
				q.Choice = &AppDeliveryChoice{Operation: "second", Candidate: selected.Candidate, Registration: appRegistrationDigest(entry.Origin)}
				f.apply("sync-successor", "sync-app", entry.Delivery.Revision(), q, state.Applied)
				stopUnsentDeliveryForHistory(t, f)
			}
			a, err := f.p.Apps(f.s)
			if err != nil {
				t.Fatal(err)
			}
			entry := a.entries[appKey("tenant", "source-app")]
			identity, err := appExecutionOrigin(entry.Origin, entry.Sync, entry.Inventory.Scope())
			if err != nil {
				t.Fatal(err)
			}
			original, _ := json.Marshal(entry.Origin)
			selection, _ := json.Marshal(entry.Sync)
			catalog, _ := f.p.Catalog(f.s)
			q := AppHistorySelection{Tenant: "tenant", App: "source-app"}
			if _, err := a.rotateHistory(entry.Inventory.Revision(), catalog, "admin", f.s, q); err == nil {
				t.Fatal("history invented its own sender epoch fence")
			}
			command := state.Command{Kind: state.ModuleWindow, Actor: "user/admin", Epoch: f.s.ModuleEpoch(), RequestID: "explicit-window", Key: StorageKey, Value: "fixture"}
			var result state.Result
			f.s, result, err = state.ApplyAdmitted(f.s, f.s.Index()+1, command, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
				return map[string][]byte{StorageKey: []byte("fixture")}, state.Applied
			}, func(state.State, state.Command) bool { return true })
			if err != nil || result.Code != state.Applied {
				t.Fatal("committed A1 window", result, err)
			}
			next, err := a.rotateHistory(entry.Inventory.Revision(), catalog, "admin", f.s, q)
			if err != nil {
				t.Fatal(err)
			}
			compacted := next.entries[appKey("tenant", "source-app")]
			if compacted.Compacted == nil || compacted.Compacted.ID != identity.Operation || !validCompactedAppSource(compacted.Inventory, compacted.Origin, compacted.Down, compacted.Sync, *compacted.Compacted) || !compacted.Inventory.OperationExpired(identity.Submitter, identity.Epoch) {
				t.Fatal("compaction lost current signed selection/floor")
			}
			after, _ := json.Marshal(compacted.Origin)
			selected, _ := json.Marshal(compacted.Sync)
			if !bytes.Equal(original, after) || !bytes.Equal(selection, selected) || compacted.Delivery == nil || !compacted.Delivery.Paused() {
				t.Fatal("compaction rewrote source/selection or resumed CD")
			}
			writes, code := f.p.appsCheckpoint(f.s, next)
			if code != state.Applied {
				t.Fatal(code)
			}
			_, anchorEpoch, _, _ := f.s.Principal("anchor")
			f.s, result, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: anchorEpoch, RequestID: "compacted-checkpoint", Key: AppsKey, Expected: f.s.Object(AppsKey).Revision, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
			if err != nil || result.Code != state.Applied {
				t.Fatal(result, err)
			}
			restored, err := f.p.Apps(f.s)
			if err != nil {
				t.Fatal("single Delivery checkpoint failed to restore", err)
			}
			view, err := restored.Operation(catalog, "admin", "tenant", AppOperationRequest{App: "source-app", ID: identity.Operation})
			if err != nil || !view.Found || view.Current || view.Operation.Status != "Retired" {
				t.Fatal("compacted original result became missing/live", view, err)
			}
			if successor {
				tampered := *compacted.Sync
				tampered.Plan[0] ^= 1
				if validCompactedAppSource(compacted.Inventory, compacted.Origin, compacted.Down, &tampered, *compacted.Compacted) {
					t.Fatal("compacted plan adopted a different selection")
				}
			}
		})
	}
}
