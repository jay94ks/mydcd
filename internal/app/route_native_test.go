// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/storage"
)

// Only native results are injected. Core transitions, signed proofs and private
// owner DB writes below are product code; no kernel/Bridge/RPC success is claimed.
type routeOutcomeDriver struct {
	executed, recovered int
	outcome             reconcile.Outcome
	err                 error
	before              func(string, reconcile.Operation)
}

func (d *routeOutcomeDriver) Execute(_ context.Context, key string, operation reconcile.Operation) (reconcile.Outcome, error) {
	d.executed++
	if d.before != nil {
		d.before(key, operation)
	}
	return d.outcome, d.err
}

func (d *routeOutcomeDriver) Recover(_ context.Context, key string, operation reconcile.Operation) (reconcile.Outcome, error) {
	d.recovered++
	if d.before != nil {
		d.before(key, operation)
	}
	return d.outcome, d.err
}

func routeNativeTestOwner(t *testing.T, path string) *Runtime {
	t.Helper()
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{161}, 32))
	return &Runtime{reports: db, Identity: &identity.Identity{Private: key, Public: [32]byte(key.Public().(ed25519.PublicKey))}}
}

func dispatchedRouteTestRecord(t *testing.T, owner *Runtime, ref services.ReferenceConsumer, record routeOwnerRecord) (services.ReferenceConsumer, routeOwnerRecord, services.RouteRuntime) {
	t.Helper()
	ref.Dispatch = &record.Dispatch
	record.Report = nil
	record.Bridge = reconcile.Lease{Generation: ref.Native.Generation, Token: 3}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Dispatch(1)
	if err != nil {
		t.Fatal(err)
	}
	record.Core, err = core.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	return ref, record, core
}

// Model only: real packet closure uses reader join and QuiesceRoute. Native
// driver tests below inject these facts instead of executing kernel effects.
func modelRoutePacketClosure(t *testing.T, owner *Runtime, ref services.ReferenceConsumer, record *routeOwnerRecord, core services.RouteRuntime) services.RouteRuntime {
	t.Helper()
	proof, err := core.PacketCloseFacts()
	if err != nil {
		t.Fatal(err)
	}
	proof.JournalSynced, proof.ReadersStopped, proof.QueueEmpty = true, true, true
	proof.AdmissionsStopped, proof.ConntrackEmpty = true, true
	proof.Signature = ed25519.Sign(owner.Identity.Private, services.RoutePacketCloseBytes(proof))
	core, err = core.ClosePackets(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.saveRouteCore(record, ref, core); err != nil {
		t.Fatal(err)
	}
	return core
}

func TestRouteNativeUnknownRecoversOriginalOperationFromSameDBWithoutExecute(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	path := filepath.Join(t.TempDir(), "observations.db")
	owner := routeNativeTestOwner(t, path)
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	driver := &routeOutcomeDriver{outcome: reconcile.EffectUnknown, err: errors.New("native reply lost")}
	driver.before = func(key string, operation reconcile.Operation) {
		t.Helper()
		stored, found, err := owner.loadRouteOwner(ref)
		if err != nil || !found || !stored.NativeStarted || stored.NativeBoot != core.Boot() || stored.Bridge != record.Bridge || key != ref.RouteNativeKey() || operation.ID != 1 || operation.Target.Generation != ref.Generation || sha256.Sum256([]byte(operation.Target.Spec)) != record.Dispatch.NativeSpec {
			t.Fatal("native call preceded original durable marker/pin or changed target", err)
		}
	}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err == nil {
		t.Fatal("unknown native outcome reported success")
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	owner = routeNativeTestOwner(t, path)
	defer owner.reports.Close()
	restored, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || !restored.NativeStarted || restored.NativeBoot != record.NativeBoot || restored.Nonce != record.Nonce || restored.Bridge != record.Bridge {
		t.Fatal("restart lost original dispatch/nonce/pin", err)
	}
	core, err = services.DecodeRouteRuntime(restored.Core)
	if err != nil || core.Journal().Pending == nil || core.Journal().Pending.ID != 1 || core.Journal().Pending.Phase != reconcile.RecoveryRequired || core.Journal().Applied.Present {
		t.Fatal("unknown original operation was replaced or applied", err)
	}
	driver.outcome, driver.err = reconcile.EffectApplied, nil
	if err := owner.runRouteDriver(t.Context(), ref, &restored, core, *core.Journal().Pending, driver, false, false); err != nil {
		t.Fatal(err)
	}
	core, err = services.DecodeRouteRuntime(restored.Core)
	if err != nil || core.Journal().Pending != nil || !core.Journal().Applied.Present || core.Journal().LastID != 1 || driver.executed != 1 || driver.recovered != 1 {
		t.Fatal("recovery retried Execute or lost original applied result", err)
	}
	before, _ := json.Marshal(restored)
	op := reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.Dispatched, Target: core.Journal().Applied}
	if err := owner.runRouteDriver(t.Context(), ref, &restored, core, op, driver, true, false); err == nil {
		t.Fatal("applied original was freshly dispatched again")
	}
	after, _ := json.Marshal(restored)
	if !bytes.Equal(before, after) || driver.executed != 1 {
		t.Fatal("rejected repeat changed original owner or sent another Apply")
	}
}

func TestRouteNativeReadbackFailurePausesAppliedProofUntilOriginalRecovery(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	defer owner.reports.Close()
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	driver := &routeOutcomeDriver{outcome: reconcile.EffectApplied}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err != nil {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	op := reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.Dispatched, Target: core.Journal().Applied}
	driver.outcome = reconcile.EffectUnknown
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, op, driver, false, true); err == nil {
		t.Fatal("unobserved original native readback was Ready")
	}
	core, err = services.DecodeRouteRuntime(record.Core)
	if err != nil || !core.Journal().Stopped || !core.Journal().Applied.Present || core.Journal().Pending != nil {
		t.Fatal("readback failure lost original applied provenance or left admission open", err)
	}
	driver.outcome = reconcile.EffectApplied
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, op, driver, false, true); err != nil {
		t.Fatal(err)
	}
	core, err = services.DecodeRouteRuntime(record.Core)
	if err != nil || core.Journal().Stopped || driver.executed != 1 || driver.recovered != 2 {
		t.Fatal("readback replaced original native instead of recovering it", err)
	}
}

func TestRouteNativePersistFailureAndUnsyncedCoreSendNothing(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	driver := &routeOutcomeDriver{outcome: reconcile.EffectApplied}
	changed, err := core.Unknown(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.runRouteDriver(t.Context(), ref, &record, changed, *changed.Journal().Pending, driver, true, false); err == nil {
		t.Fatal("unsynced core reached native driver")
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err == nil || !owner.routeStoreFailed {
		t.Fatal("native marker persistence failure left owner writable")
	}
	if driver.executed != 0 || driver.recovered != 0 || record.NativeStarted {
		t.Fatal("native send occurred before original dispatch sync")
	}
}

func TestRouteNativeWithdrawRemoveUnknownPreservesOriginalBridgeReceipt(t *testing.T) {
	ref, record, catalog, networks, authority := routeOwnerCoreFixture(t)
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	defer owner.reports.Close()
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	driver := &routeOutcomeDriver{outcome: reconcile.EffectApplied}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err != nil {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := networks.Route("first", "database")
	networks, err = networks.Withdraw(catalog, "admin", "first", "database", "first", route.Revision)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Sync(catalog, networks, authority)
	if err != nil {
		t.Fatal(err)
	}
	beforeClosure, op, err := core.Plan()
	if err != nil || op == nil {
		t.Fatal(err)
	}
	beforeClosure, err = beforeClosure.Dispatch(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.saveRouteCore(&record, ref, beforeClosure); err != nil {
		t.Fatal(err)
	}
	if err := owner.runRouteDriver(t.Context(), ref, &record, beforeClosure, *beforeClosure.Journal().Pending, driver, false, false); err == nil || driver.recovered != 0 {
		t.Fatal("native Remove ran without durable packet closure", err)
	}
	core = modelRoutePacketClosure(t, owner, ref, &record, beforeClosure)
	operation := core.Journal().Pending
	if operation == nil || operation.ID != 2 || operation.Kind != reconcile.Remove || operation.Phase != reconcile.Dispatched {
		t.Fatal("withdraw did not retire original native")
	}
	pin := record.Bridge
	instance := &tunnelInstance{}
	instance.routeReading.Store(true)
	owner.tunnel = &tunnelRuntime{routes: map[[32]byte]*tunnelInstance{ref.ID: instance}}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, false, false); err == nil || driver.recovered != 0 {
		t.Fatal("native Remove ran before the original packet reader joined", err)
	}
	instance.routeReading.Store(false)
	driver.outcome = reconcile.EffectUnknown
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, false, false); err == nil {
		t.Fatal("unknown Remove was Gone")
	}
	core, err = services.DecodeRouteRuntime(record.Core)
	if err != nil || !core.Journal().Applied.Present || core.Journal().Pending == nil || core.Journal().Pending.ID != 2 || record.Bridge != pin || record.BridgeReturned {
		t.Fatal("unknown Remove released or replaced original dependency", err)
	}
	driver.outcome = reconcile.EffectApplied
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, false, false); err != nil {
		t.Fatal(err)
	}
	core, err = services.DecodeRouteRuntime(record.Core)
	if err != nil || core.Journal().Pending != nil || core.Journal().Applied.Present || core.Journal().Desired.Present || record.Bridge != pin || record.BridgeReturned || driver.executed != 1 || driver.recovered != 2 {
		t.Fatal("native closure fabricated a Bridge return or retried Apply", err)
	}
	// The actual Manager must retire this exact pin; core/native success alone
	// cannot fabricate that separate durable receipt.
	if err := owner.returnRouteBridge(ref, &record, core); err == nil || record.BridgeReturned {
		t.Fatal("missing Bridge manager was treated as a returned dependency")
	}
}

func TestRouteNativeUnknownApplyRetirementReopensSamePendingIDAndNeverCreates(t *testing.T) {
	ref, record, catalog, networks, authority := routeOwnerCoreFixture(t)
	path := filepath.Join(t.TempDir(), "observations.db")
	owner := routeNativeTestOwner(t, path)
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	driver := &routeOutcomeDriver{outcome: reconcile.EffectUnknown}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err == nil {
		t.Fatal("unknown Apply reported success")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := networks.Route("first", "database")
	networks, err = networks.Withdraw(catalog, "admin", "first", "database", "first", route.Revision)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Sync(catalog, networks, authority)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.BeginNativeRetirement()
	if err != nil {
		t.Fatal(err)
	}
	core = modelRoutePacketClosure(t, owner, ref, &record, core)
	if err := owner.saveRouteCore(&record, ref, core); err != nil {
		t.Fatal(err)
	}
	remove := *core.Journal().Pending
	remove.Kind = reconcile.Remove
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, remove, driver, false, false); err == nil {
		t.Fatal("unknown compensating removal was Gone")
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	owner = routeNativeTestOwner(t, path)
	defer owner.reports.Close()
	restored, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || restored.BridgeReturned || restored.Bridge != record.Bridge {
		t.Fatal("retiring owner lost original dependency", err)
	}
	core, err = services.DecodeRouteRuntime(restored.Core)
	if err != nil || core.Journal().Pending == nil || core.Journal().Pending.ID != 1 || core.Journal().Pending.Kind != reconcile.Apply || core.Journal().Pending.Phase != reconcile.Retiring || core.Journal().LastID != 1 {
		t.Fatal("uncertain Apply was replaced by a fabricated new operation", err)
	}
	driver.outcome = reconcile.EffectApplied
	if err := owner.runRouteDriver(t.Context(), ref, &restored, core, remove, driver, false, false); err != nil {
		t.Fatal(err)
	}
	core, err = services.DecodeRouteRuntime(restored.Core)
	if err != nil || core.Journal().Pending != nil || core.Journal().Applied.Present || core.Journal().Desired.Present || core.Journal().LastID != 1 || restored.BridgeReturned || driver.executed != 1 || driver.recovered != 2 {
		t.Fatal("retirement created a new Apply/result or returned the Bridge prematurely", err)
	}
}

func TestRouteNativeTerminalRecordRequiresPositiveClosureAfterFirstSend(t *testing.T) {
	ref, record, catalog, networks, authority := routeOwnerCoreFixture(t)
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := networks.Route("first", "database")
	networks, err = networks.Withdraw(catalog, "admin", "first", "database", "first", route.Revision)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Sync(catalog, networks, authority)
	if err != nil || core.Journal().Pending != nil {
		t.Fatal("unsent cancellation did not close Prepared work", err)
	}
	record.Core, err = core.Encode()
	if err != nil {
		t.Fatal(err)
	}
	record.Report = nil
	record.Bridge = reconcile.Lease{Generation: ref.Native.Generation, Token: 3}
	record.NativeStarted = true
	raw, _ := json.Marshal(record)
	if _, err := decodeRouteOwner(raw, ref); err == nil {
		t.Fatal("sent native was retired using only a missing pending/applied record")
	}
}
