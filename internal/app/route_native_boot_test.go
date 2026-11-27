// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

// These are original-journal and driver-boundary tests with model kernel boots.
// They do not reboot a kernel or prove native retirement/recreation across boot.
func TestRouteNativeExecutionBootDiffersFromPreparationAndCannotBeReplaced(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	defer owner.reports.Close()
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	prepared := record.Dispatch
	executionBoot := [32]byte{201}
	core, err := core.ResumeBoot(executionBoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.saveRouteCore(&record, ref, core); err != nil {
		t.Fatal(err)
	}
	driver := &routeOutcomeDriver{outcome: reconcile.EffectUnknown}
	driver.before = func(_ string, _ reconcile.Operation) {
		stored, found, err := owner.loadRouteOwner(ref)
		if err != nil || !found || stored.NativeBoot != executionBoot || !sameRouteDispatch(stored.Dispatch, prepared) {
			t.Fatal("first execution did not sync its actual boot while preserving preparation", err)
		}
	}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err == nil {
		t.Fatal("unknown execution became success")
	}
	if record.NativeBoot != executionBoot || record.NativeBoot == prepared.Boot || driver.executed != 1 {
		t.Fatal("execution boot was inferred from preparation")
	}
	core, err = services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.ResumeBoot([32]byte{202})
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.saveRouteCore(&record, ref, core); err != nil {
		t.Fatal(err)
	}
	before, _ := owner.reports.Get(routeOwnerKey(ref.ID))
	driver.outcome = reconcile.EffectApplied // Even a same-named positive readback must not run.
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, false, false); err == nil || driver.recovered != 0 {
		t.Fatal("new kernel readback adopted original execution", err)
	}
	for _, replacement := range [][32]byte{{}, core.Boot()} {
		changed := record
		changed.NativeBoot = replacement
		if err := owner.saveRouteOwner(changed, ref); err == nil {
			t.Fatal("original execution boot was overwritten")
		}
	}
	changed := record
	changed.NativeStarted, changed.NativeBoot = false, [32]byte{}
	if err := owner.saveRouteOwner(changed, ref); err == nil {
		t.Fatal("unknown original execution was reset to unsent")
	}
	after, _ := owner.reports.Get(routeOwnerKey(ref.ID))
	if !bytes.Equal(before, after) || record.BridgeReturned || record.NativeBoot != executionBoot || !sameRouteDispatch(record.Dispatch, prepared) {
		t.Fatal("boot mismatch changed original pending work or returned its dependency")
	}
}

func TestRouteNativeLegacyRecordKeepsAbsentBootAndRejectsCrossBootRecovery(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	defer owner.reports.Close()
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	// Inject only a previous schema1 producer's bytes, not native success.
	record.NativeStarted = true
	raw, _ := json.Marshal(record)
	if bytes.Contains(raw, []byte(`"NativeBoot"`)) {
		t.Fatal("absent legacy boot changed its canonical bytes")
	}
	if err := owner.reports.Write(map[string][]byte{routeOwnerKey(ref.ID): raw}); err != nil {
		t.Fatal(err)
	}
	legacy, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || legacy.NativeBoot != ([32]byte{}) {
		t.Fatal("legacy original was replaced or assigned an inferred boot", err)
	}
	if err := legacy.requireNativeBoot(core.Boot()); err != nil {
		t.Fatal("same preparation boot was rejected", err)
	}
	if err := owner.saveRouteOwner(legacy, ref); err != nil {
		t.Fatal(err)
	}
	stored, _ := owner.reports.Get(routeOwnerKey(ref.ID))
	if !bytes.Equal(raw, stored) {
		t.Fatal("reading/saving legacy record inserted execution provenance")
	}
	changed := legacy
	changed.NativeBoot = core.Boot()
	if err := owner.saveRouteOwner(changed, ref); err == nil {
		t.Fatal("legacy execution boot was filled from current/preparation boot")
	}
	core, err = core.ResumeBoot([32]byte{203})
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.saveRouteCore(&legacy, ref, core); err != nil {
		t.Fatal(err)
	}
	driver := &routeOutcomeDriver{outcome: reconcile.EffectApplied}
	if err := owner.runRouteDriver(t.Context(), ref, &legacy, core, *core.Journal().Pending, driver, false, false); err == nil || driver.recovered != 0 || driver.executed != 0 {
		t.Fatal("unknown legacy boot was sent to current kernel driver", err)
	}
}

func TestRouteFirstNativeSendRequiresStoredPreparationAndCannotPreassignBoot(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	defer owner.reports.Close()
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	changed := record
	changed.NativeBoot = core.Boot()
	raw, _ := json.Marshal(changed)
	if _, err := decodeRouteOwner(raw, ref); err == nil {
		t.Fatal("unsent preparation acquired an execution boot")
	}
	if err := owner.reports.Write(map[string][]byte{routeOwnerKey(ref.ID): nil}); err != nil {
		t.Fatal(err)
	}
	driver := &routeOutcomeDriver{outcome: reconcile.EffectApplied}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err == nil || driver.executed != 0 || record.NativeStarted || record.NativeBoot != ([32]byte{}) {
		t.Fatal("lost preparation was replaced with a new first-send record", err)
	}
	if _, err := owner.reports.Get(routeOwnerKey(ref.ID)); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("rejected native send recreated its missing preparation", err)
	}
}
