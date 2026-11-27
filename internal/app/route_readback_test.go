// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
)

type routeReadbackDriver struct {
	routeOutcomeDriver
	inspected int
}

func (d *routeReadbackDriver) Inspect(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	d.inspected++
	if d.before != nil {
		d.before(key, op)
	}
	return d.outcome, errors.Join(d.err, ctx.Err())
}

func TestRouteReadbackObservesOriginalAppliedWithoutRecoveryOrStoreMutation(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "owner.db"))
	defer owner.reports.Close()
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	apply := &routeOutcomeDriver{outcome: reconcile.EffectApplied}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, apply, true, false); err != nil {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(record)
	inspect := &routeReadbackDriver{routeOutcomeDriver: routeOutcomeDriver{outcome: reconcile.EffectApplied}}
	inspect.before = func(key string, op reconcile.Operation) {
		if key != ref.RouteNativeKey() || op.ID != 1 || op.Kind != reconcile.Apply || op.Phase != reconcile.Dispatched || op.Target.Generation != ref.Generation || sha256.Sum256([]byte(op.Target.Spec)) != record.Dispatch.NativeSpec {
			t.Fatal("inspection changed original native operation")
		}
		stored, found, err := owner.loadRouteOwner(ref)
		if err != nil || !found {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(stored)
		if !bytes.Equal(before, raw) {
			t.Fatal("inspection changed owner DB before readback")
		}
	}
	for range 2 {
		if err := inspectAppliedRoute(t.Context(), ref, record, core, core.Boot(), inspect); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := json.Marshal(record)
	stored, _, err := owner.loadRouteOwner(ref)
	if err != nil {
		t.Fatal(err)
	}
	disk, _ := json.Marshal(stored)
	if inspect.inspected != 2 || inspect.executed != 0 || inspect.recovered != 0 || !bytes.Equal(before, after) || !bytes.Equal(before, disk) {
		t.Fatal("metadata inspection recovered/dispatched or rewrote original state")
	}
}

func TestRouteReadbackRejectsUncertainPausedAndChangedOriginal(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "owner.db"))
	defer owner.reports.Close()
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	pending := core
	driver := &routeOutcomeDriver{outcome: reconcile.EffectApplied}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err != nil {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pending", "paused", "never-started", "boot-changed", "legacy-boot-changed", "returned-bridge", "missing-bridge", "report", "retirement", "never-dispatched", "changed-dispatch", "unsynced-core"} {
		t.Run(name, func(t *testing.T) {
			r, c, boot := record, core, core.Boot()
			switch name {
			case "pending":
				c = pending
				r.Core, _ = c.Encode()
			case "paused":
				c = c.Pause()
				r.Core, _ = c.Encode()
			case "never-started":
				r.NativeStarted = false
			case "boot-changed":
				boot[0] ^= 0xff
			case "legacy-boot-changed":
				r.NativeBoot = [32]byte{}
				r.Dispatch.Boot[0] ^= 0xff
			case "returned-bridge":
				r.BridgeReturned = true
			case "missing-bridge":
				r.Bridge = reconcile.Lease{}
			case "report":
				r.Report = &control.RouteDispatchReport{}
			case "retirement":
				r.Retirement = &control.RouteRetirementReport{}
			case "never-dispatched":
				r.NeverDispatched = true
			case "changed-dispatch":
				r.Dispatch.NativeSpec[0] ^= 0xff
			case "unsynced-core":
				r.Core = append([]byte(nil), record.Core...)
				r.Core[0] ^= 1
			}
			reader := &routeReadbackDriver{routeOutcomeDriver: routeOutcomeDriver{outcome: reconcile.EffectApplied}}
			if inspectAppliedRoute(t.Context(), ref, r, c, boot, reader) == nil || reader.inspected != 0 || reader.executed != 0 || reader.recovered != 0 {
				t.Fatal("non-applied/changed work reached native inspection")
			}
		})
	}
	for _, outcome := range []reconcile.Outcome{reconcile.EffectUnknown, reconcile.EffectNotApplied} {
		reader := &routeReadbackDriver{routeOutcomeDriver: routeOutcomeDriver{outcome: outcome}}
		before, _ := json.Marshal(record)
		if inspectAppliedRoute(t.Context(), ref, record, core, core.Boot(), reader) == nil {
			t.Fatal("uncertain native readback became serving")
		}
		after, _ := json.Marshal(record)
		if !bytes.Equal(before, after) || reader.inspected != 1 || reader.recovered != 0 {
			t.Fatal("failed readback changed native owner")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	reader := &routeReadbackDriver{routeOutcomeDriver: routeOutcomeDriver{outcome: reconcile.EffectApplied}}
	if err := inspectAppliedRoute(ctx, ref, record, core, core.Boot(), reader); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled readback became serving", err)
	}
}
