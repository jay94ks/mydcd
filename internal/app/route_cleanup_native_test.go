// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

// Fixture rollback only. All original producers/Tasks have positively stopped
// before entry. Never rewrite the core/claim/journal or create product close
// receipts to turn rollback into a successful feature test.
func cleanupManagedRouteNative(t *testing.T, ctx context.Context, cfg config.Node, owner string, public [32]byte, bridges *network.Manager, dependentsStopped, expectGone bool) (clean bool) {
	t.Helper()
	clean = true
	fail := func(args ...any) { t.Error(args...); clean = false }
	path := filepath.Join(cfg.Node.StateDir, "control", "observations.db")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if exists, readErr := network.IsolationExists(owner); readErr != nil || exists {
			fail("native isolation without original owner DB", readErr)
		}
		return
	} else if err != nil {
		fail(err)
		return
	}
	db, err := storage.Open(path)
	if err != nil {
		fail("exclusive original route/isolation DB for rollback", err)
		return
	}
	defer db.Close()
	rows, err := db.Scan("route-owner/")
	if err != nil {
		fail(err)
		return
	}
	if len(rows) > 0 && !dependentsStopped {
		fail("refuse route rollback without actual producer/Task closure")
		return
	}
	driver := &network.TunnelDriver{Owner: owner}
	defer driver.Close()
	for name, raw := range rows {
		value, err := schema.Decode[routeOwnerRecord](raw)
		if err != nil {
			fail("original route rollback record", err)
			continue
		}
		core, err := services.DecodeRouteRuntime(value.Core)
		if err != nil {
			fail(err)
			continue
		}
		ref := core.Consumer()
		if name != routeOwnerKey(ref.ID) || ref.Native == nil || ref.Local.Owner != public || ref.Local.Node != cfg.Node.ID || engine.Owner(ref.Local.Cluster, ref.Local.Owner) != owner {
			fail("foreign route rollback identity")
			continue
		}
		record, err := decodeRouteOwner(raw, ref)
		if err != nil {
			fail("original route nonce/spec/signature changed", err)
			continue
		}
		journal := core.Journal()
		if expectGone && (core.FlowCount() != 0 || journal.Pending != nil || journal.Desired.Present || journal.Applied.Present || !record.BridgeReturned) {
			t.Error("product left original route/pins before rollback", name)
		}
		if !record.NeverDispatched {
			resource, err := originalRouteResource(ref, record)
			if err != nil {
				fail(err)
				continue
			}
			if err := driver.QuiesceRoute(ctx, ref.RouteNativeKey(), resource); err != nil {
				fail("original route rollback fence/census", err)
				continue
			}
			op := reconcile.Operation{ID: max(uint64(1), journal.LastID), Kind: reconcile.Remove, Target: resource}
			if outcome, err := driver.Recover(ctx, ref.RouteNativeKey(), op); err != nil || outcome != reconcile.EffectApplied {
				fail("original route rollback Remove/Gone", outcome, err)
				continue
			}
		}
		if record.BridgeReturned {
			continue
		}
		if !slices.Contains(bridges.Keys(), ref.Native.Key) {
			if record.Bridge != (reconcile.Lease{}) || record.NativeStarted {
				fail("original route rollback Bridge lease journal is missing")
			}
			continue
		}
		row, err := bridges.View(ref.Native.Key)
		if err != nil || row.State.GenerationFloor != ref.Native.Generation || row.Pins == nil {
			fail("original route rollback Bridge generation/journal changed", err)
			continue
		}
		pin, held := row.Consumers[ref.RouteNativeKey()]
		if held {
			if record.Bridge != (reconcile.Lease{}) && pin != record.Bridge || pin.Generation != ref.Native.Generation || !row.State.Applied.Present || sha256.Sum256([]byte(row.State.Applied.Spec)) != ref.Native.Spec {
				fail("original route rollback Bridge token/spec changed")
				continue
			}
			if err := bridges.Return(network.BridgeLease{Key: ref.Native.Key, Consumer: ref.RouteNativeKey(), Pin: pin}); err != nil {
				fail(err)
			}
		} else if record.Bridge != (reconcile.Lease{}) && slices.Contains(row.Pins.Active, record.Bridge) {
			fail("orphan active route Bridge token")
		}
	}
	if !clean {
		return
	} // Keep the deny table while an original route could not be proven Gone.
	clean = cleanupManagedIsolationNative(t, ctx, db, owner, dependentsStopped, expectGone)
	return
}

func cleanupManagedIsolationNative(t *testing.T, ctx context.Context, db *storage.DB, owner string, dependentsStopped, expectGone bool) (clean bool) {
	t.Helper()
	clean = true
	fail := func(args ...any) { t.Error(args...); clean = false }
	boot, err := services.NativeBootID()
	if err != nil {
		fail(err)
		return
	}
	raw, err := db.GetBounded(isolationRecordKey(boot), 100<<20)
	if errors.Is(err, storage.ErrMissing) {
		if exists, err := network.IsolationExists(owner); err != nil || exists {
			fail("isolation native has no original current-boot journal", err)
		}
		return
	}
	if err != nil {
		fail(err)
		return
	}
	record, err := decodeIsolationRecord(raw, owner, boot)
	if err != nil {
		fail(err)
		return
	}
	exists, err := network.IsolationExists(owner)
	if err != nil {
		fail(err)
		return
	}
	if expectGone && (exists || record.State.Pending != nil || record.State.Desired.Present || record.State.Applied.Present) {
		t.Error("product left isolation native/journal before rollback")
	}
	if !exists {
		return
	}
	if !dependentsStopped {
		fail("refuse isolation rollback without actual producer/Task closure")
		return
	}
	var originals []reconcile.Resource
	if record.State.Applied.Present {
		originals = append(originals, record.State.Applied)
	}
	if pending := record.State.Pending; pending != nil {
		originals = append(originals, pending.Target)
	}
	for _, resource := range originals {
		if !resource.Present {
			continue
		}
		spec, err := network.DecodeIsolation(resource.Spec)
		if err != nil || spec.Owner != owner {
			fail("original isolation target identity", err)
			return
		}
		present, err := network.InspectIsolation(spec)
		if errors.Is(err, network.ErrKernelOwnership) {
			continue
		} // Only the other recorded target may be active.
		if err != nil {
			fail(err)
			return
		}
		if !present {
			continue
		}
		if err := network.RemoveIsolation(ctx, spec); err != nil {
			fail("exact original isolation rollback", err)
			return
		}
		if remains, err := network.IsolationExists(owner); err != nil || remains {
			fail("isolation rollback did not restore absence", err)
		}
		return
	}
	fail("isolation native matches neither original Applied nor original Pending; preserved")
	return
}
