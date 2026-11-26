// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

type previousRouteAbsence struct {
	calls  int
	absent bool
	err    error
	before func(string, reconcile.Resource)
}

func (a *previousRouteAbsence) RouteAbsent(_ context.Context, key string, target reconcile.Resource) (bool, error) {
	a.calls++
	if a.before != nil {
		a.before(key, target)
	}
	return a.absent, a.err
}

// Actual product core and private DB; boot/native absence are model OS input.
// This does not establish that a physical kernel reboot or Bridge return worked.
func previousRouteOwner(t *testing.T, path string, outcome reconcile.Outcome, withdraw bool) (*Runtime, services.ReferenceConsumer, routeOwnerRecord, services.RouteRuntime, *routeOutcomeDriver) {
	t.Helper()
	ref, record, catalog, networks, authority := routeOwnerCoreFixture(t)
	owner := routeNativeTestOwner(t, path)
	t.Cleanup(func() { _ = owner.reports.Close() })
	owner.tunnel = &tunnelRuntime{}
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	driver := &routeOutcomeDriver{outcome: outcome}
	err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false)
	if outcome == reconcile.EffectApplied && err != nil || outcome == reconcile.EffectUnknown && err == nil {
		t.Fatal("original dispatch outcome", err)
	}
	core, err = services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	if withdraw {
		policy, _ := networks.Route("first", "database")
		networks, err = networks.Withdraw(catalog, "admin", "first", "database", "first", policy.Revision)
		if err != nil {
			t.Fatal(err)
		}
		core, err = core.Sync(catalog, networks, authority)
		if err != nil {
			t.Fatal(err)
		}
	}
	core, err = core.ResumeBoot([32]byte{211})
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.saveRouteCore(&record, ref, core); err != nil {
		t.Fatal(err)
	}
	return owner, ref, record, core, driver
}

func TestPreviousKernelRetirementUsesOriginalPendingAndPreservesExecutionBoot(t *testing.T) {
	for _, mode := range []string{"unknown-apply", "retiring-apply", "applied", "prepared-remove", "unknown-remove"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observations.db")
			outcome := reconcile.EffectApplied
			if mode == "unknown-apply" || mode == "retiring-apply" {
				outcome = reconcile.EffectUnknown
			}
			owner, ref, record, core, driver := previousRouteOwner(t, path, outcome, true)
			original := record
			var err error
			if mode == "retiring-apply" {
				core = modelRoutePacketClosure(t, owner, ref, &record, core)
				core, err = core.BeginNativeRetirement()
			} else if mode == "prepared-remove" || mode == "unknown-remove" {
				core = modelRoutePacketClosure(t, owner, ref, &record, core)
				core, _, err = core.Plan()
				if err == nil && mode == "unknown-remove" {
					core, err = core.Dispatch(core.Journal().Pending.ID)
					if err == nil {
						core, err = core.Unknown(core.Journal().Pending.ID)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.saveRouteCore(&record, ref, core); err != nil {
				t.Fatal(err)
			}
			// Reopen at the original persisted stop point, not reconstructed work.
			if err := owner.reports.Close(); err != nil {
				t.Fatal(err)
			}
			owner = routeNativeTestOwner(t, path)
			defer owner.reports.Close()
			owner.tunnel = &tunnelRuntime{}
			record, _, err = owner.loadRouteOwner(ref)
			if err != nil {
				t.Fatal(err)
			}
			core, err = services.DecodeRouteRuntime(record.Core)
			if err != nil {
				t.Fatal(err)
			}
			absence := &previousRouteAbsence{absent: true, before: func(key string, target reconcile.Resource) {
				stored, found, err := owner.loadRouteOwner(ref)
				expected, expectedErr := originalRouteResource(ref, original)
				if err != nil || !found || expectedErr != nil || target != expected || key != ref.RouteNativeKey() || stored.NativeBoot != original.NativeBoot {
					t.Fatal("native absence preceded original durable provenance", err, expectedErr)
				}
			}}
			core, err = owner.retirePreviousBootRoute(t.Context(), ref, &record, core, core.Boot(), absence)
			if err != nil {
				t.Fatal(err)
			}
			journal := core.Journal()
			proof, found := core.NativeObservation()
			last := uint64(2)
			if outcome == reconcile.EffectUnknown {
				last = 1
			}
			if journal.Pending != nil || journal.Applied.Present || journal.Desired.Present || journal.LastID != last || !found || !proof.Gone || proof.Operation != last || proof.Kind != reconcile.Remove || proof.Outcome != reconcile.EffectApplied || proof.Boot != core.Boot() || absence.calls != 1 || driver.executed != 1 || driver.recovered != 0 {
				t.Fatal("previous kernel retirement fabricated a replacement Apply or lost original positive closure")
			}
			if record.NativeBoot != original.NativeBoot || record.Nonce != original.Nonce || record.Bridge != original.Bridge || record.BridgeReturned || !sameRouteDispatch(record.Dispatch, original.Dispatch) {
				t.Fatal("native closure changed original execution or fabricated Bridge return")
			}
			packet, found := core.PacketClosure()
			if !found || !packet.ConntrackEmpty || !packet.ReadersStopped || !packet.JournalSynced {
				t.Fatal("positive previous-kernel closure was not durable")
			}
			if err := owner.returnRouteBridge(ref, &record, core); err == nil || record.BridgeReturned {
				t.Fatal("missing actual Bridge manager was accepted as a returned dependency")
			}
		})
	}
}

func TestPreviousKernelRetirementRejectsUnprovenOrActiveInputsWithoutNativeRead(t *testing.T) {
	for _, mode := range []string{"active", "same-boot", "legacy", "wrong-current-boot", "reader", "unsynced", "changed-record"} {
		t.Run(mode, func(t *testing.T) {
			owner, ref, record, core, _ := previousRouteOwner(t, filepath.Join(t.TempDir(), "observations.db"), reconcile.EffectUnknown, mode != "active")
			observed := core.Boot()
			switch mode {
			case "same-boot":
				var err error
				core, err = core.ResumeBoot(record.NativeBoot)
				if err != nil {
					t.Fatal(err)
				}
				if err := owner.saveRouteCore(&record, ref, core); err != nil {
					t.Fatal(err)
				}
				observed = core.Boot()
			case "legacy":
				record.NativeBoot = [32]byte{}
				raw, _ := json.Marshal(record)
				if err := owner.reports.Write(map[string][]byte{routeOwnerKey(ref.ID): raw}); err != nil {
					t.Fatal(err)
				}
			case "wrong-current-boot":
				observed = [32]byte{212}
			case "reader":
				i := &tunnelInstance{}
				i.routeReading.Store(true)
				owner.tunnel.routes = map[[32]byte]*tunnelInstance{ref.ID: i}
			case "unsynced":
				core = core.Pause()
			case "changed-record":
				record.Nonce[0]++
			}
			before, _ := owner.reports.Get(routeOwnerKey(ref.ID))
			absence := &previousRouteAbsence{absent: true}
			if _, err := owner.retirePreviousBootRoute(t.Context(), ref, &record, core, observed, absence); err == nil || absence.calls != 0 {
				t.Fatal("unproven previous kernel reached native observer", err)
			}
			after, _ := owner.reports.Get(routeOwnerKey(ref.ID))
			if !bytes.Equal(before, after) || record.BridgeReturned {
				t.Fatal("rejection changed original stored work")
			}
		})
	}
}

func TestPreviousKernelRetirementKeepsOriginalFlowDigestAcrossAnotherBoot(t *testing.T) {
	owner, ref, record, core, flow := routeFlowOwnerCandidate(t, filepath.Join(t.TempDir(), "observations.db"))
	owner.tunnel = &tunnelRuntime{}
	if err := owner.saveRouteCore(&record, ref, core); err != nil {
		t.Fatal(err)
	}
	_, _, catalog, networks, authority := routeOwnerCoreFixture(t)
	binding := services.RouteNativeBinding{Key: (tenancy.SourceIdentity{Kind: "bridge", Tenant: "second", Network: "lan", Node: "node-b"}).Key(), Generation: 8, Revision: 9, Spec: [32]byte{170}}
	var err error
	authority, _, err = authority.GrantRouteInstance(catalog, networks, "admin", "first", "database", "second", 0, binding)
	if err != nil {
		t.Fatal(err)
	}
	for i, source := range []services.Source{ref.Route.Source, ref.Route.Destination} {
		endpoint := "source"
		if i == 1 {
			endpoint = "destination"
		}
		networkID := source.Tenant + "/" + source.Network
		authority, _, err = authority.ReserveStatic(endpoint, hex.EncodeToString(source.Owner[:]), networkID, networkID+"/"+source.Pool, source.NetworkGeneration, source.Prefix.Addr().Next().Next())
		if err != nil {
			t.Fatal(err)
		}
	}
	policy, _ := networks.Route("first", "database")
	networks, err = networks.Withdraw(catalog, "admin", "first", "database", "first", policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Sync(catalog, networks, authority)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.ResumeBoot([32]byte{213})
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.saveRouteCore(&record, ref, core); err != nil {
		t.Fatal(err)
	}
	expected, err := core.PacketCloseFacts()
	if err != nil || expected.Flows != 1 || flow.Lease().Token == 0 {
		t.Fatal("original cross-boot flow was lost before packet closure", err)
	}
	core, err = owner.retirePreviousBootRoute(t.Context(), ref, &record, core, core.Boot(), &previousRouteAbsence{absent: true})
	if err != nil || core.FlowCount() != 0 {
		t.Fatal(err)
	}
	closed, found := core.PacketClosure()
	if !found || closed.Flows != expected.Flows || closed.FlowDigest != expected.FlowDigest {
		t.Fatal("previous kernel retirement substituted an empty current-boot history")
	}
	core, err = core.ResumeBoot([32]byte{214})
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.saveRouteCore(&record, ref, core); err != nil {
		t.Fatal(err)
	}
	core, err = owner.retirePreviousBootRoute(t.Context(), ref, &record, core, core.Boot(), &previousRouteAbsence{absent: true})
	again, found := core.PacketClosure()
	if err != nil || !found || !bytes.Equal(services.RoutePacketCloseBytes(closed), services.RoutePacketCloseBytes(again)) || !bytes.Equal(closed.Signature, again.Signature) {
		t.Fatal("another boot replaced the permanent original flow closure", err)
	}
}

func TestPreviousKernelAbsenceFailurePreservesOriginalPendingAndDependency(t *testing.T) {
	for _, nativeErr := range []error{nil, errors.New("native dump incomplete")} {
		owner, ref, record, core, _ := previousRouteOwner(t, filepath.Join(t.TempDir(), "observations.db"), reconcile.EffectUnknown, true)
		before := bytes.Clone(record.Core)
		absence := &previousRouteAbsence{err: nativeErr}
		if _, err := owner.retirePreviousBootRoute(t.Context(), ref, &record, core, core.Boot(), absence); err == nil || absence.calls != 1 || !bytes.Equal(before, record.Core) || record.BridgeReturned {
			t.Fatal("native absence uncertainty was converted into termination", err)
		}
	}
}

func TestPreviousKernelPacketCloseWriteFailureReopensOriginalUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.db")
	owner, ref, record, core, _ := previousRouteOwner(t, path, reconcile.EffectUnknown, true)
	original := record
	absence := &previousRouteAbsence{absent: true, before: func(_ string, _ reconcile.Resource) {
		if err := owner.reports.Close(); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := owner.retirePreviousBootRoute(t.Context(), ref, &record, core, core.Boot(), absence); err == nil || !owner.routeStoreFailed || !bytes.Equal(record.Core, original.Core) || record.BridgeReturned {
		t.Fatal("failed closure write published positive termination", err)
	}
	owner = routeNativeTestOwner(t, path)
	defer owner.reports.Close()
	owner.tunnel = &tunnelRuntime{}
	loaded, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || !bytes.Equal(loaded.Core, original.Core) || loaded.NativeBoot != original.NativeBoot || loaded.Bridge != original.Bridge {
		t.Fatal("same DB lost original unknown execution after failed closure write", err)
	}
	core, err = services.DecodeRouteRuntime(loaded.Core)
	if err != nil {
		t.Fatal(err)
	}
	core, err = owner.retirePreviousBootRoute(t.Context(), ref, &loaded, core, core.Boot(), &previousRouteAbsence{absent: true})
	if err != nil || core.Journal().Pending != nil || core.Journal().Applied.Present {
		t.Fatal("original previous kernel termination could not resume", err)
	}
}
