// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
)

// Native and Bridge outcomes are explicit model inputs. The actual product
// route core/journal, positive Gone proof, signer and observations DB are used.
func routeIdentityGoneFixture(t *testing.T, owner *Runtime) (services.ReferenceConsumer, routeOwnerRecord, control.ResourceProjection, control.RouteWork) {
	t.Helper()
	ref, record, catalog, networks, authority := routeOwnerCoreFixture(t)
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	var err error
	authority, err = authority.RecordRouteDispatch(record.Dispatch)
	if err != nil {
		t.Fatal(err)
	}
	driver := &routeOutcomeDriver{outcome: reconcile.EffectApplied}
	if err = owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err != nil {
		t.Fatal(err)
	}
	core, err = services.DecodeRouteRuntime(record.Core)
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
	core, op, err := core.Plan()
	if err != nil || op == nil {
		t.Fatal(err)
	}
	core, err = core.Dispatch(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.saveRouteCore(&record, ref, core); err != nil {
		t.Fatal(err)
	}
	core = modelRoutePacketClosure(t, owner, ref, &record, core)
	if err = owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, false, false); err != nil {
		t.Fatal(err)
	}
	core, err = services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	proof, found := core.NativeObservation()
	if !found || !proof.Gone || proof.Kind != reconcile.Remove || proof.Outcome != reconcile.EffectApplied {
		t.Fatal("fixture lacks positive original native Gone")
	}
	// The separate dependency manager is a model boundary here; no actual
	// native/manager closure is claimed by this source-level counterexample.
	record.BridgeReturned = true
	if err = owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	projection := control.ResourceProjection{NetworkAuthority: &authority, Resources: control.Resources{Networks: networks}}
	work := control.RouteWork{Schema: 1, Reference: ref, Epoch: 1, AppsRevision: 20, ResourcesRevision: 21, Retiring: true}
	report, err := owner.newRouteRetirement(projection, work, record, 300)
	if err != nil || report == nil {
		t.Fatal(err)
	}
	record.Retirement = report
	if err = owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	return ref, record, projection, work
}

func TestRouteReportCurrentIdentityRestatesSameFactsAcrossTwoRotations(t *testing.T) {
	for _, kind := range []string{"dispatch", "retirement"} {
		t.Run(kind, func(t *testing.T) {
			owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
			defer owner.reports.Close()
			var ref services.ReferenceConsumer
			var record routeOwnerRecord
			var work control.RouteWork
			if kind == "dispatch" {
				ref, record = routeOwnerRecordFixture(t)
				work = control.RouteWork{Reference: ref, Epoch: 1, AppsRevision: 10, ResourcesRevision: 11}
				if err := owner.saveRouteOwner(record, ref); err != nil {
					t.Fatal(err)
				}
			} else {
				ref, record, _, work = routeIdentityGoneFixture(t, owner)
			}
			original := record
			immutable := func(v routeOwnerRecord) []byte {
				raw, _ := json.Marshal([]any{v.Nonce, v.Core, v.Dispatch, v.Bridge, v.NativeStarted, v.NativeBoot, v.BridgeReturned, v.NeverDispatched})
				return raw
			}
			facts := immutable(record)
			for i := 0; i < 2; i++ {
				var oldRaw []byte
				var oldCommandID string
				if kind == "dispatch" {
					oldRaw, _ = json.Marshal(record.Report)
					c, _ := record.Report.Command()
					oldCommandID = c.RequestID
				} else {
					oldRaw, _ = json.Marshal(record.Retirement)
					c, _ := record.Retirement.Command()
					oldCommandID = c.RequestID
				}
				key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(180 + i)}, 32))
				owner.controlIdentity = &identity.Identity{Private: key, Public: [32]byte(key.Public().(ed25519.PublicKey))}
				if err := owner.renewRouteReportEpoch(work, &record); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(immutable(record), facts) {
					t.Fatal("rotation changed original native facts")
				}
				var reporter [32]byte
				var newCommandID string
				if kind == "dispatch" {
					reporter = record.Report.Reporter
					c, _ := record.Report.Command()
					newCommandID = c.RequestID
				} else {
					reporter = record.Retirement.Reporter
					c, _ := record.Retirement.Command()
					newCommandID = c.RequestID
					before, _ := json.Marshal([]any{original.Retirement.Close, original.Retirement.Route})
					after, _ := json.Marshal([]any{record.Retirement.Close, record.Retirement.Route})
					if !bytes.Equal(before, after) {
						t.Fatal("rotation replaced original positive Gone/closure signatures")
					}
				}
				if reporter != owner.commandIdentity().Public || oldCommandID == newCommandID {
					t.Fatal("coordination envelope did not switch current identity")
				}
				raw, err := owner.reports.GetBounded(routeReportTraceKey(ref.ID, oldRaw), 34<<20)
				if err != nil {
					t.Fatal(err)
				}
				trace, err := schema.Decode[routeReportTrace](raw)
				if err != nil || trace.Outcome != "unknown" || trace.Command.RequestID != oldCommandID || trace.Reference != ref.ID || trace.Nonce != record.Nonce || trace.NativeStarted != record.NativeStarted || trace.NativeBoot != record.NativeBoot || !bytes.Equal(trace.Report, oldRaw) || !bytes.Equal(trace.Core, record.Core) {
					t.Fatal("old unknown delivery/provenance lost", err)
				}
			}
		})
	}
}

func TestRouteReportIdentityConflictAndMissingGonePreserveOriginal(t *testing.T) {
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	defer owner.reports.Close()
	ref, record := routeOwnerRecordFixture(t)
	if err := owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(record.Report)
	if err := owner.reports.Write(map[string][]byte{routeReportTraceKey(ref.ID, raw): []byte("conflicting provenance")}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{182}, 32))
	owner.controlIdentity = &identity.Identity{Private: key, Public: [32]byte(key.Public().(ed25519.PublicKey))}
	before, _ := json.Marshal(record)
	if err := owner.renewRouteReportEpoch(control.RouteWork{Reference: ref, Epoch: 1, AppsRevision: 10}, &record); err == nil {
		t.Fatal("trace conflict replaced original unknown")
	}
	after, _ := json.Marshal(record)
	if !bytes.Equal(before, after) {
		t.Fatal("failed provenance commit changed original")
	}
	other := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "other.db"))
	defer other.reports.Close()
	ref, record, _, work := retiredRouteOwnerFixture(t, other)
	valid := record
	// This core never executed native Apply/Remove. A flag alone cannot serve
	// as positive original Gone when current identity wants to restate it.
	record.NativeStarted = true
	record.NativeBoot = record.Dispatch.Boot
	record.Bridge = reconcile.Lease{Generation: ref.Native.Generation, Token: 3}
	other.controlIdentity = owner.controlIdentity
	work.Retiring = true
	if err := other.renewRouteReportEpoch(work, &record); err == nil {
		t.Fatal("missing positive native Gone accepted")
	}
	foreign := work
	foreign.Reference.ID[0]++
	if err := other.renewRouteReportEpoch(foreign, &valid); err == nil {
		t.Fatal("foreign original reference accepted")
	}
}

func TestRouteReportSharedExactFactsSettleWithoutInventingOriginalAppliedResult(t *testing.T) {
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	defer owner.reports.Close()
	ref, record, projection, _ := routeIdentityGoneFixture(t, owner)
	old := *record.Retirement
	oldRaw, _ := json.Marshal(old)
	command, _ := old.Command()
	authority, _, err := projection.NetworkAuthority.ObserveRouteRetired(projection.Resources.Networks, old.Close, old.Route, 301)
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := authority.ReferenceConsumer(ref.ID)
	if err = owner.resolveRouteRetirement(shared, &record); err != nil {
		t.Fatal(err)
	}
	if record.Retirement != nil || !record.NativeStarted || !record.BridgeReturned {
		t.Fatal("shared exact pair did not settle same native lifetime")
	}
	raw, err := owner.reports.GetBounded(routeReportTraceKey(ref.ID, oldRaw), 34<<20)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := schema.Decode[routeReportTrace](raw)
	if err != nil || trace.Outcome != "unknown" || trace.Command != command || !bytes.Equal(trace.Report, oldRaw) {
		t.Fatal("shared effect relabeled original report Applied", err)
	}
}
