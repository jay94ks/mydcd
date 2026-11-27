// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// Real owner DB and reusable route core; native installation/boot are model
// facts. This does not exercise SFCP, Bridge, kernel, or service traffic.
func routeFlowOwnerCandidate(t *testing.T, path string) (*Runtime, services.ReferenceConsumer, routeOwnerRecord, services.RouteRuntime, services.RouteFlow) {
	t.Helper()
	ref, record, catalog, networks, authority := routeOwnerCoreFixture(t)
	owner := routeNativeTestOwner(t, path)
	t.Cleanup(func() { _ = owner.reports.Close() })
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	driver := &routeOutcomeDriver{outcome: reconcile.EffectApplied}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err != nil {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	peerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{162}, 32))
	peerOwner := &Runtime{Identity: &identity.Identity{Private: peerKey, Public: [32]byte(peerKey.Public().(ed25519.PublicKey))}}
	peerBinding := services.RouteNativeBinding{Key: (tenancy.SourceIdentity{Kind: "bridge", Tenant: "second", Network: "lan", Node: "node-b"}).Key(), Generation: 8, Revision: 9, Spec: [32]byte{170}}
	authority, peer, err := authority.GrantRouteInstance(catalog, networks, "admin", "first", "database", "second", 0, peerBinding)
	if err != nil {
		t.Fatal(err)
	}
	peerCore, err := services.NewRouteRuntime(catalog, networks, authority, peer.ID, [32]byte{171}, 2)
	if err != nil {
		t.Fatal(err)
	}
	peerCore, operation, err := peerCore.Plan()
	if err != nil || operation == nil {
		t.Fatal(err)
	}
	peerProof := peerOwner.routeNativeProof(peer, peerCore.Boot(), *operation, reconcile.EffectApplied)
	tuple := services.RouteTuple{SourcePort: 41000, DestinationPort: 3306, Protocol: 6}
	for i, source := range []services.Source{ref.Route.Source, ref.Route.Destination} {
		var allocationErr error
		networkID := source.Tenant + "/" + source.Network
		if i == 0 {
			authority, tuple.Source, allocationErr = authority.ReserveStatic("source", hex.EncodeToString(source.Owner[:]), networkID, networkID+"/"+source.Pool, source.NetworkGeneration, source.Prefix.Addr().Next().Next())
		} else {
			authority, tuple.Destination, allocationErr = authority.ReserveStatic("destination", hex.EncodeToString(source.Owner[:]), networkID, networkID+"/"+source.Pool, source.NetworkGeneration, source.Prefix.Addr().Next().Next())
		}
		if allocationErr != nil {
			t.Fatal(allocationErr)
		}
	}
	candidate, flow, err := core.BorrowFlow(catalog, networks, authority, peerProof, peerCore.Boot(), tuple, services.Clock{Boot: core.Boot(), Wall: 150, Certain: true})
	if err != nil {
		t.Fatal(err)
	}
	return owner, ref, record, candidate, flow
}

func TestRouteFlowPublicationRequiresOriginalStoredPinAndSurvivesSameDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.db")
	owner, ref, record, candidate, flow := routeFlowOwnerCandidate(t, path)
	defer func() { _ = owner.reports.Close() }()
	if _, err := owner.storedRouteFlowReceipt(ref, flow); err == nil {
		t.Fatal("in-memory candidate was signed before owner DB sync")
	}
	if err := owner.saveRouteCore(&record, ref, candidate); err != nil {
		t.Fatal(err)
	}
	first, err := owner.storedRouteFlowReceipt(ref, flow)
	if err != nil || !first.JournalSynced || first.Pin != flow.Lease() || !ed25519.Verify(ed25519.PublicKey(owner.Identity.Public[:]), services.RouteFlowReceiptBytes(first), first.Signature) {
		t.Fatal("durable original pin was not published", err)
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.storedRouteFlowReceipt(ref, flow); err == nil {
		t.Fatal("unavailable original DB produced a receipt")
	}
	owner = routeNativeTestOwner(t, path)
	again, err := owner.storedRouteFlowReceipt(ref, flow)
	if err != nil || !bytes.Equal(services.RouteFlowReceiptBytes(first), services.RouteFlowReceiptBytes(again)) || !bytes.Equal(first.Signature, again.Signature) {
		t.Fatal("same DB reissued a different original receipt", err)
	}
}

func TestClosingSourceClaimRequiresStoredClosingAndKeepsOriginalBytesAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.db")
	owner, ref, record, candidate, flow := routeFlowOwnerCandidate(t, path)
	defer func() { _ = owner.reports.Close() }()
	var err error
	candidate, err = candidate.TrackFlow(flow)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err = candidate.BeginFlowClose(flow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.storedClosingRouteClaim(ref, flow); err == nil {
		t.Fatal("unsynced in-memory Closing produced a signed claim")
	}
	if err := owner.saveRouteCore(&record, ref, candidate); err != nil {
		t.Fatal(err)
	}
	first, err := owner.storedClosingRouteClaim(ref, flow)
	if err != nil || !first.JournalSynced || first.Pin != flow.Lease() || !ed25519.Verify(ed25519.PublicKey(ref.Local.Owner[:]), services.RouteFlowReceiptBytes(first), first.Signature) {
		t.Fatal("stored Closing did not publish its exact original claim", err)
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.storedClosingRouteClaim(ref, flow); err == nil {
		t.Fatal("closed original DB supplied journal proof")
	}
	owner = routeNativeTestOwner(t, path)
	again, err := owner.storedClosingRouteClaim(ref, flow)
	if err != nil || !bytes.Equal(services.RouteFlowReceiptBytes(first), services.RouteFlowReceiptBytes(again)) || !bytes.Equal(first.Signature, again.Signature) {
		t.Fatal("same DB created a different original close claim", err)
	}
	loaded, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(loaded.Core)
	if err != nil || core.FlowCount() != 1 {
		t.Fatal("close publication returned the original source pin", err)
	}
}
