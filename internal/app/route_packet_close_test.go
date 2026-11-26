// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Real private bbolt writes/reopen and product core; kernel closure facts are
// explicit model input here. No native/reader/conntrack success is claimed.
func TestRoutePacketCloseDBFailureRetainsOriginalFenceAndResumesExactEvidence(t *testing.T) {
	ref, record, catalog, networks, authority := routeOwnerCoreFixture(t)
	path := filepath.Join(t.TempDir(), "observations.db")
	owner := routeNativeTestOwner(t, path)
	defer func() { _ = owner.reports.Close() }()
	ref, record, core := dispatchedRouteTestRecord(t, owner, ref, record)
	driver := &routeOutcomeDriver{outcome: reconcile.EffectApplied}
	if err := owner.runRouteDriver(t.Context(), ref, &record, core, *core.Journal().Pending, driver, true, false); err != nil {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
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
	if err := owner.saveRouteCore(&record, ref, core); err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(record.Core)
	proof, err := core.PacketCloseFacts()
	if err != nil {
		t.Fatal(err)
	}
	proof.JournalSynced, proof.ReadersStopped, proof.QueueEmpty = true, true, true
	proof.AdmissionsStopped, proof.ConntrackEmpty = true, true
	proof.Signature = ed25519.Sign(owner.Identity.Private, services.RoutePacketCloseBytes(proof))
	candidate, err := core.ClosePackets(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.saveRouteCore(&record, ref, candidate); err == nil || !owner.routeStoreFailed || !bytes.Equal(record.Core, before) {
		t.Fatal("failed packet close write published or replaced original fence", err)
	}
	owner = routeNativeTestOwner(t, path)
	restored, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || !bytes.Equal(restored.Core, before) || restored.Nonce != record.Nonce {
		t.Fatal("same DB lost original fenced core/nonce", err)
	}
	if err := owner.saveRouteCore(&restored, ref, candidate); err != nil {
		t.Fatal(err)
	}
	stored, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found {
		t.Fatal(err)
	}
	closed, err := services.DecodeRouteRuntime(stored.Core)
	if err != nil {
		t.Fatal(err)
	}
	actual, found := closed.PacketClosure()
	if !found || actual.FlowDigest != proof.FlowDigest || actual.Boot != proof.Boot || !bytes.Equal(actual.Signature, proof.Signature) {
		t.Fatal("same DB replaced original packet closure evidence")
	}
}
