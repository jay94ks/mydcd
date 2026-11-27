// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

func isolationRecordFixture(t *testing.T) isolationRecord {
	t.Helper()
	owner := engine.Owner([32]byte{81}, [32]byte{82})
	spec, err := network.NormalizeIsolation(network.IsolationSpec{Schema: 1, Owner: owner, Prefixes: []network.TenantPrefix{{Tenant: "first", Prefix: netip.MustParsePrefix("10.81.0.0/24")}, {Tenant: "second", Prefix: netip.MustParsePrefix("10.82.0.0/24")}}, Bridges: []network.IsolationBridge{{Tenant: "first", Device: "md0123456789ab"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(spec)
	state, err := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Generation: 1, Present: true, Spec: string(raw)}})
	if err != nil {
		t.Fatal(err)
	}
	state, op, err := reconcile.Plan(state)
	if err != nil || op == nil {
		t.Fatal(err)
	}
	state, err = reconcile.Dispatch(state, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err = reconcile.Settle(state, op.ID, reconcile.EffectUnknown)
	if err != nil {
		t.Fatal(err)
	}
	return isolationRecord{Schema: 1, Owner: owner, Boot: [32]byte{83}, Source: sha256.Sum256(raw), State: state}
}

func TestIsolationOriginalUnknownTargetSurvivesDesiredChangeAndKernelBootNamespaces(t *testing.T) {
	record := isolationRecordFixture(t)
	original := *record.State.Pending
	current, err := network.DecodeIsolation(record.State.Desired.Spec)
	if err != nil {
		t.Fatal(err)
	}
	current.Prefixes = append(current.Prefixes, network.TenantPrefix{Tenant: "second", Prefix: netip.MustParsePrefix("10.84.0.0/24")})
	current, err = network.NormalizeIsolation(current)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(current)
	record.State, err = reconcile.SetDesired(record.State, reconcile.Desired{Revision: 2, Resource: reconcile.Resource{Generation: 1, Present: true, Spec: string(raw)}})
	if err != nil {
		t.Fatal(err)
	}
	record.Source = sha256.Sum256(raw)
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := &Runtime{reports: db, owner: record.Owner}
	if err := r.saveIsolation(record); err != nil {
		t.Fatal(err)
	}
	stored, err := db.Get(isolationRecordKey(record.Boot))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeIsolationRecord(stored, record.Owner, record.Boot)
	if err != nil || restored.State.Pending == nil || *restored.State.Pending != original || restored.State.LastID != original.ID || restored.State.Desired.Spec != string(raw) {
		t.Fatal("new Desired replaced/reissued the unknown original target", err)
	}
	other := record
	other.Boot = [32]byte{84}
	if err := r.saveIsolation(other); err != nil {
		t.Fatal(err)
	}
	unchanged, err := db.Get(isolationRecordKey(record.Boot))
	if err != nil || !bytes.Equal(stored, unchanged) {
		t.Fatal("new kernel boot erased the original A2 intent", err)
	}
	if _, err := decodeIsolationRecord(stored, record.Owner, other.Boot); err == nil {
		t.Fatal("different kernel boot adopted the old native journal")
	}
	bad := record
	bad.Source = [32]byte{}
	corrupt, _ := json.Marshal(bad)
	if _, err := decodeIsolationRecord(corrupt, record.Owner, record.Boot); err == nil {
		t.Fatal("missing original source digest was accepted")
	}
}

func TestIsolationDBFailureStopsWritesAndReopensSameOriginalIntent(t *testing.T) {
	record := isolationRecordFixture(t)
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{reports: db, owner: record.Owner}
	if err := r.saveIsolation(record); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	changed := record
	changed.Source[0]++
	if err := r.saveIsolation(changed); err == nil || !r.isolationFailed {
		t.Fatal("uncertain isolation write remained ready for new work", err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw, err := db.Get(isolationRecordKey(record.Boot))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := decodeIsolationRecord(raw, record.Owner, record.Boot)
	if err != nil || actual.Source != record.Source || actual.State.Pending == nil || *actual.State.Pending != *record.State.Pending {
		t.Fatal("same DB lost the original native request", err)
	}
}

// The isolation spec follows local journals as well as the view, so it can
// change while the Raft index stands still (lab 2026-11-27: a draining
// network stopped every owner pass on one server). It must still go forward,
// and an unchanged spec must stay where it is.
func TestIsolationDesiredMovesWithoutANewIndex(t *testing.T) {
	record := isolationRecordFixture(t)
	old := record.State.Desired
	if old.Revision == 0 || !old.Present {
		t.Fatal("fixture has no present desired spec", old)
	}
	changed := old
	changed.Spec += " "
	for _, index := range []uint64{old.Revision, old.Revision - 1} {
		wanted := changed
		wanted.Revision = index
		next, err := reconcile.SetDesired(record.State, isolationDesired(old, wanted))
		if err != nil || next.Desired.Revision != old.Revision+1 || next.Desired.Spec != changed.Spec {
			t.Fatal("changed spec at an old index", index, next.Desired, err)
		}
	}
	same := old
	same.Revision = old.Revision - 1
	if next, err := reconcile.SetDesired(record.State, isolationDesired(old, same)); err != nil || next.Desired != old {
		t.Fatal("unchanged spec moved", next.Desired, err)
	}
	ahead := changed
	ahead.Revision = old.Revision + 7
	if got := isolationDesired(old, ahead); got != ahead {
		t.Fatal("a newer index was rewritten", got)
	}
}
