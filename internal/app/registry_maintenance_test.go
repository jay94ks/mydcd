// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/storage"
)

func TestOwnerMaintenanceReceiptKeepsOriginalTargetAndUncertainSentAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := Runtime{Identity: &identity.Identity{Public: [32]byte{2}}, controlPolicy: control.Policy{Cluster: [32]byte{1}}, reports: db}
	work := control.RegistryMaintenanceWork{Operation: "original/42", Change: control.RegistryMaintenanceChange{Tenant: "tenant", Operation: "original/42", Run: control.RegistryRunRef{Generation: 7, Owner: r.Identity.Public}}}
	row, err := r.loadRegistryMaintenance(work)
	if err != nil || row.Sent || row.Result != nil || row.Target != work.Change.DigestValue() {
		t.Fatal("new original intent", row, err)
	}
	row.Sent = true
	if err = r.saveRegistryMaintenance(row); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r.reports = db
	stored, err := r.loadRegistryMaintenance(work)
	if err != nil || !stored.Sent || stored.Result != nil || stored.Target != row.Target {
		t.Fatal("unknown effect reset after reopen", stored, err)
	}
	changed := work
	changed.Change.Run.Generation++
	if _, err = r.loadRegistryMaintenance(changed); err == nil {
		t.Fatal("original intent retargeted to a new run")
	}
	r.Identity.Public[0]++
	if _, err = r.loadRegistryMaintenance(work); err == nil {
		t.Fatal("original intent adopted by a different owner")
	}
	r.Identity.Public[0]--
	result := nativeMaintenanceResult("OK", 1234, map[string]string{"operation": row.Operation, "state": "done"}, 21)
	stored.Result = &result
	if err = r.saveRegistryMaintenance(stored); err != nil {
		t.Fatal(err)
	}
	done, err := r.loadRegistryMaintenance(work)
	if err != nil || done.Result == nil || *done.Result != result || !done.Sent {
		t.Fatal("positive original result lost", done, err)
	}
	// This deliberately corrupted input is not an outcome the product emits.
	// Decoding must refuse it instead of turning corruption into a new retry.
	stored.Result.Native = [32]byte{}
	raw, _ := json.Marshal(stored)
	if err = db.Write(map[string][]byte{registryMaintenanceReceiptKey(stored.Operation): raw}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.loadRegistryMaintenance(work); err == nil {
		t.Fatal("incomplete native acknowledgement became a success")
	}
}

func TestMaintenanceCleanupIdentityIgnoresReadinessButNotOriginalRunOrWriter(t *testing.T) {
	original := control.RegistryRunRef{Generation: 7, SpecRevision: 3, Owner: [32]byte{2}, DefinitionDigest: [32]byte{3}, OriginDigest: [32]byte{4}}
	observed := original
	observed.Ready = &control.RegistryObservation{Boot: [32]byte{5}, At: 99}
	observed.Draining = true
	if !sameMaintenanceRun(original, observed) {
		t.Fatal("original cleanup lost solely to readiness/drain progress")
	}
	for _, edit := range []func(*control.RegistryRunRef){
		func(r *control.RegistryRunRef) { r.Generation++ },
		func(r *control.RegistryRunRef) { r.SpecRevision++ },
		func(r *control.RegistryRunRef) { r.Owner[0]++ },
		func(r *control.RegistryRunRef) { r.Consumer.OwnerRevision++ },
		func(r *control.RegistryRunRef) { r.OriginDigest[0]++ },
	} {
		changed := observed
		edit(&changed)
		if sameMaintenanceRun(original, changed) {
			t.Fatal("cleanup borrowed another original run/writer")
		}
	}
}

func TestCurrentRegistryPermitRechecksRunInsteadOfRejectingNewerHeartbeatRoot(t *testing.T) {
	owner := [32]byte{1}
	run := control.RegistryRunRef{Generation: 7, SpecRevision: 3, Owner: owner, DefinitionDigest: [32]byte{2}, OriginDigest: [32]byte{3}}
	run.Budget.Generation = 5
	work := control.RegistryWork{MayStart: true, Index: 10, RootRevision: 20, Epoch: 1, Entry: control.RegistryWorkEntry{Active: &run}}
	if !registryWorkMatchesRun(work, run, owner) {
		t.Fatal("original current permit rejected")
	}
	work.Index, work.RootRevision = 11, 21
	refreshed := run
	refreshed.Ready = &control.RegistryObservation{At: 99, Boot: [32]byte{9}, Certificate: [32]byte{8}}
	work.Entry.Active = &refreshed
	if !registryWorkMatchesRun(work, run, owner) {
		t.Fatal("same run rejected solely for newer observation root")
	}
	work.MayStart = false
	if registryWorkMatchesRun(work, run, owner) {
		t.Fatal("newer committed revocation ignored")
	}
	work.MayStart = true
	refreshed.Generation++
	if registryWorkMatchesRun(work, run, owner) {
		t.Fatal("new generation substituted for original run")
	}
}
