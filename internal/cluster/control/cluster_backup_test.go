// SPDX-License-Identifier: Apache-2.0

package control

import (
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// A cluster-backup operation only records who asked and for which one-time
// key; the record lets that user fetch the backup within the window, keeps
// the latest records, and never blocks the storage ledger.
func TestClusterBackupRecordsAndWork(t *testing.T) {
	f := compactCoreFixture(t)
	recipient := [32]byte{9}
	managedDNSChange(t, f, "backup-one", "cluster-backup", 0, ClusterBackupChange{Operation: "backup-one", Recipient: recipient}, state.Applied)
	managedDNSChange(t, f, "backup-again", "cluster-backup", 0, ClusterBackupChange{Operation: "backup-one", Recipient: recipient}, state.ConditionFailed)
	managedDNSChange(t, f, "backup-no-key", "cluster-backup", 0, ClusterBackupChange{Operation: "backup-two"}, state.Invalid)
	managedDNSChange(t, f, "backup-cas", "cluster-backup", 1, ClusterBackupChange{Operation: "backup-two", Recipient: recipient}, state.Invalid)

	r, err := f.p.ClusterBackupWork(f.s, f.session, "backup-one", 2)
	if err != nil || r.Recipient != recipient || r.Origin.Session.User != "admin" {
		t.Fatal("recorded backup refused", err)
	}
	for name, at := range map[string]int64{"after the window": 2 + ClusterBackupWindow + 1, "before the record": 1} {
		if _, err := f.p.ClusterBackupWork(f.s, f.session, "backup-one", at); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	if _, err := f.p.ClusterBackupWork(f.s, f.session, "backup-missing", 2); err == nil {
		t.Fatal("unrecorded backup accepted")
	}
	if !f.p.storageQuiescent(f.s) {
		t.Fatal("backup records block the storage ledger")
	}

	for i := range clusterBackupKeep {
		id := fmt.Sprintf("backup-%03d", i)
		managedDNSChange(t, f, id, "cluster-backup", 0, ClusterBackupChange{Operation: id, Recipient: recipient}, state.Applied)
	}
	b, err := f.p.ClusterBackups(f.s)
	if err != nil || len(b.Records) != clusterBackupKeep {
		t.Fatal("records not trimmed", len(b.Records), err)
	}
	if _, ok := b.Record("backup-one"); ok {
		t.Fatal("oldest record kept")
	}
	raw, _ := state.Encode(f.s)
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.ClusterBackups(restored); err != nil {
		t.Fatal("snapshot lost backup records", err)
	}
}
