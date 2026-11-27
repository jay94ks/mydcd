// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/storage"
)

func nodeShellReceiptFixture() (control.NodeShellRecord, nodeShellReceipt) {
	row := control.NodeShellRecord{Owner: [32]byte{2}, Origin: control.UserOperation{Schema: 1, RequestID: "original-shell"}, Session: control.NodeShellSession{SessionID: "original-shell", Node: "node-a", CreatedAt: 10, State: "queued"}}
	p := nodeShellReceipt{Schema: 1, Cluster: [32]byte{1}, Owner: row.Owner, Origin: nodeShellOrigin(row), Instance: [32]byte{3}, Node: row.Session.Node, SessionID: row.Session.SessionID, Phase: "sent"}
	return row, p
}

func TestNodeShellReceiptKeepsOriginalEffectAcrossExclusiveReopen(t *testing.T) {
	row, p := nodeShellReceiptFixture()
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveNodeShellReceipt(db, p); err != nil {
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
	r := &Runtime{reports: db, controlPolicy: control.Policy{Cluster: p.Cluster}}
	got, originalDB, exists, err := r.nodeShellReceipt(row)
	if err != nil || !exists || originalDB != db || got != p {
		t.Fatalf("original sent receipt lost on reopen: exists=%v err=%v got=%+v", exists, err, got)
	}
	// A foreign accepted operation, node or immutable owner cannot adopt it.
	for _, mutate := range []func(*control.NodeShellRecord){
		func(v *control.NodeShellRecord) { v.Origin.RequestID = "replacement" },
		func(v *control.NodeShellRecord) { v.Owner[0]++ },
		func(v *control.NodeShellRecord) { v.Session.Node = "node-b" },
	} {
		foreign := row
		mutate(&foreign)
		if _, _, _, err := r.nodeShellReceipt(foreign); err == nil {
			t.Fatal("foreign reference adopted original receipt")
		}
	}
	// Neither a missing transient handle nor a new daemon instance changes the
	// durable sent phase. Only the runtime's explicit old-instance close path
	// may settle it; admission sees an existing receipt and refuses another SSH.
	if got.Phase != "sent" || got.Instance != p.Instance {
		t.Fatal("read fabricated closure/opening")
	}
}

func TestNodeShellReceiptRejectsInvalidPhaseAndForeignPendingReport(t *testing.T) {
	row, p := nodeShellReceiptFixture()
	if !p.valid(p.Cluster, row) {
		t.Fatal("valid sent receipt rejected")
	}
	for _, mutate := range []func(*nodeShellReceipt){
		func(v *nodeShellReceipt) { v.Instance = [32]byte{} },
		func(v *nodeShellReceipt) { v.OpenedAt = 11 },
		func(v *nodeShellReceipt) { v.BytesIn = 1 },
		func(v *nodeShellReceipt) { v.Reason = "closed" },
		func(v *nodeShellReceipt) { v.Origin[0]++ },
	} {
		bad := p
		mutate(&bad)
		if bad.valid(p.Cluster, row) {
			t.Fatal("invalid sent receipt accepted")
		}
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	report := control.NodeShellReport{Schema: 1, Cluster: p.Cluster, Reporter: [32]byte(key.Public().(ed25519.PublicKey)), Node: p.Node, SessionID: p.SessionID, Kind: "opened", At: 11, LastActivity: 11, Sequence: 1}
	report.Signature = ed25519.Sign(key, control.NodeShellReportBytes(report))
	p.Phase, p.OpenedAt, p.LastActivity, p.Pending = "opened", 11, 11, &report
	if !p.valid(p.Cluster, row) {
		t.Fatal("original signed observation rejected")
	}
	bad := report
	bad.SessionID = "foreign"
	bad.Signature = ed25519.Sign(key, control.NodeShellReportBytes(bad))
	p.Pending = &bad
	if p.valid(p.Cluster, row) {
		t.Fatal("foreign signed observation accepted")
	}
	p.Pending = &report
	row.Session.BytesOut = 1
	if p.valid(p.Cluster, row) {
		t.Fatal("local counters behind committed counters accepted")
	}
}
