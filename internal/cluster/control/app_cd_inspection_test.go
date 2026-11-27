// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/deployment"
)

func TestCDHistoryCheckpointKeepsOriginalOperationAndIgnoresUnchangedPolls(t *testing.T) {
	f := deliveryControlFixture(t)
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := a.entries[appKey("tenant", "source-app")]
	if !validCDHistory(entry) || len(entry.CDHistory) != 1 || entry.CDHistory[0].Operation == "" || entry.CDHistory[0].Status != "executing" {
		t.Fatal("original execution missing from durable metadata", entry.CDHistory)
	}
	before, _ := json.Marshal(entry.CDHistory)
	for i := 0; i < 3; i++ {
		next, err := captureCDHistory(entry, entry, 100+uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		after, _ := json.Marshal(next.CDHistory)
		if !bytes.Equal(before, after) || next.CDHistoryNext != entry.CDHistoryNext {
			t.Fatal("poll became a new candidate or changed its planned time")
		}
	}
	page, err := f.p.AppDeliveryHistory(f.s, f.session, 10, "tenant", AppCDReadRequest{App: "source-app"}, "")
	if err != nil || len(page.Records) != 1 || page.Records[0].Operation != entry.CDHistory[0].Operation {
		t.Fatal(page, err)
	}
	if _, err = f.p.AppDeliveryHistory(f.s, f.session, 10, "other", AppCDReadRequest{App: "source-app"}, ""); err == nil {
		t.Fatal("foreign tenant history returned")
	}
}

func TestCDSnapshotPartsAreExactAndCannotSpliceAnotherValue(t *testing.T) {
	value := map[string]string{"field": string(bytes.Repeat([]byte("x"), 2*deployment.ArtifactPartBytes))}
	q := AppCDReadRequest{App: "app"}
	first, err := cdSnapshotPart("tenant", "app", "field-values", q, value)
	if err != nil || len(first.Data) != deployment.ArtifactPartBytes {
		t.Fatal(err)
	}
	q.Part, q.Digest = 1, first.Digest
	second, err := cdSnapshotPart("tenant", "app", "field-values", q, value)
	if err != nil || len(second.Data) != deployment.ArtifactPartBytes {
		t.Fatal(err)
	}
	value["field"] = "changed"
	if _, err = cdSnapshotPart("tenant", "app", "field-values", q, value); err != access.ErrConflict {
		t.Fatal("different snapshot spliced", err)
	}
	for _, q := range []AppCDReadRequest{{App: "app", Part: -1}, {App: "app", Part: 1}, {App: "../other"}} {
		if q.Valid(false) {
			t.Fatal("invalid snapshot selector", q)
		}
	}
}
