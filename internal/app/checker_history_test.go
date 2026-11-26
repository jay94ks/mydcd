// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func TestCheckerRecentUsesDurableOriginalRunAndNeverPrivateReason(t *testing.T) {
	point, cluster, owner := checkerObservationFixture(t, checker.Dispatched)
	db, err := storage.Open(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := &Runtime{Identity: &identity.Identity{Public: owner}, controlPolicy: control.Policy{Cluster: cluster}, reports: db, checkerObservationSizes: map[string]int{}}
	if err = r.saveCheckerObservation(point); err != nil {
		t.Fatal(err)
	}
	machine, err := checker.Restore(point.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	run := *point.Checkpoint.Active
	machine, _, err = machine.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Fail, Reason: "private-value-marker-519"}, At: run.PreparedAt + 1, HelperExited: true, ProbesClosed: true})
	if err != nil {
		t.Fatal(err)
	}
	point.Checkpoint = machine.Checkpoint()
	for i := 0; i < 3; i++ {
		if err = r.saveCheckerObservation(point); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := db.Get(checkerObservationKey(point.Checkpoint.Definition))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := schema.Decode[checkerObservation](raw)
	if err != nil || len(restored.Recent) != 1 || restored.Recent[0].RunID != run.Request.RunID || restored.Recent[0].DurationMS != 1 || restored.Recent[0].Message != "check failed" {
		t.Fatal("recent summary was lost or duplicated", err)
	}
	public, _ := json.Marshal(restored.Recent)
	if strings.Contains(string(public), "private-value-marker-519") {
		t.Fatal("private script reason entered public history")
	}
	point.Checkpoint = restored.Checkpoint
	if err = r.retainCheckerRecent(&point, checkerObservationKey(point.Checkpoint.Definition)); err != nil || len(point.Recent) != 1 {
		t.Fatal("durable summary did not survive owner reopen/read", err)
	}
}
