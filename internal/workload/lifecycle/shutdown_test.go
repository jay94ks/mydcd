// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/json"
	"strings"
	"testing"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func TestShutdownDefinitionOwnsRetirementAndPreservesExistingBytes(t *testing.T) {
	d := testDefinition()
	raw, err := json.Marshal(d)
	if err != nil || strings.Contains(string(raw), `"Stop"`) {
		t.Fatal("absence changed legacy definition", err)
	}
	d.Request.Phase = contract.Shutdown
	d.Stop = &ShutdownScope{Operation: "original-stop", Revision: 7}
	m, err := New(d, 1000)
	if err != nil {
		t.Fatal(err)
	}
	d.Stop.Operation = "caller-mutated"
	cp := m.Checkpoint()
	if cp.Definition.Stop.Operation != "original-stop" {
		t.Fatal("caller rewrote accepted stop")
	}
	cp.Definition.Stop.Revision++
	if m.Checkpoint().Definition.Stop.Revision != 7 {
		t.Fatal("checkpoint alias changed stop")
	}
	m, run, err := m.Plan(1000)
	if err != nil {
		t.Fatal(err)
	}
	m, err = m.Dispatch(run.Request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	next := m.Checkpoint().Definition
	next.Stop = &ShutdownScope{Operation: "next-stop", Revision: 9}
	if m, err = m.Retire(); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Replace(next, 1001); err == nil {
		t.Fatal("new stop discarded pending old checker")
	}
	m, _, err = m.Finish(Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Unknown, Reason: "interrupted"}, At: 1001, HelperExited: true, ProbesClosed: true})
	if err != nil {
		t.Fatal(err)
	}
	m, err = m.Replace(next, 1002)
	if err != nil {
		t.Fatal(err)
	}
	_, nextRun, err := m.Plan(1002)
	if err != nil || nextRun.Sequence != run.Sequence+1 || nextRun.Request.RunID == run.Request.RunID {
		t.Fatal("new accepted stop reused old run", nextRun, err)
	}
	bad := next
	bad.Request.Phase = contract.Liveness
	if bad.Validate() == nil {
		t.Fatal("ordinary checker acquired stop grant")
	}
}
