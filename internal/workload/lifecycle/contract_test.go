// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/json"
	"strings"
	"testing"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func TestCheckerWireRejectsAmbiguousRequestAndExitResult(t *testing.T) {
	_, r, err := newMachine(t, testDefinition()).Plan(100)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r.Request)
	if got, err := DecodeRequest(raw); err != nil || requestDigest(got) != r.RequestDigest {
		t.Fatal("original request codec", err)
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), raw...), '\n'),
		append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"Schema":1}`)...),
		append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"Unexpected":1}`)...),
		[]byte(strings.Repeat("x", MaxRequestBytes+1)),
	} {
		if _, err := DecodeRequest(bad); err == nil {
			t.Fatal("ambiguous/overlarge request accepted")
		}
	}
	for _, status := range []contract.Status{contract.Pass, contract.Fail, contract.Unknown} {
		r := contract.Result{Schema: 1, Status: status, Reason: "public-reason"}
		raw, _ := json.Marshal(r)
		exit := map[contract.Status]int{contract.Pass: 0, contract.Fail: 1, contract.Unknown: 2}[status]
		if got, err := DecodeExitResult(raw, exit); err != nil || got != r {
			t.Fatal("exit/result contract", err)
		}
		for _, wrong := range []int{-1, 137, (exit + 1) % 3} {
			if got, err := DecodeExitResult(raw, wrong); err == nil || got.Status != contract.Unknown {
				t.Fatal("conflicting exit/signal claimed result", wrong, got, err)
			}
		}
	}
	for _, bad := range []string{`{"Schema":1,"Status":"pass","Reason":"ok","Reason":"different"}`, `{"Schema":1,"Status":"pass","Reason":"ok"} trailing`, `{"Schema":1,"Status":"pass","Reason":"raw secret output"}`} {
		if got, err := DecodeExitResult([]byte(bad), 0); err == nil || got.Status != contract.Unknown {
			t.Fatal("invalid output claimed pass", got, err)
		}
	}
}

func TestCheckerTargetAndBudgetAreBoundBeforeExecution(t *testing.T) {
	_, r, _ := newMachine(t, testDefinition()).Plan(100)
	for _, mutate := range []func(*contract.Request){
		func(r *contract.Request) { r.Schema = 2 },
		func(r *contract.Request) { r.RunID = "arbitrary" },
		func(r *contract.Request) { r.Targets[0].OwnerBoot = "" },
		func(r *contract.Request) { r.Targets[0].Revision = 2 },
		func(r *contract.Request) { r.Targets = append(r.Targets, r.Targets[0]) },
		func(r *contract.Request) { r.Parameters["path"] = strings.Repeat("x", 4097) },
		func(r *contract.Request) { r.DeadlineUnixMilli = 0 },
		func(r *contract.Request) { r.Phase = "invented" },
	} {
		q := ownRequest(r.Request)
		mutate(&q)
		if err := ValidateRequest(q); err == nil {
			t.Fatal("invalid target/budget accepted")
		}
	}
}
