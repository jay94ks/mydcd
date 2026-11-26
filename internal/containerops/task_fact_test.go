// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestTaskFactIsBoundedPublicEvidenceNotAControlResult(t *testing.T) {
	f := TaskFact{Name: "owned", State: "running", LastCheck: &TaskCheck{Checker: "docker-health", Status: "pass", At: 10}}
	if !f.Valid(10) {
		t.Fatal("valid process fact rejected")
	}
	for _, mutate := range []func(*TaskFact){func(f *TaskFact) { f.State = "ready" }, func(f *TaskFact) { f.Name = "bad\nname" }, func(f *TaskFact) { f.LastCheck.At = 11 }, func(f *TaskFact) { f.LastCheck.Status = "restart" }} {
		bad := f.Clone()
		mutate(&bad)
		if bad.Valid(10) {
			t.Fatal("unbounded/future/control metadata accepted")
		}
	}
	copy := f.Clone()
	copy.LastCheck.Status = "fail"
	if f.LastCheck.Status != "pass" {
		t.Fatal("fact clone aliases source")
	}
}

func TestTaskFactEndpointEvidencePreservesUnknownLegacyBytesAndClone(t *testing.T) {
	legacy := TaskFact{Name: "owned", Image: "sha256:original", State: "running", RestartCount: 2}
	old := struct {
		Name         string
		Image        string `json:",omitempty"`
		State        string
		RestartCount uint64
		LastCheck    *TaskCheck `json:",omitempty"`
	}{legacy.Name, legacy.Image, legacy.State, legacy.RestartCount, legacy.LastCheck}
	before, _ := json.Marshal(old)
	after, _ := json.Marshal(legacy)
	if !bytes.Equal(before, after) || legacy.EndpointPresent != nil {
		t.Fatal("legacy absent endpoint changed signed JSON bytes")
	}
	for _, present := range []bool{false, true} {
		f := legacy
		f.EndpointPresent = &present
		if !f.Valid(10) {
			t.Fatal("explicit endpoint evidence rejected")
		}
		copy := f.Clone()
		*copy.EndpointPresent = !present
		if *f.EndpointPresent != present {
			t.Fatal("endpoint clone aliases signed source")
		}
		raw, _ := json.Marshal(f)
		var restored TaskFact
		if json.Unmarshal(raw, &restored) != nil || restored.EndpointPresent == nil || *restored.EndpointPresent != present || !bytes.Contains(raw, []byte("EndpointPresent")) {
			t.Fatal("false/true endpoint evidence lost in JSON roundtrip")
		}
	}
	var restored TaskFact
	if json.Unmarshal(before, &restored) != nil || restored.EndpointPresent != nil {
		t.Fatal("legacy unknown endpoint became an explicit false")
	}
	present := true
	missing := TaskFact{State: "missing", EndpointPresent: &present}
	if missing.Valid(10) {
		t.Fatal("missing native claimed a present endpoint")
	}
	present = false
	if !missing.Valid(10) {
		t.Fatal("positive missing evidence rejected")
	}
}
