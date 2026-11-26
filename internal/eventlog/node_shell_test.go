// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNodeShellEventsAllowOnlyPublicCountsAndExplicitCloseActor(t *testing.T) {
	code := 0
	e := Event{Kind: "node-shell-closed", Scope: "node", At: 1, Target: Target{Node: "node-a"}, Detail: Detail{Actor: "alice", Operation: "original", BytesIn: 3, BytesOut: 9, Reason: "closed", ExitCode: &code, ClosedBy: &ActorIdentity{User: "bob", Username: "Bob"}}}
	if !e.Valid() {
		t.Fatal("public signed close metadata rejected")
	}
	for _, reason := range []string{"exit", "idle"} {
		n := e
		n.Detail.Reason = reason
		if n.Valid() {
			t.Fatal("exit/idle accepted a fabricated closing actor", reason)
		}
		n.Detail.ClosedBy = nil
		if !n.Valid() {
			t.Fatal("ordinary end without closing actor rejected", reason)
		}
	}
	n := e
	n.Detail.ClosedBy = nil
	if n.Valid() {
		t.Fatal("administrator close accepted missing actor")
	}
	n = e
	n.Detail.ClosedBy = &ActorIdentity{User: "bob", Username: "bad\nname"}
	if n.Valid() {
		t.Fatal("control character in closing actor accepted")
	}
	n = e
	n.Kind = "task-exited"
	if n.Valid() {
		t.Fatal("unrelated event accepted shell attribution")
	}
	legacy, _ := json.Marshal(Detail{Actor: "alice"})
	if strings.Contains(string(legacy), "ClosedBy") || strings.Contains(string(legacy), "BytesIn") || strings.Contains(string(legacy), "BytesOut") {
		t.Fatal("absent shell fields changed legacy event shape")
	}
}
