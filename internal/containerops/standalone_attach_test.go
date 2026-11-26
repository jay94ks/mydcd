// SPDX-License-Identifier: Apache-2.0

package containerops

import "testing"

func TestStandaloneAttachHasNoExecCommandAndUsesSameBoundedFlow(t *testing.T) {
	q := SessionSpec{Kind: "attach", Exec: &ExecSpec{Stdin: true, TTY: true, Rows: 24, Cols: 80}}
	if q.Validate() != nil {
		t.Fatal("attach spec rejected")
	}
	target := Target{Standalone: "debug", Cluster: [32]byte{1}, Owner: [32]byte{2}, Binding: [32]byte{3}, Tenant: "tenant", App: "scope", Service: "debug", Node: "node", Instance: "workload/task/tenant/scope/debug", Generation: 1, Revision: 1, NativeID: "original", StartedAt: "2026-01-01T00:00:00Z"}
	flow := SessionFlow{Intent: [32]byte{4}}
	next, err := flow.Accept(q, target, SessionRecord{Schema: 1, Sequence: 1, Kind: "stdout", Data: []byte("shell")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = next.Accept(q, target, SessionRecord{Schema: 1, Sequence: 2, Kind: "output-eof"}, false); err != nil {
		t.Fatal(err)
	}
	q.Exec.Argv = []string{"/bin/sh"}
	if q.Validate() == nil {
		t.Fatal("attach could create a command")
	}
	q.Exec.Argv = nil
	target.Standalone = ""
	intent := SessionIntent{Schema: 1, Request: "attach", User: "user", Session: [32]byte{1}, At: 1, Target: target, Spec: q}
	if intent.Validate() == nil {
		t.Fatal("ordinary app process became a standalone attach target")
	}
}
func TestStandalonePinNameChangeKeepsExactTaskNativeIdentity(t *testing.T) {
	before := Target{Standalone: "debug", Cluster: [32]byte{1}, Owner: [32]byte{2}, Binding: [32]byte{3}, Tenant: "tenant", App: "scope", Service: "debug", Node: "node", Instance: "task", Generation: 1, Revision: 1, NativeID: "original", StartedAt: "2026-01-01T00:00:00Z"}
	after := before
	after.Standalone = "kept"
	if !after.Matches(before) {
		t.Fatal("pin invalidated original exact target")
	}
	after.NativeID = "replacement"
	if after.Matches(before) {
		t.Fatal("public name adopted replacement native")
	}
}

func TestStandaloneReadSelectionKeepsExplicitOwnerKindAndOptionalFields(t *testing.T) {
	target := Target{Standalone: "kept", Cluster: [32]byte{1}, Owner: [32]byte{2}, Binding: [32]byte{3}, Tenant: "tenant", App: "internal-scope", Service: "debug", Node: "node", Instance: "original-task", Generation: 1, Revision: 1, NativeID: "original", StartedAt: "2026-01-01T00:00:00Z"}
	for _, selection := range []Selection{{Standalone: "kept"}, {Standalone: "kept", Service: "debug", Instance: "original-task"}} {
		if !selection.Matches(target) {
			t.Fatal("explicit standalone read rejected its internal-scope target", selection)
		}
	}
	for _, selection := range []Selection{{Standalone: "other"}, {Standalone: "kept", Service: "other"}, {Standalone: "kept", Instance: "replacement"}, {App: target.App, Service: "debug"}, {Standalone: "kept", App: target.App}} {
		if selection.Matches(target) {
			t.Fatal("read selector adopted another owner or Task", selection)
		}
	}
	target.Standalone = ""
	if !(Selection{App: target.App, Service: target.Service}).Matches(target) || (Selection{Standalone: "kept"}).Matches(target) {
		t.Fatal("ordinary app read owner matching changed")
	}
}
