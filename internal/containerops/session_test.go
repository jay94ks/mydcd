// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func TestExecReceiptSeparatesUncertainStartIOAndPositiveExit(t *testing.T) {
	r := ExecReceipt{Schema: 1, Intent: [32]byte{1}, Phase: ExecCreating}
	if r.Validate() != nil {
		t.Fatal("original create marker")
	}
	next := r
	next.ExecID, next.Phase = "native-exec", ExecCreated
	if !next.CanFollow(r) {
		t.Fatal("created ID not preserved")
	}
	r = next
	next.Phase = ExecStartSent
	if !next.CanFollow(r) {
		t.Fatal("start marker before Attach")
	}
	r = next
	unknown, err := r.Observe(false, 0)
	if err != nil || unknown.Phase != ExecStartSent || unknown.ExitCode != nil {
		t.Fatal("never-started Inspect became exit success", err)
	}
	unknown.Detached, unknown.OutputEnded, unknown.StdinClosed = true, true, true
	if !unknown.CanFollow(r) || unknown.Phase != ExecStartSent {
		t.Fatal("I/O loss changed process result")
	}
	r, err = unknown.Observe(true, 0)
	if err != nil || r.Phase != ExecStarted || !r.CanFollow(unknown) {
		t.Fatal("positive running evidence", err)
	}
	still, err := r.Observe(false, -1)
	if err != nil || still.Phase != ExecStarted || still.ExitCode != nil {
		t.Fatal("unavailable exit became completion")
	}
	finished, err := r.Observe(false, 23)
	if err != nil || finished.Phase != ExecFinished || !finished.CanFollow(r) || finished.ExitCode == nil || *finished.ExitCode != 23 {
		t.Fatal("actual nonzero exit lost", err)
	}
	for _, mutation := range []string{"new-exec", "new-intent", "rewind", "exit", "reattach"} {
		bad := finished
		switch mutation {
		case "new-exec":
			bad.ExecID = "another-exec"
		case "new-intent":
			bad.Intent[0]++
		case "rewind":
			bad.Phase, bad.ExitCode = ExecCreated, nil
		case "exit":
			zero := 0
			bad.ExitCode = &zero
		case "reattach":
			bad.Detached = false
		}
		if bad.CanFollow(finished) {
			t.Fatal("receipt allowed replay or changed evidence", mutation)
		}
	}
}

func TestContainerSessionIntentBindsActualLifetimeArgvAndRequest(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	var public [32]byte
	copy(public[:], key.Public().(ed25519.PublicKey))
	q := SessionIntent{Schema: 1, User: "alice", Request: "exec-original", Session: [32]byte{1}, At: 10,
		Target: Target{Cluster: [32]byte{1}, Owner: [32]byte{2}, Binding: [32]byte{3}, Tenant: "tenant", App: "app", Service: "web", Node: "node-a", Instance: "workload/task/tenant/app/web", Generation: 3, Revision: 4, NativeID: "container-original", StartedAt: time.Unix(1, 0).UTC().Format(time.RFC3339Nano)},
		Spec:   SessionSpec{Kind: "exec", Exec: &ExecSpec{Argv: []string{"custom-cli", "", "line\nvalue"}, Stdin: true}}}
	q.Signature = ed25519.Sign(key, SessionIntentBytes(q))
	if q.Verify(public) != nil {
		t.Fatal("valid user intent")
	}
	for _, mutation := range []string{"argv", "request", "session", "native", "started", "generation", "binding", "user"} {
		bad := q
		if mutation == "argv" {
			spec := *q.Spec.Exec
			spec.Argv = []string{"another-command"}
			bad.Spec.Exec = &spec
		}
		switch mutation {
		case "request":
			bad.Request = "replacement"
		case "session":
			bad.Session[0]++
		case "native":
			bad.Target.NativeID = "replacement"
		case "started":
			bad.Target.StartedAt = time.Unix(2, 0).UTC().Format(time.RFC3339Nano)
		case "generation":
			bad.Target.Generation++
		case "binding":
			bad.Target.Binding[0]++
		case "user":
			bad.User = "bob"
		}
		if bad.Verify(public) == nil || bad.Digest() == q.Digest() {
			t.Fatal("relay substituted original intent", mutation)
		}
	}
}

func TestContainerSessionSpecRejectsUnboundedOrMixedOperations(t *testing.T) {
	for _, q := range []SessionSpec{
		{Kind: "exec", Exec: &ExecSpec{}},
		{Kind: "exec", Exec: &ExecSpec{Argv: []string{"cmd\x00"}}},
		{Kind: "exec", Exec: &ExecSpec{Argv: []string{string([]byte{0xff})}}},
		{Kind: "exec", Exec: &ExecSpec{Argv: []string{strings.Repeat("x", 4097)}}},
		{Kind: "exec", Exec: &ExecSpec{Argv: []string{"cmd"}, TTY: true}},
		{Kind: "exec", Exec: &ExecSpec{Argv: []string{"cmd"}, Rows: 1}},
		{Kind: "exec", Exec: &ExecSpec{Argv: []string{"cmd"}}, Interval: time.Second},
		{Kind: "top", Query: &Query{Schema: 1, Kind: "top", Selection: Selection{App: "app", Service: "web"}, MaxBytes: 1024}, Interval: time.Millisecond},
	} {
		if q.Validate() == nil {
			t.Fatal("unsupported session accepted", q.Kind)
		}
	}
}
