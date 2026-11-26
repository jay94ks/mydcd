// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/ingress"
)

func TestIngressManagementTransitionsAndGlobalEventIsolation(t *testing.T) {
	f, _ := imageBuildFixture(t)
	block := ingress.Block{ID: "incident", Scope: "node", Node: "node-a", Gateway: "external", Response: "503", ExpiresAt: 100, Reason: "maintenance"}
	for _, step := range []struct {
		action, kind string
		expected     uint64
		payload      any
	}{
		{"ingress-block", "ingress-blocked", 0, IngressBlockChange{Block: block}},
		{"ingress-block-extend", "ingress-blocked", 1, IngressBlockSelection{ID: block.ID, ExpiresAt: 200}},
		{"ingress-unblock", "ingress-unblocked", 2, IngressBlockSelection{ID: block.ID}},
	} {
		before := f.s
		command := f.apply("admin", step.action, step.expected, step.payload, state.Applied)
		events, err := f.p.ProjectEvents(before, f.s, command, state.Result{Code: state.Applied, Index: f.s.Index()})
		var op UserOperation
		if json.Unmarshal([]byte(command.Value), &op) != nil {
			t.Fatal("original signed command missing")
		}
		if err != nil || len(events) != 1 || !events[0].Valid() {
			t.Fatal("committed ingress transition did not project a valid event", step.action, events, err)
		}
		e := events[0]
		if e.Kind != step.kind || e.Scope != "cluster" || e.Target.Node != block.Node || e.Target.Gateway != block.Gateway || e.Target.Tenant != "" || e.Detail.Operation != op.RequestID || e.At != uint64(op.At)*1000 {
			t.Fatal("event lost the original operation or global target", step.action, e)
		}
		denied, err := f.p.ProjectEvents(before, f.s, command, state.Result{Code: state.Forbidden, Index: f.s.Index()})
		if err != nil || len(denied) != 0 {
			t.Fatal("a refused result emitted an ingress change", err)
		}
	}
	manager, err := f.p.EventAccess(f.s, f.sessions["manager"], 2, eventlog.Query{Tenant: "tenant"})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := f.p.EventAccess(f.s, f.sessions["admin"], 2, eventlog.Query{})
	if err != nil {
		t.Fatal(err)
	}
	for index, kind := range []string{"ingress-listener-down", "ingress-listener-up", "ingress-source-rejected-spike", "ingress-blocked", "ingress-unblocked"} {
		e := eventlog.Event{Kind: kind, Scope: "node", At: 2000, Target: eventlog.Target{Node: "node-a", Gateway: "external"}}
		tag := sha256.Sum256([]byte(kind))
		record := eventlog.Record{Schema: 1, Cluster: f.p.Cluster, SourceKey: f.p.TrustRoot, SourceNode: "node-a", Stream: [16]byte{1}, Sequence: uint64(index + 1), Tag: hex.EncodeToString(tag[:]), Event: e}
		record.Signature = ed25519.Sign(f.node, eventlog.SigningBytes(record))
		if !record.Valid() || !admin(record) || manager(record) {
			t.Fatal("global ingress event leaked to tenant or disappeared for administrator", kind)
		}
	}
}
