// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/deployment"
)

func TestAppOperationHistoryScopeMissingAndImmutableResult(t *testing.T) {
	anchor := [32]byte{97}
	c, _ := access.New(anchor)
	var err error
	c, err = c.Enroll(anchor, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: anchor, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"tenant", "foreign"} {
		c, err = c.CreateTenant("admin", tenant, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	c, err = c.PutUser("admin", 0, access.User{ID: "reader", Username: "reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte{98}, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.SetMembership("admin", 0, access.Membership{Tenant: "tenant", User: "reader", Role: access.Viewer, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// Codec-valid compact history is a query fixture, not native completion evidence.
	var record struct {
		Schema                  uint8
		Cluster                 [32]byte
		Tenant, App, Deployment string
		Revision                uint64
		Active                  json.RawMessage
		History                 []deployment.OperationSummary
		MinEpoch                map[string]uint64
		Claims                  []deployment.Claim
		Stopping                bool
		Retirement              json.RawMessage
	}
	record.Schema, record.Cluster, record.Tenant, record.App, record.Deployment, record.Revision = 1, anchor, "tenant", "app", "deploy", 5
	for _, status := range []string{"Succeeded", "Closed", "Retired"} {
		record.History = append(record.History, deployment.OperationSummary{ID: "original-" + string(rune('a'+len(record.History))), Status: status, Plan: [32]byte{4}, Submitter: "original-actor", Epoch: 1, CompletedAt: 9, Failed: status == "Closed"})
	}
	raw, _ := json.Marshal(record)
	i, err := deployment.DecodeInventory(raw)
	if err != nil {
		t.Fatal("history fixture", err)
	}
	a := Apps{entries: map[string]appEntry{appKey("tenant", "app"): {Inventory: i}}}
	for _, original := range record.History {
		out, err := a.Operation(c, "reader", "tenant", AppOperationRequest{App: "app", ID: original.ID})
		if err != nil || !out.Found || out.Current || out.Operation == nil || *out.Operation != original || out.Deployment != "deploy" || out.Revision != 5 {
			t.Fatal("exact historical result", out, err)
		}
		out.Operation.Status = "forged"
		got, _ := a.Operation(c, "reader", "tenant", AppOperationRequest{App: "app", ID: original.ID})
		if *got.Operation != original {
			t.Fatal("query result aliases inventory")
		}
	}
	for _, q := range []AppOperationRequest{{App: "app", ID: "missing"}, {App: "missing", ID: "original-a"}} {
		out, err := a.Operation(c, "reader", "tenant", q)
		if err != nil || out.Found || out.Current || out.Operation != nil || out.ID != q.ID {
			t.Fatal("absence is not a terminal result", out, err)
		}
	}
	for _, q := range []AppOperationRequest{{App: "app", ID: ""}, {App: "app", ID: "original/a"}, {App: "../app", ID: "original-a"}, {App: "app", ID: "Original"}} {
		if _, err := a.Operation(c, "reader", "tenant", q); err == nil {
			t.Fatal("invalid selector accepted", q)
		}
	}
	for _, tenant := range []string{"", "foreign"} {
		if out, err := a.Operation(c, "reader", tenant, AppOperationRequest{App: "app", ID: "original-a"}); err == nil || out.Operation != nil {
			t.Fatal("foreign tenant disclosed", out, err)
		}
	}
	if _, err := a.Operation(c, "unknown", "tenant", AppOperationRequest{App: "app", ID: "original-a"}); err == nil {
		t.Fatal("unknown user disclosed history")
	}
	after, _ := i.Encode()
	if !bytes.Equal(raw, after) {
		t.Fatal("query changed the inventory")
	}
}
