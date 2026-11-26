// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/web/store"
)

// the tunnel-down event names its workspace, network, the server
// that saw the link down (Node) and the pair (Target = PairID).
func TestReconnectActionFromEvent(t *testing.T) {
	s := &Server{}
	a := incidentActionByID("reconnect-tunnel")
	sig := store.IncidentSignal{Kind: "tunnel-down", Tenant: "payments", Network: "payments-net", Node: "node-c", Target: "node-a/node-c"}
	out, why := s.buildIncidentAction(context.Background(), nil, a, &store.Incident{}, sig, nil, nil)
	if out == nil {
		t.Fatalf("no action: %s", why)
	}
	var body map[string]any
	_ = json.Unmarshal(out.Body, &body)
	if out.Path != "/api/v1/t/payments/networks/payments-net/tunnels/reconnect" || body["from"] != "node-c" || body["to"] != "node-a" {
		t.Fatalf("action: %s %v", out.Path, body)
	}
	for _, bad := range []store.IncidentSignal{
		{Tenant: "payments", Network: "payments-net", Node: "node-b", Target: "node-a/node-c"},
		{Tenant: "payments", Node: "node-a", Target: "node-a/node-c"},
		{Tenant: "payments", Network: "payments-net", Target: "node-a"},
	} {
		if out, _ := s.buildIncidentAction(context.Background(), nil, a, &store.Incident{}, bad, nil, nil); out != nil {
			t.Fatalf("built for %+v", bad)
		}
	}
}
