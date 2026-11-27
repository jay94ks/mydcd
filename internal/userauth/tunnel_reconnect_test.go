// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"testing"
)

// A reconnect plan names exactly two different servers and a status one
// operation; neither takes a tenant, node or cursor.
func TestTunnelReconnectQueriesAreStrict(t *testing.T) {
	for _, r := range []Request{
		{Schema: 1, Method: "tunnel-reconnect-plan", Params: json.RawMessage(`{"Node":"a","Peer":"b"}`)},
		{Schema: 1, Method: "tunnel-reconnect-status", Params: json.RawMessage(`{"Operation":"repair-42"}`)},
	} {
		if !r.validMethodFields() {
			t.Fatal("valid reconnect query refused", r.Method)
		}
	}
	for name, r := range map[string]Request{
		"same server":     {Schema: 1, Method: "tunnel-reconnect-plan", Params: json.RawMessage(`{"Node":"a","Peer":"a"}`)},
		"plan operation":  {Schema: 1, Method: "tunnel-reconnect-plan", Params: json.RawMessage(`{"Node":"a","Peer":"b","Operation":"x"}`)},
		"status node":     {Schema: 1, Method: "tunnel-reconnect-status", Params: json.RawMessage(`{"Operation":"repair-42","Node":"a"}`)},
		"tenant field":    {Schema: 1, Method: "tunnel-reconnect-plan", Tenant: "team", Params: json.RawMessage(`{"Node":"a","Peer":"b"}`)},
		"cursor field":    {Schema: 1, Method: "tunnel-reconnect-status", After: "cursor", Params: json.RawMessage(`{"Operation":"repair-42"}`)},
		"missing params":  {Schema: 1, Method: "tunnel-reconnect-status"},
		"empty operation": {Schema: 1, Method: "tunnel-reconnect-status", Params: json.RawMessage(`{"Operation":""}`)},
	} {
		if r.validMethodFields() {
			t.Fatal(name, "accepted")
		}
	}
}
