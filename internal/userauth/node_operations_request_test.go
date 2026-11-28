// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestNodeOperationsRejectForeignSelectorsBeforeDispatch(t *testing.T) {
	requests := map[string]string{
		"node-drain-plan":        `{"Node":"node-a","Operation":"drain-a"}`,
		"node-drain-status":      `{"Node":"node-a","Operation":"drain-a"}`,
		"node-force-remove-plan": `{"Node":"node-a","Operation":"remove-a"}`,
		"node-remove-plan":       `{"Node":"node-a"}`,
		"node-demote-plan":       `{"Node":"node-a"}`,
		"node-diagnostics":       `{"Node":"node-a"}`,
		"node-logs":              `{"Node":"node-a","App":"web","Stdout":true,"Stderr":true}`,
	}
	for method, params := range requests {
		t.Run(method, func(t *testing.T) {
			request := Request{Schema: 1, Method: method, Params: json.RawMessage(params)}
			if !request.validMethodFields() {
				t.Fatal("valid node selector rejected")
			}
			for _, mutate := range []func(*Request){
				func(r *Request) { r.Tenant = "foreign" },
				func(r *Request) { r.After = "foreign" },
				func(r *Request) { r.Method = "whoami" },
				func(r *Request) { r.Params = json.RawMessage(`{"Node":"node-a","Tenant":"foreign"}`) },
				func(r *Request) { r.Params = json.RawMessage(`{"Node":"../node"}`) },
			} {
				bad := request
				mutate(&bad)
				if bad.validMethodFields() {
					t.Fatal("foreign selector accepted", bad.Method)
				}
			}
		})
	}
}

// A valid signed session with no transport must reach common transport
// admission, rather than being stopped by a missing client method registration.
func TestNodeOperationTypedClientsReachTransportAdmission(t *testing.T) {
	_, client, session, _ := journalFixture(t)
	ctx := context.Background()
	peer := client.Peers[0]
	for _, call := range []func() error{
		func() error {
			_, err := client.NodeForceRemovePlan(ctx, peer, session, control.NodeForceQuery{Node: "node-a", Operation: "remove-a"})
			return err
		},
		func() error {
			_, err := client.NodeDrainPlan(ctx, peer, session, control.NodeDrainQuery{Node: "node-a", Operation: "drain-a"})
			return err
		},
		func() error {
			_, err := client.NodeDrainStatus(ctx, peer, session, control.NodeDrainQuery{Node: "node-a", Operation: "drain-a"})
			return err
		},
		func() error { _, err := client.NodeDiagnostics(ctx, peer, session, "node-a"); return err },
		func() error {
			_, err := client.NodeLogs(ctx, peer, session, control.NodeLogsQuery{Node: "node-a", App: "web", Stdout: true, Stderr: true})
			return err
		},
	} {
		if err := call(); !errors.Is(err, sfcp.ErrAdmission) {
			t.Fatal("typed node query did not reach transport admission", err)
		}
	}
}
