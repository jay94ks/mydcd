// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func TestNodeOperationsRejectForeignSelectorsBeforeDispatch(t *testing.T) {
	requests := []Request{
		{Method: "node-drain-plan", NodeDrain: &control.NodeDrainQuery{Node: "node-a", Operation: "drain-a"}},
		{Method: "node-drain-status", NodeDrain: &control.NodeDrainQuery{Node: "node-a", Operation: "drain-a"}},
		{Method: "node-force-remove-plan", NodeForce: &control.NodeForceQuery{Node: "node-a", Operation: "remove-a"}},
		{Method: "node-remove-plan", Node: "node-a"},
		{Method: "node-demote-plan", Node: "node-a"},
		{Method: "node-diagnostics", Node: "node-a"},
	}
	for _, request := range requests {
		t.Run(request.Method, func(t *testing.T) {
			if !request.validMethodFields() || !request.validQuerySelectors() {
				t.Fatal("valid node selector rejected")
			}
			for _, mutate := range []func(*Request){
				func(r *Request) { r.Tenant = "foreign" },
				func(r *Request) { r.App = "foreign" },
				func(r *Request) { r.After = "foreign" },
				func(r *Request) { r.PublicRead = &control.PublicReadQuery{} },
				func(r *Request) { r.Method = "whoami" },
			} {
				bad := request
				mutate(&bad)
				if bad.validMethodFields() && bad.validQuerySelectors() {
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
	} {
		if err := call(); !errors.Is(err, mydcp.ErrAdmission) {
			t.Fatal("typed node query did not reach transport admission", err)
		}
	}
}
