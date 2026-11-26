// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

func TestNodeDrainStatusOptionalOperationRequestKeepsSelectorBoundaries(t *testing.T) {
	for _, operation := range []string{"", "original"} {
		r := Request{Method: "node-drain-status", NodeDrain: &control.NodeDrainQuery{Node: "node-a", Operation: operation}}
		if !r.validMethodFields() || !r.validQuerySelectors() || !r.validLookupFields() {
			t.Fatal("valid status selector rejected", operation)
		}
		for _, edit := range []func(*Request){
			func(r *Request) { r.Tenant = "tenant" },
			func(r *Request) { r.App = "app" },
			func(r *Request) { r.Node = "node-b" },
			func(r *Request) { r.After = "cursor" },
			func(r *Request) { r.Method = "whoami" },
			func(r *Request) { r.State = "open" },
		} {
			bad := r
			edit(&bad)
			if bad.validMethodFields() || bad.validQuerySelectors() || bad.validLookupFields() {
				t.Fatal("foreign status selector accepted", bad.Method)
			}
		}
	}
	for _, r := range []Request{
		{Method: "node-drain-plan", NodeDrain: &control.NodeDrainQuery{Node: "node-a"}},
		{Method: "node-drain-status", NodeDrain: &control.NodeDrainQuery{}},
		{Method: "node-drain-status", NodeDrain: &control.NodeDrainQuery{Node: "../node"}},
		{Method: "node-drain-status", NodeDrain: &control.NodeDrainQuery{Node: "node-a", Operation: "../original"}},
	} {
		if r.validMethodFields() || r.validQuerySelectors() || r.validLookupFields() {
			t.Fatal("missing plan original or malformed status selector accepted", r.Method)
		}
	}
	for _, method := range []string{"whoami", "members", "unknown", "node-shell-policy", "node-drain-status", "login"} {
		r := Request{Method: method, State: "closed"}
		if r.validMethodFields() || r.validQuerySelectors() || r.validLookupFields() {
			t.Fatal("shell-only State field leaked to a foreign method", method)
		}
	}
	_, client, session, _ := journalFixture(t)
	if _, err := client.NodeDrainStatus(context.Background(), client.Peers[0], session, control.NodeDrainQuery{Node: "node-a"}); !errors.Is(err, mydcp.ErrAdmission) {
		t.Fatal("omitted status operation did not reach common transport admission", err)
	}
	if _, err := client.NodeDrainPlan(context.Background(), client.Peers[0], session, control.NodeDrainQuery{Node: "node-a"}); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("SDK plan accepted omitted operation", err)
	}
}

// Real TLS/QUIC and Unix frame/binding/EOF, with explicit reply model inputs.
// This tests the typed SDK's response selector; current admin/progress and
// retained Directory selection are covered by the shared control core tests.
func TestNodeDrainStatusActualSDKAcceptsOnlyResolvedOriginalSelectors(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		t.Run(network, func(t *testing.T) {
			_, client, session, node := journalFixture(t)
			peer := client.Peers[0]
			lookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
				if key == mydcp.Identity(client.Self.Public) {
					return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, true
				}
				return peer, key == peer.Key
			}
			server, err := mydcp.NewTransport(node, client.Cluster, lookup)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			type input struct {
				query  control.NodeDrainQuery
				status control.NodeDrainStatus
			}
			replies := make(chan input, 1)
			done := make(chan error, 1)
			binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
			if err = server.OnManagement(mydcp.User, func(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
				serve := func() error {
					expected := <-replies
					envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
					if err != nil {
						return err
					}
					r, err := schema.Decode[Request](envelope.Body)
					if err != nil || r.Method != "node-drain-status" || !r.validMethodFields() || !r.validQuerySelectors() || r.NodeDrain == nil || *r.NodeDrain != expected.query {
						return mydcp.ErrAdmission
					}
					if _, err = binding.binding(conn, frame.Kind, envelope); err != nil {
						return err
					}
					if err = streamEOF(stream); err != nil {
						return err
					}
					return binding.respond(stream, frame, sha256.Sum256(frame.Fields[0].Value), Reply{Schema: 1, Code: "ok", NodeDrainStatus: &expected.status})
				}()
				done <- serve
				return serve
			}); err != nil {
				t.Fatal(err)
			}
			if network == "unix" {
				root, err := os.MkdirTemp("", "mydc-drain-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(root)
				path := filepath.Join(root, "api.sock")
				if err = server.ListenUnix(path); err != nil {
					t.Fatal(err)
				}
				peer.Endpoint = "unix://" + path
			} else {
				if err = server.Listen("127.0.0.1:0"); err != nil {
					t.Fatal(err)
				}
				peer.Endpoint = server.Addr().String()
			}
			mesh, err := mydcp.NewTransport(client.Self, client.Cluster, lookup)
			if err != nil {
				t.Fatal(err)
			}
			defer mesh.Close()
			client.Mesh = mesh
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, tc := range []struct {
				name, requested, actual, node string
				valid                         bool
			}{
				{"resolved", "", "actual-original", "node-a", true},
				{"exact", "requested-original", "requested-original", "node-a", true},
				{"wrong-exact", "requested-original", "other-original", "node-a", false},
				{"missing-original", "", "", "node-a", false},
				{"malformed-original", "", "../original", "node-a", false},
				{"foreign-node", "", "actual-original", "node-b", false},
			} {
				q := control.NodeDrainQuery{Node: "node-a", Operation: tc.requested}
				replies <- input{query: q, status: control.NodeDrainStatus{Schema: 1, Node: tc.node, Operation: tc.actual, State: "Draining", Jobs: []control.NodeDrainJobStatus{}}}
				status, err := client.NodeDrainStatus(ctx, peer, session, q)
				if (err == nil) != tc.valid || tc.valid && status.Operation != tc.actual || !tc.valid && !errors.Is(err, mydcp.ErrAdmission) {
					t.Fatal("typed SDK response selector", tc.name, status.Operation, err)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal("wire fixture did not finish", tc.name, err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
		})
	}
}
