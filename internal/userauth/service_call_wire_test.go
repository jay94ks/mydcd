// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/servicecall"
)

// The real SDK, authenticated Unix/QUIC, ordered input and EOF are exercised.
// Policy/native facts are injected; this is not a Raft/Docker success claim.
func TestServiceCallActualUserWireBoundsDigestEOFAndProbe(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, mode := range []string{"full", "empty", "corrupt", "short", "extra", "lost-result", "probe", "probe-redirect"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				_, c, session, node := journalFixture(t)
				root, err := os.MkdirTemp("", "mydc-service-call-wire-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(root)
				peer := c.Peers[0]
				lookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
					if key == mydcp.Identity(c.Self.Public) {
						return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, true
					}
					return peer, key == peer.Key
				}
				server, err := mydcp.NewTransport(node, c.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				if network == "unix" {
					peer.Endpoint = "unix://" + filepath.Join(root, "api.sock")
				} else {
					if err = server.Listen("127.0.0.1:0"); err != nil {
						t.Fatal(err)
					}
					peer.Endpoint = server.Addr().String()
				}
				mesh, err := mydcp.NewTransport(c.Self, c.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer mesh.Close()
				c.Mesh = mesh
				binding := Service{Mesh: server, Self: node, Policy: control.Policy{Cluster: c.Cluster}}
				completed := make(chan error, 1)
				effects := 0
				var probeRequests atomic.Int32
				err = server.OnManagement(mydcp.User, func(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
					cause := func() error {
						envelope, e := schema.Decode[Envelope](frame.Fields[0].Value)
						if e != nil {
							return e
						}
						q, e := schema.Decode[Request](envelope.Body)
						if e != nil || !q.validMethodFields() || !q.validQuerySelectors() {
							return mydcp.ErrFrame
						}
						if _, e = binding.binding(conn, frame.Kind, envelope); e != nil {
							return e
						}
						digest := sha256.Sum256(frame.Fields[0].Value)
						if mode == "probe" || mode == "probe-redirect" {
							probeRequests.Add(1)
							if q.Method != "cd-probe" || q.CDProbe == nil {
								return mydcp.ErrFrame
							}
							if e = streamEOF(stream); e != nil {
								return e
							}
							if mode == "probe-redirect" {
								return binding.respond(stream, frame, digest, Reply{Schema: 1, Code: "not-leader", Leader: "other-provider"})
							}
							result := deployment.GitProbeResult{Node: "node", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 42}
							return binding.respond(stream, frame, digest, Reply{Schema: 1, Code: "ok", CDProbe: &result})
						}
						if q.Method != "service-call" || q.ServiceCall == nil || q.ServiceInput == nil {
							return mydcp.ErrFrame
						}
						if e = binding.respond(stream, frame, digest, Reply{Schema: 1, Code: "continue"}); e != nil {
							return e
						}
						var body []byte
						if q.ServiceInput.Length == 0 {
							if q.ServiceInput.Digest != sha256.Sum256(nil) {
								return mydcp.ErrFrame
							}
							e = streamEOF(stream)
						} else {
							body, e = readUserInput(conn, stream, frame.Request, digest, q.ServiceInput.Length, q.ServiceInput.Digest, servicecall.MaxBody)
						}
						if e != nil {
							return binding.respond(stream, frame, digest, Reply{Schema: 1, Code: "invalid"})
						}
						defer clear(body)
						effects++ // Only a complete, original digest and EOF reaches the adapter.
						if mode == "lost-result" {
							return nil
						}
						result := servicecall.Result{Task: "task", Node: "node", Status: 200, Body: bytes.Repeat([]byte("r"), servicecall.MaxResponse), Headers: map[string]string{"Content-Type": "text/plain"}}
						return binding.respond(stream, frame, digest, Reply{Schema: 1, Code: "ok", ServiceCall: &result})
					}()
					completed <- cause
					return cause
				})
				if err != nil {
					t.Fatal(err)
				}
				if network == "unix" {
					if err = server.ListenUnix(filepath.Join(root, "api.sock")); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if mode == "probe" || mode == "probe-redirect" {
					// A trusted alternate ID uses the same actual wire listener so
					// an unintended redirect produces a second observable request.
					alternate := peer
					alternate.ID = "other-provider"
					c.Peers = []mydcp.Peer{peer, alternate}
					got, e := c.ProbeCD(ctx, peer, session, "tenant", deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml", Credential: "installed"})
					if mode == "probe-redirect" {
						var refused *Error
						if !errors.As(e, &refused) || refused.Code != "not-leader" || refused.Phase != mydcp.Completed || got.Commit != "" || got.Size != 0 || probeRequests.Load() != 1 {
							t.Fatal("Git profile query left its original provider", got, e, probeRequests.Load())
						}
					} else if e != nil || got.Size != 42 || got.Node != "node" {
						t.Fatal(got, e)
					}
				} else {
					q := servicecall.Request{App: "shop", Service: "api", Port: 8080, Path: "/decide", Method: "POST", Body: bytes.Repeat([]byte("b"), servicecall.MaxBody)}
					if mode == "empty" {
						q.Body = nil
					}
					var got servicecall.Result
					var failure error
					if mode == "corrupt" || mode == "short" || mode == "extra" {
						body := q.Body
						q.Body = nil
						input := ServiceCallInput{Length: len(body), Digest: sha256.Sum256(body)}
						switch mode {
						case "corrupt":
							input.Digest[0] ^= 1
						case "short":
							body = body[:len(body)-1]
						case "extra":
							input.Length--
						}
						raw, e := requestBody(Request{Method: "service-call", Tenant: "tenant", ServiceCall: &q, ServiceInput: &input})
						if e != nil {
							t.Fatal(e)
						}
						_, failure = c.serviceCallExchange(ctx, peer, body, 1, func(conn *mydcp.Session) (Envelope, error) {
							return Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), raw))}, nil
						})
					} else {
						got, failure = c.CallService(ctx, peer, session, "tenant", q)
					}
					if mode == "full" || mode == "empty" {
						if failure != nil || got.Status != 200 || len(got.Body) != servicecall.MaxResponse {
							t.Fatal(got.Code, len(got.Body), failure)
						}
					} else if failure == nil {
						t.Fatal("incomplete/uncertain call became success", mode)
					}
				}
				select {
				case cause := <-completed:
					if cause != nil {
						t.Fatal(cause)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				want := 1
				if mode == "corrupt" || mode == "short" || mode == "extra" || mode == "probe" || mode == "probe-redirect" {
					want = 0
				}
				if effects != want {
					t.Fatal("unexpected adapter invocations", effects, want)
				}
			})
		}
	}
}

func TestServiceCallRelayBindsExactTaskAndReadShapes(t *testing.T) {
	_, c, session, node := journalFixture(t)
	q := servicecall.Request{App: "shop", Service: "api", Port: 8080, Path: "/", Method: "POST"}
	input := ServiceCallInput{Digest: sha256.Sum256(nil)}
	request := Request{Schema: 1, Method: "service-call", Tenant: "tenant", ServiceCall: &q, ServiceInput: &input}
	if !request.validMethodFields() || !request.validQuerySelectors() {
		t.Fatal("valid request")
	}
	for _, change := range []func(*Request){func(r *Request) { r.After = "cursor" }, func(r *Request) { r.Node = "node" }, func(r *Request) { r.App = "foreign" }, func(r *Request) { r.CDProbe = &deployment.GitProbeRequest{} }, func(r *Request) { r.Method = "catalog" }} {
		bad := request
		change(&bad)
		if bad.validMethodFields() && bad.validQuerySelectors() {
			t.Fatal("cross-method selector accepted")
		}
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	envelope := Envelope{Body: body, Session: &session, Relay: &Relay{Node: node.Public, Target: [32]byte{9}, Caller: c.Self.Public, Challenge: [32]byte{8}, Connection: [32]byte{7}, ServiceCall: &ServiceCallRelay{Epoch: 1}}}
	original := RelayBytes(c.Cluster, envelope)
	signature := ed25519.Sign(node.Private, original)
	envelope.Relay.ServiceCall.Epoch++
	if ed25519.Verify(node.Public[:], RelayBytes(c.Cluster, envelope), signature) {
		t.Fatal("owner relay did not bind current epoch")
	}
	envelope.Relay.ServiceCall.Epoch--
	envelope.Relay.ServiceCall.Target.Port = 8443
	if ed25519.Verify(node.Public[:], RelayBytes(c.Cluster, envelope), signature) {
		t.Fatal("owner relay did not bind exact target")
	}
}

// Both the transport gate and direct execute gate reject selectors from the
// other feature after merging the RQ7 and RQ8 authenticated request shapes.
func TestServiceCallAndRQ7ReadSelectorsRemainDisjoint(t *testing.T) {
	call := servicecall.Request{App: "shop", Service: "api", Port: 8080, Path: "/", Method: "POST"}
	input := ServiceCallInput{Digest: sha256.Sum256(nil)}
	probe := deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}
	ingress := control.IngressQuery{Tenant: "tenant", Node: "node-a", Part: "mappings"}
	requests := []Request{
		{Method: "tenant-storage", Tenant: "tenant", Node: "node-a", After: "cursor"},
		{Method: "certificates", Certificate: &control.CertificateQuery{}},
		{Method: "ingresses", Tenant: "tenant", Ingress: &ingress},
		{Method: "service-call", Tenant: "tenant", ServiceCall: &call, ServiceInput: &input},
		{Method: "cd-probe", Tenant: "tenant", CDProbe: &probe},
	}
	for _, original := range requests {
		t.Run(original.Method, func(t *testing.T) {
			if !original.validMethodFields() || !original.validQuerySelectors() {
				t.Fatal("valid merged feature rejected")
			}
			changes := []func(*Request){
				func(r *Request) { r.ServiceCall = &call; r.ServiceInput = &input },
				func(r *Request) { r.CDProbe = &probe },
				func(r *Request) { r.Certificate = &control.CertificateQuery{} },
				func(r *Request) { r.Ingress = &ingress },
			}
			for i, change := range changes {
				if i == 0 && original.Method == "service-call" || i == 1 && original.Method == "cd-probe" || i == 2 && original.Method == "certificates" || i == 3 && original.Method == "ingresses" {
					continue
				}
				bad := original
				change(&bad)
				if bad.validMethodFields() || bad.validQuerySelectors() {
					t.Fatal("mixed feature bypassed request gate", i)
				}
			}
		})
	}
}

func TestRQ8QueryAdmissionPreservesRQ7ReadMethods(t *testing.T) {
	_, client, session, _ := journalFixture(t)
	// No transport is installed. Supported SDK queries must reach the existing
	// transport admission boundary, rather than fail as unsupported methods.
	for _, request := range []Request{
		{Method: "tenant-storage", Tenant: "tenant"},
		{Method: "certificates", Certificate: &control.CertificateQuery{}},
		{Method: "ingresses", Tenant: "tenant", Ingress: &control.IngressQuery{Tenant: "tenant", Part: "mappings"}},
		{Method: "cd-probe", Tenant: "tenant", CDProbe: &deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}},
	} {
		if _, err := client.query(context.Background(), client.Peers[0], session, request); !errors.Is(err, mydcp.ErrAdmission) {
			t.Fatal("query did not reach transport admission", request.Method, err)
		}
	}
}
