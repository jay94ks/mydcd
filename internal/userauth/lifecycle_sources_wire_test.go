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
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/servicecall"
	"github.com/jay94ks/seafield/internal/sfcp"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// Actual SDK, TLS/Unix/QUIC and original source framing. Authority and the
// checked source fact are injected; the Runtime fixture proves real staging.
func TestLifecycleSourceActualUserWireKeepsExactBodyEOFAndPageDigest(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, mode := range []string{"valid", "corrupt-page", "foreign-version", "stage-unknown", "stage-lost-result"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				_, c, session, node := journalFixture(t)
				root, err := os.MkdirTemp("", "sfc-editor-wire-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(root)
				peer := c.Peers[0]
				lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
					if key == sfcp.Identity(c.Self.Public) {
						return sfcp.Peer{ID: "user", Policy: sfcp.Policy{Key: key, UserAuth: true}}, true
					}
					return peer, key == peer.Key
				}
				server, err := sfcp.NewTransport(node, c.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				if network == "quic" {
					if err = server.Listen("127.0.0.1:0"); err != nil {
						t.Fatal(err)
					}
					peer.Endpoint = server.Addr().String()
				} else {
					peer.Endpoint = "unix://" + filepath.Join(root, "api.sock")
				}
				mesh, err := sfcp.NewTransport(c.Self, c.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer mesh.Close()
				c.Mesh = mesh
				binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: c.Cluster}}
				source := append([]byte("package checker\n"), bytes.Repeat([]byte("// UTF-8 원본\n"), 8000)...)
				d := streamedSource(source)
				upload := sha256.Sum256([]byte("original editor upload"))
				done := make(chan error, 32)
				err = server.OnManagement(sfcp.User, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
					cause := func() error {
						envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
						if err != nil {
							return err
						}
						request, err := schema.Decode[Request](envelope.Body)
						if err != nil || !request.validMethodFields() || !request.validQuerySelectors() {
							return sfcp.ErrFrame
						}
						if _, err = binding.binding(conn, frame.Kind, envelope); err != nil {
							return err
						}
						digest := sha256.Sum256(frame.Fields[0].Value)
						if request.Method == "lifecycle-source-stage" {
							metadata := LifecycleStageResult{Node: "node", Owner: node.Public, Descriptor: d, Upload: upload}
							if err = binding.respond(stream, frame, digest, dataReply("continue", metadata)); err != nil {
								return err
							}
							body, err := readUserInput(conn, stream, frame.Request, digest, int(d.Length), d.Digest, checker.MaxScriptBytes)
							if err != nil {
								return err
							}
							defer clear(body)
							if !bytes.Equal(body, source) {
								return sfcp.ErrFrame
							}
							if mode == "stage-unknown" {
								return binding.respond(stream, frame, digest, Reply{Schema: 1, Code: "unknown"})
							}
							if mode == "stage-lost-result" {
								return nil
							}
							fact := checker.SourceFact{Upload: &upload, Schema: 1, Cluster: c.Cluster, Owner: node.Public, Tenant: d.Tenant, Digest: d.Digest, Length: d.Length, SDK: 1}
							fact.Signature = ed25519.Sign(node.Private, checker.SourceFactBytes(fact))
							result := LifecycleStageResult{Node: "node", Owner: node.Public, Descriptor: d, Upload: upload, Source: &fact}
							return binding.respond(stream, frame, digest, dataReply("ok", result))
						}
						var typed LifecycleSourceQuery
						if request.Method != "lifecycle-source" || strict(request.Params, &typed) != nil {
							return sfcp.ErrFrame
						}
						if err = streamEOF(stream); err != nil {
							return err
						}
						q := typed.Source
						page, err := checker.NewSourcePage(d.Tenant, q.Name, q.Revision, q.Offset, d, source)
						if err != nil {
							return err
						}
						if mode == "corrupt-page" {
							page.Data[0] ^= 1
						}
						if mode == "foreign-version" {
							page.Revision++
						}
						data, err := json.Marshal(page)
						if err != nil {
							return err
						}
						return binding.respond(stream, frame, digest, Reply{Schema: 1, Code: "ok", Data: data})
					}()
					done <- cause
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
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				staged, err := c.StageLifecycleSource(ctx, peer, session, "node", d, upload, source)
				if mode == "stage-unknown" || mode == "stage-lost-result" {
					var remote *Error
					if !errors.As(err, &remote) || remote.Phase != sfcp.Unknown || !staged.MetadataValid() || staged.Node != "node" || staged.Upload != upload || staged.Source != nil {
						t.Fatal("original upload/provider lost after unknown result", staged, err)
					}
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					return
				}
				if err != nil || staged.Source == nil || staged.Source.Digest != d.Digest {
					t.Fatal(staged, err)
				}
				got, err := c.LifecycleSource(ctx, peer, session, d.Tenant, "ready", 3)
				if mode == "valid" {
					if err != nil || got.Source != string(source) || got.Digest != d.Digest {
						t.Fatal("original UTF-8 source lost", err)
					}
				} else if err == nil {
					t.Fatal("corrupt/mixed version accepted", mode)
				}
				requests := 1 + (len(source)+checker.SourcePageBytes-1)/checker.SourcePageBytes
				if mode == "foreign-version" {
					requests = 2
				}
				for index := 0; index < requests; index++ {
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
			})
		}
	}
}
func TestLifecycleSourceRequestsCannotBorrowOtherMethodSelectors(t *testing.T) {
	d := streamedSource([]byte("package checker\n"))
	id := [32]byte{1}
	request, err := stageRequest("lifecycle-source-stage", CheckerStageQuery{Tenant: "tenant", Source: d, Upload: id})
	if err != nil || !request.validMethodFields() || !request.validQuerySelectors() {
		t.Fatal("valid editor upload")
	}
	recover, _ := stageRequest("lifecycle-source-recover", CheckerStageQuery{Tenant: "tenant", Source: d, Upload: id})
	if recover.validQuerySelectors() {
		t.Fatal("recover without its provider node admitted")
	}
	noUpload, _ := stageRequest("lifecycle-source-stage", CheckerStageQuery{Tenant: "tenant", Source: d})
	withNode, _ := stageRequest("lifecycle-source-recover", CheckerStageQuery{Tenant: "tenant", Node: "node", Source: d, Upload: id})
	for _, change := range []func(*Request){func(r *Request) { r.After = "cursor" }, func(r *Request) { r.Method = "whoami" }, func(r *Request) { r.Params = noUpload.Params }, func(r *Request) { r.Tenant = "other" }, func(r *Request) { r.Method = "checker-source-stage"; r.Params = withNode.Params }} {
		copy := request
		change(&copy)
		if copy.validMethodFields() && copy.validQuerySelectors() {
			t.Fatal("mixed editor request admitted")
		}
	}
}

func TestRQ11SourceSelectorsKeepEarlierTypedBoundaries(t *testing.T) {
	descriptor := streamedSource([]byte("package checker\n"))
	upload := [32]byte{1}
	call := servicecall.Request{App: "shop", Service: "api", Port: 8080, Path: "/", Method: "POST"}
	callInput := ServiceCallInput{Digest: sha256.Sum256(nil)}
	probe := deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}
	earlier := []Request{
		callRequest(call, callInput),
		probeRequest(probe),
		{Method: "standalone-list", Tenant: "tenant", Standalone: &control.StandaloneQuery{}},
	}
	for _, request := range earlier {
		if !request.validMethodFields() || !request.validQuerySelectors() {
			t.Fatal("earlier typed method lost", request.Method)
		}
		request.Params = json.RawMessage(`{"Tenant":"tenant"}`)
		if request.validMethodFields() || request.validQuerySelectors() {
			t.Fatal("source selector crossed earlier method", request.Method)
		}
	}
	stage, err := stageRequest("lifecycle-source-stage", CheckerStageQuery{Tenant: descriptor.Tenant, Source: descriptor, Upload: upload})
	if err != nil {
		t.Fatal(err)
	}
	sources := []Request{stage}
	for _, source := range sources {
		if !source.validMethodFields() || !source.validQuerySelectors() {
			t.Fatal("valid source method lost", source.Method)
		}
		for _, mutate := range []func(*Request){
			func(r *Request) { r.Params = json.RawMessage("{}") },
			func(r *Request) { r.Params = callRequest(call, callInput).Params },
			func(r *Request) { r.Params = probeRequest(probe).Params },
			func(r *Request) { r.Standalone = &control.StandaloneQuery{Name: "debug"} },
		} {
			bad := source
			mutate(&bad)
			if bad.validMethodFields() || bad.validQuerySelectors() {
				t.Fatal("source request borrowed earlier feature fields", source.Method)
			}
		}
	}
	_, client, session, _ := journalFixture(t)
	// No transport is installed: every finite query must still reach normal
	// transport admission rather than the unsupported-method branch.
	for _, request := range earlier {
		if request.Method == "service-call" || request.Method == "cd-probe" {
			continue // POST and the provider probe have their own client paths.
		}
		if _, err := client.query(context.Background(), client.Peers[0], session, request); !errors.Is(err, sfcp.ErrAdmission) {
			t.Fatal("SDK finite query disconnected", request.Method, err)
		}
	}
}
