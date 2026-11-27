// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/quic-go/quic-go"
)

func uploadWireSession(t *testing.T, client Client, initial access.Session, issuer *identity.Identity) access.Session {
	t.Helper()
	last := initial
	last.Scopes = slices.Clone(initial.Scopes)
	last.Scopes[0].Actions = []access.Action{access.Read, access.ManageRegistry, access.ManageVolumes}
	for i := 0; i < 256; i++ {
		trial := last
		trial.Approval = nil
		trial.Scopes = append(slices.Clone(last.Scopes), access.Scope{Tenant: fmt.Sprintf("tenant-%03d-%s", i, strings.Repeat("a", 50)), Actions: []access.Action{access.Read, access.ManageRegistry, access.ManageVolumes}})
		trial.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(trial))
		approved, err := access.ApproveSession(trial, client.Self.Private)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(approved)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 8<<10 {
			previous, _ := json.Marshal(last)
			if len(previous) < (8<<10)-256 || last.Approval == nil || client.Verify(last) != nil {
				t.Fatal("wire fixture did not reach a valid signed session near the selection boundary")
			}
			return last
		}
		last = approved
	}
	t.Fatal("wire session fixture never reached the fixed JSON boundary")
	return access.Session{}
}

// Native storage and quorum decisions are fixture outcomes here. Production
// SDK/Unix/QUIC serializers, connection proof, PartProof, Management signing,
// full member relay/permit bodies and the unchanged 128 KiB frame limit are
// actually consumed; this does not claim a live Raft/native authorization run.
func TestBuildZIPUpload32KiBActualUserAndMemberManagementWire(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, record := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/record-%t", network, record), func(t *testing.T) {
				_, client, initial, node := journalFixture(t)
				session := uploadWireSession(t, client, initial, node)
				owner, err := identity.Ephemeral()
				if err != nil {
					t.Fatal(err)
				}
				defer clear(owner.Private)
				dir, err := os.MkdirTemp("", "sfc-zip-chunk-wire-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(dir)
				peer := client.Peers[0]
				peer.Policy.Read, peer.Policy.Member = true, true
				ownerPeer := sfcp.Peer{ID: "owner", Policy: sfcp.Policy{Key: sfcp.Identity(owner.Public), Respond: true, Read: true, Member: true}}
				lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
					if key == sfcp.Identity(client.Self.Public) {
						return sfcp.Peer{ID: "user", Policy: sfcp.Policy{Key: key, UserAuth: true}}, true
					}
					if key == peer.Key {
						return peer, true
					}
					return ownerPeer, key == ownerPeer.Key
				}
				ownerMesh, err := sfcp.NewTransport(owner, client.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer ownerMesh.Close()
				server, err := sfcp.NewTransport(node, client.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				mesh, err := sfcp.NewTransport(client.Self, client.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer mesh.Close()
				client.Mesh = mesh
				chunkBytes, partBytes := uint32(imagebuild.UploadPartBytes), imagebuild.UploadPartBytes
				if !record {
					chunkBytes, partBytes = 0, imagebuild.PartBytes
				}
				payload := bytes.Repeat([]byte{173}, partBytes)
				scope := imagebuild.UploadScope{Schema: 1, Cluster: client.Cluster, Tenant: "tenant", Context: "original-context", Upload: "original-upload", Creator: session.User, Root: nodestorage.Reference{Cluster: client.Cluster, Node: "owner", Key: owner.Public, ID: "data", Generation: 1, Path: "/srv/sfc"}, ContextRevision: 7, PolicyRevision: 9, Length: int64(len(payload)), Digest: sha256.Sum256(payload), Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20, ExpiresAt: uint64(time.Now().Add(time.Hour).Unix()), ChunkBytes: chunkBytes}
				if scope.Validate() != nil || scope.Parts() != 1 {
					t.Fatal("invalid 32 KiB fixture scope")
				}
				root := nodestorage.Root{Definition: nodestorage.Definition{Node: scope.Root.Node, Key: scope.Root.Key, ID: scope.Root.ID, Path: scope.Root.Path, Tenants: []string{scope.Tenant}}, Generation: scope.Root.Generation, Revision: 4}
				var userCalls, ownerCalls, permitCalls atomic.Int32
				finished := make(chan error, 3)
				if err = ownerMesh.On(sfcp.Management, func(ctx context.Context, conn *sfcp.Session, stream *quic.Stream, frame sfcp.Frame) error {
					serve := func() error {
						encoded, err := sfcp.Encode(frame)
						if err != nil || len(encoded) > 128<<10 || frame.Kind != sfcp.KindManagementRead || conn.Peer().Key != peer.Key || !conn.Peer().Member {
							return sfcp.ErrFrame
						}
						// Decode the actual private Management signed-envelope shape;
						// CallManagement remains its sole encoder/sender under test.
						var envelope struct {
							Caller    sfcp.Identity
							Body      json.RawMessage
							Signature []byte
							Forwarded bool
						}
						if json.Unmarshal(frame.Fields[0].Value, &envelope) != nil || envelope.Caller != peer.Key || envelope.Forwarded {
							return sfcp.ErrAdmission
						}
						digest := sha256.Sum256(envelope.Body)
						signing := append([]byte("sfc-management-1"), client.Cluster[:]...)
						signing = append(signing, envelope.Body...)
						if !bytes.Equal(frame.Fields[1].Value, digest[:]) || !ed25519.Verify(node.Public[:], signing, envelope.Signature) {
							return sfcp.ErrAdmission
						}
						request, err := schema.Decode[cluster.ManagementRequest](envelope.Body)
						if err != nil || request.Schema != 1 || request.Nonce == ([16]byte{}) || request.Command != nil || request.Key != "" {
							return sfcp.ErrFrame
						}
						call, err := schema.Decode[control.ImageBuildIOCall](request.Input)
						if err != nil || call.Tenant != scope.Tenant || !sameSession(call.Session, session) || !bytes.Equal(call.Request.Data, payload) || call.Request.Record != record || call.Request.Authorize(scope, call.Session, time.Now().Unix()) != nil {
							return sfcp.ErrAdmission
						}
						var data []byte
						if request.Method == "image-build-owner" && !request.Latest {
							ownerCalls.Add(1)
							part := imagebuild.PartReceipt{Schema: 1, Scope: scope.Hash(), Index: 0, Length: uint32(len(payload)), Digest: sha256.Sum256(payload)}
							part.Signature = ed25519.Sign(owner.Private, imagebuild.PartReceiptBytes(part))
							result := control.ImageBuildIOResult{Schema: 1, Scope: scope.Hash(), Code: "OK", Part: &part, Recorded: record}
							if record {
								result.UploadRevision = 2
							}
							data, err = json.Marshal(result)
						} else if request.Method == "image-build-io-permit" && request.Latest {
							permitCalls.Add(1)
							work := control.ImageBuildIOWork{Schema: 1, Cluster: client.Cluster, Scope: scope, Root: root, Expected: 1, Epoch: 1, Index: 12}
							if record {
								work.RootRevision = 10
							}
							data, err = json.Marshal(work)
						} else {
							return sfcp.ErrFrame
						}
						if err != nil {
							return err
						}
						reply, _ := json.Marshal(cluster.ManagementReply{Schema: 1, Code: "ok", Node: "owner", Data: data})
						return sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.Management, Kind: 2, Request: frame.Request, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: reply}, {Tag: 2, Required: true, Value: digest[:]}}})
					}()
					finished <- serve
					return serve
				}); err != nil {
					t.Fatal(err)
				}
				if err = ownerMesh.Listen("127.0.0.1:0"); err != nil {
					t.Fatal(err)
				}
				ownerPeer.Endpoint = ownerMesh.Addr().String()
				binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
				if err = server.OnManagement(sfcp.User, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
					serve := func() error {
						userCalls.Add(1)
						encoded, err := sfcp.Encode(frame)
						if err != nil || len(encoded) > 128<<10 {
							return sfcp.ErrFrame
						}
						envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
						if err != nil || envelope.Session == nil || !sameSession(*envelope.Session, session) {
							return sfcp.ErrFrame
						}
						if _, err = binding.binding(conn, frame.Kind, envelope); err != nil {
							return err
						}
						request, err := schema.Decode[Request](envelope.Body)
						if err != nil || request.Method != "build-zip-transfer" || !request.validMethodFields() || !request.validQuerySelectors() || request.ImageBuildTransfer == nil || request.ImageBuildTransfer.Authorize(scope, session, time.Now().Unix()) != nil {
							return sfcp.ErrFrame
						}
						transfer := *request.ImageBuildTransfer
						if !bytes.Equal(transfer.Data, payload) || transfer.Record != record || transfer.Proof.Record != record || (transfer.Proof.Session != nil) != record || !record && bytes.Contains(envelope.Body, []byte(`"Record"`)) {
							return sfcp.ErrFrame
						}
						if err = streamEOF(stream); err != nil {
							return err
						}
						call, _ := json.Marshal(control.ImageBuildIOCall{Session: session, Tenant: scope.Tenant, Request: transfer, At: time.Now().Unix()})
						permitReply, err := cluster.CallManagement(ctx, server, node, client.Cluster, ownerPeer, cluster.ManagementRequest{Method: "image-build-io-permit", Latest: true, Input: call})
						if err != nil {
							return err
						}
						work, err := schema.Decode[control.ImageBuildIOWork](permitReply.Data)
						if err != nil || work.Scope != scope || work.Root.Reference(client.Cluster) != scope.Root || work.Scope.PartSize() != int64(len(payload)) || work.Expected != transfer.Expected || (work.RootRevision > 0) != record {
							return sfcp.ErrFrame
						}
						ownerReply, err := cluster.CallManagement(ctx, server, node, client.Cluster, ownerPeer, cluster.ManagementRequest{Method: "image-build-owner", Input: call})
						if err != nil {
							return err
						}
						result, err := schema.Decode[control.ImageBuildIOResult](ownerReply.Data)
						if err != nil || !result.Valid(scope, transfer) {
							return sfcp.ErrFrame
						}
						return binding.respond(stream, frame, sha256.Sum256(frame.Fields[0].Value), Reply{Schema: 1, Code: "ok", ImageBuildIO: &result})
					}()
					finished <- serve
					return serve
				}); err != nil {
					t.Fatal(err)
				}
				if network == "unix" {
					path := filepath.Join(dir, "api.sock")
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
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var result control.ImageBuildIOResult
				if record {
					result, err = client.PutBuildZIPPart(ctx, peer, session, scope, 1, 0, payload, true)
				} else {
					result, err = client.PutBuildZIPPart(ctx, peer, session, scope, 1, 0, payload)
				}
				if err != nil || result.Part == nil || !result.Part.Valid(scope) || result.Recorded != record || record && result.UploadRevision != 2 || !record && result.UploadRevision != 0 || userCalls.Load() != 1 || ownerCalls.Load() != 1 || permitCalls.Load() != 1 {
					t.Fatal("full original transfer did not survive User/member owner/permit serializers", result.Code, err)
				}
				for i := 0; i < 3; i++ {
					select {
					case err := <-finished:
						if err != nil {
							t.Fatal("wire handler", err)
						}
					case <-ctx.Done():
						t.Fatal("original wire handler did not finish", ctx.Err())
					}
				}
				legacy := scope
				legacy.ChunkBytes = 0
				if _, err := client.PutBuildZIPPart(ctx, peer, session, legacy, 1, 0, bytes.Repeat([]byte{173}, imagebuild.UploadPartBytes), true); err == nil || userCalls.Load() != 1 {
					t.Fatal("larger body retargeted a legacy scope")
				}
			})
		}
	}
}
