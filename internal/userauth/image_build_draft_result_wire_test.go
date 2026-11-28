// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Real Client/frame/transport binding/EOF and result-purpose proof. Native
// results and current permissions are injected, not actual Raft/FS evidence.
func TestDraftResultActualUnixAndQUICKeepsOriginalProofAndRejectsRetargetedReply(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, mode := range []string{"ok", "pending", "discarded", "changed", "freeze-ok", "freeze-pending", "freeze-discarded", "freeze-reclaimed", "freeze-changed"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				_, client, session, node := journalFixture(t)
				readFreeze := strings.HasPrefix(mode, "freeze-")
				mode = strings.TrimPrefix(mode, "freeze-")
				dir, err := os.MkdirTemp("", "sfc-draft-result-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(dir)
				peer := client.Peers[0]
				lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
					if key == sfcp.Identity(client.Self.Public) {
						return sfcp.Peer{ID: "user", Policy: sfcp.Policy{Key: key, UserAuth: true}}, true
					}
					return peer, key == peer.Key
				}
				server, err := sfcp.NewTransport(node, client.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				scope := imagebuild.DraftScope{Schema: 1, Tenant: "tenant", Context: "editable", Root: nodestorage.Reference{Cluster: client.Cluster, Node: "node", Key: node.Public, ID: "data", Generation: 1, Path: "/srv/sfc"}, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20}
				edit := imagebuild.DraftEdit{ID: "original", Kind: "mkdir", Path: "source", Expected: 1}
				now := uint64(time.Now().Unix())
				plan := imagebuild.DraftFreezePlan{Schema: 1, Scope: scope, ID: "freeze-one", Creator: session.User, Revision: 2, Draft: [32]byte{9}, CreatedAt: now - 600, ExpiresAt: now - 1}
				binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
				done := make(chan error, 1)
				if err := server.OnManagement(sfcp.User, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
					serve := func() error {
						envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
						if err != nil {
							return err
						}
						request, err := schema.Decode[Request](envelope.Body)
						var params BuildDraftQuery
						typed := err == nil && typedParams(request, BuildDraftMethod.Name, &params) && params.Tenant == scope.Tenant
						q := &params.Request
						if !typed || q.Mutation() || q.Scope == nil || *q.Scope != scope || q.Authorize(scope, session, time.Now().Unix()) != nil {
							return sfcp.ErrFrame
						}
						if readFreeze {
							if q.Kind != "freeze-result" || q.Freeze == nil || *q.Freeze != plan {
								return sfcp.ErrFrame
							}
						} else if q.Kind != "result" || q.Edit == nil || *q.Edit != edit {
							return sfcp.ErrFrame
						}
						if _, err := binding.binding(conn, frame.Kind, envelope); err != nil {
							return err
						}
						if err := streamEOF(stream); err != nil {
							return err
						}
						digest := [32]byte{7}
						out := imagebuild.DraftResponse{Schema: 1, Scope: scope, Code: "OK", Revision: 2, Digest: &digest, Edit: &imagebuild.DraftEditResult{Edit: edit.Digest(), Draft: digest, Revision: 2}}
						if readFreeze {
							archive := plan.ArchiveScope(100, [32]byte{8})
							fact := imagebuild.SealReceipt{Schema: 1, Scope: archive.Hash(), ZIP: archive.Digest, Tree: [32]byte{7}, Entries: 1, ExpandedBytes: 13}
							fact.Signature = ed25519.Sign(node.Private, imagebuild.SealReceiptBytes(fact))
							frozen := imagebuild.FrozenDraft{Schema: 1, Plan: plan, Scope: archive, Fact: fact}
							frozen.Signature = ed25519.Sign(node.Private, imagebuild.FrozenDraftBytes(frozen))
							out = imagebuild.DraftResponse{Schema: 1, Scope: scope, Code: "FROZEN", Frozen: &frozen, Reclaimed: mode == "reclaimed"}
						}
						if mode == "pending" || mode == "discarded" {
							code := "PENDING"
							if mode == "discarded" {
								code = "DISCARDED"
							}
							out = imagebuild.DraftResponse{Schema: 1, Scope: scope, Code: code}
						}
						if mode == "changed" {
							if readFreeze {
								out.Frozen.Plan.Draft[0] ^= 1
							} else {
								out.Edit.Edit = [32]byte{99}
							}
						}
						return binding.respond(stream, frame, sha256.Sum256(frame.Fields[0].Value), okReply(out))
					}()
					done <- serve
					return serve
				}); err != nil {
					t.Fatal(err)
				}
				if network == "unix" {
					path := filepath.Join(dir, "api.sock")
					if err := server.ListenUnix(path); err != nil {
						t.Fatal(err)
					}
					peer.Endpoint = "unix://" + path
				} else {
					if err := server.Listen("127.0.0.1:0"); err != nil {
						t.Fatal(err)
					}
					peer.Endpoint = server.Addr().String()
				}
				mesh, err := sfcp.NewTransport(client.Self, client.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer mesh.Close()
				client.Mesh = mesh
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var out imagebuild.DraftResponse
				want := imagebuild.DraftRequest{Context: scope.Context, Kind: "result", Scope: &scope, Edit: &edit, Proof: &imagebuild.DraftProof{Transfer: &imagebuild.DraftTransferProof{Kind: "result"}}}
				if readFreeze {
					want.Kind, want.Edit, want.Freeze = "freeze-result", nil, &plan
					want.Proof.Transfer.Kind = "freeze-result"
					out, err = client.DraftFreezeResult(ctx, peer, session, plan)
				} else {
					out, err = client.DraftEditResult(ctx, peer, session, scope, edit)
				}
				if mode == "changed" {
					if err == nil {
						t.Fatal("reply replaced original outcome", out)
					}
				} else if err != nil || !out.Valid(want) || out.Reclaimed != (mode == "reclaimed") {
					t.Fatal(out, err)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal("fixture boundary failed", err)
					}
				case <-ctx.Done():
					t.Fatal("original sender did not finish", ctx.Err())
				}
			})
		}
	}
}
