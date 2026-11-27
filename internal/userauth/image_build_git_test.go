// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
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

// Real Client/frame/binding/EOF paths; shared permission/native archive facts
// are injected and do not claim real RootManager/Raft/Git persistence.
func TestGitSaveActualUserWireKeepsUserProofAndRejectsChangedOwnerEvidence(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, mode := range []string{"saved", "pending", "changed", "missing", "result-saved", "result-reclaimed", "result-pending", "result-discarded", "result-changed"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				_, client, session, node := journalFixture(t)
				readResult := strings.HasPrefix(mode, "result-")
				mode = strings.TrimPrefix(mode, "result-")
				dir, err := os.MkdirTemp("", "sfc-git-wire-")
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
				now := uint64(time.Now().Unix())
				plan := imagebuild.GitSavePlan{Schema: 1, Tenant: "tenant", Context: "source", ID: "save-one", Creator: session.User, Root: nodestorage.Reference{Cluster: client.Cluster, Node: "node", Key: node.Public, ID: "data", Generation: 1, Path: "/srv/sfc"}, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20, Commit: strings.Repeat("a", 40), Tree: [32]byte{7}, CreatedAt: now, ExpiresAt: now + 600}
				if readResult {
					plan.CreatedAt, plan.ExpiresAt = now-600, now-1
				}
				binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
				done := make(chan error, 1)
				if err := server.OnManagement(sfcp.User, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
					serve := func() error {
						envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
						if err != nil {
							return err
						}
						request, err := schema.Decode[Request](envelope.Body)
						if err != nil || !request.validMethodFields() || !request.validQuerySelectors() || request.Method != "save-build-git" || request.ImageBuildGit == nil || request.ImageBuildGit.Plan != plan || request.ImageBuildGit.Result != readResult || request.ImageBuildGit.Authorize(session, time.Now().Unix()) != nil {
							return sfcp.ErrFrame
						}
						if _, err := binding.binding(conn, frame.Kind, envelope); err != nil {
							return err
						}
						if err := streamEOF(stream); err != nil {
							return err
						}
						scope := plan.ArchiveScope(100, [32]byte{8})
						fact := imagebuild.SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: plan.Tree, Entries: 1, ExpandedBytes: 13}
						fact.Signature = ed25519.Sign(node.Private, imagebuild.SealReceiptBytes(fact))
						saved := imagebuild.SavedGit{Schema: 1, Plan: plan, Scope: scope, Fact: fact}
						saved.Signature = ed25519.Sign(node.Private, imagebuild.SavedGitBytes(saved))
						out := imagebuild.GitSaveResponse{Schema: 1, Plan: plan.Digest(), Code: "SAVED", Saved: &saved}
						if mode == "reclaimed" {
							out.Reclaimed = true
						}
						if mode == "discarded" {
							out.Code, out.Saved = "DISCARDED", nil
						}
						if mode == "pending" {
							out.Code, out.Saved = "PENDING", nil
						}
						if mode == "missing" {
							out.Saved = nil
						}
						if mode == "changed" {
							out.Saved.Plan.Commit = strings.Repeat("b", 40)
						}
						return binding.respond(stream, frame, sha256.Sum256(frame.Fields[0].Value), Reply{Schema: 1, Code: "ok", ImageBuildGit: &out})
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
				var out imagebuild.GitSaveResponse
				if readResult {
					out, err = client.GitSaveResult(ctx, peer, session, plan)
				} else {
					out, err = client.SaveGitContext(ctx, peer, session, plan)
				}
				if mode == "saved" || mode == "pending" || mode == "discarded" || mode == "reclaimed" {
					want := "SAVED"
					if mode == "pending" {
						want = "PENDING"
					}
					if mode == "discarded" {
						want = "DISCARDED"
					}
					if err != nil || out.Code != want || out.Reclaimed != (mode == "reclaimed") {
						t.Fatal("original response", out.Code, err)
					}
				} else if err == nil {
					t.Fatal("missing/changed owner source accepted")
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal("fixture failed", err)
					}
				case <-ctx.Done():
					t.Fatal("sender did not finish", ctx.Err())
				}
			})
		}
	}
}

func TestGitSaveUserRequestCannotCarryForeignSelectors(t *testing.T) {
	_, c, s, node := journalFixture(t)
	now := uint64(time.Now().Unix())
	q := imagebuild.GitSaveRequest{Plan: imagebuild.GitSavePlan{Schema: 1, Tenant: "tenant", Context: "source", ID: "save", Creator: s.User, Root: nodestorage.Reference{Cluster: c.Cluster, Node: "node", Key: node.Public, ID: "data", Generation: 1, Path: "/srv/sfc"}, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20, Commit: strings.Repeat("a", 40), Tree: [32]byte{7}, CreatedAt: now, ExpiresAt: now + 600}}
	r := Request{Schema: 1, Method: "save-build-git", Tenant: "tenant", Nonce: [32]byte{1}, ImageBuildGit: &q}
	if !r.validMethodFields() {
		t.Fatal("valid fixed source request rejected")
	}
	for _, change := range []func(*Request){func(r *Request) { r.Method = "whoami" }, func(r *Request) { r.After = "cursor" }, func(r *Request) { r.ImageBuildGit = nil }, func(r *Request) { r.ImageBuild = &control.ImageBuildQuery{Part: "contexts"} }, func(r *Request) { r.Secret = []byte("private") }} {
		bad := r
		change(&bad)
		if bad.validMethodFields() {
			t.Fatal("mixed source selector accepted")
		}
	}
	raw, err := json.Marshal(Request{Schema: 1, Method: "whoami"})
	if err != nil || strings.Contains(string(raw), "ImageBuildGit") {
		t.Fatal("optional Git selector changed old wire shape", err)
	}
}
