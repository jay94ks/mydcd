// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

// Exercise the actual Service.execute dispatch and current catalog/session
// ceilings. Handler callbacks, Raft and native artifacts have separate gates.
func TestBuildMethodsReachTheirRealServiceAdmissionAndKeepReadSeparateFromPreparation(t *testing.T) {
	_, client, session, issuer := journalFixture(t)
	catalog, err := access.New(client.Self.Public)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = catalog.Enroll(client.Self.Public, access.User{ID: session.User, Username: session.User, Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: client.Self.Public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = catalog.CreateTenant(session.User, "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	svc := Service{Policy: control.Policy{Cluster: client.Cluster, Issuers: [][32]byte{issuer.Public}}}
	binding := userBinding{key: session.Key, challenge: [32]byte{1}}
	now := uint64(time.Now().Unix())
	git := imagebuild.GitSaveRequest{Plan: imagebuild.GitSavePlan{Schema: 1, Tenant: "tenant", Context: "source", ID: "save", Creator: session.User, Root: nodestorage.Reference{Cluster: client.Cluster, Node: "node", Key: issuer.Public, ID: "data", Generation: 1, Path: "/srv/mydc"}, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20, Commit: strings.Repeat("a", 40), Tree: [32]byte{7}, CreatedAt: now, ExpiresAt: now + 600}}
	for _, tc := range []struct {
		q    Request
		read bool
	}{
		{Request{Method: "image-builds", Tenant: "tenant", ImageBuild: &control.ImageBuildQuery{Part: "contexts"}}, true},
		{Request{Method: "image-build-cache", Tenant: "tenant", ImageBuildCache: &imagebuild.CacheQuery{Job: "build-one"}}, true},
		{Request{Method: "image-build-logs", Tenant: "tenant", ImageBuildLog: &imagebuild.LogQuery{Job: "build-one", MaxBytes: 4096}}, true},
		{Request{Method: "build-context-content", Tenant: "tenant", ImageBuildContent: &imagebuild.ContentQuery{Version: [32]byte{1}, Part: "tree"}}, true},
		{Request{Method: "image-build-job-plan", Tenant: "tenant", ImageBuildJob: &control.ImageBuildJobQuery{ID: "job", Context: "source", Version: [32]byte{1}}}, false},
		{Request{Method: "check-build-context", Tenant: "tenant", ImageBuildSource: &control.ImageBuildSourceQuery{ID: "source"}}, false},
		{Request{Method: "build-draft", Tenant: "tenant", ImageBuildDraft: &imagebuild.DraftRequest{Context: "source", Kind: "plan"}}, false},
		{Request{Method: "build-zip-transfer", Tenant: "tenant", ImageBuildTransfer: &imagebuild.Transfer{Upload: "original", Kind: "seal", Expected: 1}}, false},
		{Request{Method: "save-build-git", Tenant: "tenant", ImageBuildGit: &git}, false},
	} {
		t.Run(tc.q.Method, func(t *testing.T) {
			for _, action := range []access.Action{access.ManageRegistry, access.Read} {
				current := session
				current.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{action}}}
				current.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(current))
				raw, err := requestBody(tc.q)
				if err != nil {
					t.Fatal(err)
				}
				envelope := Envelope{Body: raw, Session: &current, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(current, binding.challenge, raw))}
				want := "ok"
				if action == access.Read && !tc.read {
					want = "denied"
				}
				if got := svc.execute(catalog, binding, tc.q, envelope); got.Code != want {
					t.Fatal("dispatch/current permission", action, got.Code, want)
				}
				foreign := tc.q
				foreign.Tenant = "other"
				raw, err = requestBody(foreign)
				if err != nil {
					t.Fatal(err)
				}
				envelope.Body = raw
				envelope.Signature = ed25519.Sign(client.Self.Private, access.RequestBytes(current, binding.challenge, raw))
				if got := svc.execute(catalog, binding, foreign, envelope); got.Code != "denied" {
					t.Fatal("foreign tenant admitted", got.Code)
				}
			}
		})
	}
}
