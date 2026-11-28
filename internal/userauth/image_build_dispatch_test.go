// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

// Every build method over the fixture's real loopback SFCP and SDK Raft: the
// session's current tenant scope decides who may read and who may prepare.
// Handler callbacks and native artifacts have separate gates.
func TestBuildMethodsActualWireKeepReadSeparateFromPreparation(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	if err := f.service.Serve(); err != nil {
		t.Fatal(err)
	}
	for !f.engines[0].IsLeader() {
		_ = f.engines[1].TransferLeadership(f.ctx, f.peers[0].ID, f.peers[0].Endpoint)
		if f.ctx.Err() != nil {
			t.Fatal(f.ctx.Err())
		}
		time.Sleep(50 * time.Millisecond)
	}
	now := uint64(time.Now().Unix())
	git := imagebuild.GitSaveRequest{Plan: imagebuild.GitSavePlan{Schema: 1, Tenant: "tenant", Context: "source", ID: "save", Creator: f.session.User, Root: nodestorage.Reference{Cluster: f.policy.Cluster, Node: "node", Key: f.nodes[0].Public, ID: "data", Generation: 1, Path: "/srv/sfc"}, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20, Commit: strings.Repeat("a", 40), Tree: [32]byte{7}, CreatedAt: now, ExpiresAt: now + 600}}
	for _, tc := range []struct {
		name string
		read bool
		run  func(access.Session, string) error
	}{
		{"image-builds", true, func(s access.Session, tenant string) error {
			_, err := call(f.ctx, f.client, f.peers[0], s, ImageBuildsMethod, ImageBuildsQuery{Tenant: tenant, Query: control.ImageBuildQuery{Part: "contexts"}})
			return err
		}},
		{"image-build-cache", true, func(s access.Session, tenant string) error {
			_, err := call(f.ctx, f.client, f.peers[0], s, ImageBuildCacheMethod, ImageBuildCacheQuery{Tenant: tenant, Query: imagebuild.CacheQuery{Job: "build-one"}})
			return err
		}},
		{"image-build-logs", true, func(s access.Session, tenant string) error {
			_, err := call(f.ctx, f.client, f.peers[0], s, ImageBuildLogsMethod, ImageBuildLogsQuery{Tenant: tenant, Query: imagebuild.LogQuery{Job: "build-one", MaxBytes: 4096}})
			return err
		}},
		{"build-context-content", true, func(s access.Session, tenant string) error {
			_, err := call(f.ctx, f.client, f.peers[0], s, BuildContextContentMethod, BuildContextContentQuery{Tenant: tenant, Query: imagebuild.ContentQuery{Version: [32]byte{1}, Part: "tree"}})
			return err
		}},
		{"image-build-job-plan", false, func(s access.Session, tenant string) error {
			_, err := call(f.ctx, f.client, f.peers[0], s, ImageBuildJobPlanMethod, ImageBuildJobPlanQuery{Tenant: tenant, Query: control.ImageBuildJobQuery{ID: "job", Context: "source", Version: [32]byte{1}}})
			return err
		}},
		{"check-build-context", false, func(s access.Session, tenant string) error {
			_, err := call(f.ctx, f.client, f.peers[0], s, CheckBuildContextMethod, CheckBuildContextQuery{Tenant: tenant, Query: control.ImageBuildSourceQuery{ID: "source"}})
			return err
		}},
		{"build-draft", false, func(s access.Session, tenant string) error {
			_, err := call(f.ctx, f.client, f.peers[0], s, BuildDraftMethod, BuildDraftQuery{Tenant: tenant, Request: imagebuild.DraftRequest{Context: "source", Kind: "plan"}})
			return err
		}},
		{"build-zip-transfer", false, func(s access.Session, tenant string) error {
			_, err := call(f.ctx, f.client, f.peers[0], s, BuildZIPTransferMethod, BuildZIPTransferQuery{Tenant: tenant, Request: imagebuild.Transfer{Upload: "original", Kind: "seal", Expected: 1}})
			return err
		}},
		{"save-build-git", false, func(s access.Session, tenant string) error {
			plan := git.Plan
			plan.Tenant = tenant
			_, err := f.client.SaveGitContext(f.ctx, f.peers[0], s, plan)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, action := range []access.Action{access.ManageRegistry, access.Read} {
				current := f.session
				current.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{action}}}
				current.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(current))
				var refused *Error
				denied := errors.As(tc.run(current, "tenant"), &refused) && refused.Code == "denied"
				if denied != (action == access.Read && !tc.read) {
					t.Fatal("current permission", action, denied)
				}
				if err := tc.run(current, "other"); !errors.As(err, &refused) || refused.Code != "denied" {
					t.Fatal("foreign tenant admitted", err)
				}
			}
		})
	}
}
