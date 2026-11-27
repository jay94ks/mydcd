// SPDX-License-Identifier: Apache-2.0

package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/moby/moby/client"
)

// Real RootManager/native DB and native ext4 identity. Quorum is injected and
// any Docker HTTP is forbidden: these cases exercise only original root I/O.
func TestImageBuildRootAdapterRecoversBorrowAndReturnWithoutNewLease(t *testing.T) {
	for _, mode := range []string{"normal", "lost-return-ack", "missing-known-lease", "cache-retirement", "cache-retirement-lost-return-ack", "cache-retirement-missing-known-lease", "input-census", "git-stage-retirement", "generated-retirement-unborrowed"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
			public := [32]byte(private.Public().(ed25519.PublicKey))
			cluster := [32]byte{2}
			root := nodestorage.Root{Definition: nodestorage.Definition{Node: "node-a", Key: public, ID: "data", Path: t.TempDir(), Tenants: []string{"tenant-a", "tenant-b"}}, Generation: 1, Revision: 1}
			handle, err := nodestorage.OpenDirectory(root.Definition.Path)
			if errors.Is(err, nodestorage.ErrUnsupported) {
				t.Skip("host lacks required native ext4 identity")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := handle.Close(); err != nil {
				t.Fatal(err)
			}
			roots, err := nodestorage.OpenRoots(filepath.Join(t.TempDir(), "roots.db"), cluster, "node-a", private)
			if err != nil {
				t.Fatal(err)
			}
			defer roots.Close()
			if err := roots.Desired(root); err != nil {
				t.Fatal(err)
			}
			if err := roots.Step(ctx, nodestorage.RootNativeKey(root.Reference(cluster))); err != nil {
				t.Fatal(err)
			}
			ref := root.Reference(cluster)
			scope := imagebuild.UploadScope{Schema: 1, Cluster: cluster, Tenant: "tenant-a", Context: "source", Upload: "upload-one", Creator: "alice", Root: ref, ContextRevision: 1, PolicyRevision: 1, Length: 10, Digest: sha256.Sum256([]byte("original")), Dockerfile: "Dockerfile", ExpandedLimit: 1 << 30, ExpiresAt: 1000}
			seal := imagebuild.SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: [32]byte{1}, Entries: 1, ExpandedBytes: 1}
			seal.Signature = ed25519.Sign(private, imagebuild.SealReceiptBytes(seal))
			policy := imagebuild.Policy{Schema: 1, Tenant: scope.Tenant, Nodes: []imagebuild.NodeRoot{{Node: "node-a", Root: ref}}, Concurrency: 1, Seconds: 600, CPUMillis: 1000, MemoryBytes: 128 << 20, WorkspaceBytes: 1 << 30, CacheBytes: 1 << 30, Registry: "private", Platforms: []string{"linux/amd64"}, BuilderImage: "docker.io/moby/buildkit@sha256:" + strings.Repeat("a", 64), Cleanup: imagebuild.CleanupPolicy{HighWaterPercent: 80, UnusedDays: 7}}
			spec := imagebuild.JobSpec{Schema: 1, Cluster: cluster, Tenant: scope.Tenant, ID: "build-one", Version: imagebuild.VersionID(seal), Number: 1, Scope: scope, Seal: seal, Context: imagebuild.ContextSpec{Tenant: scope.Tenant, ID: scope.Context, Kind: "upload", Root: ref, Dockerfile: scope.Dockerfile, Repository: "team/app", Tags: []string{"latest"}, Platforms: []string{"linux/amd64"}}, Policy: policy, ContextRevision: 1, PolicyRevision: 1, RegistryAuthority: "registry.example", RegistryGeneration: 1, RegistrySpec: [32]byte{3}, CreatedAt: 100}
			run, err := imagebuild.NewJob(spec)
			if err != nil {
				t.Fatal(err)
			}
			grant := imagebuild.NativeGrant{Run: run, Index: 1, Epoch: 1, Allowed: true}
			db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			api, err := client.New(client.WithHost("unix:///nonexistent-sfc-build.sock"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: checkerBuilderNoHTTP{t}}))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			native, err := imagebuild.OpenNativeJobs(db, &engine.Client{API: api, Owner: engine.Owner(cluster, public)}, func(context.Context, imagebuild.JobSpec, bool) (imagebuild.NativeGrant, error) { return grant, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := native.Accept(grant); err != nil {
				t.Fatal(err)
			}
			r := &Runtime{nodeRoots: roots}
			// Explicitly reserve the archive slot: the configured three consumers
			// must cover archive, job and cache; product capacity is not raised.
			archive, err := roots.Pin(ctx, root, "imagebuild/archive")
			if err != nil {
				t.Fatal(err)
			}
			if err := archive.Directory.Close(); err != nil {
				t.Fatal(err)
			}
			for _, use := range []imagebuild.RootUse{imagebuild.JobRoot, imagebuild.CacheRoot} {
				if err := native.PlanRootHold(ctx, spec, use); err != nil {
					t.Fatal(err)
				}
				consumer, err := native.RootConsumer(spec, use)
				if err != nil {
					t.Fatal(err)
				}
				original, err := roots.Pin(ctx, root, consumer)
				if err != nil {
					t.Fatal(err)
				}
				if err := original.Directory.Close(); err != nil {
					t.Fatal(err)
				}
				// Simulate Borrow committed but its native acknowledgement lost.
				opened, err := r.openImageBuildRoot(ctx, native, spec, use)
				if err != nil || opened.Lease != original.Lease || opened.Directory == nil {
					t.Fatal("replacement borrow", opened, err)
				}
				if err := opened.Directory.Close(); err != nil {
					t.Fatal(err)
				}
			}
			consumer, _ := native.RootConsumer(spec, imagebuild.JobRoot)
			pin, held, err := roots.RecordedPin(ref, consumer)
			if err != nil || !held {
				t.Fatal(held, err)
			}
			if err := native.ObserveExit(ctx, spec, true); err != nil {
				t.Fatal(err)
			}
			if mode == "lost-return-ack" {
				if err := native.BeginRootReturn(spec, imagebuild.JobRoot); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "lost-return-ack" || mode == "missing-known-lease" {
				if err := roots.Return(pin); err != nil {
					t.Fatal(err)
				}
			}
			err = r.returnImageBuildRoot(native, spec)
			if mode == "missing-known-lease" {
				if !errors.Is(err, imagebuild.ErrStorage) {
					t.Fatal("missing original pin accepted without return intent", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := r.returnImageBuildRoot(native, spec); err != nil {
				t.Fatal("return not idempotent", err)
			}
			if _, held, err := roots.RecordedPin(ref, consumer); err != nil || held {
				t.Fatal("job root retained", held, err)
			}
			cacheConsumer, _ := native.RootConsumer(spec, imagebuild.CacheRoot)
			if _, held, err := roots.RecordedPin(ref, cacheConsumer); err != nil || !held {
				t.Fatal("cache root prematurely returned", held, err)
			}
			if _, err := native.SealCompletion(grant, imagebuild.JobResult{Code: "BUILD_FAILED"}, 103, private); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(mode, "cache-retirement") {
				retirement := imagebuild.NativeCacheRetirementGrant{Source: spec, Operation: "retire-tenant", InventoryHash: [32]byte{2}, OwnersHash: [32]byte{3}, StartedRevision: 1, Index: 10, Epoch: 1}
				cachePin, held, err := roots.RecordedPin(ref, cacheConsumer)
				if err != nil || !held {
					t.Fatal(held, err)
				}
				if mode == "cache-retirement-lost-return-ack" {
					opened, err := roots.OpenRecordedPin(ref, cacheConsumer)
					if err != nil {
						t.Fatal(err)
					}
					err = native.RetireTenantCache(ctx, retirement, opened.Lease, opened.Directory.FD())
					closeErr := opened.Directory.Close()
					if err != nil || closeErr != nil {
						t.Fatal(err, closeErr)
					}
				}
				if mode != "cache-retirement" {
					if err := roots.Return(cachePin); err != nil {
						t.Fatal(err)
					}
				}
				err = r.retireImageBuildCache(ctx, native, retirement)
				if mode == "cache-retirement-missing-known-lease" {
					if !errors.Is(err, imagebuild.ErrStorage) {
						t.Fatal("missing cache lease accepted without unlink/return intent", err)
					}
					return
				}
				if err != nil {
					t.Fatal("original cache root return failed", err)
				}
				if err := r.retireImageBuildCache(ctx, native, retirement); err != nil {
					t.Fatal("cache root return was not idempotent", err)
				}
				if _, held, err := roots.RecordedPin(ref, cacheConsumer); err != nil || held {
					t.Fatal("retired cache root still held", held, err)
				}
				if _, held, err := roots.RecordedPin(ref, "imagebuild/archive"); err != nil || !held {
					t.Fatal("cache return released another root consumer", held, err)
				}
			}
			if mode == "input-census" {
				if err := roots.Return(archive); err != nil {
					t.Fatal(err)
				}
				r.reports = db
				var inputPins []nodestorage.RootPin
				for _, tenant := range []string{"tenant-a", "tenant-b"} {
					draftScope := imagebuild.DraftScope{Schema: 1, Tenant: tenant, Context: "editable", Root: ref, ContextRevision: 1, PolicyRevision: 1, Generation: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20}
					pin, err := roots.Pin(ctx, root, imagebuild.DraftRootConsumer(draftScope))
					if err != nil {
						t.Fatal(err)
					}
					spool, err := imagebuild.OpenSpool(pin.Directory.FD(), ref, db)
					if err != nil {
						t.Fatal(err)
					}
					store, err := imagebuild.OpenDraftStore(spool, draftScope, true)
					if err != nil {
						t.Fatal(err)
					}
					if err := store.Close(); err != nil {
						t.Fatal(err)
					}
					if err := spool.Close(); err != nil {
						t.Fatal(err)
					}
					if err := pin.Directory.Close(); err != nil {
						t.Fatal(err)
					}
					inputPins = append(inputPins, pin)
				}
				for _, tenant := range []string{"tenant-a", "tenant-b"} {
					if activity, err := r.tenantImageBuildInputActivity(tenant); err != nil || activity.Leases != 1 {
						t.Fatal("input pin omitted or attributed to another tenant", tenant, activity, err)
					}
				}
				if activity, err := r.tenantImageBuildInputActivity("other"); err != nil || !activity.Empty() {
					t.Fatal("other tenant's known pins counted", activity, err)
				}
				if err := roots.Return(inputPins[1]); err != nil {
					t.Fatal(err)
				}
				unknown, err := roots.Pin(ctx, root, "imagebuild-draft/"+strings.Repeat("f", 64))
				if err != nil {
					t.Fatal(err)
				}
				if err := unknown.Directory.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := r.tenantImageBuildInputActivity("other"); !errors.Is(err, imagebuild.ErrStorage) {
					t.Fatal("unattributed original pin became an empty census", err)
				}
				if err := roots.Return(unknown); err != nil {
					t.Fatal(err)
				}
				if _, err := r.tenantImageBuildInputActivity("tenant-b"); !errors.Is(err, imagebuild.ErrStorage) {
					t.Fatal("lost required draft lease became an empty census", err)
				}
				if activity, err := r.tenantImageBuildInputActivity("tenant-a"); err != nil || activity.Leases != 1 {
					t.Fatal("another tenant's known missing dependency changed this tenant", activity, err)
				}
				// Inject only the committed lifetime fence. Actual native files,
				// DB and RootManager Return/ack recovery use product adapters.
				scope := imagebuild.DraftScope{Schema: 1, Tenant: "tenant-a", Context: "editable", Root: ref, ContextRevision: 1, PolicyRevision: 1, Generation: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20}
				grant := imagebuild.DraftRetirementGrant{Scope: scope, ContextRevision: 2, Generation: 1, Deleted: true, Index: 10, Epoch: 1}
				opened, err := roots.OpenRecordedPin(ref, imagebuild.DraftRootConsumer(scope))
				if err != nil {
					t.Fatal(err)
				}
				spool, err := imagebuild.OpenExistingSpool(opened.Directory.FD(), ref, db)
				if err != nil {
					t.Fatal(err)
				}
				if err := spool.RetireDraft(ctx, grant, inputPins[0].Lease); err != nil {
					t.Fatal(err)
				}
				if err := errors.Join(spool.Close(), opened.Directory.Close(), roots.Return(inputPins[0])); err != nil {
					t.Fatal(err)
				}
				if activity, err := r.tenantImageBuildInputActivity("tenant-a"); err != nil || activity.Leases != 1 {
					t.Fatal("native acknowledgement loss became empty termination census", activity, err)
				}
				if err := r.retireImageBuildDraft(ctx, grant); err != nil {
					t.Fatal("original Return could not be settled without reopening deleted data", err)
				}
				if activity, err := r.tenantImageBuildInputActivity("tenant-a"); err != nil || !activity.Empty() {
					t.Fatal("settled original lifetime still counted", activity, err)
				}
				if _, held, err := roots.RecordedPin(ref, cacheConsumer); err != nil || !held {
					t.Fatal("draft closure returned independent native cache", held, err)
				}
			}
			if mode == "git-stage-retirement" || mode == "generated-retirement-unborrowed" {
				if err := roots.Return(archive); err != nil {
					t.Fatal(err)
				}
				r.reports, r.Identity = db, &identity.Identity{Private: private, Public: public}
				var body bytes.Buffer
				writer := zip.NewWriter(&body)
				file, err := writer.Create("Dockerfile")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(file, "FROM scratch\n"); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				tree, err := imagebuild.InspectZIP(ctx, bytes.NewReader(body.Bytes()), int64(body.Len()), "Dockerfile", 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				plan := imagebuild.GitSavePlan{Schema: 1, Tenant: "tenant-a", Context: "git-source", ID: "save-one", Creator: "alice", Root: ref, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20, Commit: strings.Repeat("a", 40), Tree: tree.Digest(), CreatedAt: 100, ExpiresAt: 1000}
				stage, err := roots.Pin(ctx, root, imagebuild.GitRootConsumer(plan))
				if err != nil {
					t.Fatal(err)
				}
				spool, err := imagebuild.OpenSpool(stage.Directory.FD(), ref, db)
				if err != nil {
					t.Fatal(err)
				}
				scope, err := spool.PrepareGit(ctx, plan, func(w io.Writer) (imagebuild.Tree, error) { _, err := w.Write(body.Bytes()); return tree, err })
				if err != nil {
					t.Fatal(err)
				}
				if mode == "generated-retirement-unborrowed" {
					if err := errors.Join(spool.Close(), stage.Directory.Close()); err != nil {
						t.Fatal(err)
					}
					g := imagebuild.GeneratedArchiveGrant{Artifact: imagebuild.GeneratedArtifact{Scope: scope, Git: &plan}, ContextRevision: 1, PolicyRevision: 2, Index: 11, Epoch: 1}
					if err := r.reclaimImageBuildGenerated(ctx, g); err != nil {
						t.Fatal("prepared archive could not retire through original stage pin", err)
					}
					if _, held, err := roots.RecordedPin(ref, imagebuild.ArtifactRootConsumer(scope)); err != nil || held {
						t.Fatal("cleanup allocated an archive lease", held, err)
					}
					if activity, err := r.tenantImageBuildInputActivity(plan.Tenant); err != nil || activity.Leases != 1 {
						t.Fatal("archive cleanup returned independent stage", activity, err)
					}
					if err := r.retireImageBuildGitStage(ctx, imagebuild.GitStageGrant{Plan: plan, ContextRevision: 1, PolicyRevision: 2, Index: 11, Epoch: 1}); err != nil {
						t.Fatal(err)
					}
					if activity, err := r.tenantImageBuildInputActivity(plan.Tenant); err != nil || !activity.Empty() {
						t.Fatal("original inputs not settled", activity, err)
					}
					if _, held, err := roots.RecordedPin(ref, cacheConsumer); err != nil || !held {
						t.Fatal("input cleanup returned native cache", held, err)
					}
					return
				}
				artifact, err := roots.Pin(ctx, root, imagebuild.ArtifactRootConsumer(scope))
				if err != nil {
					t.Fatal(err)
				}
				saved, err := spool.AdoptGit(ctx, plan, private)
				if err != nil {
					t.Fatal(err)
				}
				grant := imagebuild.GitStageGrant{Plan: plan, ContextRevision: 1, PolicyRevision: 1, Index: 10, Epoch: 1}
				if err := spool.RetireGitStage(ctx, grant, stage.Lease); err != nil {
					t.Fatal(err)
				}
				if err := errors.Join(spool.Close(), stage.Directory.Close(), artifact.Directory.Close(), roots.Return(stage)); err != nil {
					t.Fatal(err)
				}
				if activity, err := r.tenantImageBuildInputActivity(plan.Tenant); err != nil || activity.Leases != 2 {
					t.Fatal("lost native Return ack omitted from census", activity, err)
				}
				if err := r.retireImageBuildGitStage(ctx, grant); err != nil {
					t.Fatal(err)
				}
				if activity, err := r.tenantImageBuildInputActivity(plan.Tenant); err != nil || activity.Leases != 1 {
					t.Fatal("stage settlement lost independent archive", activity, err)
				}
				// Inject the authorization boundary only. Actual replay uses the
				// Runtime owner method, native archive and exact RootManager pin.
				current := func() (control.ImageBuildGitWork, error) {
					return control.ImageBuildGitWork{Read: control.ImageBuildSourceRead{Epoch: 1}, Root: root}, nil
				}
				out, fetch, err := r.writeImageBuildGit(ctx, control.ImageBuildGitCall{Tenant: plan.Tenant, Request: imagebuild.GitSaveRequest{Plan: plan}}, current, nil)
				if err != nil || fetch || out.Saved == nil || string(imagebuild.SavedGitBytes(*out.Saved)) != string(imagebuild.SavedGitBytes(saved)) {
					t.Fatal("returned stage did not replay original archive", out, fetch, err)
				}
				if _, held, err := roots.RecordedPin(ref, imagebuild.GitRootConsumer(plan)); err != nil || held {
					t.Fatal("replay allocated replacement stage", held, err)
				}
				for _, consumer := range []string{imagebuild.ArtifactRootConsumer(scope), cacheConsumer} {
					if _, held, err := roots.RecordedPin(ref, consumer); err != nil || !held {
						t.Fatal("stage Return released another consumer", consumer, held, err)
					}
				}
				// Native deletion and actual root Return commit, then the native
				// acknowledgement is deliberately left pending for Runtime recovery.
				a := imagebuild.GeneratedArtifact{Scope: scope, Git: &plan}
				g := imagebuild.GeneratedArchiveGrant{Artifact: a, ContextRevision: 1, PolicyRevision: 2, Index: 11, Epoch: 1}
				opened, err := roots.OpenRecordedPin(ref, imagebuild.ArtifactRootConsumer(scope))
				if err != nil {
					t.Fatal(err)
				}
				spool, err = imagebuild.OpenExistingSpool(opened.Directory.FD(), ref, db)
				if err != nil {
					t.Fatal(err)
				}
				if err := spool.ReclaimGenerated(ctx, g, artifact.Lease); err != nil {
					t.Fatal(err)
				}
				if err := errors.Join(spool.Close(), opened.Directory.Close(), roots.Return(artifact)); err != nil {
					t.Fatal(err)
				}
				if activity, err := r.tenantImageBuildInputActivity(plan.Tenant); err != nil || activity.Leases != 1 {
					t.Fatal("unsettled archive Return became empty census", activity, err)
				}
				if err := r.reclaimImageBuildGenerated(ctx, g); err != nil {
					t.Fatal("original archive Return could not settle without stage/data reopening", err)
				}
				if activity, err := r.tenantImageBuildInputActivity(plan.Tenant); err != nil || !activity.Empty() {
					t.Fatal("settled original archive retained input activity", activity, err)
				}
				if _, held, err := roots.RecordedPin(ref, cacheConsumer); err != nil || !held {
					t.Fatal("artifact Return released cache", held, err)
				}
				// Current user/quorum work is injected. The actual Runtime result
				// path must not need a root manager/fetcher after physical closure.
				r.ctx, r.nodeRoots = ctx, nil
				resultCall := control.ImageBuildGitCall{Tenant: plan.Tenant, Request: imagebuild.GitSaveRequest{Plan: plan, Result: true, Proof: imagebuild.GitSaveProof{Result: true}}}
				result, err := r.saveImageBuildGitOwnerWork(ctx, resultCall, current)
				if err != nil || result.Code != "SAVED" || !result.Reclaimed || result.Saved == nil || string(imagebuild.SavedGitBytes(*result.Saved)) != string(imagebuild.SavedGitBytes(saved)) {
					t.Fatal("Runtime historical read required files/pins/fetch or lost original result", result, err)
				}
			}
		})
	}
}
