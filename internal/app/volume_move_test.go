// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestRealVolumeMoveRecipeMemberReadBoundary(t *testing.T) {
	testRealManagedJoin(t, true, "volume-move-recipe")
}

func TestRealVolumeMoveQuorumAuthorityAndSameDB(t *testing.T) {
	testRealManagedJoin(t, true, "volume-move")
}

func verifyVolumeMoveAuthority(t *testing.T, ctx context.Context, a *Runtime, source **Runtime, cfg config.Node, client userauth.Client, session access.Session, leader sfcp.Peer, p control.Policy, submit func(string, string, uint64, any), wait func(string, func() bool), recipeOnly ...bool) {
	t.Helper()
	read := func() state.State {
		t.Helper()
		v, err := a.Engine().Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		return v.State
	}
	registry := func() control.Volumes {
		t.Helper()
		v, err := p.Volumes(read())
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	submit("move-tenant", "create-tenant", 0, control.TenantID{ID: "tenant"})
	catalog, err := p.Catalog(read())
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	submit("move-placement", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a", "node-b"}))
	scope := volumes.Scope{Cluster: p.Cluster, Tenant: "tenant", App: "app", ID: "data", Generation: 1}
	// Native facts are signed fixture INPUTS to the actual authenticated
	// management/Raft/DB boundary. No Docker/clean exit or file is asserted here.
	spec := volumes.NativeSpec{Schema: 1, Scope: scope, Node: "node-b", NodeKey: (*source).Identity.Public, Materialization: "initial", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
	raw, _ := json.Marshal(spec)
	docker := engine.Client{Owner: engine.Owner(p.Cluster, spec.NodeKey)}
	id, err := docker.Identity("volume", volumes.NativeKey(spec), reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	ready := volumes.NativeReady{Schema: 1, Spec: spec, Generation: 1, Owner: volumes.Owner{Node: spec.Node, Key: spec.NodeKey, Native: id.Name}}
	ready.Signature = ed25519.Sign((*source).Identity.Private, volumes.NativeReadyBytes(ready))
	submit("move-register-source", "create-volume", 0, ready)
	if len(recipeOnly) == 1 && recipeOnly[0] {
		peer, ok := a.Mesh.Peer(sfcp.Identity((*source).Identity.Public))
		if !ok {
			t.Fatal("installed source peer missing")
		}
		input, _ := json.Marshal(ready)
		observed, err := cluster.CallManagement(ctx, a.Mesh, a.Identity, p.Cluster, peer, cluster.ManagementRequest{Method: "volume-move-recipe-observe", Input: input})
		// Native is disabled in this actual wire fixture: routing must reach the
		// owner's unavailable adapter, rather than unsupported-method dispatch.
		if err == nil || observed.Code != "unavailable" || observed.Message != "volume observation unavailable" {
			t.Fatal("remote member recipe dispatch", observed.Code, observed.Message, err)
		}
		denied, err := cluster.CallManagement(ctx, a.Mesh, a.Identity, p.Cluster, peer, cluster.ManagementRequest{Method: "volume-move-recipe-observe", Input: input, Latest: true})
		if err == nil || denied.Code != "denied" {
			t.Fatal("recipe allowed authority-read mode", denied.Code, err)
		}
		return
	}
	core, _ := registry().Volume(scope)
	submit("move-source-reservation", "set-volume-capacity", core.Revision(), control.VolumeCapacity{Scope: scope, Native: control.VolumeNativeDigest(ready), Bytes: 128 << 10})
	for _, node := range []string{"node-a", "node-b"} {
		for _, tenant := range []string{"", "tenant"} {
			submit("move-policy-"+node+tenant, "set-volume-backup-limit", 0, control.VolumeBackupLimit{Tenant: tenant, Node: node, Bytes: 128 << 10, Count: 1, StagingBytes: 128 << 10, StagingCount: 1, Original: &control.OriginalVolumeLimit{Bytes: 256 << 10, Count: 2}})
		}
	}
	core, _ = registry().Volume(scope)
	submit("move-original-writer", "acquire-volume", core.Revision(), control.VolumeAcquire{Scope: scope, Consumer: "database", Generation: 1, Writable: true})
	core, _ = registry().Volume(scope)
	writer := core.Consumers()[0]
	target := spec
	target.Node = "node-a"
	target.NodeKey = a.Identity.Public
	target.Materialization = "m-move"
	_, ownerRevision := core.Owner()
	q := control.VolumeMoveBegin{Scope: scope, ID: "move", OwnerRevision: ownerRevision, Target: target, Compatibility: [32]byte{9}, MaxBytes: 128 << 10, MaxEntries: 16, CapacityBytes: 128 << 10, ExpiresAt: time.Now().Unix() + 300}
	submit("move-original-intent", "begin-volume-move", core.Revision(), q)
	job, move, ok := registry().Move(control.VolumeMoveSelection{Scope: scope, ID: q.ID})
	if !ok || move.Phase != volumes.Prepared {
		t.Fatal("no actual shared move")
	}
	if _, err = (*source).volumeMovePermit(ctx, job, "fence"); err == nil {
		t.Fatal("writer still held while authorizing fence")
	}
	// The original writer permit is revoked by Prepare. A preexisting pin
	// remains a retirement reference, not a reactivation grant.
	start := volumes.StartRequest{Scope: scope, Consumer: writer, Boot: [32]byte{1}, Challenge: [32]byte{2}, Sequence: 1}
	input, _ := json.Marshal(start)
	if _, err = (*source).appCall(ctx, "volume-permit", input); err == nil {
		t.Fatal("new Start escaped prepared move")
	}
	closed := volumes.Gone{Scope: scope, Consumer: writer, Stopped: true, MountsGone: true}
	closed.Signature = ed25519.Sign((*source).Identity.Private, volumes.GoneBytes(closed))
	core, _ = registry().Volume(scope)
	submit("move-writer-closed-fixture", "release-volume", core.Revision(), closed)
	permit, err := (*source).volumeMovePermit(ctx, job, "fence")
	if err != nil || permit.Move.Binding != job.Binding {
		t.Fatal("actual member quorum fence permit", err)
	}
	if _, err = a.volumeMovePermit(ctx, job, "fence"); err == nil {
		t.Fatal("target impersonated source")
	}
	input, _ = json.Marshal(control.VolumeMovePermitRequest{Selection: job.Selection(), Kind: "fence"})
	if _, err = cluster.CallManagement(ctx, (*source).Mesh, (*source).Identity, p.Cluster, leader, cluster.ManagementRequest{Method: "volume-move-permit", Input: input, Latest: false}); err == nil {
		t.Fatal("local nonbarrier permit accepted")
	}
	fence := volumes.FenceProof{Binding: job.Binding, FenceThrough: ownerRevision, Stopped: true, MountsGone: true, StartsSettled: true, Synced: true}
	fence.Signature = ed25519.Sign((*source).Identity.Private, volumes.FenceBytes(fence))
	if err = (*source).publishVolumeMoveSource(ctx, permit, "fenced", &fence); err != nil {
		t.Fatal("actual member/Raft signed fence report", err)
	}
	permit, err = (*source).volumeMovePermit(ctx, job, "read")
	if err != nil {
		t.Fatal(err)
	}
	if err = (*source).publishVolumeMoveSource(ctx, permit, "reader", nil); err != nil {
		t.Fatal("actual original reader commit", err)
	}
	permit, err = (*source).volumeMovePermit(ctx, job, "read")
	if err != nil || permit.Reader == nil {
		t.Fatal("actual original reader permit", err)
	}
	originalReader := *permit.Reader
	wait("move follower original pin", func() bool {
		v, err := (*source).Engine().Read(ctx, false)
		if err != nil {
			return false
		}
		store, err := p.Volumes(v.State)
		if err != nil {
			return false
		}
		core, ok := store.Volume(scope)
		if !ok {
			return false
		}
		r, ok := core.MoveReader(job.Binding)
		return ok && r == originalReader
	})
	if err = (*source).Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = (*source).Close(); err != nil {
		t.Fatal(err)
	}
	*source = nil
	*source, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wait("same source DB replay and current leader discovery", func() bool {
		_, leader := (*source).Engine().Leader()
		if leader == "" {
			return false
		}
		_, err := (*source).Engine().InstalledConfiguration(ctx, false)
		return err == nil
	})
	permit, err = (*source).volumeMovePermit(ctx, job, "read")
	if err != nil || permit.Reader == nil || *permit.Reader != originalReader || permit.Job.Digest() != job.Digest() {
		t.Fatal("same source DB lost original move/reader", err)
	}
	// Placement revocation stops new copy while preserving cleanup references.
	catalog, err = p.Catalog(read())
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ = catalog.Tenant("tenant")
	submit("move-revoke-target", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-b"}))
	if _, err = (*source).volumeMovePermit(ctx, job, "read"); err == nil {
		t.Fatal("revoked target copy still admitted")
	}
	core, _ = registry().Volume(scope)
	submit("move-cancel-original", "cancel-volume-move", core.Revision(), job.Selection())
	permit, err = (*source).volumeMovePermit(ctx, job, "cleanup")
	if err != nil || permit.Reader == nil || *permit.Reader != originalReader {
		t.Fatal("original cleanup lost after revoke", err)
	}
	report := control.VolumeMoveReport{Operation: "move", Schema: 1, Selection: job.Selection(), Binding: job.Digest(), Epoch: permit.Epoch, RootRevision: permit.RootRevision, Revision: permit.Revision, At: time.Now().Unix(), Kind: "reader-gone"}
	closed = volumes.Gone{Scope: scope, Consumer: originalReader, Stopped: true, MountsGone: true}
	closed.Signature = ed25519.Sign((*source).Identity.Private, volumes.GoneBytes(closed))
	report.Closed = &closed
	report.Signature = ed25519.Sign((*source).Identity.Private, control.VolumeMoveReportBytes(report))
	input, _ = json.Marshal(report)
	reply, err := (*source).appCall(ctx, "volume-move-report", input)
	if err != nil || reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		t.Fatal("original cleanup report", err)
	}
	original := reply.Committed.Result
	reply, err = (*source).appCall(ctx, "volume-move-report", input)
	if err != nil || reply.Committed == nil || reply.Committed.Result != original {
		t.Fatal("original report ACK replay changed result", err)
	}
	core, _ = registry().Volume(scope)
	if len(core.Consumers()) != 0 || registry().Quiescent() {
		t.Fatal("unknown target/staging reclaimed after source reader alone")
	}
	if err = a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	// Keep this actual wire envelope checked against the product codec.
	if _, err = schema.Decode[control.VolumeMoveReport](input); err != nil {
		t.Fatal(err)
	}
	t.Log("actual signed user operation/SFCP/N1+installed nonvoter/Raft/bbolt -> atomic move budgets/frozen original writer -> source-only latest quorum permit -> signed fence/read consumer -> source same DB/key/Snapshot -> target placement revoke/read deny -> original cancel/reader Gone and exact report ACK replay; source/target native facts are fixtures, no Docker/transfer/SQL/complete move claim")
}
