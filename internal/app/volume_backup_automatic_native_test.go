// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/jay94ks/seafield/tests/enginefixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

func verifyAutomaticBackupBoundary(t *testing.T, ctx context.Context, a *Runtime, owner **Runtime, cfg config.Node, root string, admin userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), ready volumes.NativeReady, docker *engine.Client, gate *volumeUsageGate, withRestore bool, scenario volumeOwnerScenario) {
	t.Helper()
	backend := os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if backend == "" {
		t.Fatal("explicit user-prebuilt writer required")
	}
	fixture := enginefixture.OpenPrepared(t, ctx, docker.Owner, os.Getenv("SFC_DOCKER_TEST_OWNER"), []string{`USER 10001:10001`}, backend)
	registry := func() control.Volumes {
		t.Helper()
		v, e := p.Volumes(read().State)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	core, _ := registry().Volume(ready.Spec.Scope)
	change("writer", "acquire-volume", core.Revision(), control.VolumeAcquire{Scope: ready.Spec.Scope, Consumer: "database", Generation: 1, Writable: true})
	core, _ = registry().Volume(ready.Spec.Scope)
	writer := core.Consumers()[0]
	// Prepare a real standalone volume writer using the existing member
	// quorum-permit/activation contract while the Runtime/DB owner is stopped.
	// No runtime callback, source receipt, native response or backup report is
	// substituted. The normal Runtime later opens these same owner databases.
	if err := (*owner).Close(); err != nil {
		t.Fatal(err)
	}
	*owner = nil
	key, err := identity.Load(cfg.Node.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	mesh, err := sfcp.NewTransport(key, admin.Cluster, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	native, err := volumes.OpenNative(filepath.Join(cfg.Node.StateDir, "workload", "volumes.db"), docker)
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	authority := func(c context.Context, request volumes.StartRequest) (volumes.Permit, error) {
		raw, _ := json.Marshal(request)
		reply, e := cluster.CallManagement(c, mesh, key, admin.Cluster, peer, cluster.ManagementRequest{Method: "volume-permit", Input: raw, Latest: true})
		if e != nil {
			return volumes.Permit{}, e
		}
		return schema.Decode[volumes.Permit](reply.Data)
	}
	activation, err := volumes.OpenActivations(filepath.Join(cfg.Node.StateDir, "workload", "activations.db"), native, docker, admin.Cluster, key.Public, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer activation.Close()
	spec := workload.ContainerSpec{Schema: 1, Node: docker.Owner, Image: fixture.Image, Bridge: "network/bridge/tenant/app/net", BridgeGeneration: 1, IPv4: netip.MustParseAddr("10.40.0.2"), Memory: 64 << 20, NanoCPU: 100_000_000, Process: &workload.Process{ImageID: fixture.Image, User: "10001:10001", Command: []string{"/backend", "--volume-exit=clean"}}, Volumes: []workload.VolumeMount{{Scope: ready.Spec.Scope, Consumer: writer, NativeKey: volumes.NativeKey(ready.Spec), NativeGeneration: ready.Generation, Target: "/data"}}}
	raw, _ := json.Marshal(spec)
	ref := volumes.Activation{Scope: ready.Spec.Scope, Consumer: writer, NativeKey: volumes.NativeKey(ready.Spec), NativeGeneration: ready.Generation, TaskKey: "workload/task/tenant/app/database", Task: reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}, Operation: 1}
	if err = activation.Plan(ctx, ref); err != nil {
		t.Fatal(err)
	}
	id, err := docker.Identity("container", ref.TaskKey, ref.Task)
	if err != nil {
		t.Fatal(err)
	}
	created, err := docker.API.ContainerCreate(ctx, client.ContainerCreateOptions{Name: id.Name, Config: &container.Config{Image: fixture.Image, User: "10001:10001", Cmd: []string{"/backend", "--volume-exit=clean"}, Labels: id.Labels}, HostConfig: &container.HostConfig{NetworkMode: "none", Mounts: []mount.Mount{{Type: mount.TypeVolume, Source: ready.Owner.Native, Target: "/data", VolumeOptions: &mount.VolumeOptions{NoCopy: true}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = activation.Activate(ctx, ref); err != nil {
		t.Fatal("real quorum/native writer", err)
	}
	disk, err := docker.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wait := func(label string, predicate func() bool) {
		t.Helper()
		for !predicate() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	wait("actual initialized writer", func() bool {
		data, e := os.ReadFile(filepath.Join(disk.Volume.Mountpoint, "exit-marker"))
		return e == nil && string(data) == "--volume-exit=clean"
	})
	if err = activation.Retire(ctx, ref); err != nil {
		t.Fatal(err)
	}
	source, err := activation.ColdSource(ctx, ready)
	if err != nil || source.NativeID != created.ID {
		t.Fatal("actual durable source", err)
	}
	closed, err := activation.Gone(ctx, ref, key.Private)
	if err != nil {
		t.Fatal(err)
	}
	core, _ = registry().Volume(ready.Spec.Scope)
	change("writer-release", "release-volume", core.Revision(), closed)
	for _, close := range []func() error{activation.Close, native.Close, mesh.Close} {
		if err = close(); err != nil {
			t.Fatal(err)
		}
	}
	*owner, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"", ready.Spec.Scope.Tenant} {
		change("auto-limit-"+tenant, "set-volume-backup-limit", 0, control.VolumeBackupLimit{Tenant: tenant, Node: ready.Owner.Node, Bytes: 128 << 10, Count: 2})
	}
	assertLimits := func(expectedCount uint32) {
		t.Helper()
		for _, tenant := range []string{"", ready.Spec.Scope.Tenant} {
			page := readNativePublicPage(t, ctx, admin, peer, session, "volume-backup-limits", tenant, control.PublicReadQuery{Node: ready.Owner.Node})
			if len(page.Rows) != 1 || page.Rows[0].BackupLimit == nil {
				t.Fatal("actual backup limit source", page)
			}
			limit := page.Rows[0].BackupLimit
			var original control.VolumeBackupLimit
			for _, row := range registry().BackupLimits() {
				if row.Tenant == tenant && row.Node == ready.Owner.Node {
					original = row
				}
			}
			var expectedBytes uint64
			for _, job := range registry().Backups() {
				if job.Phase == "Ready" || job.Phase == "Deleting" {
					expectedBytes += job.Receipt.Bytes
				}
			}
			if limit.Revision != original.Revision || limit.Bytes != original.Bytes || limit.Count != original.Count || limit.StagingBytes != original.StagingBytes || limit.StagingCount != original.StagingCount || limit.UsedCount != expectedCount || limit.UsedBytes != expectedBytes || limit.UsedStagingCount != 0 || limit.UsedStagingBytes != 0 || !limit.GlobalPresent {
				t.Fatal("backup limit/current native reservation accounting", limit, original)
			}
		}
	}
	assertLimits(0)
	// Change through the original CAS reducer, then consume that same revision
	// in the public read. This remains a logical budget, not a disk quota.
	for _, limit := range registry().BackupLimits() {
		change("auto-limit-update-"+limit.Tenant, "set-volume-backup-limit", limit.Revision, control.VolumeBackupLimit{Tenant: limit.Tenant, Node: limit.Node, Bytes: 256 << 10, Count: 3, StagingBytes: 128 << 10, StagingCount: 1})
	}
	assertLimits(0)
	home := filepath.Join(root, "automatic-client")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "automatic-client.yaml")
	text := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", admin.Cluster, a.Identity.Public, peer.Endpoint)
	if err = os.WriteFile(profile, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	selectedTenant := ""
	cli := func(args ...string) {
		t.Helper()
		args = withTenant(selectedTenant, args)
		stdout, stderr, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), home, profile, args, nil)
		if err != nil {
			t.Fatal(args, err, string(stderr))
		}
		if bytes.Contains(stdout, []byte("retained volume usage fixture")) {
			t.Fatal("raw data in CLI")
		}
	}
	cli("wallet", "init")
	cli("login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	selectedTenant = ready.Spec.Scope.Tenant
	selection := control.VolumeBackupSelection{Scope: ready.Spec.Scope, ID: "automatic"}
	preflight, err := admin.VolumeBackupSource(ctx, peer, session, ready.Spec.Scope.Tenant, control.VolumeSelector{App: ready.Spec.Scope.App, ID: ready.Spec.Scope.ID})
	if err != nil || preflight.Source.Compatibility != backupCompatibility(source) || preflight.Source.Image != fixture.Image {
		t.Fatal("actual original source recipe", err)
	}
	if scenario == volumeOwnerBackupMount {
		verifyBackupMountBoundary(t, ctx, *owner, root, p, read, ready, preflight.Source, cli)
		return
	}
	if scenario == volumeOwnerMoveSource || scenario == volumeOwnerMoveCommit {
		verifyAutomaticMoveSource(t, ctx, a, owner, cfg, root, p, read, change, ready, preflight.Source, docker, cli, scenario == volumeOwnerMoveCommit, admin, peer, session)
		return
	}
	if scenario == volumeOwnerBackupIntentIO {
		verifyBackupIntentBoundary(t, ctx, a, owner, cfg, root, p, read, ready, cli)
		return
	}
	if scenario == volumeOwnerBackupIO {
		verifyBackupIOBoundary(t, ctx, a, owner, cfg, root, admin, peer, session, p, read, ready, cli)
		return
	}
	if _, err = admin.VolumeBackupSource(ctx, peer, session, "other", control.VolumeSelector{App: "app", ID: "data"}); err == nil {
		t.Fatal("foreign tenant source read")
	}
	readerKey, err := identity.Load(filepath.Join(root, "reader"))
	if err != nil {
		t.Fatal(err)
	}
	readerSession, err := admin.Login(ctx, peer, "reader", readerKey.Private)
	clear(readerKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := gate.arm(ready.Owner.Native)
	defer release()
	answer := make(chan error, 1)
	go func() {
		_, e := admin.VolumeBackupSource(ctx, peer, readerSession, ready.Spec.Scope.Tenant, control.VolumeSelector{App: "app", ID: "data"})
		answer <- e
	}()
	select {
	case <-entered:
	case e := <-answer:
		t.Fatal("source failed before actual Inspect", e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	membership, _ := catalog.Membership("tenant", "reader")
	change("source-revoke-reader", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: "reader", Role: access.Manager, Enabled: false})
	release()
	var denied *userauth.Error
	if e := <-answer; !errors.As(e, &denied) || denied.Code != "denied" {
		t.Fatal("revoked source observation published", e)
	}
	cli("volume", "show", "app/data")
	cli("volume", "backup", "create", "app/data", "--name", "automatic", "--max-size", "131072", "--max-entries", "16", "--id", "automatic-begin", "--no-wait")
	job := func(id string) control.VolumeBackup {
		t.Helper()
		j, ok := registry().Backup(ready.Spec.Scope, id)
		if !ok {
			t.Fatal("missing original job", id)
		}
		return j
	}
	wait("daemon autonomous Ready", func() bool { return job(selection.ID).Phase == "Ready" })
	assertLimits(1)
	cli("volume", "backup", "limits", "--node", ready.Owner.Node)
	original := job(selection.ID)
	if original.Completion == nil || original.Receipt == nil || original.Receipt.DataBytes == 0 || original.Binding.Origin.RequestID != "automatic-begin" {
		t.Fatal("missing real original completion")
	}
	local, e := (*owner).backupArtifacts.journal.Read(backupArtifactKey(original.Binding))
	if e != nil || local.State.LastID != 1 || local.State.Pending != nil || !local.State.Applied.Present {
		t.Fatal("daemon did not use original A2", e)
	}
	cli("volume", "backup", "list")
	cli("volume", "backup", "show", "app/data", "automatic")
	cli("op", "show", "automatic-begin")
	cli("op", "resume", "automatic-begin")
	if err = (*owner).Close(); err != nil {
		t.Fatal(err)
	}
	*owner, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	local, e = (*owner).backupArtifacts.journal.Read(backupArtifactKey(original.Binding))
	if e != nil || local.State.LastID != 1 || local.State.Pending != nil {
		t.Fatal("same owner DB changed original artifact operation", e)
	}
	if scenario == volumeOwnerRestoreBudget {
		verifyRestoreOriginalBudget(t, ctx, owner, cfg, docker, root, admin, peer, session, p, read, ready, original, cli)
		return
	}
	if withRestore {
		verifyAutomaticRestoreBoundary(t, ctx, a, owner, cfg, root, admin, peer, session, p, read, change, ready, docker, gate, original, cli)
		return
	}
	// A deliberately too-small accepted limit leaves the original local
	// dispatched file/copy Unknown. Recovery must not submit another copy.
	cli("volume", "backup", "create", "app/data", "--name", "small", "--max-size", "1024", "--max-entries", "16", "--id", "small-begin", "--no-wait")
	small := job("small")
	wait("original bounded copy Unknown", func() bool {
		row, e := (*owner).backupArtifacts.journal.Read(backupArtifactKey(small.Binding))
		return e == nil && row.State.Pending != nil && row.State.Pending.ID == 1 && row.State.Pending.Phase == reconcile.RecoveryRequired
	})
	if job("small").Phase != "Reserved" {
		t.Fatal("failed copy released shared reservation")
	}
	if err = (*owner).Close(); err != nil {
		t.Fatal(err)
	}
	*owner, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	local, e = (*owner).backupArtifacts.journal.Read(backupArtifactKey(small.Binding))
	if e != nil || local.State.Pending == nil || local.State.Pending.ID != 1 || local.State.LastID != 1 {
		t.Fatal("lost original copy Unknown", e)
	}
	cli("volume", "backup", "cancel", "app/data", "small", "--id", "small-cancel", "--no-wait")
	wait("daemon original cancel settlement", func() bool { return job("small").Phase == "Cancelled" })
	// A completed artifact is independent of its original source. Remove the
	// now-unreferenced exact native source BEFORE requesting artifact deletion.
	if err = (*owner).nativeVolumes.DeleteDesired(volumes.NativeKey(ready.Spec), 2, ready.Generation); err != nil {
		t.Fatal(err)
	}
	if err = (*owner).nativeVolumes.Step(ctx, volumes.NativeKey(ready.Spec)); err != nil {
		t.Fatal(err)
	}
	if gone, e := (*owner).nativeVolumes.Gone(ctx, volumes.NativeKey(ready.Spec), 2, ready.Generation); e != nil || !gone {
		t.Fatal("original source cleanup", e)
	}
	// Repeating the accepted begin still reads its original result after the
	// source is gone; it must not redo source preflight or stage a new intent.
	cli("op", "show", "automatic-begin")
	cli("volume", "backup", "delete", "app/data", "automatic", "--id", "automatic-delete", "--no-wait")
	wait("daemon artifact deletion/Gone", func() bool { return job(selection.ID).Phase == "Deleted" })
	assertLimits(0)
	cli("volume", "backup", "list")
	current := job(selection.ID)
	if current.Receipt == nil || *current.Receipt != *original.Receipt || current.Completion == nil || current.Completion.Binding != original.Binding.Digest() {
		t.Fatal("lost original completion/tombstone")
	}
	core, _ = registry().Volume(ready.Spec.Scope)
	if len(core.Consumers()) != 0 {
		t.Fatal("shared cold reader leaked")
	}
	t.Log("actual standalone original writer/quorum/exit -> actual user/member source preflight/current revocation -> dedicated CLI original begin/result/resume/status -> normal Runtime automatic A2 copy/file+directory sync/report/Ready -> same owner DB -> original bounded copy Unknown/no recopy -> CLI cancel/Cancelled -> native source explicitly removed -> original begin result after source gone -> dedicated CLI independent artifact delete/actual Gone/tombstone; independent control/native-owner Runtime instances in one test process, separate CLI, not full app/MySQL/restore/KVM")
}
