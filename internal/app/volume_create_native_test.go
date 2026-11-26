// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/moby/moby/client"
)

func verifyVolumeCreateBoundary(t *testing.T, ctx context.Context, a *Runtime, owner **Runtime, cfg config.Node, root string, admin userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), scope volumes.Scope, docker *engine.Client, gate *volumeUsageGate, scenario volumeOwnerScenario) {
	cancelDispatched := scenario == volumeOwnerCreateCancel
	loseJournal := scenario == volumeOwnerCreateLostJournal
	t.Helper()
	// Producer defers run before this cleanup. Resolve ONLY original immutable
	// journal identities; use the exact journal's nonforce retirement on failure.
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		native, err := volumes.OpenNative(filepath.Join(cfg.Node.StateDir, "workload", "volumes.db"), docker)
		if err != nil {
			t.Error(err)
			return
		}
		defer native.Close()
		for _, key := range native.Keys() {
			row, err := native.View(key)
			if err != nil || !row.State.Applied.Present && row.State.Pending == nil {
				continue
			}
			if !t.Failed() {
				t.Error("product left original native volume unsettled", key)
			}
			revision := row.State.Desired.Revision
			if row.State.Desired.Present {
				revision++
			}
			if err = native.DeleteDesired(key, revision, row.State.GenerationFloor); err != nil {
				t.Error(err)
				continue
			}
			for step := 0; step < 3; step++ {
				if err = native.Step(clean, key); err != nil {
					t.Error(err)
					break
				}
				if gone, err := native.Gone(clean, key, revision, row.State.GenerationFloor); err == nil && gone {
					break
				}
			}
		}
	})
	for _, tenant := range []string{"", scope.Tenant} {
		change("create-budget-"+tenant, "set-node-quota", 0, tenancy.NodeLimit{Tenant: tenant, Node: cfg.Node.ID, MaxConsumers: 4})
	}
	home, profile := filepath.Join(root, "create-client"), filepath.Join(root, "create-client.yaml")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", admin.Cluster, a.Identity.Public, peer.Endpoint)
	if err := os.WriteFile(profile, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	selectedTenant := ""
	cli := func(want int, args ...string) map[string]any {
		t.Helper()
		args = withTenant(selectedTenant, args)
		cmd := nativeCLICmd(ctx, os.Getenv("MYDC_TEST_CLI"), home, profile, args...)
		var out, diagnostic bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diagnostic
		err := cmd.Run()
		code := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != want {
			t.Fatal("create CLI", args, code, diagnostic.String(), out.String())
		}
		var reply map[string]any
		if len(out.Bytes()) != 0 && json.Unmarshal(out.Bytes(), &reply) != nil {
			t.Fatal("CLI JSON")
		}
		return reply
	}
	registry := func() control.Volumes {
		t.Helper()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	job := func(scope volumes.Scope) control.VolumeCreation {
		t.Helper()
		j, ok := registry().Creation(scope)
		if !ok {
			t.Fatal("missing original creation")
		}
		return j
	}
	wait := func(label string, check func() bool) {
		t.Helper()
		for !check() {
			select {
			case <-ctx.Done():
				if *owner != nil {
					(*owner).mu.RLock()
					t.Log("creation controller", (*owner).volumeBackupError)
					(*owner).mu.RUnlock()
				}
				t.Fatal(label, ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	stop := func() {
		t.Helper()
		if err := (*owner).Close(); err != nil {
			t.Fatal(err)
		}
		*owner = nil
	}
	start := func() {
		t.Helper()
		var err error
		*owner, err = Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
	}
	creates := func() int { gate.mu.Lock(); defer gate.mu.Unlock(); return gate.creates }
	cli(0, "wallet", "init")
	cli(0, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	selectedTenant = scope.Tenant
	stop()
	create := func(id, request string, generation string) {
		t.Helper()
		cli(0, "--tenant", scope.Tenant, "volume", "create", scope.App+"/"+id, "--node", cfg.Node.ID, "--uid", "10001", "--gid", "10001", "--generation", generation, "--id", request, "--no-wait")
	}
	create(scope.ID, "create-original", "1")
	original := job(scope)
	if original.Phase != "Reserved" {
		t.Fatal("offline native owner already marked Ready")
	}
	inspected := cli(0, "--tenant", scope.Tenant, "volume", "show", scope.App+"/"+scope.ID)
	if row := inspected; row["Phase"] != "Reserved" || row["Owner"].(map[string]any)["Native"] != "" {
		t.Fatal("pending creation fabricated native readiness")
	}
	key := volumes.NativeKey(original.Spec)
	spec, _ := json.Marshal(original.Spec)
	identity, err := docker.Identity("volume", key, reconcile.Resource{Present: true, Generation: 1, Spec: string(spec)})
	if err != nil {
		t.Fatal(err)
	}
	inspections := 0
	entered, release := gate.armWhen(identity.Name, func() bool { inspections++; return inspections == 2 })
	defer release()
	start()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("actual Create post-effect readback", ctx.Err())
	}
	catalog, _ := p.Catalog(read().State)
	tenant, _ := catalog.Tenant(scope.Tenant)
	change("revoke-create-placement", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: scope.Tenant})
	revoked := read().State.Object(control.CatalogKey).Revision
	if cancelDispatched {
		cli(0, "--tenant", scope.Tenant, "volume", "delete", scope.App+"/"+scope.ID, "--id", "cancel-dispatched", "--no-wait")
	}
	if err = a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	stop()
	journal, err := volumes.OpenNative(filepath.Join(cfg.Node.StateDir, "workload", "volumes.db"), docker)
	if err != nil {
		t.Fatal(err)
	}
	before, err := journal.View(key)
	_ = journal.Close()
	if err != nil || before.State.Pending == nil || before.State.Pending.Kind != reconcile.Apply || creates() != 1 {
		t.Fatal("original native dispatch not retained", err, creates())
	}
	originalID := before.State.Pending.ID
	if got, err := docker.API.VolumeInspect(ctx, identity.Name, client.VolumeInspectOptions{}); err != nil || !identity.Matches(got.Volume.Name, got.Volume.Labels) {
		t.Fatal("original SDK Create did not actually execute", err)
	}
	release()
	if loseJournal {
		catalog, _ = p.Catalog(read().State)
		tenant, _ = catalog.Tenant(scope.Tenant)
		change("allow-missing-intent-probe", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: scope.Tenant, Nodes: []string{cfg.Node.ID}})
		path := filepath.Join(cfg.Node.StateDir, "workload", "volumes.db")
		backup := path + ".original"
		if err := os.Rename(path, backup); err != nil {
			t.Fatal(err)
		}
		restore := func() {
			if *owner != nil {
				stop()
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := os.Rename(backup, path); err != nil {
				t.Fatal(err)
			}
		}
		restored := false
		defer func() {
			if !restored {
				restore()
			}
		}()
		start()
		missing := func(phase string) bool {
			(*owner).mu.RLock()
			e := (*owner).volumeBackupError
			(*owner).mu.RUnlock()
			return errors.Is(e, storage.ErrMissing) && strings.Contains(e.Error(), phase)
		}
		wait("missing original intent cannot recreate or adopt", func() bool { return missing("Creating") })
		if _, err := (*owner).nativeVolumes.View(key); !errors.Is(err, storage.ErrMissing) || creates() != 1 || job(scope).Phase != "Creating" {
			t.Fatal("lost journal was silently replaced", err, creates())
		}
		cli(0, "--tenant", scope.Tenant, "volume", "delete", scope.App+"/"+scope.ID, "--id", "cancel-dispatched", "--no-wait")
		wait("missing authorized dispatch cannot claim cancellation", func() bool { return missing("Cancelling") })
		if job(scope).Phase != "Cancelling" || job(scope).Gone != nil {
			t.Fatal("missing journal falsely proved closure")
		}
		restore()
		restored = true
		cancelDispatched = true
	}
	start()
	if cancelDispatched {
		wait("original dispatched native creation retired", func() bool { return job(scope).Phase == "Cancelled" })
		after, err := (*owner).nativeVolumes.View(key)
		if err != nil || after.State.Pending != nil || after.State.Applied.Present || after.State.LastID != originalID || creates() != 1 {
			t.Fatal("cancellation replaced original Apply or recreated native data", err, creates())
		}
		if _, err := docker.API.VolumeInspect(ctx, identity.Name, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatal("cancelled original native still present", err)
		}
		proof := job(scope).Gone
		if proof == nil || proof.Verify() != nil || proof.Key != key || proof.Owner.Native != identity.Name {
			t.Fatal("original native closure proof missing")
		}
		if _, found := registry().Native(scope.Tenant, scope.App, scope.ID); found {
			t.Fatal("cancelled dispatch published a usable volume")
		}
		cli(0, "op", "show", "create-original")
		cli(0, "op", "resume", "cancel-dispatched")
		if creates() != 1 {
			t.Fatal("cancelled original retry recreated data")
		}
		t.Log("actual SDK Create/readback loss -> current placement revoke/cancel -> same owner DB/original Apply retirement/nonforce Remove -> signed Gone/Cancelled/no publication; original request results and one Create")
		return
	}
	wait("same owner sees current placement revocation", func() bool {
		v, err := (*owner).Engine().Read(ctx, false)
		return err == nil && v.State.Object(control.CatalogKey).Revision >= revoked
	})
	if job(scope).Phase != "Creating" {
		t.Fatal("revoked creation published native Ready")
	}
	catalog, _ = p.Catalog(read().State)
	tenant, _ = catalog.Tenant(scope.Tenant)
	change("restore-create-placement", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: scope.Tenant, Nodes: []string{cfg.Node.ID}})
	wait("same native Apply recovered and published", func() bool { return job(scope).Phase == "Ready" })
	after, err := (*owner).nativeVolumes.View(key)
	if err != nil || after.State.LastID != originalID || after.State.Pending != nil || creates() != 1 || job(scope).Ready.Owner.Native != identity.Name {
		t.Fatal("recovery replaced original native creation", err, creates())
	}
	cli(0, "--tenant", scope.Tenant, "volume", "usage", scope.App+"/"+scope.ID)
	cli(0, "op", "show", "create-original")
	cli(0, "op", "resume", "create-original")
	stop()
	cancelled := scope
	cancelled.ID = "cancelled"
	create(cancelled.ID, "create-cancelled", "1")
	cancelledSpec := job(cancelled).Spec
	cli(0, "--tenant", scope.Tenant, "volume", "delete", scope.App+"/"+cancelled.ID, "--id", "cancel-original", "--no-wait")
	start()
	wait("original no-dispatch cancellation", func() bool { return job(cancelled).Phase == "Cancelled" })
	if creates() != 1 {
		t.Fatal("cancel-before-dispatch created a native volume")
	}
	if _, err := (*owner).nativeVolumes.View(volumes.NativeKey(cancelledSpec)); err == nil {
		t.Fatal("cancel-before-dispatch fabricated a native journal")
	}
	cli(0, "op", "show", "cancel-original")
	cli(0, "op", "resume", "cancel-original")
	create(cancelled.ID, "create-next-generation", "2")
	next := cancelled
	next.Generation++
	wait("explicit new logical generation", func() bool { return job(next).Phase == "Ready" })
	if creates() != 2 || job(next).Spec.Materialization == cancelledSpec.Materialization {
		t.Fatal("explicit generation reused cancelled native identity")
	}
	for _, current := range []volumes.Scope{scope, next} {
		cli(0, "--tenant", scope.Tenant, "volume", "delete", current.App+"/"+current.ID, "--id", "delete-"+current.ID, "--no-wait")
		wait("original registered data explicit deletion", func() bool {
			c, ok := registry().Volume(current)
			return ok && c.Deleted()
		})
		j := job(current)
		if _, err := docker.API.VolumeInspect(ctx, j.Ready.Owner.Native, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatal("original native deletion incomplete", err)
		}
	}
	create(scope.ID, "create-original", "1") // original result only, even after native deletion
	if creates() != 2 {
		t.Fatal("original user retry recreated deleted data")
	}
	t.Log("actual create CLI -> shared reservation/Creating -> SDK effect/readback loss/current revoke -> Snapshot/same owner DB/original Apply1/one Create -> Ready/usage -> no-dispatch cancel/Gone -> explicit next generation -> existing delete/original result; no physical quota or app mount claim")
}
