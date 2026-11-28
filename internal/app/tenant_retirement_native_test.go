// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
)

// Shares the existing owned Engine/netns/native rollback fixture. The other
// tenant remains actually running while this tenant's retained data is settled.
func TestE7TenantRetirementNativeVolumeOwnerAndOtherTenant(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppTenantRetirement, true, false, true)
}
func verifyManagedTenantRetirement(t *testing.T, ctx context.Context, r *Runtime, root string, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) map[string]any {
	t.Helper()
	wait := func(label string, done func() bool) {
		t.Helper()
		for !done() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(30 * time.Millisecond):
			}
		}
	}
	before, err := r.workload.Status(ctx, deployment.ResourceKey("task", "tenant", "app", "web"))
	if err != nil || !before.Running {
		t.Fatal("other tenant's actual running Task", err)
	}
	change("retirement-create-tenant", "create-tenant", 0, control.TenantID{ID: "retirement"})
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("retirement")
	change("retirement-node", "set-nodes", tenant.Revision, control.NodeChangeTo("retirement", tenant.AllowedNodes, []string{"node-a"}))
	change("retirement-quota", "set-node-quota", 0, tenancy.NodeLimit{Tenant: "retirement", Node: "node-a", Capacity: workload.Resources{CPU: 100000000, Memory: 16 << 20}, MaxConsumers: 8})
	scope := volumes.Scope{Cluster: user.Cluster, Tenant: "retirement", App: "data", ID: "retained", Generation: 1}
	// Register rollback before the first native Volume effect. It only resumes
	// the original explicit delete, never destroys a foreign/unnamed volume.
	deletionStarted, removed := false, false
	var deleteOperation *control.UserOperation
	cleanup := func(call context.Context) error {
		if removed {
			return nil
		}
		view, err := r.Engine().Read(call, true)
		if err != nil {
			return err
		}
		v, err := p.Volumes(view.State)
		if err != nil {
			return err
		}
		volume, exists := v.Volume(scope)
		if !exists {
			return nil
		}
		if volume.Deleted() {
			removed = true
			return nil
		}
		if !deletionStarted {
			fresh := deleteOperation == nil
			if fresh {
				raw, err := control.ChangeBytes("delete-volume", session.User, volume.Revision(), scope)
				if err != nil {
					return err
				}
				var change control.Change
				if err = json.Unmarshal(raw, &change); err != nil {
					return err
				}
				op, err := user.Prepare(call, peer, session, "retirement-volume-delete", change)
				if err != nil {
					return err
				}
				deleteOperation = &op
				raw, err = json.Marshal(op)
				if err != nil {
					return err
				}
				if err = os.WriteFile(filepath.Join(root, "tenant-retirement-original-delete.json"), raw, 0600); err != nil {
					return err
				}
			}
			var reply userauth.Reply
			if fresh {
				reply, err = user.Operation(call, peer, *deleteOperation, false)
			} else {
				reply, err = user.Result(call, peer, session, *deleteOperation)
			}
			if err != nil {
				return err
			}
			if !reply.Found || reply.Result == nil || reply.Result.Code != state.Applied {
				return cluster.ErrUnknown
			}
			deletionStarted = true
		}

		for {
			view, err = r.Engine().Read(call, true)
			if err != nil {
				return err
			}
			v, err = p.Volumes(view.State)
			if err != nil {
				return err
			}
			volume, exists = v.Volume(scope)
			if !exists {
				return control.ErrCatalog
			}
			if volume.Deleted() {
				removed = true
				return nil
			}
			select {
			case <-call.Done():
				return call.Err()
			case <-time.After(30 * time.Millisecond):
			}
		}
	}
	defer func() {
		if !removed {
			clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			if err := cleanup(clean); err != nil {
				t.Error("original tenant test Volume rollback", err)
			}
		}
	}()
	change("retirement-volume-create", "begin-volume-create", 0, control.VolumeCreate{Scope: scope, Node: "node-a", UID: 10001, GID: 10001, Mode: 0700, QuotaMode: "observe"})
	var native volumes.NativeReady
	wait("actual native Volume creation", func() bool {
		v, err := p.Volumes(read().State)
		if err != nil {
			return false
		}
		var ok bool
		native, ok = v.Native(scope.Tenant, scope.App, scope.ID)
		return ok && native.Verify() == nil
	})
	if _, err := r.docker.API.VolumeInspect(ctx, native.Owner.Native, client.VolumeInspectOptions{}); err != nil {
		t.Fatal("actual Engine Volume", err)
	}
	catalog, err = p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ = catalog.Tenant("retirement")
	selection := control.TenantRetirementSelection{Tenant: tenant.ID, Operation: "retire-tenant"}
	change("retirement-begin", "begin-tenant-retirement", tenant.Revision, selection)
	status, err := user.TenantRetirement(ctx, peer, session, tenant.ID, "")
	if err != nil || status.RemainingCount == 0 || status.ClosedOwners != 0 {
		t.Fatal("retained bytes did not block owner closure", err)
	}
	var public control.TenantRetirementStatus
	catalog, _ = p.Catalog(read().State)
	if catalog.Authorize(session.User, tenant.ID, access.Deploy, "node-a") == nil {
		t.Fatal("retiring tenant accepted new work")
	}
	if err := cleanup(ctx); err != nil {
		t.Fatal("actual original Volume deletion", err)
	}
	wait("actual owner-signed tenant closure", func() bool {
		reply, err := user.TenantRetirement(ctx, peer, session, tenant.ID, "")
		if err != nil {
			return false
		}
		public = reply
		return public.RemainingCount == 0 && public.OwnerCount > 0 && public.ClosedOwners == public.OwnerCount
	})
	change("retirement-finish", "finish-tenant-retirement", public.Tenant.Revision, selection)
	reply, err := user.TenantRetirement(ctx, peer, session, tenant.ID, "")
	if err != nil || reply.Tenant.Phase != access.TenantDeleted {
		t.Fatal("tenant tombstone", err)
	}
	after, err := r.workload.Status(ctx, deployment.ResourceKey("task", "tenant", "app", "web"))
	if err != nil || !after.Ready || after.NativeID != before.NativeID || after.StartedAt != before.StartedAt {
		t.Fatal("unrelated tenant was stopped/replaced", err)
	}
	return map[string]any{"tenant": tenant.ID, "phase": "deleted", "native_volume": native.Owner.Native, "owner_reports": public.ClosedOwners, "other_tenant_native_preserved": true, "cli_status": true}
}
