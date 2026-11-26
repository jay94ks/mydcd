// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestActivationBatchFixedTenantScopeUsesActualAppTask(t *testing.T) {
	cluster, node := [32]byte{1}, [32]byte{2}
	task := reconcile.Resource{Present: true, Generation: 7, Spec: "original-public-task"}
	managed := Activation{Scope: Scope{Cluster: cluster, Tenant: "tenant", App: "app", ID: "logs", Generation: 1}, Consumer: Consumer{ID: "logs", Generation: 7, Lease: reconcile.Lease{Generation: 1, Token: 1}, Owner: Owner{Node: "node-a", Key: node, Native: "original-managed"}, OwnerRevision: 1}, NativeKey: "volume/tenant/app/logs/initial", NativeGeneration: 1, TaskKey: "workload/task/tenant/app/database", Task: task, Operation: 1}
	fixed := managed
	fixed.Scope.App = ""
	fixed.Scope.ID = "data"
	fixed.Scope.Generation = 3
	fixed.NativeKey = FixedNativeKey(fixed.Scope)
	fixed.NativeGeneration = 3
	fixed.NativeBinding = strings.Repeat("a", 64)
	fixed.Consumer.ID = "data"
	fixed.Consumer.Writable = true
	fixed.Consumer.Lease.Generation = 3
	fixed.Consumer.Owner.Native = FixedNativeName(fixed.Scope)
	if _, err := activationBatch([]Activation{managed, fixed}); err != nil {
		t.Fatal("real app Task cannot mix managed and tenant fixed references", err)
	}
	for _, change := range []func(*Activation){func(r *Activation) { r.TaskKey = "workload/task/tenant//database" }, func(r *Activation) { r.TaskKey = "workload/task/other/app/database" }, func(r *Activation) { r.NativeGeneration++ }, func(r *Activation) { r.Consumer.Owner.Native = "foreign" }, func(r *Activation) { r.TaskKey = "workload/task/tenant/another-app/database" }} {
		bad := fixed
		change(&bad)
		if _, err := activationBatch([]Activation{managed, bad}); err == nil {
			t.Fatal("missing/foreign Task or fixed source identity accepted")
		}
	}
}
