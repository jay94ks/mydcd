// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// a tenant manager (not a system admin) adds a storage root from
// tenant-storage to the build policy; a root of another tenant, or one
// being drained, is refused.
func TestBuildPolicyTenantStorageRoot(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	rows, err := alice.TenantStoragePage(ctx, "shop", "", "")
	if err != nil || len(rows.Items) != 1 || rows.Items[0].Root.Validate() != nil || rows.Items[0].Root.Path != "/srv/mydc-ssd" {
		t.Fatalf("tenant-storage %+v %v", rows.Items, err)
	}
	ssd := rows.Items[0].Root
	put := func(roots ...imagebuild.NodeRoot) ResultCode {
		t.Helper()
		cur, _ := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "policy"}, "")
		p := control.ImageBuildPolicyPut{Spec: cur.Policies[0].Spec.Own()}
		p.Spec.Nodes = append(p.Spec.Nodes, roots...)
		_, res := submit(t, alice, ActionSetImageBuildPolicy, cur.Policies[0].Revision, p, rootFor(t, alice, ActionSetImageBuildPolicy))
		return res.Code
	}
	payments := f.w.storageRef(f.w.nodeStorage[1]) // node-c/hdd, payments only
	if code := put(imagebuild.NodeRoot{Node: "node-c", Root: payments}); code != ResultInvalid {
		t.Fatalf("another tenant's root: %v", code)
	}
	f.mu.Lock()
	f.w.nodeStorage[0].Draining = true
	f.mu.Unlock()
	if code := put(imagebuild.NodeRoot{Node: "node-b", Root: ssd}); code != ResultInvalid {
		t.Fatalf("draining root: %v", code)
	}
	f.mu.Lock()
	f.w.nodeStorage[0].Draining = false
	f.mu.Unlock()
	if code := put(imagebuild.NodeRoot{Node: "node-b", Root: ssd}); code != ResultApplied {
		t.Fatalf("add node-b ssd: %v", code)
	}
	cur, _ := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "policy"}, "")
	if n := cur.Policies[0].Spec.Nodes; len(n) != 2 || n[1].Root != ssd {
		t.Fatalf("policy nodes %+v", n)
	}
}
