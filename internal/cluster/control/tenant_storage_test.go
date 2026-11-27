// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

func TestTenantStorageScopePagingAndCurrentAuthority(t *testing.T) {
	f := newNodeStorageFixture(t)
	admin := f.sessions["admin"]
	admin.Scopes[0].Actions = append(admin.Scopes[0].Actions, access.ManageMembers)
	admin.Signature = ed25519.Sign(f.node, access.SessionBytes(admin))
	f.sessions["admin"] = admin
	f.apply("admin", "create-tenant", 0, TenantID{ID: "payments"}, state.Applied)
	for i := 0; i < 10; i++ {
		f.apply("admin", "add-node-storage", 0, nodestorage.Definition{Node: "node-a", ID: fmt.Sprintf("ssd%02d", i), Path: fmt.Sprintf("/mnt/ssd%02d", i), Tenants: []string{"tenant"}}, state.Applied)
	}
	f.apply("admin", "add-node-storage", 0, nodestorage.Definition{Node: "node-a", ID: "payments-only", Path: "/mnt/payments-private", Tenants: []string{"payments"}}, state.Applied)
	page, err := f.p.TenantStoragePage(f.s, f.sessions["manager"], 2, "tenant", "", "")
	if err != nil || len(page.Items) != 8 || page.Next == "" {
		t.Fatal("first permitted page", page, err)
	}
	raw, _ := json.Marshal(page)
	if strings.Contains(string(raw), "payments") || strings.Contains(string(raw), "Tenants") || strings.Contains(string(raw), "Attestation") {
		t.Fatal("foreign ACL/native facts leaked", string(raw))
	}
	for _, row := range page.Items {
		if !row.Allowed || row.Root.Validate() != nil || row.Root.Node != row.Node || row.Root.ID != row.ID || row.Root.Generation != row.Generation {
			t.Fatal("incomplete root reference", row)
		}
	}
	next, err := f.p.TenantStoragePage(f.s, f.sessions["manager"], 2, "tenant", "", page.Next)
	if err != nil || len(next.Items) != 2 || next.Next != "" {
		t.Fatal("remaining permitted roots", next, err)
	}
	if _, _, err = f.p.NodeStoragePage(f.s, f.users, "manager", "", ""); err == nil {
		t.Fatal("tenant query widened system node-storage")
	}
	if _, err = f.p.TenantStoragePage(f.s, f.sessions["manager"], 2, "payments", "", ""); err == nil {
		t.Fatal("foreign tenant roots returned")
	}
	if _, err = f.p.TenantStoragePage(f.s, f.sessions["manager"], 2, "tenant", "foreign-node", ""); err == nil {
		t.Fatal("unassigned node accepted")
	}
	viewerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{78}, 32))
	defer clear(viewerKey)
	f.apply("admin", "put-user", 0, access.User{ID: "viewer", Username: "viewer", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(viewerKey.Public().(ed25519.PublicKey)), Enabled: true}}}, state.Applied)
	f.apply("admin", "set-membership", 0, access.Membership{Tenant: "tenant", User: "viewer", Role: access.Viewer, Enabled: true}, state.Applied)
	viewerUsers, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	viewerUser, _ := viewerUsers.User("viewer")
	viewer := f.sessions["manager"]
	viewer.User = "viewer"
	viewer.ID = "viewer-session"
	viewer.AccountRevision = viewerUser.Revision
	viewer.Key = [32]byte(viewerKey.Public().(ed25519.PublicKey))
	viewer.Signature = ed25519.Sign(f.node, access.SessionBytes(viewer))
	if _, err = f.p.TenantStoragePage(f.s, viewer, 2, "tenant", "", ""); err == nil {
		t.Fatal("viewer role obtained physical root paths")
	}
	// Account changes invalidate the old cursor, so take a new first page before
	// exercising a root-policy change against that same snapshot.
	page, err = f.p.TenantStoragePage(f.s, f.sessions["manager"], 2, "tenant", "", "")
	if err != nil {
		t.Fatal(err)
	}
	limited := f.sessions["manager"]
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	limited.Signature = ed25519.Sign(f.node, access.SessionBytes(limited))
	if _, err = f.p.TenantStoragePage(f.s, limited, 2, "tenant", "", ""); err == nil {
		t.Fatal("read-only credential obtained root paths")
	}
	root := page.Items[0]
	f.apply("admin", "drain-node-storage", root.Revision, NodeStorageSelection{Node: root.Node, ID: root.ID}, state.Applied)
	if _, err = f.p.TenantStoragePage(f.s, f.sessions["manager"], 2, "tenant", "", page.Next); err != access.ErrConflict {
		t.Fatal("mixed root revision cursor accepted", err)
	}
	current, err := f.p.TenantStoragePage(f.s, f.sessions["manager"], 2, "tenant", "node-a", "")
	if err != nil || len(current.Items) == 0 || !current.Items[0].Draining {
		t.Fatal("draining status lost", current, err)
	}
	users, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	member, _ := users.Membership("tenant", "manager")
	f.apply("admin", "set-membership", member.Revision, access.Membership{Tenant: "tenant", User: "manager", Role: access.Manager, Enabled: false}, state.Applied)
	if _, err = f.p.TenantStoragePage(f.s, f.sessions["manager"], 2, "tenant", "", ""); err == nil {
		t.Fatal("old session bypassed current membership")
	}
}

// Existing production membership/FSM and signed attestation cores. Native
// install/filesystem facts are injected; no two-node runtime success is claimed.
func TestTenantStorageSelectedReferenceFeedsBuildPolicyAndPreservesRootFences(t *testing.T) {
	f, _ := imageBuildFixture(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	defer clear(private)
	key := [32]byte(private.Public().(ed25519.PublicKey))
	peer := config.Peer{ID: "node-b", Key: hex.EncodeToString(key[:]), Endpoint: "127.0.0.1:8002"}
	directory, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	advance := func(next membership.Directory, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		directory = next
	}
	advance(directory.Invite(peer, "tenant-storage-node-b", nil))
	entry, _ := directory.Entry(peer.ID)
	advance(directory.Dispatch(peer.ID, entry.Revision, entry.Job.Pending.ID, 1, f.p.TrustRoot))
	entry, _ = directory.Entry(peer.ID)
	advance(directory.Observe(peer.ID, entry.Revision, entry.Job.Pending.ID, 4, peer))
	entry, _ = directory.Entry(peer.ID)
	ack := membership.Ack{Schema: 1, Cluster: f.p.Cluster, Node: peer.ID, JoinID: entry.JoinID, Key: key, ConfigurationIndex: 4, AppliedIndex: 5}
	ack.Signature = ed25519.Sign(private, membership.AckBytes(ack))
	advance(directory.Installed(ack, entry.Revision))
	writes, code := f.p.memberCheckpoint(f.s, directory)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.checkpoint(MembersKey, writes)
	users, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("tenant")
	f.apply("admin", "set-nodes", tenant.Revision, NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a", "node-b"}), state.Applied)
	f.apply("admin", "add-node-storage", 0, nodestorage.Definition{Node: "node-b", ID: "ssd", Path: "/mnt/ssd", Tenants: []string{"tenant"}}, state.Applied)
	roots, err := f.p.NodeStorage(f.s)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := roots.Root("node-b", "ssd")
	fact := nodestorage.RootFact{Schema: 1, Root: root.Reference(f.p.Cluster), Directory: nodestorage.Directory{Filesystem: "ext4", FilesystemPath: "/tenant-ssd", UUID: [16]byte{2}, HandleType: 1, Handle: bytes.Repeat([]byte{6}, 8), Inode: 6, DeviceMajor: 8, DeviceMinor: 2, Boot: [32]byte{2}, Namespace: [32]byte{3}, MountID: 4}}
	fact.Signature = ed25519.Sign(private, nodestorage.RootFactBytes(fact))
	f.report(NodeStorageReport{Action: "registered", Expected: root.Revision, Ready: &fact}, private, state.Applied)
	page, err := f.p.TenantStoragePage(f.s, f.sessions["manager"], 2, "tenant", "node-b", "")
	if err != nil || len(page.Items) != 1 || page.Items[0].Root.Path != "/mnt/ssd" || page.Items[0].Root.Key != key {
		t.Fatal("nonadmin root selection", page, err)
	}
	builds, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := builds.Policy("tenant")
	spec := policy.Spec.Own()
	spec.Nodes = append(spec.Nodes, imagebuild.NodeRoot{Node: "node-b", Root: page.Items[0].Root})
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: spec}, state.Applied)
	builds, err = f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ = builds.Policy("tenant")
	if len(policy.Spec.Nodes) != 2 || policy.Spec.Nodes[1].Root != page.Items[0].Root {
		t.Fatal("selected complete reference changed during save")
	}
	users, err = f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ = users.Tenant("tenant")
	f.apply("admin", "set-nodes", tenant.Revision, NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a"}), state.Applied)
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: spec}, state.Forbidden)
	users, _ = f.p.Catalog(f.s)
	tenant, _ = users.Tenant("tenant")
	f.apply("admin", "set-nodes", tenant.Revision, NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a", "node-b"}), state.Applied)
	forged := spec.Own()
	forged.Nodes[1].Root.Generation++
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: forged}, state.Forbidden)
	forged = spec.Own()
	forged.Nodes[1].Root.Path = "/mnt/foreign"
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: forged}, state.Forbidden)
	roots, _ = f.p.NodeStorage(f.s)
	root, _ = roots.Root("node-b", "ssd")
	f.apply("admin", "set-node-storage-policy", root.Revision, NodeStoragePolicy{Node: "node-b", ID: "ssd", RemoveTenants: []string{"tenant"}}, state.Applied)
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: spec}, state.Forbidden)
	roots, _ = f.p.NodeStorage(f.s)
	root, _ = roots.Root("node-b", "ssd")
	f.apply("admin", "set-node-storage-policy", root.Revision, NodeStoragePolicy{Node: "node-b", ID: "ssd", AddTenants: []string{"tenant"}}, state.Applied)
	roots, _ = f.p.NodeStorage(f.s)
	root, _ = roots.Root("node-b", "ssd")
	f.apply("admin", "drain-node-storage", root.Revision, NodeStorageSelection{Node: "node-b", ID: "ssd"}, state.Applied)
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: spec}, state.Forbidden)
}
