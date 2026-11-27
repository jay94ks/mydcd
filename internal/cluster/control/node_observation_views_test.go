// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/observability"
)

func TestNodeObservationProjectionFiltersTenantBeforeHostAndFilesystemAggregation(t *testing.T) {
	f := newBackupCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	f.apply("observation-other-tenant", "create-tenant", 0, struct{ ID string }{"other"}, state.Applied)
	public := [32]byte(f.node.Public().(ed25519.PublicKey))
	f.apply("observation-storage-root", "add-node-storage", 0, nodestorage.Definition{Node: "node-a", Key: public, ID: "data", Path: "/srv/sfc-data", Tenants: []string{"tenant"}}, state.Applied)
	roots, err := f.p.NodeStorage(f.s)
	if err != nil {
		t.Fatal(err)
	}
	root, found := roots.Root("node-a", "data")
	if !found {
		t.Fatal("registered root")
	}
	sign := func(r observability.Report) observability.Report {
		r.Kind, r.Schema, r.Cluster, r.Node, r.Key, r.Index, r.At = "node-observation", 1, f.p.Cluster, "node-a", public, f.s.Index(), 10000
		r.Signature = ed25519.Sign(f.node, observability.SigningBytes(r))
		if !r.Valid() {
			t.Fatal("signed observation fixture", r.Source())
		}
		return r
	}
	cpu, memory := uint64(100), uint64(200)
	foreignCPU, foreignMemory := uint64(771), uint64(772)
	id := observability.FilesystemID("node-a", "same-filesystem")
	system := observability.Disk{Source: "system", ID: id, Mount: "/", Device: "/dev/system-hidden", Filesystem: "ext4", Total: 1000, Used: 500, Free: 500, Available: 400, InodesFree: 100}
	storage := system
	storage.Source, storage.RootID, storage.RootGeneration, storage.RootRevision = "root/data", "data", root.Generation, root.Revision
	reports := []observability.Report{
		sign(observability.Report{Host: &observability.Host{Version: "1", CPUCapacity: 4e9, ModuleReady: true}}),
		sign(observability.Report{Disk: &system}), sign(observability.Report{Disk: &storage}),
		sign(observability.Report{Usage: &observability.Usage{Tenant: "tenant", Containers: 1, Problems: 0, CPUUsed: &cpu, MemoryUsed: &memory, Complete: true}}),
		sign(observability.Report{Usage: &observability.Usage{Tenant: "other", Containers: 7, Problems: 2, CPUUsed: &foreignCPU, MemoryUsed: &foreignMemory, Complete: true}}),
	}
	admin, err := f.p.NodeSummary(f.s, f.session, 10, "", "", "", reports, true)
	if err != nil || len(admin.Nodes) != 1 || admin.Nodes[0].Admin == nil || len(admin.Nodes[0].Admin.Tenants) != 2 || admin.Nodes[0].Admin.DiskTotal == nil || *admin.Nodes[0].Admin.DiskTotal != 1000 {
		t.Fatal("admin full node and deduplicated disk", admin, err)
	}
	f.apply("observation-reader", "put-user", 0, access.User{ID: "reader", Username: "reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(f.admin.Public().(ed25519.PublicKey)), Enabled: true}}}, state.Applied)
	f.apply("observation-membership", "set-membership", 0, access.Membership{Tenant: "tenant", User: "reader", Role: access.Manager, Enabled: true}, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	user, _ := catalog.User("reader")
	reader := f.session
	reader.User, reader.AccountRevision = "reader", user.Revision
	reader.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read, access.ManageVolumes}}}
	reader.Signature = ed25519.Sign(f.node, access.SessionBytes(reader))
	page, err := f.p.NodeSummary(f.s, reader, 10, "tenant", "", "", reports, true)
	if err != nil || len(page.Nodes) != 1 || page.Nodes[0].Admin != nil || page.Nodes[0].Usage == nil || page.Nodes[0].Usage.Containers == nil || *page.Nodes[0].Usage.Containers != 1 {
		t.Fatal("tenant summary", page, err)
	}
	raw, _ := json.Marshal(page)
	for _, hidden := range []string{"other", "771", "772", "127.0.0.1", "Role", "Version", "Consensus", "system-hidden", "Signature"} {
		if bytes.Contains(raw, []byte(hidden)) {
			t.Fatal("tenant summary leaked unrelated metadata", hidden)
		}
	}
	disks, err := f.p.NodeDisks(f.s, reader, 10, "tenant", "node-a", "", reports)
	if err != nil || len(disks.Disks) != 1 || disks.Disks[0].Device != "" || disks.Disks[0].Mount != "/srv/sfc-data" || len(disks.Disks[0].Purposes) != 1 || disks.Disks[0].Purposes[0] != "storage-root" {
		t.Fatal("tenant disk source filtering happened after grouping", disks, err)
	}
	if _, err := f.p.NodeSummary(f.s, reader, 10, "tenant", "hidden-node", "", reports, true); !errors.Is(err, access.ErrDenied) {
		t.Fatal("hidden node existence", err)
	}
	if _, err := f.p.NodeSummary(f.s, reader, 10, "", "", "", reports, true); !errors.Is(err, access.ErrDenied) {
		t.Fatal("tenant acquired full system summary", err)
	}
	stale, err := f.p.NodeSummary(f.s, reader, 131, "tenant", "", "", reports, true)
	if err != nil || !stale.Nodes[0].Stale || stale.Nodes[0].Ready || stale.Nodes[0].Usage == nil || !stale.Nodes[0].Usage.Stale || stale.Nodes[0].Usage.Containers == nil {
		t.Fatal("stale sample lost last known fact or became Ready", stale, err)
	}
	unknown, err := f.p.NodeSummary(f.s, reader, 10, "tenant", "", "", nil, true)
	if err != nil || unknown.Nodes[0].Ready || unknown.Nodes[0].Usage.Containers != nil {
		t.Fatal("missing sample fabricated zero/Ready", unknown, err)
	}
}

func TestNodeBuildCapabilityComesFromAFreshHostReport(t *testing.T) {
	f := newBackupCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	public := [32]byte(f.node.Public().(ed25519.PublicKey))
	host := func(build *observability.Build) []observability.Report {
		r := observability.Report{Kind: "node-observation", Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Key: public, Index: f.s.Index(), At: 10000, Host: &observability.Host{Version: "1", CPUCapacity: 4e9, ModuleReady: true, Build: build}}
		r.Signature = ed25519.Sign(f.node, observability.SigningBytes(r))
		if !r.Valid() {
			t.Fatal("signed host fixture")
		}
		return []observability.Report{r}
	}
	for _, c := range []struct {
		reports []observability.Report
		at      int64
		want    NodeBuildView
		refused bool
	}{
		{host(&observability.Build{Enabled: true}), 10, NodeBuildView{Enabled: true}, false},
		{host(&observability.Build{Reason: "ENGINE_BUILD_OFF"}), 10, NodeBuildView{Reason: "ENGINE_BUILD_OFF"}, true},
		{host(&observability.Build{Reason: "ENGINE_BUILD_OFF"}), 131, NodeBuildView{Reason: "UNKNOWN"}, false}, // stale
		{host(nil), 10, NodeBuildView{Reason: "UNKNOWN"}, false},
		{nil, 10, NodeBuildView{Reason: "UNKNOWN"}, false},
	} {
		page, err := f.p.NodeSummary(f.s, f.session, c.at, "", "", "", c.reports, true)
		if err != nil || len(page.Nodes) != 1 || page.Nodes[0].Build != c.want {
			t.Fatal("build view", c.want, page, err)
		}
		if err := f.p.CheckBuildNode(f.s, "node-a", c.reports, c.at); errors.Is(err, ErrBuildDisabled) != c.refused {
			t.Fatal("build node check", c.want, err)
		}
	}
	for _, bad := range []observability.Build{{Enabled: true, Reason: "WORKLOAD_OFF"}, {Reason: "elsewhere"}, {}} {
		r := host(&observability.Build{Enabled: true})[0]
		r.Host.Build = &bad
		if r.Valid() {
			t.Fatal("an invalid build fact passed", bad)
		}
	}
}
