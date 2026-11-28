// SPDX-License-Identifier: Apache-2.0

package compat

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/clusterfixture"
)

// scenario runs Raft-bound actions of several kinds on c: a node joining
// and promoted (clusterfixture), a user, a workspace with servers and
// quotas, a membership and a TUN network. Add actions here as features are
// added; a bundle recorded from it keeps them (devel/design/upgrades.md 3-8).
func scenario(t *testing.T, c *clusterfixture.Cluster) {
	t.Helper()
	alice, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c.Change(0, "alice", "put-user", 0, access.User{ID: "u-alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: alice.Public, Enabled: true}}})
	c.Change(0, "shop", "create-tenant", 0, control.TenantID{ID: "shop"})
	catalog, err := c.Policy.Catalog(c.State())
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("shop")
	c.Change(0, "shop-nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("shop", tenant.AllowedNodes, []string{"node-0", "node-1"}))
	for _, scope := range []string{"", "shop"} {
		c.Change(0, "quota-node-0-"+scope, "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-0", Capacity: workload.Resources{CPU: 2e9, Memory: 1 << 30}, Networks: 2, MaxConsumers: 8, PacketQueuePackets: 64, PacketQueueBytes: 1 << 20})
	}
	c.Change(0, "alice-shop", "set-membership", 0, access.Membership{Tenant: "shop", User: "u-alice", Role: access.Manager, Enabled: true})
	resources, err := c.Policy.Resources(c.State())
	if err != nil {
		t.Fatal(err)
	}
	lan := tenancy.TUNNode{Node: "node-0", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.199.1.0/24"), Gateway: netip.MustParseAddr("10.199.1.1"), MTU: 1280}}}
	c.Change(0, "shop-lan", "create-tun-network", resources.Networks.Revision(), tenancy.TUNDefinition{Tenant: "shop", Name: "lan", Members: []tenancy.TUNNode{lan}})
}

// This build replays the scenario's whole Raft log to the state its own FSM
// checkpoint holds, and a bundle it records checks again. With
// SFC_COMPAT_RECORD=<name> the bundle is also written to testdata/<name>
// (at a release: devel/design/upgrades.md 3-8).
func TestReplayScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real sfcd nodes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := clusterfixture.New(t, ctx, 2)
	scenario(t, c)
	n := c.Nodes[0]
	if err := n.Runtime.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Replay(n.Config, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if catalog, err := c.Policy.Catalog(s); err != nil {
		t.Fatal(err)
	} else if _, ok := catalog.Tenant("shop"); !ok {
		t.Fatal("replayed state lacks the scenario")
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if name := os.Getenv("SFC_COMPAT_RECORD"); name != "" {
		dir = filepath.Join("testdata", name)
	}
	if err = Record(dir, n.Config, s); err != nil {
		t.Fatal(err)
	}
	if err = Check(dir, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SFC_COMPAT_RECORD") == "" {
		if err = os.WriteFile(filepath.Join(dir, "state.sha256"), []byte(strings.Repeat("0", 64)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err = Check(dir, t.TempDir()); err == nil {
			t.Fatal("a different recorded state passed")
		}
	}
}

// Every recorded bundle replays with this build to the recorded state.
func TestBundles(t *testing.T) {
	dirs, err := Bundles("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			if err := Check(dir, t.TempDir()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
