// SPDX-License-Identifier: Apache-2.0

package compat

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/clusterfixture"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
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
	deployApp(t, c, "shop", "prod", appDocument)
}

// appDocument is the app.yaml the scenario deploys. Raft keeps it as the
// app's original, and a starting sfcd parses it again with its own app.yaml
// rules (2026-11-28 lab: renamed keys stopped every server). Use the keys an
// app may use; a later build must keep reading them.
var appDocument = "name: web\n" +
	"services:\n" +
	"  web:\n" +
	"    image: docker.io/library/nginx@sha256:" + strings.Repeat("a", 64) + "\n" +
	"    command: [/web, --port, \"8080\"]\n" +
	"    environment: {MODE: prod, PORT: \"8080\"}\n" +
	"    labels: {team: shop}\n" +
	"    cpus: 0.1\n" +
	"    mem_limit: 16m\n" +
	"    networks: {app: {ipv4_address: 10.199.1.10}}\n" +
	"    x-sfc: {node: node-0}\n" +
	"networks:\n" +
	"  app: {external: true, name: lan}\n"

// deployApp deploys doc as `sfcli app up` does: plan, upload the artifact,
// accept it.
func deployApp(t *testing.T, c *clusterfixture.Cluster, tenant, deploymentID, doc string) {
	t.Helper()
	image := "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64)
	var cfg dockerspec.DockerOCIImage
	cfg.Config.User, cfg.Config.Cmd, cfg.Config.Env = "10001:10001", []string{"/web"}, []string{"PATH=/usr/bin"}
	c.Nodes[0].Engine.Publish(cfg, image)
	artifact := c.PlanApp(0, tenant, control.AppPlanRequest{Document: []byte(doc), Deployment: deploymentID})
	plan, err := deployment.DecodeBlueprint(artifact)
	if err != nil {
		t.Fatal(err)
	}
	app, id := plan.Scope().App, "compat-"+plan.Scope().App
	c.Change(0, id+"-upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: tenant, App: app, Deployment: deploymentID, ID: id, Length: len(artifact), Digest: sha256.Sum256(artifact)})
	for i := 0; i*deployment.ArtifactPartBytes < len(artifact); i++ {
		end := min(len(artifact), (i+1)*deployment.ArtifactPartBytes)
		c.Change(0, fmt.Sprintf("%s-part-%03d", id, i), "put-app-part", uint64(i+1), control.AppUploadPart{Tenant: tenant, ID: id, Index: i, Data: artifact[i*deployment.ArtifactPartBytes : end]})
	}
	target := control.AppCreateTarget(c.ID, tenant, app, deploymentID)
	c.Change(0, id+"-accept", "begin-app", 0, control.AppBegin{Target: &target, Tenant: tenant, App: app, Deployment: deploymentID, Upload: id, Operation: id})
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
	// The upgrade dry run works on a copy while the server runs.
	if r, err := app.DryRun(n.Config, t.TempDir()); err != nil || !r.Replayed || r.Checkpoint == 0 {
		t.Fatal("dry run", r.Replayed, r.Checkpoint, err)
	}
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
	if apps, err := c.Policy.Apps(s); err != nil {
		t.Fatal(err)
	} else if _, ok := apps.Inventory("shop", "web"); !ok {
		t.Fatal("replayed state lacks the deployed app")
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
