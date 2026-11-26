// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/tests/clusterfixture"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
)

// newRealFixture serves the web server on the real mydcd adapter, pinned to
// node-0 of a real cluster of nodes (devel/refactor/16). Only host work is
// fake. The bootstrap key is system administrator "admin" (u-admin).
func newRealFixture(t *testing.T, ctx context.Context, nodes int, opts ...clusterfixture.Option) (*fixture, *clusterfixture.Cluster) {
	t.Helper()
	if testing.Short() {
		t.Skip("starts real mydcd nodes")
	}
	c := clusterfixture.New(t, ctx, nodes, opts...)
	return realFixtureOn(t, c), c
}

// newIsolatedFixture is newRealFixture with node-1 onward in their own
// network namespaces (clusterfixture.NewIsolated), for networks that span
// servers. It needs root.
func newIsolatedFixture(t *testing.T, ctx context.Context, nodes int) (*fixture, *clusterfixture.Cluster) {
	t.Helper()
	if testing.Short() {
		t.Skip("starts real mydcd nodes")
	}
	if os.Geteuid() != 0 {
		t.Skip("network namespaces need root")
	}
	c := clusterfixture.NewIsolated(t, ctx, nodes)
	return realFixtureOn(t, c), c
}

// TestMain lets clusterfixture.NewIsolated run its child nodes.
func TestMain(m *testing.M) { clusterfixture.Main(m) }

func realFixtureOn(t *testing.T, c *clusterfixture.Cluster) *fixture {
	t.Helper()
	n := c.Nodes[0]
	client, err := mydc.NewReal(mydc.RealConfig{Socket: n.Socket, Cluster: c.ID, Node: n.ID, NodeKey: n.Key})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(Options{Client: client, Store: st, Logger: discardLogger(), Socket: n.Socket})
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	jar, _ := cookiejar.New(nil)
	f := &fixture{t: t, store: st, srv: srv, http: hs}
	f.hc = hs.Client()
	f.hc.Jar = jar
	return f
}

// realOpID numbers web operation IDs for one test.
func realOpID() func() string {
	n := 0
	return func() string { n++; return fmt.Sprintf("c0ffee00-0000-4000-8000-%012d", n) }
}

// Through the web server on a real two-node cluster: the administrator
// logs in with the browser's key flow, sees both servers, and creates a
// work space with a signed operation that mydcd applies.
func TestRealServerLoginNodesAndTenant(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the fake engine makes kernel bridges (needs root)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	code, out := f.do("GET", "/api/v1/nodes", nil)
	if code != 200 || len(out["items"].([]any)) != 2 {
		t.Fatalf("nodes: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/ops", map[string]any{"opId": op(), "action": "create-tenant", "principal": "u-admin", "expected": 0, "payload": map[string]any{"ID": "shop"}})
	if state := opState(t, code, out); state != "applied" {
		t.Fatalf("create tenant: %s %d %v", state, code, out)
	}
	if code, out := f.do("GET", "/api/v1/tenants", nil); code != 200 || !hasItem(out, "id", "shop") {
		t.Fatalf("tenants: %d %v", code, out)
	}
}

// realShop prepares work space "shop" as an administrator does before a
// deploy: both servers assigned, node and tenant quotas, and a managed TUN
// network "lan" with a pool on node-1.
func realShop(t *testing.T, c *clusterfixture.Cluster) {
	t.Helper()
	realShopOn(t, c, "node-1")
}

// realShopOn is realShop with "lan" pools on the given nodes (more than one
// needs NewIsolated: in one namespace their routes collide).
func realShopOn(t *testing.T, c *clusterfixture.Cluster, lan ...string) {
	t.Helper()
	c.Change(0, "shop", "create-tenant", 0, control.TenantID{ID: "shop"})
	catalog, err := c.Policy.Catalog(c.State())
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("shop")
	c.Change(0, "shop-nodes", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "shop", Nodes: []string{"node-0", "node-1"}})
	for _, node := range []string{"node-0", "node-1"} {
		for _, scope := range []string{"", "shop"} {
			c.Change(0, "quota-"+node+"-"+scope, "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: node, Capacity: workload.Resources{CPU: 2e9, Memory: 1 << 30}, Networks: 2, MaxConsumers: 8, PacketQueuePackets: 64, PacketQueueBytes: 1 << 20})
		}
	}
	resources, err := c.Policy.Resources(c.State())
	if err != nil {
		t.Fatal(err)
	}
	pools := map[string]tenancy.TUNNode{
		"node-0": {Node: "node-0", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.199.1.0/24"), Gateway: netip.MustParseAddr("10.199.1.1"), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix("10.199.2.0/32")}},
		"node-1": {Node: "node-1", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.199.0.0/24"), Gateway: netip.MustParseAddr("10.199.0.1"), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix("10.199.2.1/32")}},
	}
	var members []tenancy.TUNNode
	for _, node := range lan {
		members = append(members, pools[node])
	}
	c.Change(0, "shop-lan", "create-tun-network", resources.Networks.Revision(), tenancy.TUNDefinition{Tenant: "shop", Name: "lan", Members: members})
}

// The web plans and deploys an app on node-1 through mydcd: the plan is
// mydcd's blueprint, node-1 pulls the image from the fake registry and runs
// the container on the TUN network's bridge, the deploy settles Succeeded and
// the web reads the task's detail and logs (devel/refactor/16 step 4).
func TestRealServerPlanAndDeploy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	realShop(t, c)
	image := "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64)
	var cfg dockerspec.DockerOCIImage
	cfg.Config.User, cfg.Config.Cmd, cfg.Config.Env = "10001:10001", []string{"/web"}, []string{"PATH=/usr/bin"}
	c.Nodes[1].Engine.Publish(cfg, image)
	doc := "name: web\nservices:\n web:\n  image: docker.io/library/nginx@sha256:" + strings.Repeat("a", 64) + "\n  cpus: 0.1\n  mem_limit: 16m\n  networks: {app: {ipv4_address: 10.199.0.10}}\n  x-mydc: {node: node-1}\nnetworks:\n app: {external: true, name: lan}\n"
	code, out := f.do("POST", "/api/v1/t/shop/apps/plan", map[string]any{"yaml": doc, "deployment": "prod"})
	if code != 200 || out["app"] != "web" || !strings.Contains(fmt.Sprint(out["services"]), "node:node-1") {
		t.Fatalf("plan: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/apps/deploy", map[string]any{"opId": op(), "yaml": doc, "deployment": "prod"})
	if state := opState(t, code, out); state != "applied" {
		t.Fatalf("deploy: %s %d %v", state, code, out)
	}
	code, out = f.do("GET", "/api/v1/t/shop/apps", nil)
	if code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("apps: %d %v", code, out)
	}
	// node-1 pulls the image from its "registry", creates and starts the
	// container on the TUN network's bridge, and mydcd settles the deploy.
	c.Wait("deploy succeeded", func() bool {
		_, out = f.do("GET", "/api/v1/t/shop/apps", nil)
		app := out["items"].([]any)[0].(map[string]any)
		return app["operation"].(map[string]any)["status"] == "Succeeded" && app["health"] == "Healthy"
	})
	if pulls := c.Nodes[1].Engine.Pulls(); len(pulls) != 1 || pulls[0] != image {
		t.Fatalf("pulls on node-1: %v", pulls)
	}
	ids := c.Nodes[1].Engine.Containers(map[string]string{"org.mydc.key": "workload/task/shop/web/web"})
	if len(ids) != 1 || len(c.Nodes[0].Engine.Containers(nil)) != 0 {
		t.Fatalf("containers: node-1 %v node-0 %v", ids, c.Nodes[0].Engine.Containers(nil))
	}
	// The task list names the instance; detail and logs read the running
	// container on node-1 through mydcd.
	code, out = f.do("GET", "/api/v1/t/shop/apps/web/tasks", nil)
	tasks, _ := out["items"].([]any)
	if code != 200 || len(tasks) != 1 {
		t.Fatalf("tasks: %d %v", code, out)
	}
	task := tasks[0].(map[string]any)
	if task["node"] != "node-1" || task["observed"] != "running" {
		t.Fatalf("task: %v", task)
	}
	q := "?service=web&instance=" + task["instance"].(string)
	code, out = f.do("GET", "/api/v1/t/shop/apps/web/task"+q, nil)
	if code != 200 || out["node"] != "node-1" || out["nativeID"] != ids[0] || out["image"] != image || out["user"] != "10001:10001" || fmt.Sprint(out["command"]) != "[/web]" {
		t.Fatalf("task detail: %d %v", code, out)
	}
	if nets := fmt.Sprint(out["networks"]); !strings.Contains(nets, "ip:10.199.0.10") {
		t.Fatalf("task networks: %s", nets)
	}
	if err := c.Nodes[1].Engine.Log(ids[0], false, "listening on 10.199.0.10:8080"); err != nil {
		t.Fatal(err)
	}
	code, out = f.do("GET", "/api/v1/t/shop/apps/web/task/logs"+q+"&limit=10", nil)
	if lines := fmt.Sprint(out["lines"]); code != 200 || !strings.Contains(lines, "stream:stdout text:listening on 10.199.0.10:8080") {
		t.Fatalf("task logs: %d %v", code, out)
	}
}
