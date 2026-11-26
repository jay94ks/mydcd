// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/tests/registryfixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Requires an explicit external rollback baseline and a prebuilt static image.
func TestRQ3TwoNodeTwoTenantDockerTasksAndOriginalSource(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("MYDC_NATIVE_MANIFEST") == "" || !filepath.IsAbs(os.Getenv("MYDC_DOCKER_TEST_BACKEND")) || os.Getenv("MYDC_DOCKER_TEST_CIDR") == "" {
		t.Skip("requires owned native rollback baseline and prepared backend")
	}
	testRealManagedJoin(t, false, "observations-native")
}

func verifyTwoNodeNativeObservations(t *testing.T, ctx context.Context, a, b *Runtime, ac, bc config.Node, user userauth.Client, session access.Session, ap, bp mydcp.Peer, p control.Policy, change func(string, string, uint64, any), wait func(string, func() bool), root string, detailsOnly bool) {
	t.Helper()
	cfgs := []config.Node{ac, bc}
	runtimes := []*Runtime{a, b}
	owners := []string{engine.Owner(user.Cluster, a.Identity.Public), engine.Owner(user.Cluster, b.Identity.Public)}
	manifest := map[string]any{"Cluster": user.Cluster, "Owners": owners, "Root": root, "CIDR": os.Getenv("MYDC_DOCKER_TEST_CIDR")}
	save := func() {
		t.Helper()
		raw, _ := json.Marshal(manifest)
		if e := os.WriteFile(os.Getenv("MYDC_NATIVE_MANIFEST"), raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	save()
	var registry *registryfixture.Fixture
	// Stop every producer first, then use the existing journal-based rollback
	// helpers. No shared FSM receipt or success is manufactured by rollback.
	t.Cleanup(func() {
		for _, r := range runtimes {
			if e := r.Close(); e != nil {
				t.Error(e)
			}
		}
		clean, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		for i, cfg := range cfgs {
			c, e := engine.Open(clean, "unix:///var/run/docker.sock", owners[i])
			if e != nil {
				t.Error(e)
				continue
			}
			n, e := network.OpenManager(filepath.Join(cfg.Node.StateDir, "network", "journal.db"), c)
			if e != nil {
				t.Error(e)
				c.Close()
				continue
			}
			cleanupManagedTaskVolumes(t, clean, c, cfg, n, map[string]any{"Cluster": user.Cluster, "NodeKey": runtimes[i].Identity.Public, "KeepImages": true})
			if cleanupManagedRouteNative(t, clean, cfg, owners[i], runtimes[i].Identity.Public, n, true, false) {
				for _, key := range n.Keys() {
					record, e := n.View(key)
					if e != nil {
						t.Error(e)
						continue
					}
					for id, pin := range record.Consumers {
						if e = n.ReturnConsumer(key, id, pin.Generation); e != nil {
							t.Error(e)
						}
					}
					resource := record.State.Desired.Resource
					if !resource.Present {
						resource = record.State.Applied
					}
					if resource.Present {
						if e = n.Desired(key, record.State.Desired.Revision+1, resource.Generation, nil, max(1, record.Capacity)); e == nil {
							e = n.Step(clean, key)
						}
						if e != nil {
							t.Error("owned bridge rollback", e)
						}
					}
				}
			}
			if rows, e := c.API.ContainerList(clean, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.mydc.owner="+owners[i])}); e != nil || len(rows.Items) != 0 {
				t.Error("owned container remains", e)
			}
			if rows, e := c.API.NetworkList(clean, client.NetworkListOptions{Filters: client.Filters{}.Add("label", "org.mydc.owner="+owners[i])}); e != nil || len(rows.Items) != 0 {
				t.Error("owned bridge remains", e)
			}
			n.Close()
			c.Close()
		}
		if registry != nil {
			c, e := engine.Open(clean, "unix:///var/run/docker.sock", owners[0])
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			image, e := c.API.ImageInspect(clean, registry.Reference)
			if e != nil {
				t.Error(e)
				return
			}
			if image.Config == nil || image.Config.Labels["org.mydc.test.owner"] != owners[0] {
				t.Error("fixture image ownership mismatch")
				return
			}
			if _, e = c.API.ImageRemove(clean, registry.Reference, client.ImageRemoveOptions{}); e != nil {
				t.Error("fixture image rollback", e)
			}
		}
	})
	registry = registryfixture.OpenPrepared(t, os.Getenv("MYDC_DOCKER_TEST_BACKEND"), container.Config{Cmd: []string{"/backend"}, User: "10001:10001", Labels: map[string]string{"org.mydc.test.owner": owners[0]}})
	manifest["Image"] = registry.Reference
	save()
	read := func() control.Apps {
		t.Helper()
		v, e := a.Engine().Read(ctx, true)
		if e != nil {
			t.Fatal(e)
		}
		apps, e := p.Apps(v.State)
		if e != nil {
			t.Fatal(e)
		}
		return apps
	}
	prefix := netip.MustParsePrefix(os.Getenv("MYDC_DOCKER_TEST_CIDR"))
	documents := map[string][]byte{}
	for i, tenant := range []string{"first", "second"} {
		node := cfgs[i].Node.ID
		change("native-tenant-"+tenant, "create-tenant", 0, control.TenantID{ID: tenant})
		view, e := a.Engine().Read(ctx, true)
		if e != nil {
			t.Fatal(e)
		}
		catalog, _ := p.Catalog(view.State)
		scope, _ := catalog.Tenant(tenant)
		change("native-node-"+tenant, "set-nodes", scope.Revision, control.NodeAssignment{Tenant: tenant, Nodes: []string{node}})
		view, e = a.Engine().Read(ctx, true)
		if e != nil {
			t.Fatal(e)
		}
		catalog, _ = p.Catalog(view.State)
		scope, _ = catalog.Tenant(tenant)
		change("native-trust-"+tenant, "set-trust", scope.Revision, control.TrustAssignment{Tenant: tenant, Rules: append(scope.ImageSources, access.TrustRule{Registry: registry.Registry, Repository: "fixture"})})
		for _, namespace := range []string{"", tenant} {
			change("native-quota-"+tenant+namespace, "set-node-quota", 0, tenancy.NodeLimit{Tenant: namespace, Node: node, Capacity: workload.Resources{CPU: 1e9, Memory: 256 << 20}, Networks: 2, MaxConsumers: 8})
		}
		subnet := prefix
		if i == 1 {
			base := prefix.Addr().As4()
			base[2]++
			subnet = netip.PrefixFrom(netip.AddrFrom4(base), prefix.Bits())
		}
		view, e = a.Engine().Read(ctx, true)
		if e != nil {
			t.Fatal(e)
		}
		resources, _ := p.Resources(view.State)
		change("native-network-"+tenant, "create-tun-network", resources.Networks.Revision(), tenancy.TUNDefinition{Tenant: tenant, Name: "services", Members: []tenancy.TUNNode{{Node: node, Pools: []tenancy.Subnet{{ID: "pool", Prefix: subnet, Gateway: subnet.Addr().Next(), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("198.18.251.%d/32", i+1))}}}})
		directory := filepath.Join(root, "registered-"+node)
		if e = os.Mkdir(directory, 0700); e != nil {
			t.Fatal(e)
		}
		change("native-root-"+tenant, "add-node-storage", 0, nodestorage.Definition{Node: node, Key: runtimes[i].Identity.Public, ID: "data", Path: directory, Tenants: []string{tenant}, MaxVolumes: 4})
		document := []byte(fmt.Sprintf("# exact original %s\nname: app\nservices:\n web:\n  image: %s\n  cpus: '0.1'\n  mem_limit: 64m\n  networks: {lan: {ipv4_address: %s}}\n  x-mydc: {node: %s}\nnetworks:\n lan: {external: true, name: services}\n", tenant, registry.Reference, subnet.Addr().Next().Next(), node))
		if detailsOnly {
			document = bytes.Replace(document, []byte("  cpus:"), []byte("  healthcheck: {test: [CMD, /backend, --probe], interval: 1s, timeout: 1s, retries: 2}\n  cpus:"), 1)
		}
		documents[tenant] = document
		acceptNativeObservationApp(t, ctx, user, ap, session, change, read, tenant, "initial-"+tenant, document)
	}
	lastTaskState := ""
	wait("both actual Docker Tasks running", func() bool {
		reply, e := user.TasksPage(ctx, ap, session, control.TaskSelection{}, "")
		diagnostic, _ := json.Marshal(reply.Tasks)
		state := fmt.Sprintf("%v %s", e, diagnostic)
		if state != lastTaskState {
			t.Log("native Task observation", state)
			lastTaskState = state
		}
		if e != nil || len(reply.Tasks) != 2 {
			return false
		}
		for _, task := range reply.Tasks {
			if task.Observed != "running" || !strings.Contains(task.Image, "@sha256:") || task.Container == "" {
				return false
			}
		}
		return true
	})

	change("native-reader", "put-user", 0, access.User{ID: "reader", Username: "reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: user.Self.Public, Enabled: true}}})
	change("native-reader-member", "set-membership", 0, access.Membership{Tenant: "first", User: "reader", Role: access.Viewer, Enabled: true})
	reader, err := user.Login(ctx, ap, "reader", user.Self.Private)
	if err != nil {
		t.Fatal(err)
	}
	if detailsOnly {
		change("detail-second-reader", "put-user", 0, access.User{ID: "second-reader", Username: "second-reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: user.Self.Public, Enabled: true}}})
		change("detail-second-membership", "set-membership", 0, access.Membership{Tenant: "second", User: "second-reader", Role: access.Viewer, Enabled: true})
		second, err := user.Login(ctx, ap, "second-reader", user.Self.Private)
		if err != nil {
			t.Fatal(err)
		}
		verifyTwoTenantDetailsNative(t, ctx, runtimes, user, ap, []access.Session{reader, second}, wait)
		return
	}
	hidden, err := user.TasksPage(ctx, ap, reader, control.TaskSelection{Node: "node-b"}, "")
	if err != nil || len(hidden.Tasks) != 0 {
		t.Fatal("live foreign node Task existence leaked", err)
	}
	if _, _, err = user.ReadAppSource(ctx, ap, reader, "second", control.AppSourceSelection{App: "app"}); err == nil {
		t.Fatal("foreign original app source returned")
	}
	// Filter all three selectors independently on the live two-tenant state.
	for _, q := range []control.TaskSelection{{Node: "node-b"}, {Tenant: "first"}, {Tenant: "second", App: "app"}} {
		reply, e := user.TasksPage(ctx, ap, session, q, "")
		if e != nil || len(reply.Tasks) != 1 {
			t.Fatal("native Task filter", q, e, len(reply.Tasks))
		}
	}
	// Original bytes, including comments, survive native activation and a second
	// accepted comment-only revision without replacing the immutable native.
	original, version, e := user.ReadAppSource(ctx, bp, session, "first", control.AppSourceSelection{App: "app"})
	if e != nil || version.Revision != 1 || !bytes.Equal(original, documents["first"]) {
		t.Fatal("native original bytes", e, version)
	}
	wait("first rollout completely settled", func() bool {
		execution, ok := read().Execution("first", "app")
		return ok && execution.Status() == "Succeeded"
	})
	updated := append(bytes.Clone(original), []byte("\n# second exact accepted version\n")...)
	acceptNativeObservationApp(t, ctx, user, ap, session, change, read, "first", "updated-first", updated)
	latest, meta, e := user.ReadAppSource(ctx, ap, session, "first", control.AppSourceSelection{App: "app"})
	if e != nil || meta.Revision != 2 || !bytes.Equal(latest, updated) {
		t.Fatal("native consecutive source revision", e, meta)
	}
	old, _, e := user.ReadAppSource(ctx, ap, session, "first", control.AppSourceSelection{App: "app", Revision: 1})
	if e != nil || !bytes.Equal(old, original) {
		t.Fatal("prior source lost", e)
	}
	first, e := user.TasksPage(ctx, ap, session, control.TaskSelection{Tenant: "first"}, "")
	if e != nil {
		t.Fatal(e)
	}
	task := first.Tasks[0]
	if _, e = a.docker.API.ContainerStop(ctx, task.Container, client.ContainerStopOptions{}); e != nil {
		t.Fatal(e)
	}
	wait("actual Docker exit is signed and visible", func() bool {
		reply, e := user.TasksPage(ctx, ap, session, control.TaskSelection{Tenant: "first"}, "")
		return e == nil && len(reply.Tasks) == 1 && reply.Tasks[0].Observed == "exited"
	})
	if _, e = a.docker.API.ContainerStart(ctx, task.Container, client.ContainerStartOptions{}); e != nil {
		t.Fatal(e)
	}
	wait("same native Task resumes", func() bool {
		reply, e := user.TasksPage(ctx, ap, session, control.TaskSelection{Tenant: "first"}, "")
		return e == nil && len(reply.Tasks) == 1 && reply.Tasks[0].Observed == "running" && reply.Tasks[0].Container == task.Container
	})
	// Collect actual host/Docker/root stats and deliver them using the ordinary
	// signed member report adapter; the receiver checks current member + index.
	for i, r := range runtimes {
		view, e := r.Engine().Read(ctx, false)
		if e != nil {
			t.Fatal(e)
		}
		rows, e := r.collectNodeObservations(ctx, view)
		if e != nil {
			t.Fatal(e)
		}
		peer := ap
		if i == 0 {
			peer = bp
		}
		link, e := r.Mesh.Dial(ctx, peer)
		if e != nil {
			t.Fatal(e)
		}
		for _, raw := range rows {
			if e = r.storeNodeObservation(mydcp.Identity(r.Identity.Public), raw); e != nil {
				t.Fatal(e)
			}
			if e = link.Report(ctx, raw); e != nil {
				t.Fatal(e)
			}
		}
	}

	scoped, err := user.NodeObservationPage(ctx, ap, reader, "node-summary", "first", "", "")
	if err != nil || scoped.NodeSummary == nil || len(scoped.NodeSummary.Nodes) != 1 || scoped.NodeSummary.Nodes[0].Node != "node-a" || scoped.NodeSummary.Nodes[0].Admin != nil || scoped.NodeSummary.Nodes[0].Usage == nil || scoped.NodeSummary.Nodes[0].Usage.Containers == nil || *scoped.NodeSummary.Nodes[0].Usage.Containers != 1 {
		t.Fatal("actual tenant native count/filter", err, scoped.NodeSummary)
	}
	visible, _ := json.Marshal(scoped.NodeSummary)
	for _, foreign := range []string{"second", "node-b", bp.Endpoint, "Version", "Role"} {
		if bytes.Contains(visible, []byte(foreign)) {
			t.Fatal("foreign tenant/host metadata in native summary", foreign)
		}
	}
	for _, node := range []string{"node-a", "node-b"} {
		reply, e := user.NodeObservationPage(ctx, ap, session, "node-disks", "", node, "")
		if e != nil || reply.NodeDisks == nil {
			t.Fatal(e)
		}
		purposes := map[string]bool{}
		seen := map[string]bool{}
		for _, disk := range reply.NodeDisks.Disks {
			if seen[disk.ID] {
				t.Fatal("same filesystem counted twice")
			}
			seen[disk.ID] = true
			for _, purpose := range disk.Purposes {
				purposes[purpose] = true
			}
		}
		for _, purpose := range []string{"system", "container-runtime", "storage-root"} {
			if !purposes[purpose] {
				t.Fatal("native disk source absent", node, purpose)
			}
		}
	}
	t.Log("two actual nodes/two tenants/Docker Tasks: node/tenant/app filters, signed exited/running transitions, exact original and consecutive preserved app revisions, approved three-source filesystem deduplication")
}

func acceptNativeObservationApp(t *testing.T, ctx context.Context, user userauth.Client, peer mydcp.Peer, session access.Session, change func(string, string, uint64, any), read func() control.Apps, tenant, id string, document []byte) {
	t.Helper()
	raw, e := user.StreamAppPlan(ctx, peer, session, tenant, control.AppPlanRequest{Document: document})
	if e != nil {
		t.Fatal("native app plan", e)
	}
	change(id+"-upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: tenant, App: "app", Deployment: "app", ID: id, Length: len(raw), Digest: sha256.Sum256(raw)})
	revision := uint64(1)
	for part, start := 0, 0; start < len(raw); part, start = part+1, start+deployment.ArtifactPartBytes {
		change(fmt.Sprintf("%s-part-%d", id, part), "put-app-part", revision, control.AppUploadPart{Tenant: tenant, ID: id, Index: part, Data: raw[start:min(start+deployment.ArtifactPartBytes, len(raw))]})
		revision++
	}
	expected := uint64(0)
	if inventory, ok := read().Inventory(tenant, "app"); ok {
		expected = inventory.Revision()
	}
	change(id+"-begin", "begin-app", expected, control.AppBegin{Tenant: tenant, App: "app", Deployment: "app", Upload: id, Operation: id})
}
