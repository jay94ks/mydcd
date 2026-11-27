// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/jay94ks/seafield/tests/registryfixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestRealBoundarySingleFileCombinedInputsAndReadiness(t *testing.T) {
	tag, backend, cidr := os.Getenv("SFC_DOCKER_TEST_OWNER"), os.Getenv("SFC_DOCKER_TEST_BACKEND"), os.Getenv("SFC_DOCKER_TEST_CIDR")
	if tag == "" || backend == "" || cidr == "" || os.Geteuid() != 0 {
		t.Skip("requires owned Docker rollback prestate and user-prebuilt test/backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	var cluster [32]byte
	if _, err := rand.Read(cluster[:]); err != nil {
		t.Fatal(err)
	}
	f := makeFixtureCluster(t, cluster)
	owner := engine.Owner(cluster, public(f.nb))
	root := t.TempDir() // Removed only after the native rollback callbacks.
	c, err := engine.Open(ctx, "unix:///var/run/docker.sock", owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	registry := registryfixture.OpenPrepared(t, backend, container.Config{Cmd: []string{"/backend"}, User: "10001:10001", Volumes: map[string]struct{}{"/data": {}}, Labels: map[string]string{"org.sfc.test.owner": tag}})
	filters := client.Filters{}.Add("label", "org.sfc.owner="+owner)
	before, err := c.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil || len(before.Items) != 0 {
		t.Fatal("owner initially nonempty", err)
	}
	if _, err = c.API.ImageInspect(ctx, registry.Reference); !cerrdefs.IsNotFound(err) {
		t.Fatal("fixture image initially present", err)
	}
	// This fallback is registered before any pull/native mutation. It cannot
	// turn a product cleanup failure into success or delete unrelated IDs.
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		containers, e := c.API.ContainerList(clean, client.ContainerListOptions{All: true, Filters: filters})
		if e != nil {
			t.Error(e)
			return
		}
		for _, item := range containers.Items {
			if item.Labels["org.sfc.owner"] != owner || item.Labels["org.sfc.kind"] != "container" {
				t.Error("container ownership")
				continue
			}
			if !t.Failed() {
				t.Error("product left owned container")
			}
			if _, e = c.API.ContainerRemove(clean, item.ID, client.ContainerRemoveOptions{Force: true}); e != nil {
				t.Error(e)
			}
		}
		networks, e := c.API.NetworkList(clean, client.NetworkListOptions{Filters: filters})
		if e != nil {
			t.Error(e)
			return
		}
		for _, item := range networks.Items {
			if item.Labels["org.sfc.owner"] != owner || item.Labels["org.sfc.kind"] != "bridge" {
				t.Error("bridge ownership")
				continue
			}
			if !t.Failed() {
				t.Error("product left owned bridge")
			}
			if _, e = c.API.NetworkRemove(clean, item.ID, client.NetworkRemoveOptions{}); e != nil {
				t.Error(e)
			}
		}
		values, e := c.API.VolumeList(clean, client.VolumeListOptions{Filters: filters})
		if e != nil {
			t.Error(e)
			return
		}
		for _, item := range values.Items {
			if item.Labels["org.sfc.owner"] != owner || item.Labels["org.sfc.kind"] != "volume" {
				t.Error("volume ownership")
				continue
			}
			if !t.Failed() {
				t.Error("product left owned volume")
			}
			if _, e = c.API.VolumeRemove(clean, item.Name, client.VolumeRemoveOptions{}); e != nil {
				t.Error(e)
			}
		}
		image, e := c.API.ImageInspect(clean, registry.Reference)
		if e == nil {
			if image.Config == nil || image.Config.Labels["org.sfc.test.owner"] != tag {
				t.Error("image ownership")
				return
			}
			if !t.Failed() {
				t.Error("product left fixture image")
			}
			if _, e = c.API.ImageRemove(clean, image.ID, client.ImageRemoveOptions{}); e != nil {
				t.Error(e)
			}
		} else if !cerrdefs.IsNotFound(e) {
			t.Error(e)
		}
	})
	networks0, e := c.API.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if e != nil || len(networks0.Items) != 0 {
		t.Fatal("owner network initially nonempty", e)
	}
	volumes0, e := c.API.VolumeList(ctx, client.VolumeListOptions{Filters: filters})
	if e != nil || len(volumes0.Items) != 0 {
		t.Fatal("owner volume initially nonempty", e)
	}
	t.Logf("nativeOwner=%s registry=%s", owner, registry.Registry)
	tenant, _ := f.c.Tenant("tenant")
	f.c, err = f.c.ChangeTrust("alice", "tenant", tenant.Revision, []access.TrustRule{{Registry: registry.Registry, Repository: "fixture"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	native, err := volumes.OpenNative(filepath.Join(root, "volumes.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	scope := f.v["tenant/php-mysql/mysql-data"].Scope()
	vs := volumes.NativeSpec{Schema: 1, Scope: scope, Node: "node-b", NodeKey: public(f.nb), Materialization: "initial", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
	vkey, err := native.Desired(vs, 1, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = native.Step(ctx, vkey); err != nil {
		t.Fatal(err)
	}
	ready, err := native.Ready(ctx, vkey, f.nb)
	if err != nil {
		t.Fatal(err)
	}
	f.v[VolumeKey(scope)], err = volumes.New(f.c, "alice", scope, ready.Owner, 4)
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix(cidr)
	address := prefix.Addr().Next().Next()
	input, err := ParseCompose([]byte(fmt.Sprintf(`
name: php-mysql
services:
  db:
    image: %s
    cpus: 0.1
    mem_limit: 32m
    environment: {SFC_PROJECTION_FILE: /run/secrets/db-password, SFC_VOLUME_FIXTURE: "1", SFC_READINESS_FIXTURE: "1"}
    secrets: [{source: db-password, target: /run/secrets/db-password, uid: "10001", gid: "10001", mode: 0400}]
    volumes: [mysql-data:/data]
    tmpfs: ["/scratch:size=4m,uid=10001,gid=10001,mode=0700"]
    healthcheck: {test: [CMD, /backend, --projection-probe], interval: 1s, timeout: 1s, retries: 2}
    networks: {app: {ipv4_address: %s}}
    x-sfc: {node: node-b, secrets_from: [group/common], ready: {http: /readyz, port: 8080}}
networks:
  app:
    x-sfc: {mtu: 1280, pools: {node-b: {cidr: %s, gateway: %s}}}
volumes:
  mysql-data:
    x-sfc: {node: node-b, uid: 10001, gid: 10001, mode: "0750"}
secrets:
  db-password:
    x-sfc: {key: DB_PASSWORD}
`, registry.Reference, address, prefix, prefix.Addr().Next())))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(input, f.c, contextFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	needs, err := b.Inputs("db", "database", 11, public(private(30)))
	if err != nil {
		t.Fatal(err)
	}
	f.approveAll(needs)
	bound := f.reserve(needs).Bindings[0]
	stage, err := bound.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, f.values(needs), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Destroy()
	allowed := true
	gate := func(context.Context, Binding) error {
		if !allowed {
			return ErrInputs
		}
		return bound.Check(f.bindings, f.c, f.trees, f.a, f.v, 100)
	}
	projections, err := OpenProjections(filepath.Join(root, "inputs"), cluster, public(f.nb), 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = projections.Close() }()
	ref, err := projections.Publish(ctx, bound, stage, 11, 4)
	if err != nil {
		t.Fatal(err)
	}
	netID := PoolID("tenant", "php-mysql", "app", "node-b")
	bridge := network.BridgeSpec{Schema: 1, Network: netID, Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "pool", Network: netID, Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}
	npath, wpath, apath := filepath.Join(root, "network.db"), filepath.Join(root, "workload.db"), filepath.Join(root, "activations.db")
	n, err := network.OpenManager(npath, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	bridgeKey := ResourceKey("bridge", "tenant", "php-mysql", "app/node-b")
	if err = n.Desired(bridgeKey, 1, 1, &bridge, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	material := TaskMaterial{Binding: bound, Projection: &ref, Volumes: []volumes.NativeReady{ready}, Network: ObjectRef{bridgeKey, 1, 1}, Bridge: bridge}
	spec, err := b.ResolveTask(ctx, "db", material, f.c, c, true)
	if err != nil {
		t.Fatal("real trusted Registry/recipe", err)
	}
	pulled, err := c.API.ImageInspect(ctx, registry.Reference)
	if err != nil || spec.Process.ImageID != pulled.ID || !slices.Contains(pulled.RepoDigests, registry.Reference) || !slices.Equal(pulled.RootFS.Layers, []string{registry.LayerDigest}) || registry.Manifests.Load() == 0 || registry.Blobs.Load() < 2 {
		t.Fatal("real registry reference/rootfs/transfer boundary", err)
	}
	// Authority/approval metadata here is the reused core fixture. The prior
	// actual SFCP/Raft Volume permit tests remain the quorum evidence.
	authority := func(ctx context.Context, r volumes.StartRequest) (volumes.Permit, error) {
		if err := ctx.Err(); err != nil {
			return volumes.Permit{}, err
		}
		return f.v[VolumeKey(r.Scope)].PermitStart(f.c, "alice", r)
	}
	activation, err := volumes.OpenActivations(apath, native, c, cluster, public(f.nb), authority)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = activation.Close() }()
	w, err := workload.OpenManagerWithResources(wpath, c, n, projections, activation)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	taskKey := ResourceKey("task", "tenant", "php-mysql", "db")
	if err = w.Desired(taskKey, 11, 11, &spec, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	var status workload.ContainerStatus
	for {
		status, err = w.Status(ctx, taskKey)
		if err != nil {
			t.Fatal(err)
		}
		if status.Ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("combined readiness", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !status.HTTPConfigured || !status.HTTPReady || !status.HealthConfigured {
		t.Fatal("readiness condition dropped")
	}
	nativeID := status.NativeID
	row, err := w.View(taskKey)
	if err != nil {
		t.Fatal(err)
	}
	activationRef := volumes.Activation{Scope: scope, Consumer: bound.Pins()[0].Consumer, NativeKey: vkey, NativeGeneration: 1, TaskKey: taskKey, Task: row.State.Applied, Operation: 1}
	changeReadiness := func(value string) {
		t.Helper()
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address.String()+":8080/readiness-state?ready="+value, nil)
		if e != nil {
			t.Fatal(e)
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := http.Client{Transport: transport, Timeout: time.Second}
		reply, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		_ = reply.Body.Close()
		if reply.StatusCode != http.StatusNoContent {
			t.Fatal("fixture readiness state")
		}
	}
	changeReadiness("0")
	status, err = w.Status(ctx, taskKey)
	if err != nil || !status.Running || status.Ready || status.HTTPReady {
		t.Fatal("running misreported as HTTP ready", err)
	}
	changeReadiness("1")
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = projections.Close(); err != nil {
		t.Fatal(err)
	}
	if err = activation.Close(); err != nil {
		t.Fatal(err)
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	projections, err = OpenProjections(filepath.Join(root, "inputs"), cluster, public(f.nb), 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	activation, err = volumes.OpenActivations(apath, native, c, cluster, public(f.nb), authority)
	if err != nil {
		t.Fatal(err)
	}
	n, err = network.OpenManager(npath, c)
	if err != nil {
		t.Fatal(err)
	}
	w, err = workload.OpenManagerWithResources(wpath, c, n, projections, activation)
	if err != nil {
		t.Fatal(err)
	}
	allowed = false
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("original running required new grant", err)
	}
	status, err = w.Status(ctx, taskKey)
	if err != nil || status.NativeID != nativeID || !status.Ready {
		t.Fatal("same DB/ID/readiness", err)
	}
	timeout := 1
	if _, err = c.API.ContainerStop(ctx, nativeID, client.ContainerStopOptions{Timeout: &timeout}); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err == nil {
		t.Fatal("revoked combined activation started")
	}
	if err = w.Desired(taskKey, 12, 11, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("combined original Remove", err)
	}
	if gone, e := w.Gone(ctx, taskKey, 12, 11); e != nil || !gone {
		t.Fatal("task closure", e)
	}
	if err = projections.Drain(ctx, ref, 12); err != nil {
		t.Fatal(err)
	}
	proof, err := projections.SecretClosure(ref, f.nb)
	if err != nil || len(proof.Volumes) != 0 {
		t.Fatal("Secret-only fact", err)
	}
	if _, err = f.bindings.Release(f.bindings.Revision(), bound, f.a, f.v, proof); err == nil {
		t.Fatal("Secret fact released live Volume usage")
	}
	vg, err := activation.Gone(ctx, activationRef, f.nb)
	if err != nil {
		t.Fatal(err)
	}
	proof.Volumes = append(proof.Volumes, vg)
	released, err := f.bindings.Release(f.bindings.Revision(), bound, f.a, f.v, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = projections.Forget(ref, released.Inventory); err != nil {
		t.Fatal(err)
	}
	retained, err := c.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(retained.Volume.Mountpoint, "marker"))
	if err != nil || string(data) != "volume-original" {
		t.Fatal("retained writer data", err)
	}
	if err = native.DeleteDesired(vkey, 2, 1); err != nil {
		t.Fatal(err)
	}
	if err = native.Step(ctx, vkey); err != nil {
		t.Fatal(err)
	}
	if err = n.Desired(bridgeKey, 2, 1, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	if _, err = c.API.ImageRemove(ctx, pulled.ID, client.ImageRemoveOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Log("single YAML -> current tenant trust -> real registry manifest/config/layer -> exact Blueprint/Binding/NativeReady -> read-only Secret+NoCopy Volume+bounded tmpfs -> A2/health+HTTP -> same DB/ID -> current deny -> exact removal -> separate signed Secret/Volume closures/whole core release -> retain/native cleanup; authority/approval registry is a core fixture, not app/Vault/Raft completion")
}
