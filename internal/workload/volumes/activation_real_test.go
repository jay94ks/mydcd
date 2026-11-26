// SPDX-License-Identifier: Apache-2.0

package volumes_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/jay94ks/mydcd/tests/enginefixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestRealBoundaryWorkloadManagedVolumesQuorumAndRetirement(t *testing.T) {
	testRealWorkloadManagedVolumes(t, false)
}

func TestRealBoundaryWorkloadActivationSyncFailureBeforeNativeStart(t *testing.T) {
	testRealWorkloadManagedVolumes(t, true)
}

func testRealWorkloadManagedVolumes(t *testing.T, syncFault bool) {
	tag, backend := os.Getenv("MYDC_DOCKER_TEST_OWNER"), os.Getenv("MYDC_DOCKER_TEST_BACKEND")
	if tag == "" || backend == "" || os.Getenv("MYDC_DOCKER_TEST_CIDR") == "" || os.Geteuid() != 0 {
		t.Skip("requires prebuilt backend/test binary and owned Docker rollback prestate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	adminKey, err := identity.Create(filepath.Join(root, "admin-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(adminKey.Private)
	p, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := p.LocalAddr().String()
	_ = p.Close()
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = "node-a", address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "control"), filepath.Join(root, "node-key")
	initialized, err := app.Initialize(ctx, cfg, adminKey.Public, "init-activation")
	if err != nil {
		t.Fatal(err)
	}
	node, err := app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if _, err = node.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	clusterID := initialized.Installation.Root.Cluster
	policy := control.Policy{Cluster: clusterID, BootstrapKey: adminKey.Public, TrustRoot: node.Identity.Public, Genesis: initialized.Installation.Genesis}
	peer := mydcp.Peer{ID: cfg.Node.ID, Endpoint: address, Policy: mydcp.Policy{Key: mydcp.Identity(node.Identity.Public), Respond: true}}
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	mesh, err := mydcp.NewTransport(self, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	user := userauth.Client{Mesh: mesh, Self: self, Cluster: clusterID, Peers: []mydcp.Peer{peer}}
	enrolled, err := user.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-activation", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: adminKey.Public, Enabled: true}}}}, adminKey.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	session, err := user.Login(ctx, peer, "admin", adminKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	submit := func(id, action string, expected uint64, payload any) {
		t.Helper()
		raw, e := control.ChangeBytes(action, "admin", expected, payload)
		if e != nil {
			t.Fatal(e)
		}
		var change control.Change
		_ = json.Unmarshal(raw, &change)
		op, e := user.Prepare(ctx, peer, session, id, change)
		if e != nil {
			t.Fatal(e)
		}
		reply, e := user.Operation(ctx, peer, op, false)
		if e != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal(id, reply.Code, reply.Result, e)
		}
	}
	read := func() cluster.View {
		t.Helper()
		for {
			v, e := node.Engine().Read(ctx, true)
			if e == nil {
				return v
			}
			if !errors.Is(e, raft.ErrNotLeader) && !errors.Is(e, raft.ErrLeadershipLost) {
				t.Fatal(e)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	submit("tenant", "create-tenant", 0, control.TenantID{ID: "tenant"})
	catalog, err := policy.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	submit("grant", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{cfg.Node.ID}})
	owner := engine.Owner(clusterID, node.Identity.Public)
	manifest := map[string]any{"Owner": owner, "Root": root, "CIDR": os.Getenv("MYDC_DOCKER_TEST_CIDR"), "Tag": tag}
	saveManifest := func() {
		t.Helper()
		if path := os.Getenv("MYDC_NATIVE_MANIFEST"); path != "" {
			raw, _ := json.Marshal(manifest)
			if err := os.WriteFile(path, raw, 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	saveManifest()
	// Register native fallback before image import or Volume creation. Fixture
	// cleanup runs first, then exact-owner nonforce Volume cleanup.
	cleanupClient, err := engine.Open(ctx, "unix:///var/run/docker.sock", owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanupClient.Close() })
	filter := client.Filters{}.Add("label", "org.mydc.owner="+owner)
	before, err := cleanupClient.API.VolumeList(ctx, client.VolumeListOptions{Filters: filter})
	if err != nil || len(before.Items) != 0 {
		t.Fatal("owner not initially empty", err)
	}
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		items, e := cleanupClient.API.VolumeList(clean, client.VolumeListOptions{Filters: filter})
		if e != nil {
			t.Error(e)
			return
		}
		for _, v := range items.Items {
			if v.Labels["org.mydc.owner"] != owner || v.Labels["org.mydc.kind"] != "volume" {
				t.Error("volume cleanup ownership")
				continue
			}
			if !t.Failed() {
				t.Error("product retained test volume")
			}
			if _, e = cleanupClient.API.VolumeRemove(clean, v.Name, client.VolumeRemoveOptions{}); e != nil {
				t.Error(e)
			}
		}
	})
	f := enginefixture.OpenPrepared(t, ctx, owner, tag, []string{`USER 10001:10001`, `VOLUME ["/data","/logs"]`}, backend)
	native, err := volumes.OpenNative(filepath.Join(root, "native.db"), f.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = native.Close() }()
	type managed struct {
		key      string
		scope    volumes.Scope
		ready    volumes.NativeReady
		consumer volumes.Consumer
	}
	entries := []managed{}
	for _, name := range []string{"data", "logs"} {
		scope := volumes.Scope{Cluster: clusterID, Tenant: "tenant", App: "app", ID: name, Generation: 1}
		spec := volumes.NativeSpec{Schema: 1, Scope: scope, Node: cfg.Node.ID, NodeKey: node.Identity.Public, Materialization: "initial", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
		key, e := native.Desired(spec, 1, 1, 1)
		if e != nil {
			t.Fatal(e)
		}
		if e = native.Step(ctx, key); e != nil {
			t.Fatal(e)
		}
		ready, e := native.Ready(ctx, key, node.Identity.Private)
		if e != nil {
			t.Fatal(e)
		}
		submit(name+"-volume", "create-volume", 0, ready)
		submit(name+"-writer", "acquire-volume", 1, control.VolumeAcquire{Scope: scope, Consumer: "database", Generation: 1, Writable: true})
		registry, e := policy.Volumes(read().State)
		if e != nil {
			t.Fatal(e)
		}
		core, _ := registry.Volume(scope)
		entries = append(entries, managed{key, scope, ready, core.Consumers()[0]})
	}
	image, err := f.Client.Image(ctx, f.Image, false)
	if err != nil {
		t.Fatal(err)
	}
	process, err := workload.ResolveImageProcess(image, workload.ProcessOverrides{MountTargets: []string{"/data", "/logs"}, Environment: map[string]string{"MYDC_VOLUME_FIXTURE": "1", "MYDC_VOLUME_SECOND_FIXTURE": "1"}, Healthcheck: &container.HealthConfig{Test: []string{"CMD", "/backend", "--volume-probe"}, Interval: time.Second, Timeout: time.Second, Retries: 2}})
	if err != nil {
		t.Fatal(err)
	}
	path, npath, wpath := filepath.Join(root, "activations.db"), filepath.Join(root, "network.db"), filepath.Join(root, "workload.db")
	var activation *volumes.Activations
	closeOnPermit, closedStore := false, false
	authority := func(ctx context.Context, r volumes.StartRequest) (volumes.Permit, error) {
		permit, err := cluster.CallVolumePermit(ctx, node.Mesh, node.Identity, clusterID, peer, r)
		if err == nil && closeOnPermit {
			closeOnPermit = false
			if err := volumes.CloseActivationStorageForTest(activation); err != nil {
				return volumes.Permit{}, err
			}
			closedStore = true
		}
		return permit, err
	}
	activation, err = volumes.OpenActivations(path, native, f.Client, clusterID, node.Identity.Public, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = activation.Close() }()
	n, err := network.OpenManager(npath, f.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	prefix := netip.MustParsePrefix(os.Getenv("MYDC_DOCKER_TEST_CIDR"))
	bridgeKey, taskKey := "network/managed-volume", "workload/task/tenant/app/database"
	bridge := network.BridgeSpec{Schema: 1, Network: "managed-volume", Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "managed-volume", Network: "managed-volume", Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}
	if err = n.Desired(bridgeKey, 1, 1, &bridge, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	w, err := workload.OpenManagerWithResources(wpath, f.Client, n, nil, activation)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	task := func() workload.ContainerSpec {
		s := workload.ContainerSpec{Schema: 1, Node: owner, Image: f.Image, Bridge: bridgeKey, BridgeGeneration: 1, IPv4: prefix.Addr().Next().Next(), Memory: 32 << 20, NanoCPU: 100000000, Process: &process}
		for _, e := range entries {
			s.Volumes = append(s.Volumes, workload.VolumeMount{Scope: e.scope, Consumer: e.consumer, NativeKey: e.key, NativeGeneration: 1, Target: "/" + e.scope.ID})
		}
		return s
	}
	setNodes := func(id string, allowed bool) {
		t.Helper()
		catalog, e := policy.Catalog(read().State)
		if e != nil {
			t.Fatal(e)
		}
		tenant, _ := catalog.Tenant("tenant")
		nodes := []string(nil)
		if allowed {
			nodes = []string{cfg.Node.ID}
		}
		submit(id, "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: nodes})
	}
	refsFor := func(resource reconcile.Resource, operation uint64) []volumes.Activation {
		refs := []volumes.Activation{}
		for _, e := range entries {
			refs = append(refs, volumes.Activation{Scope: e.scope, Consumer: e.consumer, NativeKey: e.key, NativeGeneration: 1, TaskKey: taskKey, Task: resource, Operation: operation})
		}
		return refs
	}
	releaseShared := func(refs []volumes.Activation, id string) {
		t.Helper()
		for i, r := range refs {
			proof, e := activation.Gone(ctx, r, node.Identity.Private)
			if e != nil {
				t.Fatal(e)
			}
			registry, e := policy.Volumes(read().State)
			if e != nil {
				t.Fatal(e)
			}
			core, _ := registry.Volume(r.Scope)
			submit(id+entries[i].scope.ID, "release-volume", core.Revision(), proof)
		}
	}
	// First original Apply creates one exact container, but current shared
	// authority denies Start. Drain must retire THAT Apply, not fake success.
	reopenLocal := func() {
		t.Helper()
		for _, close := range []func() error{w.Close, n.Close, activation.Close, native.Close} {
			if e := close(); e != nil {
				t.Fatal(e)
			}
		}
		native, err = volumes.OpenNative(filepath.Join(root, "native.db"), f.Client)
		if err != nil {
			t.Fatal(err)
		}
		activation, err = volumes.OpenActivations(path, native, f.Client, clusterID, node.Identity.Public, authority)
		if err != nil {
			t.Fatal(err)
		}
		n, err = network.OpenManager(npath, f.Client)
		if err != nil {
			t.Fatal(err)
		}
		w, err = workload.OpenManagerWithResources(wpath, f.Client, n, nil, activation)
		if err != nil {
			t.Fatal(err)
		}
	}
	setNodes("initial-deny", false)
	spec := task()
	if err = w.Desired(taskKey, 1, 1, &spec, 4); err != nil {
		t.Fatal(err)
	}
	blocker, e := native.Pin(ctx, entries[1].key, "test-unsent-blocker", 1)
	if e != nil {
		t.Fatal(e)
	}
	if err = w.Step(ctx, taskKey); err == nil {
		t.Fatal("blocked native pin allowed SDK Create")
	}
	preparedRecord, e := w.View(taskKey)
	if e != nil || preparedRecord.State.Pending == nil || preparedRecord.State.LastID != 1 {
		t.Fatal("lost original precreate Apply", e)
	}
	preparedRefs := refsFor(preparedRecord.State.Pending.Target, 1)
	if yes, e := activation.CreatePreparedAll(preparedRefs); e != nil || !yes {
		t.Fatal("missing positive SDK no-Create fact", e)
	}
	objects, e := f.Client.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filter})
	if e != nil || len(objects.Items) != 0 {
		t.Fatal("SDK Create before all original pins", e)
	}
	if e = native.Return(blocker); e != nil {
		t.Fatal(e)
	}
	reopenLocal()
	if yes, e := activation.CreatePreparedAll(preparedRefs); e != nil || !yes {
		t.Fatal("same DB lost no-Create checkpoint", e)
	}
	if err = w.Step(ctx, taskKey); err == nil {
		t.Fatal("revoked first writer started")
	}

	first, err := w.View(taskKey)
	if err != nil || first.State.Pending == nil || first.State.Applied.Present || first.State.Pending.ID != 1 {
		t.Fatal("original Apply lost", err)
	}
	firstRefs := refsFor(first.State.Pending.Target, 1)
	if err = w.Desired(taskKey, 2, 1, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("original Apply retirement", err)
	}
	closed, err := w.View(taskKey)
	if err != nil || closed.State.Pending != nil || closed.State.Applied.Present || closed.State.LastID != 1 {
		t.Fatal("retirement fabricated Apply or new ID", err)
	}
	if gone, e := w.Gone(ctx, taskKey, 2, 1); e != nil || !gone {
		t.Fatal("original task closure", e)
	}
	releaseShared(firstRefs, "first-release-")
	setNodes("initial-restore", true)
	for i := range entries {
		e := &entries[i]
		registry, er := policy.Volumes(read().State)
		if er != nil {
			t.Fatal(er)
		}
		core, _ := registry.Volume(e.scope)
		submit(e.scope.ID+"-writer2", "acquire-volume", core.Revision(), control.VolumeAcquire{Scope: e.scope, Consumer: "database", Generation: 2, Writable: true})
		registry, er = policy.Volumes(read().State)
		if er != nil {
			t.Fatal(er)
		}
		core, _ = registry.Volume(e.scope)
		e.consumer = core.Consumers()[0]
	}
	spec = task()
	if err = w.Desired(taskKey, 3, 2, &spec, 4); err != nil {
		t.Fatal(err)
	}
	closeOnPermit = syncFault
	err = w.Step(ctx, taskKey)
	failedNativeID := ""
	if syncFault {
		if !closedStore || err == nil {
			t.Fatal("actual activation store sync failure not exercised", err)
		}
		original, e := w.View(taskKey)
		if e != nil || original.State.Pending == nil || original.State.Pending.ID != 2 || original.State.Pending.Phase != reconcile.RecoveryRequired || original.State.Applied.Present {
			t.Fatal("failed sync lost original Apply/Unknown", e)
		}
		identity, e := f.Client.Identity("container", taskKey, original.State.Pending.Target)
		if e != nil {
			t.Fatal(e)
		}
		got, e := f.Client.API.ContainerInspect(ctx, identity.Name, client.ContainerInspectOptions{})
		if e != nil || got.Container.State.Running || got.Container.State.Status != "created" {
			t.Fatal("native Start before whole permit batch sync", e)
		}
		failedNativeID = got.Container.ID
		for _, ref := range refsFor(original.State.Pending.Target, 2) {
			checkpoint, e := activation.Checkpoint(ref)
			if e != nil || checkpoint.Starting != nil {
				t.Fatal("failed permit sync published a Starting gate", e)
			}
			row, e := native.View(ref.NativeKey)
			if e != nil || len(row.Consumers) != 1 {
				t.Fatal("sync failure dropped original native Volume pin", e)
			}
		}
		reopenLocal()
		restored, e := w.View(taskKey)
		if e != nil || !reflect.DeepEqual(restored, original) {
			t.Fatal("same DB changed original pending Apply", e)
		}
		err = w.Step(ctx, taskKey)
		manifest["SyncFailure"] = map[string]any{"native_id": failedNativeID, "apply_id": 2, "original_volume_pins": len(entries), "status_before_reopen": "created", "starting_published": false}
		saveManifest()
	}
	if err != nil {
		t.Fatal("actual parent A2 multi-volume Start", err)
	}
	applied, err := w.View(taskKey)
	if err != nil || applied.State.LastID != 2 || !applied.State.Applied.Present {
		t.Fatal("original second Apply", err)
	}
	refs := refsFor(applied.State.Applied, 2)
	status, err := w.Status(ctx, taskKey)
	if err != nil || !status.Running {
		t.Fatal(err)
	}
	nativeID := status.NativeID
	if syncFault && nativeID != failedNativeID {
		t.Fatal("failed sync replaced original native container")
	}
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
			t.Fatal("two nonroot writer health", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	// Reopen every local owner DB while retaining the original native object.
	reopenLocal()
	setNodes("revoke-running", false)
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("original Running needed new grant", err)
	}
	status, err = w.Status(ctx, taskKey)
	if err != nil || status.NativeID != nativeID {
		t.Fatal("reopen changed ID", err)
	}
	timeout := 1
	if _, err = f.Client.API.ContainerStop(ctx, nativeID, client.ContainerStopOptions{Timeout: &timeout}); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err == nil {
		t.Fatal("revoked node restarted writer")
	}
	for _, r := range refs {
		if _, err = activation.Fence(r, r.Consumer.OwnerRevision); err != nil {
			t.Fatal("durable fence", err)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = activation.Close(); err != nil {
		t.Fatal(err)
	}
	activation, err = volumes.OpenActivations(path, native, f.Client, clusterID, node.Identity.Public, authority)
	if err != nil {
		t.Fatal(err)
	}
	w, err = workload.OpenManagerWithResources(wpath, f.Client, n, nil, activation)
	if err != nil {
		t.Fatal(err)
	}
	setNodes("restore-after-fence", true)
	if err = w.Step(ctx, taskKey); err == nil {
		t.Fatal("restored grant bypassed persistent fence")
	}
	if err = w.Desired(taskKey, 4, 2, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("original Remove/Apply binding", err)
	}
	done, err := w.View(taskKey)
	if err != nil || done.State.Pending != nil || done.State.Applied.Present || done.State.LastID != 3 {
		t.Fatal("ordinary Remove changed original bindings", err)
	}
	if gone, e := w.Gone(ctx, taskKey, 4, 2); e != nil || !gone {
		t.Fatal("final task closure", e)
	}
	releaseShared(refs, "last-release-")
	for _, e := range entries {
		retained, er := f.Client.API.VolumeInspect(ctx, e.ready.Owner.Native, client.VolumeInspectOptions{})
		if er != nil {
			t.Fatal("retain", er)
		}
		data, er := os.ReadFile(filepath.Join(retained.Volume.Mountpoint, "marker"))
		if er != nil || string(data) != "volume-original" {
			t.Fatal("retained nonroot data", er)
		}
		if er = native.DeleteDesired(e.key, 2, 1); er != nil {
			t.Fatal(er)
		}
		if er = native.Step(ctx, e.key); er != nil {
			t.Fatal(er)
		}
		if gone, er := native.Gone(ctx, e.key, 2, 1); er != nil || !gone {
			t.Fatal("native Gone", er)
		}
	}
	if err = n.Desired(bridgeKey, 2, 1, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	t.Log("actual parent Workload A2/Bridge/two named NoCopy mounts -> quorum-denied original Apply/Retiring -> original shared release -> new generation Apply -> one process/nonroot writes both Volumes -> same DB/ID -> revoked Running retained/stopped denied -> durable all-volume fence -> original Remove/Apply bindings -> signed local/shared return -> retained data/native cleanup")
}
