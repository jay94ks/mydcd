// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/jay94ks/seafield/tests/registryfixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// The existing fixture owns two private namespaces/Engines, daemon shutdown,
// native journal cleanup and kernel baseline rollback. This scenario adds only
// inputs to the normal CLI/controller/Volume move, never an alternate mover.
func testManagedNodeDrain(t *testing.T, ctx context.Context, a *Runtime, root, products string, configs, sockets [2]string, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), run func(int, []string, ...string) ([]byte, error)) {
	t.Helper()
	p := a.controlPolicy
	backend := os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if !filepath.IsAbs(backend) {
		t.Fatal("user-prebuilt static backend required")
	}
	registry := registryfixture.OpenPreparedAt(t, backend, container.Config{Cmd: []string{"/backend"}, Env: []string{"SFC_VOLUME_FIXTURE=1", "SFC_READINESS_FIXTURE=1", "SFC_GRACEFUL_FIXTURE=1"}, User: "10001:10001", Labels: map[string]string{"org.sfc.test.owner": os.Getenv("SFC_KERNEL_TEST_OWNER")}}, "192.0.2.1:0")
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	change("drain/trust", "set-trust", tenant.Revision, control.TrustChange{Tenant: "tenant", Add: []access.TrustRule{access.TrustRule{Registry: registry.Registry, Repository: "fixture"}}})
	var docker [2]*engine.Client
	var keys [2][32]byte
	public := sqlPublicFixture{Images: map[string]string{registry.Reference: registry.ConfigDigest}}
	for n, path := range configs {
		cfg, err := loadTestNode(path)
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.Load(cfg.Node.IdentityDir)
		if err != nil {
			t.Fatal(err)
		}
		keys[n] = id.Public
		clear(id.Private)
		docker[n], err = engine.Open(ctx, "unix://"+sockets[n], engine.Owner(p.Cluster, keys[n]))
		if err != nil {
			t.Fatal(err)
		}
		defer docker[n].Close()
		info, err := docker[n].API.Info(ctx, client.InfoOptions{})
		if err != nil {
			t.Fatal(err)
		}
		public.EngineIDs[n] = info.Info.ID
	}
	if public.EngineIDs[0] == "" || public.EngineIDs[0] == public.EngineIDs[1] {
		t.Fatal("independent private Engines required")
	}
	// The existing SQL cleanup helper consumes this exact owned image/Engine
	// manifest even when acceptance or a transfer fails before app down.
	publicRaw, _ := json.Marshal(public)
	if err := os.WriteFile(filepath.Join(root, "sql-fixture.json"), publicRaw, 0644); err != nil {
		t.Fatal(err)
	}
	definition := tenancy.TUNDefinition{Tenant: "tenant", Name: "drain-lan", GatewayMode: network.ManagedGatewayMode}
	for n, node := range []string{"node-a", "node-b"} {
		definition.Members = append(definition.Members, tenancy.TUNNode{Node: node, Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix(fmt.Sprintf("198.19.90.%d/28", n*16)), Gateway: netip.MustParseAddr(fmt.Sprintf("198.19.90.%d", n*16+1)), MTU: 1280}}})
		for _, tenant := range []string{"", "tenant"} {
			change("drain/native-budget/"+tenant+"/"+node, "set-volume-backup-limit", 0, control.VolumeBackupLimit{Tenant: tenant, Node: node, Bytes: 256 << 10, Count: 2, StagingBytes: 256 << 10, StagingCount: 2, Original: &control.OriginalVolumeLimit{Bytes: 512 << 10, Count: 4}})
		}
	}
	resources, _ := p.Resources(read().State)
	change("drain/network", "create-tun-network", resources.Networks.Revision(), definition)
	remote := sfcp.Peer{ID: "node-b", Endpoint: "192.0.2.2:44101", Policy: sfcp.Policy{Key: sfcp.Identity(keys[1]), Member: true, Read: true, Respond: true}}
	observe := func(n int, key string) (ModuleObservation, error) {
		var raw []byte
		var err error
		if n == 0 {
			raw, err = a.observeManaged(ctx, key, read())
		} else {
			reply, callErr := cluster.CallManagement(ctx, a.Mesh, a.Identity, p.Cluster, remote, cluster.ManagementRequest{Method: "observe", Key: key})
			raw, err = reply.Data, callErr
		}
		var row ModuleObservation
		if err == nil {
			err = json.Unmarshal(raw, &row)
		}
		return row, err
	}
	var bridges [2]string
	var nativeConsumers [2]int
	wait("both approved members serve the same management TUN name before drain", func() bool {
		resources, err := p.Resources(read().State)
		sources, sourceErr := resources.Networks.TUNSources("tenant", "drain-lan")
		if err != nil || sourceErr != nil || len(sources) != 2 {
			return false
		}
		for _, source := range sources {
			n := 0
			if source.Network.Node == "node-b" {
				n = 1
			}
			for _, key := range []string{source.BridgeKey, source.TunnelKey} {
				row, err := observe(n, key)
				if key == "" || err != nil || !row.Ready || row.NativeID == "" {
					return false
				}
				if key == source.BridgeKey {
					bridges[n] = key
					nativeConsumers[n] = row.Journal.Consumers
				}
			}
		}
		return true
	})
	managementBefore := read().State.Objects(tenancy.ManagedNetworkSourcePrefix)
	profile, home, file := filepath.Join(root, "drain-client.yaml"), filepath.Join(root, "drain-home"), filepath.Join(root, "drain-app.yaml")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%s', endpoint: '192.0.2.1:44101', voter: true}\n", p.Cluster, a.Identity.Actor())), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(args ...string) []byte {
		t.Helper()
		body, diagnostic, err := runManagedCLICommand(ctx, filepath.Join(products, "sfc"), home, profile, args, nil)
		if err != nil {
			t.Fatal("actual drain CLI", args, err, string(diagnostic), string(body))
		}
		return body
	}
	call("wallet", "init")
	call("login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin/key.pem"))
	document := fmt.Sprintf(`name: app
services:
 web:
  image: %s
  command: [/backend]
  user: '10001:10001'
  cpus: 0.1
  mem_limit: 32m
  networks: {lan: {}}
  volumes: [data:/data, logs:/logs]
  healthcheck: {test: [CMD, /backend, --volume-probe], interval: 1s, timeout: 1s, retries: 2}
  x-sfc: {node: node-a, ready: {http: /readyz, port: 8080}}
networks:
 lan: {external: true, name: drain-lan}
volumes:
 data:
  x-sfc: {node: node-a, size: 131072, uid: 10001, gid: 10001, mode: '0750'}
 logs:
  x-sfc: {node: node-a, size: 131072, uid: 10001, gid: 10001, mode: '0750'}
`, registry.Reference)
	if err := os.WriteFile(file, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	call("compose", "up", "--tenant", "tenant", "--operation", "before-drain", "-f", file, "--no-input")
	taskKey := deployment.ResourceKey("task", "tenant", "app", "web")
	wait("original actual Task and Volume ready", func() bool {
		apps, err := p.Apps(read().State)
		e, found := apps.Execution("tenant", "app")
		stage, _ := e.Stage(taskKey)
		return err == nil && found && e.Status() == "Succeeded" && stage.Observation != nil && stage.Observation.Healthy
	})
	volumesBefore, _ := p.Volumes(read().State)
	original, found := volumesBefore.Native("tenant", "app", "data")
	originalLogs, logsFound := volumesBefore.Native("tenant", "app", "logs")
	oldTask, err := a.workload.Status(ctx, taskKey)
	if !found || !logsFound || err != nil || !oldTask.Ready {
		t.Fatal("original native source", err)
	}
	var plan control.NodeDrainPlan
	if err := json.Unmarshal(call("node", "drain-plan", "node-a", "--operation", "drain-original"), &plan); err != nil || len(plan.Jobs) != 1 || len(plan.Tasks) != 1 || len(plan.Blockers) != 0 || !plan.Tasks[0].Movable || plan.Tasks[0].Target != "node-b" || plan.Jobs[0].Move == nil || len(plan.Jobs[0].AdditionalMoves) != 1 {
		t.Fatal("actual drain plan did not select the approved original network/Volume target", err, plan.Blockers)
	}
	children := append([]control.NodeDrainVolumeMove{*plan.Jobs[0].Move}, plan.Jobs[0].AdditionalMoves...)
	call("node", "drain", "node-a", "--operation", "drain-original", "--expected-revision", fmt.Sprint(plan.Expected), "--request-id", "drain-original-request")
	var job control.VolumeMove
	var move volumes.Move
	wait("original drain child reaches actual fence/copy/target activation and consumer settlement", func() bool {
		v, err := p.Volumes(read().State)
		if err != nil {
			return false
		}
		for _, child := range children {
			current, fact, found := v.Move(control.VolumeMoveSelection{Scope: child.Begin.Scope, ID: child.Begin.ID})
			if !found || fact.Phase != volumes.Completed || fact.Fence == nil || fact.Manifest == nil || fact.ReaderClosed == nil || fact.Activated == nil || fact.SourceCleanup == nil || fact.TargetCleanup == nil {
				return false
			}
			if child.Begin.Scope.ID == "data" {
				job, move = current, fact
			}
		}
		return job.Binding.Scope.ID == "data"
	})
	if job.Origin.Change.Action != "drain-node" || job.App == nil || job.App.Target == nil || job.Binding.Source != original.Owner || job.Binding.Target.Node != "node-b" || job.Binding.Target.Key != keys[1] {
		t.Fatal("child detached from the original signed drain or native owner")
	}
	for _, original := range []volumes.NativeReady{original, originalLogs} {
		v, _ := p.Volumes(read().State)
		var selected control.VolumeMove
		for _, child := range children {
			if child.Begin.Scope == original.Spec.Scope {
				selected, _, _ = v.Move(control.VolumeMoveSelection{Scope: child.Begin.Scope, ID: child.Begin.ID})
			}
		}
		cold, err := a.activations.ColdSource(ctx, original)
		if err != nil {
			t.Fatal("original writer record", err)
		}
		fence, err := a.activations.Checkpoint(cold.Writer)
		if err != nil || selected.App == nil || selected.App.Target == nil || selected.App.Target.Operation != job.App.Target.Operation || fence.FenceThrough < selected.Binding.SourceOwnerRevision {
			t.Fatal("drain did not keep every actual original writer fence in the same app group", err)
		}
	}
	if _, err := docker[0].API.ContainerInspect(ctx, oldTask.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("old source container did not positively close", err)
	}
	var status control.NodeDrainStatus
	if err := json.Unmarshal(call("node", "drain-status", "node-a", "--operation", "drain-original"), &status); err != nil || status.Total != 1 || status.Moved != 1 || status.Blocked != 0 {
		t.Fatal("drain did not report original moved/total", err, status)
	}
	directory, _ := p.Members(read().State)
	if !directory.Cordon("node-a").Enabled || !directory.MemberKey(keys[0]) || !directory.MemberKey(keys[1]) {
		t.Fatal("drain removed a member or reopened new source placement")
	}
	wait("same app and original management name serve target native Task", func() bool {
		apps, err := p.Apps(read().State)
		e, found := apps.Execution("tenant", "app")
		stage, _ := e.Stage(taskKey)
		return err == nil && found && e.ActiveOperation() == job.App.Target.Operation && e.Status() == "Succeeded" && stage.Observation != nil && stage.Observation.Healthy && stage.Observation.Owner == keys[1]
	})
	v, _ := p.Volumes(read().State)
	targetVolume, found := v.Native("tenant", "app", "data")
	if !found || targetVolume.Owner != job.Binding.Target {
		t.Fatal("same logical Volume lost target native")
	}
	apps, _ := p.Apps(read().State)
	e, _ := apps.Execution("tenant", "app")
	stage, _ := e.Stage(taskKey)
	bound, found := apps.Binding(deployment.ObjectRef{Key: taskKey, Revision: stage.Result.Revision, Generation: stage.Result.Generation})
	if !found || len(bound.Pins()) != 2 || move.Activated.Consumer.Owner != targetVolume.Owner {
		t.Fatal("same target Task lost one of its atomically moved Volume consumers")
	}
	native, err := docker[1].API.ContainerInspect(ctx, stage.Observation.Native, client.ContainerInspectOptions{})
	if err != nil || native.Container.NetworkSettings == nil || native.Container.State == nil || !native.Container.State.Running {
		t.Fatal("actual target container", err)
	}
	mounted := 0
	for _, mount := range native.Container.Mounts {
		if mount.Name == targetVolume.Owner.Native && mount.RW {
			mounted++
		}
	}
	if mounted != 1 {
		t.Fatal("target did not consume the exact moved native Volume")
	}
	bridge, err := observe(1, bridges[1])
	if err != nil || !bridge.Ready {
		t.Fatal("same management network target", err)
	}
	joined := false
	for _, endpoint := range native.Container.NetworkSettings.Networks {
		joined = joined || endpoint != nil && endpoint.NetworkID == bridge.NativeID && definition.Members[1].Pools[0].Prefix.Contains(endpoint.IPAddress)
	}
	if !joined {
		t.Fatal("target did not consume the original drain-lan target member")
	}
	disk, err := docker[1].API.VolumeInspect(ctx, targetVolume.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	marker, err := run(1, nil, "cat", filepath.Join(disk.Volume.Mountpoint, "marker"))
	if err != nil || strings.TrimSpace(string(marker)) != "volume-original" {
		t.Fatal("actual target did not retain original Volume data", err)
	}
	call("compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "after-drain-down")
	wait("target down returns original Task/Volume/network consumers", func() bool {
		apps, err := p.Apps(read().State)
		i, found := apps.Inventory("tenant", "app")
		_, retiring := i.Retirement()
		v, volumeErr := p.Volumes(read().State)
		if err != nil || volumeErr != nil || !found || retiring || len(apps.Bindings().Live()) != 0 {
			return false
		}
		for _, ready := range []volumes.NativeReady{original, originalLogs} {
			state, found := v.Volume(ready.Spec.Scope)
			if !found || len(state.Consumers()) != 0 {
				return false
			}
		}
		for n, key := range bridges {
			row, err := observe(n, key)
			if err != nil || !row.Ready || row.Journal.Consumers != nativeConsumers[n] || read().State.Object(key) != managementBefore[key] {
				return false
			}
		}
		return true
	})
	if err := a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	// Keep the original retained volumes and management sources for the
	// fixture's existing owner-journal cleanup after BOTH producers join.
	t.Log("actual CLI drain on preapproved two-member TUN: same app/name, dynamic target IP, original Volume fence/copy/consumer settlement, membership preserved, final native down")
}
