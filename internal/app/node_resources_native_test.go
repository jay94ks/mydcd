// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

// Uses the existing owned Docker/CLI/Secret/Volume/Ingress fixture and rollback.
// No zero-count proof is supplied by the test. One native owner and a joined
// control exercise live work before positive closure and SDK owner removal.
func TestRealBoundaryManagedNodeResourceIsolationAndRestore(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppNodeIsolation, true, true, true)
}

func verifyManagedNodeResourceIsolation(t *testing.T, ctx context.Context, runtime **Runtime, cfg config.Node, root string, original []byte, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), networkKey string, checks []func(), addControl func() *Runtime) {
	t.Helper()
	r := *runtime
	key := r.Identity.Public
	nodeID := cfg.Node.ID
	taskKey := deployment.ResourceKey("task", "tenant", "app", "web")
	wait("original resource-bearing app healthy", func() bool {
		apps, err := p.Apps(read().State)
		if err != nil {
			return false
		}
		execution, found := apps.Execution("tenant", "app")
		stage, ok := execution.Stage(taskKey)
		return found && ok && execution.Status() == "Succeeded" && stage.Result != nil && stage.Observation != nil && stage.Observation.Applied && stage.Observation.Healthy
	})
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	execution, _ := apps.Execution("tenant", "app")
	stage, _ := execution.Stage(taskKey)
	task := deployment.ObjectRef{Key: taskKey, Generation: stage.Result.Generation, Revision: stage.Result.Revision}
	binding, found := apps.Binding(task)
	status, err := r.workload.Status(ctx, taskKey)
	if err != nil || !status.Ready || !found || len(binding.Pins()) != 1 || len(binding.Grants()) != 1 {
		t.Fatal("original native Task/writer/Secret binding", err)
	}
	verifyManagedIngressServing(t, ctx, r, cfg, p, read, wait)
	if len(checks) != 3 {
		t.Fatal("original CLI deploy/down/result checks required")
	}
	checks[0]()
	successor := addControl()
	joinedStatus, err := r.workload.Status(ctx, taskKey)
	if successor == nil || err != nil || !joinedStatus.Running || joinedStatus.NativeID != status.NativeID || joinedStatus.StartedAt != status.StartedAt {
		t.Fatal("live node addition changed the original native workload", err)
	}
	// Prepare the management retirement before isolation. After isolation only
	// drain/fence/empty-member retirement is admitted through this ingress.
	projection, err := p.ProjectResources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	network := projection.ManagedSources[networkKey].Network
	target := network
	target.Generation, target.Revision, target.PendingChange = 0, 0, 0
	change("node-network-retirement-plan", "plan-network-change", network.Revision, control.NetworkChangePlan{Tenant: network.Tenant, ID: network.ID, Change: "node-network-retirement", Target: target})
	wait("actual runtime node configuration published", func() bool {
		d, err := p.Members(read().State)
		return err == nil && d.Runtime != nil
	})
	d, _ := p.Members(read().State)
	topology, _ := d.Topology()
	node, _ := topology.Node(nodeID)
	nodeCLI := func(method, operation, request string, revision, epoch uint64, resume bool) state.Result {
		t.Helper()
		args := []string{"node", method, nodeID, "--operation", operation, "--request-id", request, "--expected-revision", strconv.FormatUint(revision, 10), "--node-epoch", strconv.FormatUint(epoch, 10)}
		if resume {
			args = append(args, "--resume-original")
		}
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
		var reply struct {
			Status           string
			NativeCompletion bool `json:"native_completion"`
			Result           *state.Result
		}
		if err != nil || json.Unmarshal(out, &reply) != nil || reply.Status != "accepted" || reply.NativeCompletion || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal("actual node CLI acceptance/result", args, err, string(diagnostic), string(out))
		}
		return *reply.Result
	}
	// Open a real request before isolation. The original listener/request is
	// independent of the control transition and must remain in the IO census
	// until its own deadline/drain/cleanup actually closes it.
	ingressKey := deployment.ResourceKey("ingress", "tenant", "app", "http")
	spec := projection.Goals[ingressKey].Ingress
	if spec == nil || len(spec.Listeners) == 0 {
		t.Fatal("original managed ingress listener required")
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://"+spec.Listeners[0].Address+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest.Host = "app.test"
	response, err := httpClient.Do(httpRequest)
	if err != nil {
		t.Fatal("original ingress stream", err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil || response.StatusCode != http.StatusOK || line != "data: ready\n" {
		t.Fatal("original native SSE response", response.StatusCode, line, err)
	}
	streamDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, reader)
		close(streamDone)
	}()
	defer func() {
		cancelRequest()
		_ = response.Body.Close()
		<-streamDone
	}()
	wait("actual held ingress request appears in local node census", func() bool {
		activity, err := r.nodeLocalActivity(ctx)
		return err == nil && activity.Flows > 0
	})
	isolateRevision, isolateEpoch := node.Revision, topology.Epoch()
	isolateReceipt := nodeCLI("isolate", "isolate-resource-owner", "node-isolate-with-live-app", isolateRevision, isolateEpoch, false)
	d, err = p.Members(read().State)
	view, found := d.NodeView(nodeID)
	activity, activityErr := p.NodeActivity(read().State, key)
	if err != nil || activityErr != nil || !found || view.AdmitsWork || view.Node.Phase != lifecycle.Isolating || view.Node.Closure != nil || activity.Resources == 0 || activity.Writers == 0 || activity.Leases == 0 {
		t.Fatal("live resources were hidden behind a completed node closure", activity, err, activityErr)
	}
	request := control.AppBindingRequest{Task: task, Digest: binding.Digest()}
	// The same signed down/retirement collector proves actual native Gone,
	// writer/input release, retained bytes and Snapshot/same-DB non-resurrection.
	verifyAutomaticAppRetirement(t, ctx, runtime, cfg, p, read, change, wait, request, status.NativeID, true, checks...)
	wait("original ingress stream really ends before owner closure", func() bool {
		select {
		case <-streamDone:
			return true
		default:
			return false
		}
	})
	r = *runtime
	d, err = p.Members(read().State)
	view, found = d.NodeView(nodeID)
	if err != nil || !found || view.Node.Phase != lifecycle.Isolating || view.Node.Closure != nil {
		t.Fatal("retained management native was ignored after same-DB restart", err)
	}
	if _, err := r.network.Inspect(ctx, networkKey); err != nil {
		t.Fatal("app down removed a borrowed management network", err)
	}
	change("node-network-drain", "drain-network", network.Revision, control.NetworkSelection{Tenant: network.Tenant, ID: network.ID})
	var closure tenancy.NetworkClosure
	wait("original management network owner closure", func() bool {
		raw, err := r.observeManaged(ctx, networkKey, read())
		var observation ModuleObservation
		return err == nil && json.Unmarshal(raw, &observation) == nil && len(observation.Retirement) > 0 && json.Unmarshal(observation.Retirement, &closure) == nil
	})
	resources, err := p.Resources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	reservation, found := resources.Networks.Change(network.Tenant, network.ID)
	if !found {
		t.Fatal("original management retirement reservation lost")
	}
	change("node-network-fence", "fence-network-change", reservation.Revision, control.NetworkChangeFence{Tenant: network.Tenant, ID: network.ID, Generation: reservation.Generation, Closed: closure})
	resources, _ = p.Resources(read().State)
	reservation, _ = resources.Networks.Change(network.Tenant, network.ID)
	change("node-network-retire", "reconfigure-tun-network", resources.Networks.Revision(), control.NetworkReconfigure{Target: tenancy.TUNDefinition{Tenant: network.Tenant, Name: network.Logical, Members: []tenancy.TUNNode{}}, Members: []tenancy.NetworkChangeVersion{{Tenant: network.Tenant, ID: network.ID, Generation: reservation.Generation, Revision: reservation.Revision}}})
	wait("runtime actual resource-free owner proof", func() bool {
		d, err := p.Members(read().State)
		view, found := d.NodeView(nodeID)
		return err == nil && found && view.Node.Phase == lifecycle.Isolated && view.Node.Closure != nil
	})
	d, _ = p.Members(read().State)
	topology, _ = d.Topology()
	view, _ = d.NodeView(nodeID)
	proof := *view.Node.Closure
	if !proof.Closed || proof.Ready || proof.ConfigurationIndex != topology.Configuration().Index || !ed25519.Verify(key[:], lifecycle.ProofBytes(proof), proof.Signature) || d.WorkKey(key) || !d.MemberKey(key) {
		t.Fatal("runtime closure identity/configuration or control/Work boundary")
	}
	nodeCLI("restore", "restore-resource-owner", "node-restore-original-owner", view.Node.Revision, topology.Epoch(), false)
	wait("fresh original-key native readiness", func() bool {
		d, err := p.Members(read().State)
		view, found := d.NodeView(nodeID)
		return err == nil && found && d.WorkKey(key) && view.Node.Phase == lifecycle.Active && view.Node.Closure != nil && view.Node.Closure.Ready && view.Node.Closure.Operation == "restore-resource-owner"
	})
	if (*runtime).Identity.Public != key {
		t.Fatal("restore replaced the original owner key")
	}
	d, err = p.Members(read().State)
	beforeReplay, found := d.NodeView(nodeID)
	if err != nil || !found {
		t.Fatal("restored node before original CLI result replay", err)
	}
	replayedReceipt := nodeCLI("isolate", "isolate-resource-owner", "node-isolate-with-live-app", isolateRevision, isolateEpoch, true)
	d, err = p.Members(read().State)
	afterReplay, found := d.NodeView(nodeID)
	if err != nil || !found || replayedReceipt != isolateReceipt || afterReplay.Node.Revision != beforeReplay.Node.Revision || afterReplay.Node.Phase != lifecycle.Active || afterReplay.Node.Closure == nil || afterReplay.Node.Closure.Operation != "restore-resource-owner" {
		t.Fatal("original isolate CLI result replay changed restored owner", err)
	}
	resources, err = p.Resources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	change("restore-owner-new-network-generation", "create-tun-network", resources.Networks.Revision(), tenancy.TUNDefinition{Tenant: network.Tenant, Name: network.Logical, GatewayMode: network.GatewayMode, Members: []tenancy.TUNNode{{Node: nodeID, Pools: network.Pools, Addresses: network.TunnelAddresses}}})
	projection, err = p.ProjectResources(read().State)
	if err != nil || projection.ManagedSources[networkKey].Network.Generation <= network.Generation {
		t.Fatal("restore reused a retired management network generation", err)
	}
	input, err := deployment.ParseApp(original)
	if err != nil {
		t.Fatal(err)
	}
	volume, found := input.Volumes["data"]
	if !found {
		t.Fatal("original retained Volume declaration missing")
	}
	delete(input.Volumes, "data")
	input.Volumes["restored"] = volume
	for name, service := range input.Services {
		for i := range service.Volumes {
			if service.Volumes[i].Source == "data" {
				service.Volumes[i].Source = "restored"
			}
		}
		input.Services[name] = service
	}
	body, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "node-restored-app.yaml")
	if err := os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
		if err != nil {
			t.Fatal("restored owner CLI", args, err, string(diagnostic), string(out))
		}
	}
	cli("compose", "up", "--tenant", "tenant", "--file", file, "--operation", "node-restored-rollout", "--no-input")
	wait("restored owner consumes real Secret/Volume/Task/Ingress", func() bool {
		a, err := p.Apps(read().State)
		e, found := a.Execution("tenant", "app")
		current, exists := e.Stage(taskKey)
		native, nativeErr := r.workload.Status(ctx, taskKey)
		return err == nil && nativeErr == nil && found && exists && e.ActiveOperation() == "node-restored-rollout" && e.Status() == "Succeeded" && current.Result != nil && current.Result.Generation > task.Generation && native.Ready && native.Running && native.NativeID != status.NativeID
	})
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"data", "restored"} {
		ready, found := registry.Native("tenant", "app", id)
		if !found {
			t.Fatal("retained/new Volume identity lost", id)
		}
		disk, err := r.docker.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		marker, err := os.ReadFile(filepath.Join(disk.Volume.Mountpoint, "marker"))
		if err != nil || string(marker) != "volume-original" {
			t.Fatal("original retained/new workload data", id, err)
		}
	}
	projection, err = p.ProjectResources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	removalNetwork := projection.ManagedSources[networkKey].Network
	removalTarget := removalNetwork
	removalTarget.Generation, removalTarget.Revision, removalTarget.PendingChange = 0, 0, 0
	change("plan-final-network-retirement", "plan-network-change", removalNetwork.Revision, control.NetworkChangePlan{Tenant: removalNetwork.Tenant, ID: removalNetwork.ID, Change: "final-network-retirement", Target: removalTarget})
	d, err = p.Members(read().State)
	topology, _ = d.Topology()
	view, found = d.NodeView(nodeID)
	if err != nil || !found {
		t.Fatal("live owner before removal", err)
	}
	nodeCLI("remove", "remove-resource-owner", "node-remove-with-live-app", view.Node.Revision, topology.Epoch(), false)
	d, err = p.Members(read().State)
	view, found = d.NodeView(nodeID)
	activity, activityErr = p.NodeActivity(read().State, key)
	if err != nil || activityErr != nil || !found || view.Node.Phase != lifecycle.Removing || view.Node.Pending == nil || view.Node.Pending.ID != "remove-resource-owner" || !d.MemberKey(key) || activity.Resources == 0 || activity.Writers == 0 {
		t.Fatal("live app owner removed without original resource closure", activity, err, activityErr)
	}
	cli("compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "node-restored-down")
	wait("restored owner returns all original consumers", func() bool {
		a, err := p.Apps(read().State)
		i, found := a.Inventory("tenant", "app")
		return err == nil && found && i.Quiescent() && len(a.Bindings().Live()) == 0
	})
	verifyPlannedManagedNetworkRetirement(t, ctx, r, p, read, change, wait, networkKey, removalNetwork, 0)
	wait("removed owner positive closure and actual successor configuration", func() bool {
		v, err := successor.Engine().Read(ctx, true)
		if err != nil {
			return false
		}
		d, err := p.Members(v.State)
		view, found := d.NodeView(nodeID)
		return err == nil && found && view.Node.Phase == lifecycle.Removed && view.Node.Closure != nil && view.Node.Closure.Closed && view.Node.Closure.Operation == "remove-resource-owner" && !d.MemberKey(key) && !d.ReplicationKey(key) && d.HistoricalMemberKey(key)
	})
	installed, err := successor.Engine().InstalledConfiguration(ctx, true)
	if err != nil || len(installed.Configuration.Servers) != 1 || string(installed.Configuration.Servers[0].ID) != successor.installation.record.Root.Self.ID || r.Engine().IsLeader() {
		t.Fatal("live owner removal did not finish actual SDK removal", installed, err)
	}
	t.Log("real live app -> actual control add/promotion with native identity preserved -> CLI isolate/pending -> down/whole release/retained bytes/Snapshot/same DB -> borrowed network closure/runtime Isolated proof -> CLI restore/original isolate replay preserves exact receipt and restored state -> second actual app -> CLI owner remove stays pending with resources/writer -> original app/network closure -> actual SDK RemoveServer with original historical key retained; one native Engine, leader-removal handoff is separate coverage, no remote packet/CD/KVM claim")
}
