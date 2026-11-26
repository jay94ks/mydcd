// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/desired"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/tests/enginefixture"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

func TestRealBoundaryDaemonDesiredDockerPlacementAndRetirement(t *testing.T) {
	testDaemonDesiredDocker(t, false, false)
}
func TestRealBoundaryDaemonQuorumServiceContinuity(t *testing.T) {
	testDaemonDesiredDocker(t, true, false)
}
func TestRealBoundaryDaemonIngressNetworkReferences(t *testing.T) {
	testDaemonDesiredDocker(t, false, true)
}
func testDaemonDesiredDocker(t *testing.T, quorum, withIngress bool) {
	tag := os.Getenv("MYDC_DOCKER_TEST_OWNER")
	if tag == "" {
		t.Skip("requires docs/testing/system-rollback.md prestate and explicit fixture owner")
	}
	clusterBytes, err := hex.DecodeString(os.Getenv("MYDC_MODULE_TEST_CLUSTER"))
	if err != nil || len(clusterBytes) != 32 {
		t.Fatal("explicit test cluster required", err)
	}
	clusterID := [32]byte(clusterBytes)
	prefix, err := netip.ParsePrefix(os.Getenv("MYDC_DOCKER_TEST_CIDR"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	t.Cleanup(cancel)
	root := t.TempDir()
	workspace, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	build := exec.CommandContext(ctx, "go", "build", "-p", "2", "-o", bin+string(os.PathSeparator), "./cmd/mydc", "./cmd/mydcd")
	build.Dir = workspace
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("products: %v %s", err, out)
	}
	names := []string{"a", "b"}
	if quorum {
		names = []string{"a", "b", "c", "d"}
	}
	keys := make([]*identity.Identity, len(names)+1)
	for i := range keys {
		keys[i], err = identity.Create(filepath.Join(root, fmt.Sprint("identity-", i)))
		if err != nil {
			t.Fatal(err)
		}
	}
	addresses := make([]string, len(names))
	for i := range addresses {
		socket, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		addresses[i] = socket.LocalAddr().String()
		if e = socket.Close(); e != nil {
			t.Fatal(e)
		}
	}
	owner := desired.Owner(clusterID, keys[0].Public)
	t.Logf("nativeOwner=%s cluster=%x CIDR=%s; a=nonvoter/modules b=voter/report receiver", owner, clusterID, prefix)
	fixture := enginefixture.Open(t, ctx, owner, tag)
	peers := ""
	for i, id := range names {
		peers += fmt.Sprintf("    - {id: %s, key: '%s', endpoint: '%s', voter: %t}\n", id, keys[i].Actor(), addresses[i], i != 0)
	}
	configs := make([]string, len(names))
	for i, id := range names {
		networkModule := "{enabled: false}"
		workloadModule := "{enabled: false}"
		ingressModule := "{enabled: false}"
		bootstrap := "false"
		if i == 1 {
			bootstrap = "true"
		}
		if i == 0 {
			networkModule = "{enabled: true, docker_socket: 'unix:///var/run/docker.sock'}"
			workloadModule = "{enabled: true}"
			if withIngress {
				ingressModule = "{enabled: true}"
			}
		}
		text := fmt.Sprintf("version: 1\ncommon:\n  cluster: '%x'\n  admin: '%s'\n  peers:\n%snode:\n  id: %s\n  state_dir: '%s'\n  identity_dir: '%s'\n  listen: '%s'\n  bootstrap: %s\nmodules:\n  network: %s\n  workload: %s\n  ingress: %s\n", clusterID, keys[len(names)].Actor(), peers, id, filepath.Join(root, "state-"+id), filepath.Join(root, fmt.Sprint("identity-", i)), addresses[i], bootstrap, networkModule, workloadModule, ingressModule)
		configs[i] = filepath.Join(root, id+".yaml")
		if err = os.WriteFile(configs[i], []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	clientFile := filepath.Join(root, "client.yaml")
	if err = os.WriteFile(clientFile, []byte(fmt.Sprintf("version: 1\ncluster: '%x'\nidentity_dir: '%s'\npeers:\n%s", clusterID, filepath.Join(root, fmt.Sprint("identity-", len(names))), peers)), 0600); err != nil {
		t.Fatal(err)
	}
	logs := make([]string, len(names))
	children := make([]*exec.Cmd, len(names))
	done := make([]chan error, len(names))
	stop := func(i int) {
		t.Helper()
		if children[i] == nil {
			return
		}
		if e := children[i].Process.Signal(syscall.SIGTERM); e != nil {
			t.Error("daemon stop", e)
		}
		select {
		case e := <-done[i]:
			if e != nil {
				b, _ := os.ReadFile(logs[i])
				t.Error("daemon exit", e, string(b))
			}
		case <-time.After(8 * time.Second):
			_ = children[i].Process.Kill()
			<-done[i]
			t.Error("daemon failed to stop")
		}
		children[i] = nil
	}
	t.Cleanup(func() {
		for i := range children {
			stop(i)
		}
		allLogs, _ := filepath.Glob(filepath.Join(root, "daemon-*.log"))
		for _, log := range allLogs {
			b, _ := os.ReadFile(log)
			t.Logf("daemon %s: %s", filepath.Base(log), b)
		}
	})
	start := func(i int) {
		t.Helper()
		logs[i] = filepath.Join(root, fmt.Sprintf("daemon-%d-%d.log", i, time.Now().UnixNano()))
		log, e := os.Create(logs[i])
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.CommandContext(ctx, filepath.Join(bin, "mydcd"), "--config", configs[i], "run")
		cmd.Stdout = log
		cmd.Stderr = log
		if e = cmd.Start(); e != nil {
			log.Close()
			t.Fatal(e)
		}
		children[i] = cmd
		done[i] = make(chan error, 1)
		go func() { e := cmd.Wait(); log.Close(); done[i] <- e }()
	}
	for i := range names {
		start(i)
	}
	cli := func(peer string, args ...string) (cluster.ManagementReply, error) {
		call, stop := context.WithTimeout(ctx, 4*time.Second)
		defer stop()
		argv := []string{"--config", clientFile, "--peer", peer, "--timeout", "3s"}
		argv = append(argv, args...)
		cmd := exec.CommandContext(call, filepath.Join(bin, "mydc"), argv...)
		out, e := cmd.Output()
		var reply cluster.ManagementReply
		if len(out) > 0 {
			if decodeErr := json.Unmarshal(out, &reply); decodeErr != nil {
				return reply, fmt.Errorf("CLI decode: %v %q", decodeErr, out)
			}
		}
		return reply, e
	}
	wait := func(what string, predicate func() bool) {
		t.Helper()
		tick := time.NewTicker(40 * time.Millisecond)
		defer tick.Stop()
		for {
			if predicate() {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("timeout: " + what)
			case <-tick.C:
				for i := range children {
					if children[i] != nil {
						select {
						case e := <-done[i]:
							b, _ := os.ReadFile(logs[i])
							children[i] = nil
							t.Fatalf("daemon %d exited: %v %s", i, e, b)
						default:
						}
					}
				}
			}
		}
	}
	wait("actual quorum status", func() bool { reply, e := cli("a", "status"); return e == nil && reply.Code == "ok" })
	sequence := 0
	submit := func(key string, value any, expected uint64, remove bool, want state.Code) state.Result {
		t.Helper()
		sequence++
		valueFile := filepath.Join(root, fmt.Sprintf("value-%d.json", sequence))
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(valueFile, b, 0600); e != nil {
			t.Fatal(e)
		}
		action := []string{"command", "--request", fmt.Sprintf("module-%d", sequence), "--expected", fmt.Sprint(expected), "set", key, valueFile}
		if remove {
			action = []string{"command", "--request", fmt.Sprintf("module-%d", sequence), "--expected", fmt.Sprint(expected), "delete", key}
		}
		cmd := exec.CommandContext(ctx, filepath.Join(bin, "mydc"), append([]string{"--config", clientFile}, action...)...)
		command, e := cmd.Output()
		if e != nil {
			t.Fatal("encode command", e)
		}
		commandFile := filepath.Join(root, fmt.Sprintf("command-%d.bin", sequence))
		if e = os.WriteFile(commandFile, command, 0600); e != nil {
			t.Fatal(e)
		}
		reply, e := cli("a", "submit", commandFile)
		if reply.Committed == nil || reply.Committed.Result.Code != want || e != nil && want == state.Applied {
			t.Fatalf("%s commit: %+v err=%v", key, reply, e)
		}
		return reply.Committed.Result
	}
	observe := func(peer, key string) (ModuleObservation, error) {
		reply, e := cli(peer, "observe", key)
		var o ModuleObservation
		if e == nil {
			e = json.Unmarshal(reply.Data, &o)
		}
		return o, e
	}
	nodeKey, bridgeKey, taskKey := desired.NodePrefix+"a", desired.BridgePrefix+"a", desired.TaskPrefix+"a"
	submit(nodeKey, desired.NodeSpec{Schema: 1, Owner: owner, CPU: 1_000_000_000, Memory: 128 << 20, MaxBridges: 2, MaxContainers: 3, MaxEndpoints: 3, MaxConsumers: 8, MaxIngressInstances: 2, MaxIngressListeners: 4, MaxIngressRequests: 4, MaxIngressConnections: 16, IngressBufferBytes: 256 << 10}, 0, false, state.Applied)
	bridge := network.BridgeSpec{Schema: 1, Network: "boundary", Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "a", Network: "boundary", Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}
	bridgeResult := submit(bridgeKey, bridge, 0, false, state.Applied)
	wait("actual Bridge and fresh authenticated report at nonvoter", func() bool {
		b, e := observe("a", bridgeKey)
		if e != nil || !b.Ready {
			return false
		}
		remote, e := observe("b", nodeKey)
		return e == nil && remote.Ready && remote.Report != nil && remote.Report.Node.ID == owner
	})
	in := workload.PlacementInput{Schema: 1, Key: taskKey, Network: bridge.Network, Template: workload.ContainerSpec{Schema: 1, Image: fixture.Image, Command: []string{"/backend"}, Memory: 32 << 20, NanoCPU: 100000000}}
	planFile := filepath.Join(root, "plan.json")
	input, _ := json.Marshal(in)
	if err = os.WriteFile(planFile, input, 0600); err != nil {
		t.Fatal(err)
	}
	planReply, err := cli("b", "plan", planFile)
	if err != nil {
		t.Fatal("actual plan forwarded to leader", err, planReply)
	}
	var plan workload.PlacementPlan
	if err = json.Unmarshal(planReply.Data, &plan); err != nil || plan.Spec.Node != owner || plan.Spec.IPv4 != prefix.Addr().Next().Next() || plan.Expected != 0 {
		t.Fatal("actual plan", plan, err)
	}
	if reply, e := cli("a", "get", taskKey); e != nil || reply.Object == nil || reply.Object.Present {
		t.Fatal("read-only proposal committed state", reply, e)
	}
	taskResult := submit(taskKey, plan.Spec, plan.Expected, false, state.Applied)
	var original ModuleObservation
	wait("actual running container", func() bool {
		o, e := observe("a", taskKey)
		if e == nil && o.Ready {
			original = o
			return true
		}
		return false
	})
	response := func() bool {
		h := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
		defer h.CloseIdleConnections()
		reply, e := h.Get(fmt.Sprintf("http://%s:8080/ping", plan.Spec.IPv4))
		if e != nil {
			return false
		}
		defer reply.Body.Close()
		b, e := io.ReadAll(reply.Body)
		return e == nil && string(b) == "mydc-boundary /ping"
	}
	wait("container HTTP", response)
	var ingressSpec ingress.Spec
	var ingressResult state.Result
	ingressKey := desired.IngressPrefix + "a"
	consumers := 1
	var proxyURL string
	proxyResponse := func() bool {
		h := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
		defer h.CloseIdleConnections()
		res, e := h.Get(proxyURL + "/ping")
		if e != nil {
			return false
		}
		defer res.Body.Close()
		b, e := io.ReadAll(res.Body)
		return e == nil && res.StatusCode == 200 && string(b) == "mydc-boundary /ping"
	}
	if withIngress {
		ln, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		address := ln.Addr().String()
		ln.Close()
		proxyURL = "http://" + address
		ingressSpec = ingress.Spec{Schema: 1, Owner: owner, Listeners: []ingress.Listener{{ID: "http", Address: address}}, Routes: []ingress.Route{{ID: "r", Host: "*", Prefix: "/", Service: "api"}}, Services: []ingress.Service{{ID: "api", Backends: []ingress.BackendSpec{{ID: "a", Task: taskKey, Network: bridge.Network, Generation: taskResult.Generation, Address: plan.Spec.IPv4, Port: 8080, Weight: 1, Capacity: 4, HealthPath: "/ping"}}}}, MaxRequests: 4, MaxConnections: 16, MaxHeaderBytes: 4096, BufferBytes: 256 << 10, MaxBodyBytes: 1024, RequestTimeoutMS: 5000, DialTimeoutMS: 500, ResponseHeaderTimeoutMS: 500, HealthIntervalMS: 100}
		ingressResult = submit(ingressKey, ingressSpec, 0, false, state.Applied)
		consumers = 2
		wait("real daemon ingress Network backend and durable pin", func() bool {
			o, e := observe("a", ingressKey)
			b, e2 := observe("a", bridgeKey)
			return e == nil && e2 == nil && o.Ready && o.Ingress != nil && b.Journal.Consumers == consumers && proxyResponse()
		})
		blocked := plan.Spec
		blocked.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{9}}
		submit(taskKey, blocked, taskResult.Revision, false, state.Invalid)
	}
	stop(0)
	if !response() {
		t.Fatal("daemon shutdown stopped owned service")
	}
	start(0)
	wait("same root original container and pin", func() bool {
		o, e := observe("a", taskKey)
		b, e2 := observe("a", bridgeKey)
		return e == nil && e2 == nil && o.Ready && o.NativeID == original.NativeID && b.Journal.Consumers == consumers
	})
	if !response() {
		t.Fatal("same DB restart lost HTTP")
	}
	if withIngress {
		wait("same DB original ingress dependency and HTTP", proxyResponse)
	}
	if quorum {
		leader := ""
		wait("current three-voter leader", func() bool { reply, e := cli("a", "status"); leader = reply.Leader; return e == nil && leader != "" })
		oldLeader := -1
		for i, id := range names {
			if id == leader {
				oldLeader = i
			}
		}
		if oldLeader <= 0 {
			t.Fatal("invalid voter leader", leader)
		}
		stop(oldLeader)
		wait("majority service handoff", func() bool {
			reply, e := cli("a", "status")
			return e == nil && reply.Leader != "" && reply.Leader != leader && response()
		})
		submit("workload/checkpoint/after-handoff", map[string]int{"schema": 1}, 0, false, state.Applied)
		// Losing every voting peer also severs this nonvoter's control path. Its
		// committed native service and durable dependency remain locally owned.
		current, err := cli("a", "status")
		if err != nil {
			t.Fatal("current majority leader", err)
		}
		minority := -1
		for i := 1; i < len(names); i++ {
			if names[i] == current.Leader {
				minority = i
			} else {
				stop(i)
			}
		}
		if minority < 1 {
			t.Fatal("no current voter leader", current)
		}
		if !response() {
			t.Fatal("control disconnect stopped committed service")
		}
		command := state.Command{Actor: keys[len(names)].Actor(), RequestID: "quorum-reject", Epoch: 1, Key: "workload/checkpoint/no-quorum", Value: "must-not-commit"}
		encoded, e := state.EncodeCommand(command)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(root, "no-quorum.bin")
		if e = os.WriteFile(path, encoded, 0600); e != nil {
			t.Fatal(e)
		}
		reply, e := cli("a", "submit", path)
		if e == nil || reply.Committed != nil || (reply.Code != "unavailable" && reply.Code != "unknown" && reply.Code != "not-leader") {
			t.Fatal("no quorum accepted change", reply, e)
		}
		stop(minority)
		stop(0)
		if !response() {
			t.Fatal("offline daemon stop lost original service")
		}
		start(0)
		wait("offline same DB/native original", func() bool {
			o, e := observe("a", taskKey)
			b, e2 := observe("a", bridgeKey)
			return e == nil && e2 == nil && o.Ready && o.NativeID == original.NativeID && b.Journal.Consumers == consumers && response()
		})
		for i := 1; i < len(names); i++ {
			start(i)
		}
		wait("same DB voting group recovered", func() bool { reply, e := cli("a", "status"); return e == nil && reply.Leader != "" })
		submit("workload/checkpoint/after-recovery", map[string]int{"schema": 1}, 0, false, state.Applied)
		reply, e = cli("a", "get", "workload/checkpoint/no-quorum")
		if e != nil || reply.Object == nil || reply.Object.Present {
			t.Fatal("rejected change appeared after recovery", reply, e)
		}
		o, e := observe("a", taskKey)
		if e != nil || !o.Ready || o.NativeID != original.NativeID || !response() {
			t.Fatal("control recovery replaced original", o, e)
		}
		t.Logf("actual voter leader %s exit/new majority commit; all control paths disconnected/no commit; offline same DB/native/pin restart; same voting DB recovery", leader)
	}
	if withIngress {
		ingressSpec.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{3}}
		drained := submit(ingressKey, ingressSpec, ingressResult.Revision, false, state.Applied)
		var gone ModuleObservation
		wait("daemon ingress listener closed and Network pin returned", func() bool {
			o, e := observe("a", ingressKey)
			b, e2 := observe("a", bridgeKey)
			if e == nil && e2 == nil && o.Ready && o.Ingress != nil && o.Ingress.Gone && len(o.Retirement) > 0 && b.Journal.Consumers == 1 {
				gone = o
				return true
			}
			return false
		})
		if proxyResponse() {
			t.Fatal("Gone kept listener serving")
		}
		var released ingress.Spec
		if e := json.Unmarshal(gone.Retirement, &released); e != nil {
			t.Fatal(e)
		}
		done := submit(ingressKey, released, drained.Revision, false, state.Applied)
		submit(ingressKey, nil, done.Revision, true, state.Applied)
		t.Log("actual CLI/Raft ingress Desired, native Bridge pin=2, container proxy, premature task Drain rejection, same DB service/pin reacquire, listener Wait/Gone, owner proof/CAS, pin=1 before task removal")
	}
	draining := plan.Spec
	draining.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
	drainResult := submit(taskKey, draining, taskResult.Revision, false, state.Applied)
	// The reservation remains authoritative through native removal until the
	// owner's observed absence proof is committed by an ordinary administrator.
	submit(desired.TaskPrefix+"contender", plan.Spec, 0, false, state.Invalid)
	bridge.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{2}}
	bridgeDrain := submit(bridgeKey, bridge, bridgeResult.Revision, false, state.Applied)
	var taskGone, bridgeGone ModuleObservation
	wait("actual container removal and signed retirement", func() bool {
		o, e := observe("a", taskKey)
		if e == nil && o.Ready && len(o.Retirement) > 0 {
			taskGone = o
			return true
		}
		return false
	})
	var released workload.ContainerSpec
	if err = json.Unmarshal(taskGone.Retirement, &released); err != nil {
		t.Fatal(err)
	}
	releaseResult := submit(taskKey, released, drainResult.Revision, false, state.Applied)
	submit(taskKey, nil, releaseResult.Revision, true, state.Applied)
	wait("actual Bridge/kernel removal and signed retirement", func() bool {
		o, e := observe("a", bridgeKey)
		if e == nil && o.Ready && len(o.Retirement) > 0 {
			bridgeGone = o
			return true
		}
		return false
	})
	var bridgeReleased network.BridgeSpec
	if err = json.Unmarshal(bridgeGone.Retirement, &bridgeReleased); err != nil {
		t.Fatal(err)
	}
	bridgeRelease := submit(bridgeKey, bridgeReleased, bridgeDrain.Revision, false, state.Applied)
	submit(bridgeKey, nil, bridgeRelease.Revision, true, state.Applied)
	filters := client.Filters{}.Add("label", "org.mydc.owner="+owner)
	containers, e := fixture.Client.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if e != nil || len(containers.Items) != 0 {
		t.Fatal("product retained native containers", e)
	}
	networks, e := fixture.Client.API.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if e != nil || len(networks.Items) != 0 {
		t.Fatal("product retained native Bridges", e)
	}
	t.Logf("actual two daemons/CLI: committed Bridge + remote durable report receipt + read-only placement/CAS + container HTTP; same DB/pin/original=%s; Drain preserves IP until native signed absence; product removed container/Bridge before fixture rollback", original.NativeID)
}
