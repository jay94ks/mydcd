// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/enginefixture"
	"github.com/moby/moby/client"
)

// startSfed runs the Seafield engine on the fixture's engine socket
// (/var/run/docker.sock) under a minimal sfcd that answers only purpose 36,
// the engine's sfc network driver hooks. The caller sets the network module
// with useNetwork once its engine client is open.
func startSfed(t *testing.T, binary, owner string) (useNetwork func(*network.Manager)) {
	t.Helper()
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	mesh, err := sfcp.NewTransport(self, [32]byte{1}, func(sfcp.Identity) (sfcp.Peer, bool) { return sfcp.Peer{}, false })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mesh.Close() })
	r := &Runtime{owner: owner}
	r.engineNetwork = &network.EngineHooks{Owner: owner, Admit: r.engineNetworkAdmit}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil || mesh.AllowEnginePeer(binary) != nil {
		t.Fatal("engine peer", err)
	}
	table, err := engineops.NewTable(r.engineNetworkOps()...)
	if err != nil {
		t.Fatal(err)
	}
	if err = routeEngineOps(mesh, table); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("", "sfed-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "sfcd-engine.sock")
	if err = mesh.ListenEngine(socket); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(map[string]any{"data-root": filepath.Join(root, "data"), "exec-root": filepath.Join(root, "exec"), "hosts": []string{"unix:///var/run/docker.sock"}, "bridge": "none", "iptables": false, "ip6tables": false, "pidfile": filepath.Join(root, "sfed.pid"), "features": map[string]bool{"buildkit": false}})
	if err = os.WriteFile(filepath.Join(root, "daemon.json"), config, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(root, "sfed.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("sfed log:", log.Name())
	cmd := exec.Command(binary, "--config-file", filepath.Join(root, "daemon.json"))
	cmd.Env = append(os.Environ(), "SEAFIELD_SFCD_SOCKET="+socket, "SEAFIELD_ALLOWED_PEERS="+exe)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		_ = log.Close()
		if exec.Command("umount", "-R", filepath.Join(root, "exec")).Run() == nil || !t.Failed() {
			_ = os.RemoveAll(root)
		}
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, ok := mesh.Engine(); ok {
			if c, err := client.New(client.WithHost("unix:///var/run/docker.sock")); err == nil {
				_, pingErr := c.Ping(context.Background(), client.PingOptions{})
				_ = c.Close()
				if pingErr == nil {
					break
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("sfed did not come up with its sfcd session")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return func(n *network.Manager) {
		r.network = n
		n.UseEngineHooks(r.engineNetwork)
	}
}

func answers(ctx context.Context, address netip.Addr, within time.Duration) bool {
	c := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer c.CloseIdleConnections()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+address.String()+":8080/", nil)
		if response, err := c.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// One Task on the real Seafield engine: created on two Bridges, then the
// extra Bridge detached and attached again in place. The same container
// answers on each attached address and not on a detached one; the detached
// pin is returned and removal returns every pin.
func TestRealBoundarySfedTaskNetworksAttachDetachInPlace(t *testing.T) {
	owner, backend, sfed := os.Getenv("SFC_DOCKER_TEST_OWNER"), os.Getenv("SFC_DOCKER_TEST_BACKEND"), os.Getenv("SFC_SFED_TEST_BINARY")
	whole, cidrErr := netip.ParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	if owner == "" || backend == "" || sfed == "" || cidrErr != nil || !whole.Addr().Is4() || whole.Bits() > 29 || os.Geteuid() != 0 {
		t.Skip("requires root, SFC_SFED_TEST_BINARY, a prebuilt backend, an owner and a /29-or-larger IPv4 SFC_DOCKER_TEST_CIDR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	useNetwork := startSfed(t, sfed, owner)
	f := enginefixture.OpenPrepared(t, ctx, owner, owner, []string{`USER 10001:10001`}, backend)
	root := t.TempDir()
	n, err := network.OpenManager(filepath.Join(root, "network.db"), f.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	useNetwork(n)
	w, err := workload.OpenManager(filepath.Join(root, "workload.db"), f.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	first := netip.PrefixFrom(whole.Masked().Addr(), whole.Bits()+1)
	upper := first.Addr().As4()
	upper[3] += byte(1 << (32 - first.Bits()))
	second := netip.PrefixFrom(netip.AddrFrom4(upper), first.Bits())
	keys := []string{"network/sfed-a", "network/sfed-b"}
	var addresses []netip.Addr
	for i, prefix := range []netip.Prefix{first, second} {
		name := []string{"sfed-a", "sfed-b"}[i]
		gateway := prefix.Addr().Next()
		bridge := network.BridgeSpec{Schema: 1, Network: name, Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: name, Network: name, Owner: owner, Prefix: prefix, Gateway: gateway, MTU: 1280}}}
		if err = n.Desired(keys[i], 1, 1, &bridge, 4); err != nil {
			t.Fatal(err)
		}
		if err = n.Step(ctx, keys[i]); err != nil {
			t.Fatal("bridge", name, err)
		}
		addresses = append(addresses, gateway.Next())
	}
	image, err := f.Client.Image(ctx, f.Image, false)
	if err != nil {
		t.Fatal(err)
	}
	process, err := workload.ResolveImageProcess(image, workload.ProcessOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	taskKey := "workload/sfed-networks"
	single := workload.ContainerSpec{Schema: 1, Node: owner, Image: f.Image, Bridge: keys[0], BridgeGeneration: 1, IPv4: addresses[0], Memory: 32 << 20, NanoCPU: 100000000, Process: &process}
	extra := workload.TaskAttachment{Bridge: keys[1], BridgeGeneration: 1, IPv4: addresses[1]}
	two := single
	two.Attachments = []workload.TaskAttachment{extra}
	revision := uint64(2)
	apply := func(label string, s workload.ContainerSpec) workload.ContainerStatus {
		t.Helper()
		if err := w.Desired(taskKey, revision, 2, &s, 4); err != nil {
			t.Fatal(label, err)
		}
		revision++
		if err := w.Step(ctx, taskKey); err != nil {
			t.Fatal(label, err)
		}
		status, err := w.Status(ctx, taskKey)
		if err != nil || !status.Running {
			t.Fatal(label, "not running", status, err)
		}
		inspect, err := f.Client.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
		if err != nil || len(inspect.Container.NetworkSettings.Networks) != len(s.Networks()) {
			t.Fatal(label, "endpoints differ from the attachments", err)
		}
		return status
	}
	pins := func(key string) int {
		t.Helper()
		r, err := n.View(key)
		if err != nil {
			t.Fatal(err)
		}
		return len(r.Consumers)
	}
	created := apply("create on two networks", two)
	for _, address := range addresses {
		if !answers(ctx, address, 30*time.Second) {
			t.Fatal("no answer on", address)
		}
	}
	detached := apply("detach in place", single)
	if detached.NativeID != created.NativeID || detached.StartedAt != created.StartedAt {
		t.Fatal("detach replaced or restarted the container", created.NativeID, detached.NativeID)
	}
	if !answers(ctx, addresses[0], 10*time.Second) || answers(ctx, addresses[1], 2*time.Second) {
		t.Fatal("detached container still on the second network or off the first")
	}
	if pins(keys[0]) != 1 || pins(keys[1]) != 0 {
		t.Fatal("detach kept the dropped pin or lost the kept one")
	}
	if closed, err := w.AttachmentClosed(ctx, taskKey, 2, extra); err != nil || !closed {
		t.Fatal("detached attachment not closed", closed, err)
	}
	attached := apply("attach in place", two)
	if attached.NativeID != created.NativeID || attached.StartedAt != created.StartedAt {
		t.Fatal("attach replaced or restarted the container", created.NativeID, attached.NativeID)
	}
	if !answers(ctx, addresses[1], 30*time.Second) || !answers(ctx, addresses[0], 5*time.Second) {
		t.Fatal("attached container does not answer on both networks")
	}
	if pins(keys[1]) != 1 {
		t.Fatal("attach took no pin")
	}
	if err = w.Desired(taskKey, revision, 2, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	if gone, err := w.Gone(ctx, taskKey, revision, 2); err != nil || !gone {
		t.Fatal("task closure", gone, err)
	}
	for _, key := range keys {
		if pins(key) != 0 {
			t.Fatal("removal kept a Bridge pin", key)
		}
		if err = n.Desired(key, 2, 1, nil, 4); err != nil {
			t.Fatal(err)
		}
		if err = n.Step(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("sfed: two networks at create -> detach in place -> attach in place, same container, each address answers only while attached")
}
