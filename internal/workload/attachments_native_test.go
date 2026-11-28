// SPDX-License-Identifier: Apache-2.0

package workload_test

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/enginefixture"
	"github.com/moby/moby/client"
)

// One Task on two Bridges: the engine creates both endpoints before Start,
// the process answers on both addresses, and removal returns both pins.
func TestRealBoundaryTaskOnTwoNetworksReturnsEveryPin(t *testing.T) {
	owner, backend := os.Getenv("SFC_DOCKER_TEST_OWNER"), os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if owner == "" || backend == "" || os.Geteuid() != 0 {
		t.Skip("requires owned rollback prestate and user-prebuilt backend/test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	f := enginefixture.OpenPrepared(t, ctx, owner, owner, []string{`USER 10001:10001`}, backend)
	root := t.TempDir()
	n, err := network.OpenManager(filepath.Join(root, "network.db"), f.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	w, err := workload.OpenManager(filepath.Join(root, "workload.db"), f.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	// Split the owned test range into two Bridge pools.
	whole := netip.MustParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	if whole.Bits() > 29 {
		t.Skip("SFC_DOCKER_TEST_CIDR must hold two /30-or-larger pools")
	}
	first := netip.PrefixFrom(whole.Addr(), whole.Bits()+1)
	upper := whole.Addr().As4()
	upper[3] += byte(1 << (32 - first.Bits()))
	second := netip.PrefixFrom(netip.AddrFrom4(upper), first.Bits())
	keys := []string{"network/two-a", "network/two-b"}
	var addresses []netip.Addr
	for i, prefix := range []netip.Prefix{first, second} {
		name := []string{"two-a", "two-b"}[i]
		gateway := prefix.Addr().Next()
		bridge := network.BridgeSpec{Schema: 1, Network: name, Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: name, Network: name, Owner: owner, Prefix: prefix, Gateway: gateway, MTU: 1280}}}
		if err = n.Desired(keys[i], 1, 1, &bridge, 4); err != nil {
			t.Fatal(err)
		}
		if err = n.Step(ctx, keys[i]); err != nil {
			t.Fatal(err)
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
	taskKey := "workload/two-networks"
	spec := workload.ContainerSpec{Schema: 1, Node: owner, Image: f.Image, Bridge: keys[0], BridgeGeneration: 1, IPv4: addresses[0], Memory: 32 << 20, NanoCPU: 100000000, Process: &process, Attachments: []workload.TaskAttachment{{Bridge: keys[1], BridgeGeneration: 1, IPv4: addresses[1]}}}
	if err = w.Desired(taskKey, 2, 2, &spec, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	status, err := w.Status(ctx, taskKey)
	if err != nil || !status.Running || status.TaskFact == nil || status.TaskFact.EndpointPresent == nil || !*status.TaskFact.EndpointPresent {
		t.Fatal("two-network Task not running with every endpoint", status, err)
	}
	inspect, err := f.Client.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
	if err != nil || len(inspect.Container.NetworkSettings.Networks) != 2 {
		t.Fatal("engine did not create both endpoints", err)
	}
	httpClient := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer httpClient.CloseIdleConnections()
	for _, address := range addresses {
		for {
			req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+address.String()+":8080/", nil)
			response, err := httpClient.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("no answer on", address, err)
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	for _, key := range keys {
		r, err := n.View(key)
		if err != nil || len(r.Consumers) != 1 {
			t.Fatal("each attachment needs its own pin", key, r.Consumers, err)
		}
	}
	if err = w.Desired(taskKey, 3, 2, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	if gone, err := w.Gone(ctx, taskKey, 3, 2); err != nil || !gone {
		t.Fatal("task closure", gone, err)
	}
	for _, key := range keys {
		r, err := n.View(key)
		if err != nil || len(r.Consumers) != 0 {
			t.Fatal("removal kept a Bridge pin", key, r.Consumers, err)
		}
		if err = n.Desired(key, 4, 1, nil, 4); err != nil {
			t.Fatal(err)
		}
		if err = n.Step(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("one Task on two Bridges -> both endpoints before Start -> answers on both addresses -> removal returns both pins")
}
