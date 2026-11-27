// SPDX-License-Identifier: Apache-2.0

package enginefake

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engine"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func start(t *testing.T) *Engine {
	t.Helper()
	// Unix socket paths are limited to 107 bytes; t.TempDir can be longer.
	root, err := os.MkdirTemp("", "ef")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	e, err := Start(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = e.Close()
		if u := e.Unknown(); len(u) > 0 {
			t.Errorf("calls the fake engine does not know: %v", u)
		}
	})
	return e
}

// The SDK client sfcd uses talks to the fake: one container's life with a
// network address, a volume and logs.
func TestContainerLife(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	e := start(t)
	c, err := engine.Open(ctx, e.Endpoint(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer c.API.Close()
	api := c.API
	events := api.Events(ctx, client.EventsListOptions{Filters: client.Filters{}.Add("type", "container")})

	subnet := netip.MustParsePrefix("10.77.0.0/24")
	if _, err = api.NetworkCreate(ctx, "app", client.NetworkCreateOptions{Driver: "bridge", IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: subnet}}}, Labels: map[string]string{"org.sfc.owner": "node-a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.NetworkCreate(ctx, "other", client.NetworkCreateOptions{IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix("10.77.0.128/25")}}}}); err == nil {
		t.Fatal("overlapping subnet accepted")
	}
	if _, err = api.VolumeCreate(ctx, client.VolumeCreateOptions{Name: "data", Labels: map[string]string{"org.sfc.owner": "node-a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.VolumeCreate(ctx, client.VolumeCreateOptions{Name: "../escape"}); err == nil {
		t.Fatal("volume name with a path accepted")
	}
	imageID := e.AddImage(dockerspec.DockerOCIImage{}, "registry.test/web:1")
	labels := map[string]string{"org.sfc.owner": "node-a", "org.sfc.key": "task/web"}
	created, err := api.ContainerCreate(ctx, client.ContainerCreateOptions{Name: "web", Config: &container.Config{Image: "registry.test/web:1", Labels: labels}, HostConfig: &container.HostConfig{NetworkMode: "app", Mounts: []mount.Mount{{Type: mount.TypeVolume, Source: "data", Target: "/data"}}, NanoCPUs: 1e9, Memory: 1 << 28}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = api.ContainerCreate(ctx, client.ContainerCreateOptions{Name: "web", Config: &container.Config{Image: "registry.test/web:1"}}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if _, err = api.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := api.ContainerInspect(ctx, "web", client.ContainerInspectOptions{})
	if err != nil || !got.Container.State.Running || got.Container.Image != imageID || got.Container.HostConfig.NanoCPUs != 1e9 {
		t.Fatalf("inspect: %+v %v", got.Container.State, err)
	}
	ep := got.Container.NetworkSettings.Networks["app"]
	if ep == nil || ep.IPAddress != netip.MustParseAddr("10.77.0.2") || ep.Gateway != netip.MustParseAddr("10.77.0.1") {
		t.Fatalf("endpoint: %+v", ep)
	}
	vol, err := api.VolumeInspect(ctx, "data", client.VolumeInspectOptions{})
	if err != nil || len(got.Container.Mounts) != 1 || got.Container.Mounts[0].Source != vol.Volume.Mountpoint {
		t.Fatalf("mounts: %+v %+v %v", got.Container.Mounts, vol.Volume, err)
	}
	if st, err := os.Stat(vol.Volume.Mountpoint); err != nil || !st.IsDir() {
		t.Fatal("volume data directory", err)
	}
	listed, err := api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner=node-a")})
	if err != nil || len(listed.Items) != 1 || listed.Items[0].ID != created.ID {
		t.Fatalf("list: %+v %v", listed.Items, err)
	}
	if listed, _ = api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner=node-b")}); len(listed.Items) != 0 {
		t.Fatal("label filter")
	}

	_ = e.Log("web", false, "ready")
	_ = e.Log("web", true, "warning")
	logs, err := api.ContainerLogs(ctx, "web", client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if _, err = stdcopy.StdCopy(&stdout, &stderr, logs); err != nil || stdout.String() != "ready\n" || stderr.String() != "warning\n" {
		t.Fatalf("logs: %q %q %v", stdout.String(), stderr.String(), err)
	}
	_ = logs.Close()

	wait := api.ContainerWait(ctx, created.ID, client.ContainerWaitOptions{})
	if err = e.Exit("web", 3); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-wait.Result:
		if r.StatusCode != 3 {
			t.Fatal("exit code", r.StatusCode)
		}
	case err = <-wait.Error:
		t.Fatal(err)
	}
	if _, err = api.VolumeRemove(ctx, "data", client.VolumeRemoveOptions{}); err == nil {
		t.Fatal("removed a volume in use")
	}
	if _, err = api.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.NetworkRemove(ctx, "app", client.NetworkRemoveOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.ImageRemove(ctx, "registry.test/web:1", client.ImageRemoveOptions{}); err != nil {
		t.Fatal(err)
	}

	var actions []string
	for len(actions) < 4 {
		select {
		case m := <-events.Messages:
			if m.Action != "seafield.logs" { // the log queue's "lines stored", as sfed sends
				actions = append(actions, string(m.Action))
			}
		case err = <-events.Err:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal("events", actions)
		}
	}
	if actions[0] != "create" || actions[1] != "start" || actions[2] != "die" || actions[3] != "destroy" {
		t.Fatal("events", actions)
	}
}

// With Host, a bridge network is a kernel bridge and a running container
// has its own namespace on it, named by its PID and sandbox key.
func TestHostNamespaces(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	e := start(t)
	e.UseHost("")
	c, err := engine.Open(ctx, e.Endpoint(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer c.API.Close()
	api := c.API
	opts := map[string]string{"com.docker.network.bridge.name": "ef-test0", "com.docker.network.driver.mtu": "1400"}
	if _, err = api.NetworkCreate(ctx, "app", client.NetworkCreateOptions{Driver: "bridge", Options: opts, IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix("10.78.0.0/24")}}}}); err != nil {
		t.Fatal(err)
	}
	bridge, err := netlink.LinkByName("ef-test0")
	if err != nil || bridge.Type() != "bridge" || bridge.Attrs().MTU != 1400 {
		t.Fatal("bridge", bridge, err)
	}
	e.AddImage(dockerspec.DockerOCIImage{}, "registry.test/web:1")
	created, err := api.ContainerCreate(ctx, client.ContainerCreateOptions{Name: "web", Config: &container.Config{Image: "registry.test/web:1"}, HostConfig: &container.HostConfig{NetworkMode: "app"}})
	if err == nil {
		_, err = api.ContainerStart(ctx, created.ID, client.ContainerStartOptions{})
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := api.ContainerInspect(ctx, "web", client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	key := got.Container.NetworkSettings.SandboxKey
	if pid := got.Container.State.Pid; pid < 1 || key != "/proc/"+strconv.Itoa(pid)+"/ns/net" {
		t.Fatalf("sandbox: pid %d key %q", pid, key)
	}
	ns, err := netns.GetFromPath(key)
	if err != nil {
		t.Fatal(err)
	}
	h, err := netlink.NewHandleAt(ns)
	_ = ns.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	eth, err := h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := h.AddrList(eth, netlink.FAMILY_V4)
	if err != nil || len(addrs) != 1 || addrs[0].IPNet.String() != "10.78.0.2/24" || eth.Attrs().MTU != 1400 {
		t.Fatalf("eth0: %v mtu %d %v", addrs, eth.Attrs().MTU, err)
	}
	routes, err := h.RouteList(eth, netlink.FAMILY_V4)
	if err != nil || !slices.ContainsFunc(routes, func(r netlink.Route) bool {
		return (r.Dst == nil || r.Dst.String() == "0.0.0.0/0") && r.Gw.String() == "10.78.0.1"
	}) {
		t.Fatalf("default route: %v %v", routes, err)
	}
	if err = e.Exit("web", 0); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(key); err == nil {
		t.Fatal("namespace outlived the container")
	}
	if _, err = api.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{}); err == nil {
		_, err = api.NetworkRemove(ctx, "app", client.NetworkRemoveOptions{})
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = netlink.LinkByName("ef-test0"); err == nil {
		t.Fatal("bridge left behind")
	}
}
