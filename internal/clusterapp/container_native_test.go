// SPDX-License-Identifier: Apache-2.0

package clusterapp

import (
	"net/netip"

	"context"
	"errors"
	"fmt"
	dockernet "github.com/moby/moby/api/types/network"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/moby/moby/client"

	"archive/tar"
	"bytes"
	"io"
)

// The container runs this test binary: with the child variable set it only
// waits for SIGTERM.
func TestMain(m *testing.M) {
	if os.Getenv("SFC_CLUSTERAPP_CHILD") == "1" {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM)
		<-c
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type fakeBridges struct {
	mu        sync.Mutex
	id, name  string
	consumers map[string]bool
}

func (b *fakeBridges) lease(key, consumer string) network.BridgeLease {
	return network.BridgeLease{Key: key, Consumer: consumer, NetworkID: b.id, NetworkName: b.name}
}
func (b *fakeBridges) Acquire(_ context.Context, key, consumer string, _ uint64) (network.BridgeLease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consumers[consumer] = true
	return b.lease(key, consumer), nil
}
func (b *fakeBridges) InspectConsumer(_ context.Context, key, consumer string, _ uint64) (network.BridgeLease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.consumers[consumer] {
		return network.BridgeLease{}, fmt.Errorf("no lease %s", consumer)
	}
	return b.lease(key, consumer), nil
}
func (b *fakeBridges) ReturnConsumer(_, consumer string, _ uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.consumers, consumer)
	return nil
}
func (b *fakeBridges) held() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for c := range b.consumers {
		out = append(out, c)
	}
	return out
}

// childImage is a one-layer image holding this static test binary.
func childImage(t *testing.T) []byte {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err = tw.WriteHeader(&tar.Header{Name: "app", Mode: 0755, Size: int64(len(raw))}); err != nil {
		t.Fatal(err)
	}
	tw.Write(raw)
	tw.Close()
	return buf.Bytes()
}

// TestRealBoundaryClusterAppContainerLifecycle runs on a real local Engine:
// create and start, repair after docker rm, replace on a spec change, and
// remove on shutdown, leaving no container or Bridge lease behind.
func TestRealBoundaryClusterAppContainerLifecycle(t *testing.T) {
	if os.Getenv("SFC_CLUSTERAPP_NATIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("set SFC_CLUSTERAPP_NATIVE=1 and run as root with a disposable local Engine at /var/run/docker.sock (CGO_ENABLED=0)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	owner := engine.Owner([32]byte{1}, [32]byte{2})
	c, err := engine.Open(ctx, "unix:///var/run/docker.sock", owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	layerBytes := childImage(t)
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(layerBytes)), nil })
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	cf, _ := img.ConfigFile()
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", "amd64"
	cf.Config.Entrypoint = []string{"/app"}
	cf.Config.Env = []string{"SFC_CLUSTERAPP_CHILD=1"}
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	loaded, err := c.LoadImage(ctx, img)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := img.Digest()

	// A fixed container address needs a user-defined subnet on the network.
	subnet := netip.MustParsePrefix("172.31.250.0/24")
	address := netip.MustParseAddr("172.31.250.2")
	ipam := &dockernet.IPAM{Driver: "default", Config: []dockernet.IPAMConfig{{Subnet: subnet, Gateway: netip.MustParseAddr("172.31.250.1")}}}
	net, err := c.API.NetworkCreate(ctx, "sfc-clusterapp-test", client.NetworkCreateOptions{Driver: "bridge", IPAM: ipam})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		c.API.ContainerRemove(ctx, ContainerName(Web), client.ContainerRemoveOptions{Force: true})
		c.API.NetworkRemove(ctx, net.ID, client.NetworkRemoveOptions{})
		c.API.ImageRemove(ctx, loaded.ID, client.ImageRemoveOptions{Force: true})
	})
	bridges := &fakeBridges{id: net.ID, name: "sfc-clusterapp-test", consumers: map[string]bool{}}
	data := t.TempDir()
	o, err := OpenOwner(filepath.Join(t.TempDir(), "journal.db"), c, bridges)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()

	spec := ContainerSpec{Schema: 1, App: Web, Image: loaded.ID, Digest: digest.String(), Bridge: "bridge/key", BridgeGeneration: 3, Address: address, User: "10001:10001", Cmd: []string{"-listen", ":8080"}, Env: []string{"A=1"}, Binds: []Bind{{Source: data, Target: "/data"}}}
	running := func(step string) Status {
		t.Helper()
		s, ok, err := o.Status(ctx, Web)
		if err != nil || !ok || s.State != "running" || s.Address == "" {
			t.Fatalf("%s: %+v %v %v", step, s, ok, err)
		}
		return s
	}
	if err = o.Set(ctx, Web, &spec); err != nil {
		t.Fatal(err)
	}
	first := running("create")
	got, err := c.API.ContainerInspect(ctx, first.ID, client.ContainerInspectOptions{})
	if err != nil || got.Container.Config.Labels["org.sfc.cluster-app"] != Web || got.Container.Config.Labels["org.sfc.owner"] != owner || got.Container.HostConfig.RestartPolicy.Name != "no" || !got.Container.HostConfig.ReadonlyRootfs {
		t.Fatal("container identity or policy", err)
	}

	if err = o.Set(ctx, Web, &spec); err != nil || running("same spec").ID != first.ID {
		t.Fatal("same spec replaced the container", err)
	}

	// The Engine never restarts it; sfcd starts a stopped container again.
	if err = c.StopContainer(ctx, first.ID, stopPolicy); err != nil {
		t.Fatal(err)
	}
	if err = o.Set(ctx, Web, &spec); err != nil {
		t.Fatal("revive", err)
	}
	if revived := running("revive"); revived.ID != first.ID || revived.Restarts != 1 || revived.LastRestart == "" {
		t.Fatalf("revive: %+v", revived)
	}

	if _, err = c.API.ContainerRemove(ctx, first.ID, client.ContainerRemoveOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	if err = o.Set(ctx, Web, &spec); err != nil {
		t.Fatal("repair after docker rm", err)
	}
	repaired := running("repair")
	if repaired.ID == first.ID {
		t.Fatal("repair kept a removed container")
	}

	next := spec
	next.Cmd = []string{"-listen", ":9090"}
	if err = o.Set(ctx, Web, &next); err != nil {
		// Remove the old generation, then create the new one.
		if err = o.Set(ctx, Web, &next); err != nil {
			t.Fatal("replace", err)
		}
	}
	replaced := running("replace")
	if replaced.ID == repaired.ID {
		t.Fatal("changed spec kept the old container")
	}
	if held := bridges.held(); len(held) != 1 || !strings.HasSuffix(held[0], "/2") {
		t.Fatal("old generation still holds its Bridge lease", held)
	}

	if err = o.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := o.Status(ctx, Web); ok || err != nil {
		t.Fatal("container left after shutdown", err)
	}
	if held := bridges.held(); len(held) != 0 {
		t.Fatal("lease left after shutdown", held)
	}

	// docker rmi: the next Set says the image is gone, so sfcd loads it again.
	if _, err = c.API.ImageRemove(ctx, loaded.ID, client.ImageRemoveOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	if err = o.Set(ctx, Web, &next); !errors.Is(err, ErrImageNotFound) {
		t.Fatal("lost image not reported as not found", err)
	}
	if _, ok, err := o.Status(ctx, Web); ok || err != nil {
		t.Fatal("container created without its image", err)
	}
	if held := bridges.held(); len(held) != 0 {
		t.Fatal("failed create kept its Bridge lease", held)
	}
}
