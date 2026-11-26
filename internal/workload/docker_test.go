// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

func TestRealBoundaryDockerManagedLifetime(t *testing.T) {
	testRealDockerManagedLifetime(t, false)
}

func TestRQ3DockerTaskFactsUseOriginalNativeAcrossStopAndStart(t *testing.T) {
	testRealDockerManagedLifetime(t, true)
}

func testRealDockerManagedLifetime(t *testing.T, factsOnly bool) {
	owner := os.Getenv("MYDC_DOCKER_TEST_OWNER")
	if owner == "" {
		t.Skip("requires explicit owner and docs/testing/system-rollback.md prestate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := engine.Open(ctx, "unix:///var/run/docker.sock", owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	root := t.TempDir()
	imageRef := "mydc-boundary/" + owner + ":local"
	if _, err = c.API.ImageInspect(ctx, imageRef); !cerrdefs.IsNotFound(err) {
		t.Fatal("test image must be initially absent", err)
	}
	fixture := os.Getenv("MYDC_DOCKER_TEST_BACKEND")
	if fixture == "" {
		fixture = filepath.Join(root, "backend")
		build := exec.CommandContext(ctx, "go", "build", "-p", "2", "-o", fixture, "../../apps/dockerbackend")
		build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOMAXPROCS=2", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("backend fixture build: %v %s", err, out)
		}
	} else if !filepath.IsAbs(fixture) {
		t.Fatal("prepared backend must be an absolute path")
	}
	f, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, _ := f.Stat()
	archive, err := os.Create(filepath.Join(root, "rootfs.tar"))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	tw := tar.NewWriter(archive)
	if err = tw.WriteHeader(&tar.Header{Name: "backend", Mode: 0755, Size: info.Size()}); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(tw, f); err != nil {
		t.Fatal(err)
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = archive.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	// Register cleanup before import; an accepted request can outlive its reply.
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		im, e := c.API.ImageInspect(clean, imageRef)
		if cerrdefs.IsNotFound(e) {
			return
		}
		if e != nil {
			t.Error("image cleanup inspect", e)
			return
		}
		if im.Config == nil || im.Config.Labels["org.mydc.test.owner"] != owner {
			t.Error("image cleanup ownership mismatch")
			return
		}
		if _, e = c.API.ImageRemove(clean, imageRef, client.ImageRemoveOptions{}); e != nil {
			t.Error("image cleanup", e)
		}
		if _, e = c.API.ImageInspect(clean, imageRef); !cerrdefs.IsNotFound(e) {
			t.Error("image retained", e)
		}
	}()
	stream, err := c.API.ImageImport(ctx, client.ImageImportSource{Source: archive, SourceName: "-"}, imageRef, client.ImageImportOptions{Changes: []string{`CMD ["/backend"]`, "LABEL org.mydc.test.owner=" + owner}})
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(stream)
	for {
		var msg struct{ Error string }
		err = d.Decode(&msg)
		if err == io.EOF {
			break
		}
		if err != nil || msg.Error != "" {
			stream.Close()
			t.Fatal("image import", msg.Error, err)
		}
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	image, err := c.API.ImageInspect(ctx, imageRef)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("owner=%s image=%s ref=%s", owner, image.ID, imageRef)
	nPath, wPath := filepath.Join(root, "network.db"), filepath.Join(root, "workload.db")
	n, err := network.OpenManager(nPath, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	key := "network/pool-a"
	prefix := netip.MustParsePrefix(os.Getenv("MYDC_DOCKER_TEST_CIDR"))
	spec := network.BridgeSpec{Schema: 1, Network: "boundary", Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "a", Network: "boundary", Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}
	if err = n.Desired(key, 1, 1, &spec, 8); err != nil {
		t.Fatal(err)
	}
	nRecord, _ := n.View(key)
	bridgeID, err := c.Identity("bridge", key, nRecord.State.Desired.Resource)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		got, e := c.API.NetworkInspect(clean, bridgeID.Name, client.NetworkInspectOptions{})
		if cerrdefs.IsNotFound(e) {
			return
		}
		if e != nil {
			t.Error("bridge cleanup inspect", e)
			return
		}
		if !bridgeID.Matches(got.Network.Name, got.Network.Labels) {
			t.Error("bridge cleanup ownership")
			return
		}
		if _, e = c.API.NetworkRemove(clean, got.Network.ID, client.NetworkRemoveOptions{}); e != nil {
			t.Error("bridge cleanup", e)
		}
	}()
	if err = n.Step(ctx, key); err != nil {
		t.Fatal("bridge apply", err)
	}
	actual, err := c.API.NetworkInspect(ctx, bridgeID.Name, client.NetworkInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("bridge=%s kernel=%s CIDR=%s MTU=1280", actual.Network.ID, actual.Network.Options["com.docker.network.bridge.name"], prefix)
	w, err := OpenManager(wPath, c, n)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	workKey := "workload/service-a"
	containerSpec := ContainerSpec{Schema: 1, Node: owner, Image: image.ID, Command: []string{"/backend"}, Bridge: key, BridgeGeneration: 1, IPv4: prefix.Addr().Next().Next(), Memory: 32 << 20, NanoCPU: 100000000}
	if err = w.Desired(workKey, 2, 2, &containerSpec, 8); err != nil {
		t.Fatal(err)
	}
	wRecord, _ := w.View(workKey)
	containerID, err := c.Identity("container", workKey, wRecord.State.Desired.Resource)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		got, e := c.API.ContainerInspect(clean, containerID.Name, client.ContainerInspectOptions{})
		if cerrdefs.IsNotFound(e) {
			return
		}
		if e != nil {
			t.Error("container cleanup inspect", e)
			return
		}
		if got.Container.Config == nil || !containerID.Matches(got.Container.Name, got.Container.Config.Labels) {
			t.Error("container cleanup ownership")
			return
		}
		if _, e = c.API.ContainerRemove(clean, got.Container.ID, client.ContainerRemoveOptions{Force: true}); e != nil {
			t.Error("container cleanup", e)
		}
	}()
	if err = w.Step(ctx, workKey); err != nil {
		got, _ := c.API.ContainerInspect(ctx, containerID.Name, client.ContainerInspectOptions{})
		b, _ := json.Marshal(got.Container)
		t.Logf("first failure native inspect=%s", b)
		t.Fatal("container apply", err)
	}
	got, err := c.API.ContainerInspect(ctx, containerID.Name, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	originalID := got.Container.ID
	assertTaskFact := func(want string) {
		t.Helper()
		status, e := w.Status(ctx, workKey)
		if e != nil || status.TaskFact == nil || status.TaskFact.State != want || status.TaskFact.Name != containerID.Name || status.TaskFact.Image != image.ID || status.NativeID != originalID {
			t.Fatalf("exact native Task fact state=%s status=%+v error=%v", want, status, e)
		}
		inspected, e := c.API.ContainerInspect(ctx, originalID, client.ContainerInspectOptions{})
		if e != nil || inspected.Container.NetworkSettings == nil || len(inspected.Container.NetworkSettings.Networks) != 1 {
			t.Fatal("exact native endpoint inspection", e)
		}
		present := false
		for _, endpoint := range inspected.Container.NetworkSettings.Networks {
			present = endpoint.EndpointID != "" && endpoint.NetworkID == string(inspected.Container.HostConfig.NetworkMode)
		}
		if status.TaskFact.EndpointPresent == nil || *status.TaskFact.EndpointPresent != present {
			t.Fatal("Task fact differs from actual endpoint IDs", status.TaskFact.EndpointPresent, present)
		}
	}
	assertTaskFact("running")
	if _, err = c.API.ContainerStop(ctx, originalID, client.ContainerStopOptions{}); err != nil {
		t.Fatal(err)
	}
	assertTaskFact("exited")
	if err = w.Step(ctx, workKey); err != nil {
		t.Fatal("settled original start continuation", err)
	}
	// An exited original is a completed Start, not evidence that Start never
	// happened. Observation and settled maintenance must not resurrect it.
	assertTaskFact("exited")
	if _, err = c.API.ContainerStart(ctx, originalID, client.ContainerStartOptions{}); err != nil {
		t.Fatal("explicit native restart input", err)
	}
	resumed, err := c.API.ContainerInspect(ctx, originalID, client.ContainerInspectOptions{})
	if err != nil || resumed.Container.ID != originalID || !resumed.Container.State.Running {
		t.Fatal("stopped original replaced", err)
	}
	assertTaskFact("running")
	if factsOnly {
		return
	}
	// A same-name/generation object with different immutable Desired must never
	// be stopped or adopted just because its visible name matches.
	wrongSpec := containerSpec
	wrongSpec.Memory = 64 << 20
	wrongBytes, _ := json.Marshal(wrongSpec)
	wrongOp := reconcile.Operation{ID: 99, Kind: reconcile.Remove, Phase: reconcile.Retiring, Target: reconcile.Resource{Generation: 2, Spec: string(wrongBytes), Present: true}}
	// Recovery inspects the exact immutable native before retirement. Execute
	// intentionally rejects every bare Remove without Journal's durable receipt.
	if _, e := w.driver.Recover(ctx, workKey, wrongOp); !errors.Is(e, engine.ErrOwnership) {
		t.Fatal("mismatched immutable resource was mutated", e)
	}
	got, err = c.API.ContainerInspect(ctx, originalID, client.ContainerInspectOptions{})
	if err != nil || !got.Container.State.Running {
		t.Fatal("ownership rejection disturbed original", err)
	}
	url := fmt.Sprintf("http://%s:8080/ping", containerSpec.IPv4)
	httpClient := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer httpClient.CloseIdleConnections()
	// Read-only readiness observation; no product mutation/re-execution.
	for {
		resp, e := httpClient.Get(url)
		if e == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) != "mydc-boundary /ping" {
				t.Fatalf("backend response=%q", b)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("backend unreachable", e)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	n, err = network.OpenManager(nPath, c)
	if err != nil {
		t.Fatal(err)
	}
	w, err = OpenManager(wPath, c, n)
	if err != nil {
		t.Fatal(err)
	}
	nRecord, err = n.View(key)
	if err != nil || len(nRecord.Consumers) != 1 {
		t.Fatal("restart lost actual container's pin", err)
	}
	if err = w.Step(ctx, workKey); err != nil {
		t.Fatal(err)
	}
	got, err = c.API.ContainerInspect(ctx, containerID.Name, client.ContainerInspectOptions{})
	if err != nil || got.Container.ID != originalID || !got.Container.State.Running {
		t.Fatal("same DB restart replaced running original", err)
	}
	if err = n.Desired(key, 3, 0, nil, 8); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, key); !errors.Is(err, reconcile.ErrLease) && !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("bridge deleted under actual container", err)
	}
	if native, err := c.API.NetworkInspect(ctx, bridgeID.Name, client.NetworkInspectOptions{}); err != nil || native.Network.ID != actual.Network.ID {
		t.Fatal("pinned original bridge did not remain present", err)
	}
	beforeMissing, err := w.View(workKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.API.ContainerRemove(ctx, originalID, client.ContainerRemoveOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, workKey); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("missing original must remain unknown", err)
	}
	if _, err = c.API.ContainerInspect(ctx, containerID.Name, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("missing original automatically recreated", err)
	}
	afterMissing, err := w.View(workKey)
	if err != nil || !reflect.DeepEqual(beforeMissing, afterMissing) {
		t.Fatal("missing original changed durable operation", err)
	}
	dependency, err := n.View(key)
	if err != nil || len(dependency.Consumers) != 1 {
		t.Fatal("unknown original lost dependency", err)
	}
	if err = w.Desired(workKey, 4, 0, nil, 8); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, workKey); err != nil {
		t.Fatal("container removal/pin return", err)
	}
	if _, err = c.API.ContainerInspect(ctx, originalID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("removed container still exists", err)
	}
	nRecord, _ = n.View(key)
	if len(nRecord.Consumers) != 0 {
		t.Fatal("actual removal did not return durable Bridge pin")
	}
	if err = n.Step(ctx, key); err != nil {
		t.Fatal("bridge removal", err)
	}
	if _, err = c.API.NetworkInspect(ctx, actual.Network.ID, client.NetworkInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("removed bridge exists", err)
	}
	t.Logf("actual container=%s HTTP exchange; same DB reopen preserves original/pin; Drain blocks live Bridge removal; native container/network absence and pin return", originalID)
	if strings.Contains(image.ID, "latest") {
		t.Fatal("image was not pinned")
	}
}

// The actual Manager journal, ownership matcher and SDK decoder are reused;
// only finite Docker responses are injected. No native execution is claimed.
func TestDockerTaskEndpointEvidenceComesFromMatchedInspectionIDs(t *testing.T) {
	for _, tc := range []struct {
		name              string
		running           bool
		endpoint, network string
		want              bool
	}{{"running-attached", true, "native-endpoint", "fixture-network", true}, {"running-no-endpoint", true, "", "fixture-network", false}, {"stopped-attached", false, "native-endpoint", "fixture-network", true}, {"stopped-detached", false, "", "", false}, {"stopped-incomplete", false, "native-endpoint", "", false}} {
		t.Run(tc.name, func(t *testing.T) {
			m, f := networkIdentityFixture(t)
			f.native.State.Running = tc.running
			if !tc.running {
				f.native.State.Status = "exited"
				f.native.State.Pid = 0
			}
			endpoint := f.native.NetworkSettings.Networks["fixture-bridge"]
			endpoint.EndpointID, endpoint.NetworkID = tc.endpoint, tc.network
			status, err := m.Status(context.Background(), "task")
			if err != nil || status.TaskFact == nil || status.TaskFact.EndpointPresent == nil || *status.TaskFact.EndpointPresent != tc.want {
				t.Fatal("endpoint inferred from process Running instead of exact IDs", status, err)
			}
		})
	}
	for _, mode := range []string{"foreign-network", "foreign-owner", "missing-container"} {
		t.Run(mode, func(t *testing.T) {
			m, f := networkIdentityFixture(t)
			switch mode {
			case "foreign-network":
				f.native.NetworkSettings.Networks["fixture-bridge"].NetworkID = "foreign-network"
			case "foreign-owner":
				f.native.Config.Labels["org.mydc.owner"] = "foreign"
			case "missing-container":
				f.gone = true
			}
			status, err := m.Status(context.Background(), "task")
			if err == nil || status.TaskFact != nil {
				t.Fatal("unmatched/missing inspection manufactured a public endpoint fact", status, err)
			}
		})
	}
}
