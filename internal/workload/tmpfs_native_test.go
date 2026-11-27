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
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestRealBoundaryTmpfsImageVolumesAndOriginalRestart(t *testing.T) {
	owner := os.Getenv("SFC_DOCKER_TEST_OWNER")
	if owner == "" {
		t.Skip("requires owned Docker rollback prestate including Volume IDs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	f := enginefixture.OpenConfigured(t, ctx, owner, owner, []string{`USER 10001:10001`, `VOLUME ["/scratch", "/runtime"]`})
	root := t.TempDir()
	nPath, wPath := filepath.Join(root, "network.db"), filepath.Join(root, "workload.db")
	n, err := network.OpenManager(nPath, f.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	w, err := workload.OpenManager(wPath, f.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	prefix := netip.MustParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	bridgeKey, taskKey := "network/tmpfs", "workload/tmpfs"
	bridge := network.BridgeSpec{Schema: 1, Network: "tmpfs", Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "tmpfs", Network: "tmpfs", Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}
	if err = n.Desired(bridgeKey, 1, 1, &bridge, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	image, err := f.Client.Image(ctx, f.Image, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(image.Config.Volumes) != 2 {
		t.Fatal("image VOLUME precondition")
	}
	process, err := workload.ResolveImageProcess(image, workload.ProcessOverrides{MountTargets: []string{"/scratch", "/runtime"}, Environment: map[string]string{"SFC_TMPFS_FIXTURE": "1"}, Healthcheck: &container.HealthConfig{Test: []string{"CMD", "/backend", "--tmpfs-probe"}, Interval: time.Second, Timeout: time.Second, Retries: 2}})
	if err != nil {
		t.Fatal(err)
	}
	spec := workload.ContainerSpec{Schema: 1, Node: owner, Image: f.Image, Bridge: bridgeKey, BridgeGeneration: 1, IPv4: prefix.Addr().Next().Next(), Memory: 32 << 20, NanoCPU: 100000000, Process: &process, Tmpfs: []workload.Tmpfs{{Target: "/scratch", SizeBytes: 4 << 20, UID: 10001, GID: 10001, Mode: 0700}, {Target: "/runtime", SizeBytes: 4 << 20, Mode: 01777}}}
	if err = w.Desired(taskKey, 2, 2, &spec, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("native tmpfs apply", err)
	}
	waitReady := func() string {
		t.Helper()
		for {
			s, e := w.Status(ctx, taskKey)
			if e != nil {
				t.Fatal("tmpfs inspection", e)
			}
			if s.Ready {
				return s.NativeID
			}
			select {
			case <-ctx.Done():
				t.Fatal("kernel tmpfs health", ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	id := waitReady()
	got, err := f.Client.API.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Container.Mounts) != 0 || len(got.Container.HostConfig.Tmpfs) != 2 {
		t.Fatal("unexpected image VOLUME/anonymous mount")
	}
	httpClient := http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer httpClient.CloseIdleConnections()
	marker := func(query, want string) {
		t.Helper()
		r, e := http.NewRequestWithContext(ctx, "GET", "http://"+spec.IPv4.String()+":8080/tmpfs-state"+query, nil)
		if e != nil {
			t.Fatal(e)
		}
		resp, e := httpClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		body, e := io.ReadAll(io.LimitReader(resp.Body, 64))
		if e != nil || resp.StatusCode != 200 || string(body) != want {
			t.Fatal("tmpfs lifetime", string(body), e)
		}
	}
	marker("", "missing")
	marker("?write=1", "present")
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	n, err = network.OpenManager(nPath, f.Client)
	if err != nil {
		t.Fatal(err)
	}
	w, err = workload.OpenManager(wPath, f.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	if waitReady() != id {
		t.Fatal("running journal recovery replaced native ID")
	}
	marker("", "present")
	timeout := 1
	if _, err = f.Client.API.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &timeout}); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("original container restart", err)
	}
	if waitReady() != id {
		t.Fatal("tmpfs restart replaced native ID")
	}
	marker("", "missing")
	state, err := w.View(taskKey)
	if err != nil || state.State.Pending != nil || state.State.LastID != 1 {
		t.Fatal("restart replaced original journal/pin", err)
	}
	if err = w.Desired(taskKey, 3, 2, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	gone, err := w.Gone(ctx, taskKey, 3, 2)
	if err != nil || !gone {
		t.Fatal("native tmpfs closure", err)
	}
	if err = n.Desired(bridgeKey, 4, 1, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal("original dependency return", err)
	}
	t.Log("actual image VOLUME -> exact bounded tmpfs, kernel size/UID/GID/0700/01777/nosuid/nodev/noexec, nonroot write, running DB recovery preserves marker, original-ID restart erases marker, original journal/pin closure")
}
