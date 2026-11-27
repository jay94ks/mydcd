// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

func TestRealBoundaryPrecreateRejectionAndDependencyReturn(t *testing.T) {
	owner := os.Getenv("SFC_DOCKER_TEST_OWNER")
	if owner == "" {
		t.Skip("requires explicit owner and docs/testing/system-rollback.md prestate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := engine.Open(ctx, "unix:///var/run/docker.sock", owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	n, err := network.OpenManager(filepath.Join(t.TempDir(), "network.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	wPath := filepath.Join(t.TempDir(), "workload.db")
	w, err := OpenManager(wPath, c, n)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	prefix := netip.MustParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	bridge := network.BridgeSpec{Schema: 1, Network: "precreate", Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "a", Network: "precreate", Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}
	bridgeKey, taskKey := "network/precreate", "workload/precreate"
	if err = n.Desired(bridgeKey, 1, 1, &bridge, 2); err != nil {
		t.Fatal(err)
	}
	br, _ := n.View(bridgeKey)
	id, err := c.Identity("bridge", bridgeKey, br.State.Desired.Resource)
	if err != nil {
		t.Fatal(err)
	}
	// Registered before the first native mutation, used only on failure.
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		got, e := c.API.NetworkInspect(clean, id.Name, client.NetworkInspectOptions{})
		if cerrdefs.IsNotFound(e) {
			return
		}
		if e != nil || !id.Matches(got.Network.Name, got.Network.Labels) {
			t.Error("rollback ownership", e)
			return
		}
		_, e = c.API.NetworkRemove(clean, got.Network.ID, client.NetworkRemoveOptions{})
		t.Error("product failed to remove bridge; fallback", e)
	}()
	missing := sha256.Sum256([]byte("absent-image:" + owner))
	image := "sha256:" + hex.EncodeToString(missing[:])
	if _, err = c.API.ImageInspect(ctx, image); !cerrdefs.IsNotFound(err) {
		t.Fatal("precondition: image must be absent", err)
	}
	spec := ContainerSpec{Schema: 1, Node: owner, Image: image, Command: []string{"/backend"}, Bridge: bridgeKey, BridgeGeneration: 1, IPv4: prefix.Addr().Next().Next(), Memory: 32 << 20, NanoCPU: 100000000}
	if err = w.Desired(taskKey, 2, 2, &spec, 2); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("unready dependency rejection", err)
	}
	first, _ := w.View(taskKey)
	if first.State.Pending != nil || first.State.Applied.Present || first.State.LastID != 1 {
		t.Fatal("precreate rejection stranded original", first.State)
	}
	_ = w.Close()
	w, err = OpenManager(wPath, c, n)
	if err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal("actual bridge apply", err)
	}
	if err = w.Step(ctx, taskKey); !cerrdefs.IsNotFound(err) {
		t.Fatal("missing image should preserve its original error", err)
	}
	r, _ := w.View(taskKey)
	br, _ = n.View(bridgeKey)
	if r.State.Pending != nil || r.State.Applied.Present || r.State.LastID != 2 || len(br.Consumers) != 0 || br.Pins.Next == 0 {
		t.Fatal("precreate failure leaked original dependency", r, br)
	}
	if gone, e := c.Gone(ctx, "container", taskKey); e != nil || !gone {
		t.Fatal("precreate failure made a container", e)
	}
	if err = w.Desired(taskKey, 3, 2, nil, 2); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal(err)
	}
	if gone, e := w.Gone(ctx, taskKey, 3, 2); e != nil || !gone {
		t.Fatal("never-created task drain", e)
	}
	if err = n.Desired(bridgeKey, 4, 1, nil, 2); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal("precreate dependency drain", err)
	}
	if gone, e := n.Gone(ctx, bridgeKey, 4, 1, bridge); e != nil || !gone {
		t.Fatal("precreate dependency native removal", e)
	}
	t.Log("real Engine unready dependency and missing image; no container create; original errors/DB reopen, returned pin and actual Bridge retirement")
}
