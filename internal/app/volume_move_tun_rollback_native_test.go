// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/vishvananda/netlink"
)

func TestRealBoundaryMoveTunnelLinkDownRestoresOriginalRoutes(t *testing.T) {
	host := os.Getenv("SFC_KERNEL_HOST_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	if host == "" {
		t.Skip("owned isolated kernel namespace and rollback required")
	}
	if err != nil || current == host || os.Geteuid() != 0 {
		t.Fatal("refuse TUN mutation outside owned private namespace", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	spec := network.TunnelSpec{Schema: 1, Owner: "e4-route-rollback", Network: "route-rollback", MTU: 1280, RouteMetric: 100, Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.74.1/32")}, Routes: []netip.Prefix{netip.MustParsePrefix("10.249.74.0/24"), netip.MustParsePrefix("198.18.74.2/32")}}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := network.DecodeTunnel(string(raw)); err != nil {
		t.Fatal("kernel counterexample requires canonical valid input before effects", err)
	}
	manager, err := network.OpenTunnelManager(filepath.Join(t.TempDir(), "tunnel.db"), "e4-route-rollback")
	if err != nil {
		t.Fatal(err)
	}
	key := "network/tun/route-rollback"
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := manager.Desired(key, 2, 1, nil, 1); err != nil {
			t.Error(err)
		} else if err := manager.Step(cleanup, key); err != nil {
			t.Error(err)
		} else if gone, err := manager.Gone(cleanup, key, 2, 1, spec); err != nil || !gone {
			t.Error("original TUN Remove2/Gone", err)
		}
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := manager.Desired(key, 1, 1, &spec, 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	name, restore := pauseMoveTunnel(t, ctx, manager, key)
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	index := link.Attrs().Index
	if _, err := manager.Inspect(ctx, key); err == nil {
		t.Fatal("down original TUN was accepted as prepared")
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	link, err = netlink.LinkByName(name)
	row, readErr := manager.View(key)
	if err != nil || readErr != nil || link.Attrs().Index != index || row.State.LastID != 1 || row.State.Pending != nil || row.State.Applied.Generation != 1 || len(row.Consumers) != 0 {
		t.Fatal("link/route rollback replaced original native Apply1 or pin identity", err, readErr)
	}
	t.Log("actual link down/refused readiness -> same ifindex/alias/original static routes restored -> original Apply1 retained; original Remove2/Gone follows in cleanup")
}
