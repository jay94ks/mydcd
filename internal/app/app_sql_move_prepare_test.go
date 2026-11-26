// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A kernel link-down can remove static routes. Restore only the original
// goal-owned snapshot on the same interface; link-up alone is insufficient.
func pauseMoveTunnel(t *testing.T, ctx context.Context, manager *network.TunnelManager, key string) (string, func() error) {
	t.Helper()
	name, err := manager.Inspect(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil || link.Attrs().Flags&net.FlagUp == 0 {
		t.Fatal("original target TUN must be up before fault", err)
	}
	row, err := manager.View(key)
	spec, decodeErr := network.DecodeTunnel(row.State.Applied.Spec)
	if err != nil || decodeErr != nil {
		t.Fatal("original TUN goal required before route snapshot", err, decodeErr)
	}
	index, alias := link.Attrs().Index, link.Attrs().Alias
	all, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{LinkIndex: index}, netlink.RT_FILTER_OIF)
	if err != nil {
		t.Fatal(err)
	}
	var routes []netlink.Route
	for _, route := range all {
		if route.Protocol != unix.RTPROT_STATIC {
			continue
		}
		owned := false
		for _, prefix := range spec.Routes {
			owned = owned || route.Dst != nil && route.Dst.String() == prefix.String()
		}
		if !owned || route.Table != unix.RT_TABLE_MAIN || route.Priority != spec.RouteMetric || route.MTU != spec.MTU || len(route.MultiPath) != 0 {
			t.Fatal("refuse link-down with a foreign/unrecorded static route")
		}
		routes = append(routes, route)
	}
	if len(routes) != len(spec.Routes) {
		t.Fatal("original goal route snapshot incomplete")
	}
	paused := true
	restore := func() error {
		if !paused {
			return nil
		}
		got, err := netlink.LinkByName(name)
		if err != nil || got.Attrs().Index != index || got.Attrs().Alias != alias || got.Type() != link.Type() {
			return errors.Join(err, fmt.Errorf("refuse replacement of original TUN %s/%d", name, index))
		}
		if err := netlink.LinkSetUp(got); err != nil {
			return err
		}
		current, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{LinkIndex: index}, netlink.RT_FILTER_OIF)
		if err != nil {
			return err
		}
		for _, original := range routes {
			present := false
			for _, actual := range current {
				want, have := original, actual
				// Carrier/linkdown flags describe live I/O, not route policy.
				want.Flags, have.Flags = 0, 0
				present = present || reflect.DeepEqual(want, have)
			}
			if !present {
				original.Flags = 0 // kernel carrier flags are not restoration input
				if err := netlink.RouteAdd(&original); err != nil {
					return fmt.Errorf("restore original TUN route %s: %w", original.String(), err)
				}
			}
		}
		check, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if native, err := manager.Inspect(check, key); err != nil || native != name {
			return errors.Join(err, errors.New("original TUN goal readback not restored"))
		}
		paused = false
		return nil
	}
	t.Cleanup(func() {
		if err := restore(); err != nil {
			t.Error("restore original TUN/link/static routes before native rollback", err)
		}
	})
	if err := netlink.LinkSetDown(link); err != nil {
		t.Fatal(err)
	}
	return name, restore
}

// Arm both real native failures before the CLI grants target inputs. Restoring
// TUN first leaves DNS closed, so the normal producer cannot race to prepare
// between the two negative observations. Both use the same accepted move.
func armSQLMoveNativePreparation(t *testing.T, ctx context.Context, target *Runtime, source *engine.Client, original volumes.NativeReady, network, tlsKey string, releasePort func(string), read func() cluster.View, wait func(string, func() bool)) func(control.VolumeMove) {
	t.Helper()
	host := os.Getenv("MYDC_KERNEL_HOST_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || host == "" || current == host || target.tunnel == nil {
		t.Fatal("SQL preparation fault requires the original private namespace/TUN", err)
	}
	projection, err := target.controlPolicy.ProjectResources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tunnelKey := ""
	for key, managed := range projection.ManagedSources {
		if managed.Tunnel != nil && managed.Network.Tenant == original.Spec.Scope.Tenant && managed.Network.Logical == network && managed.Network.Owner == target.Identity.Public {
			if tunnelKey != "" {
				t.Fatal("ambiguous original managed TUN")
			}
			tunnelKey = key
		}
	}
	if tunnelKey == "" {
		t.Fatal("original target managed TUN missing")
	}
	apps, err := target.controlPolicy.Apps(read().State)
	_, dnsRows, known := apps.NetworkDNS(target.Identity.Public)
	owner := target.dnsOwner()
	if err != nil || !known || len(dnsRows) != 1 || owner == nil {
		t.Fatal("original target managed DNS required", err)
	}
	dns := dnsRows[0]
	wait("original target DNS ready and no outstanding query before owned pause", func() bool {
		status, err := owner.Inspect(ctx, dns.Config.Tenant, dns.Config.ID)
		return err == nil && status.Ready && status.Queries == 0
	})
	containers, err := source.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", original.Owner.Native)})
	if err != nil || len(containers.Items) != 1 {
		t.Fatal("original SQL source container required", err)
	}
	sourceID := containers.Items[0].ID
	key, err := os.Open(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, err := key.Stat()
	if err != nil || !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0077 != 0 {
		key.Close()
		t.Fatal("original private fixture TLS key required", err)
	}
	t.Cleanup(func() {
		if err := key.Chmod(keyInfo.Mode().Perm()); err != nil {
			t.Error("restore original fixture TLS key mode", err)
		}
		if err := key.Close(); err != nil {
			t.Error(err)
		}
	})
	// The original test root remains private. Change only this owned inode's
	// mode, never key bytes or the already-running source TLS listener.
	if err := key.Chmod(keyInfo.Mode().Perm() | 0040); err != nil {
		t.Fatal(err)
	}
	paused := false
	restoreDNS := func() error {
		if !paused {
			return nil
		}
		resumed, err := target.newAppDNSOwner()
		if err != nil {
			return err
		}
		target.dnsMu.Lock()
		if target.dns != owner {
			target.dnsMu.Unlock()
			return errors.Join(fmt.Errorf("original SQL DNS owner replaced during pause"), resumed.Close())
		}
		target.dns = resumed
		target.dnsMu.Unlock()
		paused = false
		return nil
	}
	t.Cleanup(func() {
		if err := restoreDNS(); err != nil {
			t.Error("reopen original SQL DNS DB before native rollback", err)
		}
	})
	paused = true
	if err := owner.Close(); err != nil {
		t.Fatal("pause actual original DNS owner", err)
	}
	name, restoreTunnel := pauseMoveTunnel(t, ctx, target.tunnel.manager, tunnelKey)
	return func(job control.VolumeMove) {
		t.Helper()
		permit, err := target.volumeMoveInputPermit(ctx, job.Selection())
		if err != nil {
			t.Fatal(err)
		}
		inputs, err := target.controlPolicy.VolumeMovePreparationInputs(read().State, target.Identity.Public, permit, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		hasTunnel, hasDNS, hasTLS, hasTCP, hasUDP := false, false, false, false, false
		for _, resource := range inputs.Resources {
			if resource.Owner == target.Identity.Public {
				hasTunnel = hasTunnel || resource.Kind == "native-tunnel" && resource.Key == tunnelKey
				hasDNS = hasDNS || resource.Kind == "native-dns" && resource.Key == dns.Source.Key
			}
			if resource.Kind == "ingress" && resource.Ingress != nil {
				for _, listener := range resource.Ingress.Listeners {
					hasTLS = hasTLS || listener.TLS && listener.HTTP3
					hasTCP = hasTCP || listener.Address == sqlMoveBlockedTCP && !listener.HTTP3
					hasUDP = hasUDP || listener.Address == sqlMoveBlockedUDP && listener.HTTP3
				}
			}
		}
		if !hasTunnel || !hasDNS || !hasTLS || !hasTCP || !hasUDP {
			t.Fatal("accepted SQL move read-set must consume the original TUN/DNS/TLS and declared occupied TCP/UDP endpoints")
		}
		assertSourcePreserved := func() {
			t.Helper()
			if err := target.prepareMoveTarget(ctx, job); err == nil {
				t.Fatal("unavailable real target native produced preparation")
			}
			registry, err := target.controlPolicy.Volumes(read().State)
			if err != nil {
				t.Fatal(err)
			}
			stored, move, found := registry.Move(job.Selection())
			core, exists := registry.Volume(original.Spec.Scope)
			if !exists {
				t.Fatal("original SQL Volume disappeared during target preparation")
			}
			owner, revision := core.Owner()
			if !found || stored.Digest() != job.Digest() || move.Phase != volumes.Prepared || move.Preparation != nil || move.Fence != nil || move.Manifest != nil || move.CommitRevision != 0 || owner != original.Owner || revision != job.Binding.SourceOwnerRevision {
				t.Fatal("failed SQL target preparation retired or replaced original source")
			}
			actual, err := source.API.ContainerInspect(ctx, sourceID, client.ContainerInspectOptions{})
			if err != nil || actual.Container.State == nil || !actual.Container.State.Running {
				t.Fatal("original SQL source stopped before full target preparation", err)
			}
		}
		if _, err := target.tunnel.manager.Inspect(ctx, tunnelKey); err == nil {
			t.Fatal("actual target TUN down was not detected")
		}
		assertSourcePreserved()
		if err := restoreTunnel(); err != nil {
			t.Fatal(err)
		}
		wait("original SQL target TUN ifindex/packet plane resumes beside paused DNS", func() bool {
			got, err := target.tunnel.manager.Inspect(ctx, tunnelKey)
			return err == nil && got == name && target.tunnel.Ready(tunnelKey) == nil
		})
		if _, err := owner.Inspect(ctx, dns.Config.Tenant, dns.Config.ID); err == nil {
			t.Fatal("closed actual target DNS was not detected")
		}
		assertSourcePreserved()
		if err := restoreDNS(); err != nil {
			t.Fatal(err)
		}
		wait("same SQL DNS DB/instance resumes before TLS-only preparation failure", func() bool {
			status, err := target.dnsOwner().Inspect(ctx, dns.Config.Tenant, dns.Config.ID)
			return err == nil && status.Ready
		})
		assertSourcePreserved()
		if err := key.Chmod(keyInfo.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
		assertSourcePreserved()
		releasePort("tcp")
		assertSourcePreserved()
		releasePort("udp")
		t.Log("same accepted SQL move/current approval -> actual target TUN down/DNS I/O closed -> prepare refused/original SQL native Running and owner unchanged -> original ifindex up/DNS still refuses -> same DNS DB resumes/TLS mode refuses -> original TLS mode restored/TCP refusal -> TCP returned/HTTP3 UDP refusal -> UDP returned/child Wait and same normal move continues")
	}
}
