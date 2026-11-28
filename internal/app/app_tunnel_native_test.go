// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/gitfixture"
	"github.com/jay94ks/seafield/tests/vaultfixture"
	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v3"
)

// Only real kernel UDP sockets are used. This fixture never reads TUN or
// forwards packets; the two product packet planes must carry the IP traffic.
func TestManagedTunnelUDPHelper(t *testing.T) {
	mode := os.Getenv("SFC_MANAGED_UDP")
	if mode == "" {
		t.Skip("owned native fixture only")
	}
	addresses := strings.Split(os.Getenv("SFC_MANAGED_UDP_ADDRESSES"), ",")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	var sockets []*net.UDPConn
	defer func() {
		for _, c := range sockets {
			_ = c.Close()
		}
	}()
	for _, address := range addresses {
		a, err := netip.ParseAddr(address)
		if err != nil {
			t.Fatal(err)
		}
		af := "udp4"
		if a.Is6() {
			af = "udp6"
		}
		if mode == "echo" {
			c, e := net.ListenUDP(af, &net.UDPAddr{IP: net.IP(a.AsSlice()), Port: 53001})
			if e != nil {
				t.Fatal(e)
			}
			sockets = append(sockets, c)
			go func() {
				b := make([]byte, 2048)
				for {
					n, from, e := c.ReadFromUDP(b)
					if e != nil {
						return
					}
					_, _ = c.WriteToUDP(b[:n], from)
				}
			}()
		} else if mode == "probe" {
			c, e := net.DialUDP(af, nil, &net.UDPAddr{IP: net.IP(a.AsSlice()), Port: 53001})
			if e != nil {
				t.Fatal(e)
			}
			sockets = append(sockets, c)
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			payload := bytes.Repeat([]byte{0x67}, 1252)
			if _, e = c.Write(payload); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 2048)
			n, e := c.Read(b)
			if e != nil || !bytes.Equal(payload, b[:n]) {
				t.Fatal("actual managed kernel UDP", address, e)
			}
		} else {
			t.Fatal("unknown UDP mode")
		}
	}
	if mode == "echo" {
		fmt.Println("managed kernel UDP ready")
		<-ctx.Done()
	}
}

func TestManagedTunnelCleanupHelper(t *testing.T) {
	path := os.Getenv("SFC_MANAGED_TUN_CLEANUP")
	if path == "" {
		t.Skip("owned namespace cleanup only")
	}
	host := os.Getenv("SFC_KERNEL_HOST_NETNS")
	current, namespaceErr := os.Readlink("/proc/self/ns/net")
	if host == "" || namespaceErr != nil || current == host || os.Geteuid() != 0 {
		t.Fatal("refuse native cleanup outside the explicitly owned non-host namespace", namespaceErr)
	}
	cfg, e := loadTestNode(path)
	if e != nil {
		t.Fatal(e)
	}
	_, record, e := bootstrap.Effective(cfg)
	if e != nil {
		t.Fatal(e)
	}
	self, e := identity.Load(cfg.Node.IdentityDir)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(self.Private)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	owner := engine.Owner(record.Root.Cluster, self.Public)
	root := filepath.Dir(path)
	if !filepath.IsAbs(root) || !strings.HasPrefix(cfg.EngineAPI, "unix://"+filepath.Join(root, "engine-")) || !strings.HasPrefix(cfg.Node.StateDir, root+string(os.PathSeparator)) {
		t.Fatal("refuse native rollback outside original private fixture root/Engine")
	}
	docker, e := engine.Open(ctx, cfg.EngineAPI, owner)
	if e != nil {
		t.Fatal(e)
	}
	defer docker.Close()
	bridges, e := network.OpenManager(filepath.Join(cfg.Node.StateDir, "network/journal.db"), docker)
	if e != nil {
		t.Fatal(e)
	}
	defer bridges.Close()
	dependentsStopped := os.Getenv("SFC_TEST_OWNED_DEPENDENTS_STOPPED") == "1"
	if dependentsStopped {
		rows, err := docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner="+owner)})
		if err != nil || len(rows.Items) != 0 {
			t.Fatal("refuse original app borrow return while owned native Tasks remain", err)
		}
	}
	if !cleanupManagedRouteNative(t, ctx, cfg, owner, self.Public, bridges, dependentsStopped, os.Getenv("SFC_TEST_EXPECT_GONE") == "1") {
		t.Fatal("route/isolation rollback incomplete; original Bridge dependencies preserved")
	}
	tunnels, e := network.OpenTunnelManager(filepath.Join(cfg.Node.StateDir, "network/tunnel.db"), owner)
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range tunnels.Keys() {
		row, e := tunnels.View(key)
		if e != nil {
			t.Error(e)
			continue
		}
		_, held, e := journalTunnelNetwork(row)
		if e != nil {
			t.Error(e)
			continue
		}
		if !held {
			continue
		}
		if os.Getenv("SFC_TEST_EXPECT_GONE") == "1" {
			t.Error("product left native TUN journal", key)
		}
		resource := row.State.Applied
		if !resource.Present {
			resource = row.State.Desired.Resource
		}
		if row.State.Pending != nil {
			resource = row.State.Pending.Target
		}
		spec, e := network.DecodeTunnel(resource.Spec)
		if e != nil || spec.Owner != owner {
			t.Error("cleanup exact TUN source", e)
			continue
		}
		for name, pin := range row.Consumers {
			if name != "packet-plane" {
				identity, err := tenancy.ParseSourceIdentity(key)
				digest, hexErr := hex.DecodeString(strings.TrimPrefix(name, "network-reference/"))
				if !dependentsStopped || !strings.HasPrefix(name, "network-reference/") || hexErr != nil || len(digest) != 32 || err != nil || identity.Kind != "tun" || identity.Node != record.Root.Self.ID || spec.Network != tenancy.PacketNamespace(identity.Tenant, identity.Network) || pin.Generation != resource.Generation {
					t.Error("unproven original TUN consumer closure", name)
					continue
				}
				identity.Kind = "bridge"
				bridge, err := bridges.View(identity.Key())
				bridgePin, held := bridge.Consumers[name]
				bridgeSpec, decodeErr := network.DecodeBridge(bridge.State.Applied.Spec)
				if err != nil || decodeErr != nil || !held || bridge.State.Pending != nil || bridgePin.Generation != bridge.State.Applied.Generation || bridgeSpec.Owner != owner {
					t.Error("original app borrow has no matching owner-local Bridge pin", name, err, decodeErr)
					continue
				}
				if _, err := bridges.Inspect(ctx, identity.Key()); err != nil {
					t.Error("original app borrow Bridge native proof", err)
					continue
				}
			}
			if e = tunnels.Return(network.TunnelLease{Key: key, Consumer: name, Pin: pin}); e != nil {
				t.Error(e)
			}
		}
		revision := row.State.Desired.Revision + 1
		if e = tunnels.Desired(key, revision, resource.Generation, nil, max(1, row.Capacity)); e == nil {
			e = tunnels.Step(ctx, key)
		}
		if e != nil {
			t.Error(e)
		} else if gone, e := tunnels.Gone(ctx, key, revision, resource.Generation, spec); e != nil || !gone {
			t.Error("cleanup TUN not Gone", e)
		}
	}
	_ = tunnels.Close()
	for _, key := range bridges.Keys() {
		row, e := bridges.View(key)
		if e != nil {
			t.Error(e)
			continue
		}
		if row.State.Pending == nil && !row.State.Applied.Present && !row.State.Desired.Present && len(row.Consumers) == 0 {
			continue
		}
		if os.Getenv("SFC_TEST_EXPECT_GONE") == "1" {
			t.Error("product left Bridge journal", key)
		}
		resource := row.State.Applied
		if !resource.Present {
			resource = row.State.Desired.Resource
		}
		if row.State.Pending != nil {
			resource = row.State.Pending.Target
		}
		spec, e := network.DecodeBridge(resource.Spec)
		if e != nil || spec.Owner != owner {
			t.Error("cleanup exact Bridge source", e)
			continue
		}
		for name, pin := range row.Consumers {
			if e = bridges.ReturnConsumer(key, name, pin.Generation); e != nil {
				t.Error(e)
			}
		}
		revision := row.State.Desired.Revision + 1
		if e = bridges.Desired(key, revision, resource.Generation, nil, max(1, row.Capacity)); e == nil {
			e = bridges.Step(ctx, key)
		}
		if e == nil {
			settled, readErr := bridges.View(key)
			if readErr != nil {
				e = readErr
			} else if settled.State.Pending == nil && settled.State.Applied.Present && !settled.State.Desired.Present {
				e = bridges.Step(ctx, key)
			}
		}
		if e != nil {
			t.Error(e)
		} else if gone, e := bridges.Gone(ctx, key, revision, resource.Generation, spec); e != nil || !gone {
			t.Error("cleanup Bridge not Gone", e)
		}
	}
	rows, e := docker.API.NetworkList(ctx, client.NetworkListOptions{Filters: client.Filters{}.Add("label", "org.sfc.owner="+owner)})
	if e != nil || len(rows.Items) != 0 {
		t.Error("owned Bridge cleanup incomplete", e)
	}
}

func TestRealBoundaryManagedMultiNetworkTunnels(t *testing.T) { testManagedTwoNodeFixture(t, false) }
func TestRealBoundaryManagedCrossTenantRoutes(t *testing.T) {
	testManagedTwoNodeFixture(t, false, managedTwoNodeOptions{crossTenantRoute: true})
}

// Focused RQ10 acceptance: discovery, bilateral traffic and final ownership return.
// Full route restart/flow-GC/revocation remains in its original selector.
func TestRealBoundaryPublishedCrossTenantRouteEndpoints(t *testing.T) {
	testManagedTwoNodeFixture(t, false, managedTwoNodeOptions{crossTenantRoute: true, routeDiscovery: true})
}

func TestE3ManagedDNSRuntimeAcrossOwnersAndPools(t *testing.T) {
	testManagedTwoNodeFixture(t, false, managedTwoNodeOptions{managedDNSRuntime: true})
}

func TestE3ManagedRouteFaultBoundaries(t *testing.T) {
	testManagedTwoNodeFixture(t, false, managedTwoNodeOptions{crossTenantRoute: true, routeFaults: true})
}
func TestP0RealBoundaryManagedNamedTunnels(t *testing.T) {
	testManagedTwoNodeFixture(t, false, managedTwoNodeOptions{managedNetwork: true})
}
func TestRealBoundaryManagedTwoNodePHPMySQL(t *testing.T) { testManagedTwoNodeFixture(t, true) }
func TestRealBoundaryManagedTwoNodeDNSPHPMySQL(t *testing.T) {
	testManagedTwoNodeFixture(t, true, managedTwoNodeOptions{dns: true})
}
func TestRealBoundaryManagedTwoNodeDNSPHPHealth(t *testing.T) {
	testManagedTwoNodeFixture(t, true, managedTwoNodeOptions{dns: true, dnsOnly: true})
}
func TestRealBoundaryManagedMySQLBackupRestore(t *testing.T) {
	testManagedTwoNodeFixture(t, true, managedTwoNodeOptions{restoreSQL: true})
}

func TestRealBoundaryManagedMySQLColdMove(t *testing.T) {
	testManagedTwoNodeFixture(t, true, managedTwoNodeOptions{dns: true, moveSQL: true})
}

func TestE7TwoNodeGitCDSQLAndQuorumRecovery(t *testing.T) {
	testManagedTwoNodeFixture(t, true, managedTwoNodeOptions{dns: true, gitSQL: true})
}

func TestRQ5TwoNodeReplicasRollingAndStatelessMoveNative(t *testing.T) {
	testManagedTwoNodeFixture(t, false, managedTwoNodeOptions{replicaTopology: true})
}

func TestRQ12NodeDrainKeepsManagedTUNNameAndMovesOriginalVolume(t *testing.T) {
	testManagedTwoNodeFixture(t, false, managedTwoNodeOptions{nodeDrain: true})
}

type managedTwoNodeOptions struct{ restoreSQL, dns, dnsOnly, moveSQL, managedNetwork, crossTenantRoute, managedDNSRuntime, routeFaults, routeDiscovery, gitSQL, replicaTopology, nodeDrain, identityTraffic, identityDNSClosure bool }

func testManagedTwoNodeFixture(t *testing.T, sqlMode bool, options ...managedTwoNodeOptions) {
	var option managedTwoNodeOptions
	if len(options) == 1 {
		option = options[0]
	}
	withRestore := option.restoreSQL
	containerMode := sqlMode || option.crossTenantRoute || option.managedDNSRuntime || option.replicaTopology || option.nodeDrain
	firewallMode := option.crossTenantRoute || option.managedDNSRuntime || option.replicaTopology || option.nodeDrain
	host, tag, products, manifest := os.Getenv("SFC_KERNEL_HOST_NETNS"), os.Getenv("SFC_KERNEL_TEST_OWNER"), os.Getenv("SFC_TUNNEL_PRODUCTS"), os.Getenv("SFC_NATIVE_MANIFEST")
	current, e := os.Readlink("/proc/self/ns/net")
	if host == "" || tag == "" || products == "" || manifest == "" || os.Geteuid() != 0 {
		t.Skip("user-prebuilt products and owned namespace/host rollback required")
	}
	if e != nil || current == host {
		t.Fatal("refuse host namespace mutation")
	}
	budget := 100 * time.Second
	if option.managedNetwork {
		budget = 240 * time.Second // E3 adds grouped gateway/owner/final-retirement cycles to the original bounded fixture.
	}
	if option.crossTenantRoute {
		budget = 480 * time.Second
	} // Finite TCP/UDP lifetime and original DB restart, not load testing.
	if option.managedDNSRuntime {
		budget = 240 * time.Second
	}
	if option.replicaTopology {
		budget = 6 * time.Minute // one owned app: move, peer loss, two finite updates and final down
	}
	if option.nodeDrain {
		budget = 6 * time.Minute // one original Volume copy and two finite app lifecycles
	}
	if sqlMode {
		budget = 240 * time.Second
		if option.dns && !option.dnsOnly {
			// Real image preparation, named SQL, same-DB restart and twelve
			// original retirement targets share this development fixture budget.
			budget = 360 * time.Second
		}
	}
	if withRestore || option.moveSQL {
		budget = 480 * time.Second // two app lifecycles plus cold copy/verify, same finite CPU budget
	}
	if option.moveSQL {
		// Forward and reverse cold moves, target first writes, a real daemon
		// cut/recovery, and retained-data cleanup span THREE app lifecycles.
		// This is only the whole scenario envelope; per-operation, transfer,
		// no-progress, CPU and data-size limits remain independent.
		budget = 15 * time.Minute
	}
	if option.gitSQL {
		// E7 includes initial SQL admission, a second Git/Task lifecycle,
		// quorum and native failures, same-DB recovery and final retirement.
		// This bounds the whole development scenario only; native/RPC
		// deadlines, Raft timers, CPU and finite load remain unchanged.
		budget = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	root, e := os.MkdirTemp("", "sfc-managed-tunnels-state-")
	if e != nil {
		t.Fatal(e)
	}
	var a *Runtime
	var daemon *exec.Cmd
	var holder *systemProcess
	var engines [2]*systemProcess
	var containerds [2]*systemProcess
	var sockets [2]string
	var daemonDone chan error
	var ns, mnt *os.File
	var echoes []*exec.Cmd
	var echoDone []chan error
	normal := false
	stop := func(cmd **exec.Cmd, done chan error) {
		if *cmd == nil {
			return
		}
		_ = (*cmd).Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = (*cmd).Process.Kill()
			<-done
		}
		*cmd = nil
	}
	self, _ := os.Executable()
	nsPath, mntPath := "", ""
	var configs [2]string
	var owners [2]string
	var before [2][]byte
	var rawBefore, rawLast [2][]byte
	var forwarding [2]string
	var forwarding6 [2]string
	run := func(where int, env []string, args ...string) ([]byte, error) {
		limit := 15 * time.Second
		if containerMode {
			limit = 50 * time.Second
		}
		c, stop := context.WithTimeout(context.Background(), limit)
		defer stop()
		cmd := exec.CommandContext(c, args[0], args[1:]...)
		if where == 1 {
			prefix := []string{"--net=" + nsPath}
			if containerMode {
				prefix = append(prefix, "--mount="+mntPath)
			}
			cmd = exec.CommandContext(c, "nsenter", append(append(prefix, "--"), args...)...)
		}
		cmd.Env = append(os.Environ(), env...)
		return cmd.CombinedOutput()
	}
	snapshot := func(where int) []byte {
		t.Helper()
		rows := map[string]json.RawMessage{}
		for name, args := range map[string][]string{"link": {"ip", "-j", "link"}, "addr": {"ip", "-j", "addr"}, "rule4": {"ip", "-j", "-4", "rule"}, "rule6": {"ip", "-j", "-6", "rule"}, "v4": {"ip", "-j", "-4", "route", "show", "table", "all"}, "v6": {"ip", "-j", "-6", "route", "show", "table", "all"}, "nft": {"nft", "-j", "list", "ruleset"}} {
			b, e := run(where, nil, args...)
			if e != nil {
				t.Fatal("namespace baseline", name, e, string(b))
			}
			rows[name] = b
		}
		raw, _ := json.Marshal(rows)
		rawLast[where] = bytes.Clone(raw)
		if firewallMode {
			value, err := routeSnapshotStructure(raw)
			if err != nil {
				t.Fatal("route native snapshot structure", err)
			}
			return value
		}
		return raw
	}
	t.Cleanup(func() {
		for n := range echoes {
			stop(&echoes[n], echoDone[n])
		}
		stop(&daemon, daemonDone)
		ownersStopped := true
		if a != nil {
			if err := a.Close(); err != nil {
				t.Error("original owner shutdown before native rollback", err)
				ownersStopped = false
			}
			a = nil
		}
		clean := ownersStopped
		var cleanupStopped [2]bool
		for n, path := range configs {
			if path == "" {
				continue
			}
			cfg, e := loadTestNode(path)
			if e != nil {
				t.Error(e)
				clean = false
				continue
			}
			if _, _, e = bootstrap.Effective(cfg); e != nil {
				continue
			}
			expected := "0"
			if normal {
				expected = "1"
			}
			if containerMode {
				cleanupVariable, cleanupTest := "SFC_SQL_CLEANUP", "TestManagedSQLCleanupHelper"
				if option.crossTenantRoute {
					cleanupVariable, cleanupTest = "SFC_ROUTE_CLEANUP", "TestManagedRouteAppCleanupHelper"
				}
				if option.managedDNSRuntime {
					cleanupVariable, cleanupTest = "SFC_DNS_CLEANUP", "TestManagedDNSAppCleanupHelper"
				}
				b, e := run(n, []string{cleanupVariable + "=" + path, "SFC_TEST_EXPECT_GONE=" + expected}, self, "-test.run=^"+cleanupTest+"$", "-test.v")
				if e != nil {
					t.Error("original SQL cleanup", n, e, string(b))
					clean = false
				}
				if e == nil && ownersStopped {
					// This node's original SQL helper positively closed its
					// Tasks/Ingress/inputs; no daemon/packet worker remains.
					cleanupStopped[n] = true
				}
			}
			networkExpected := expected
			if sqlMode || option.replicaTopology || option.nodeDrain {
				networkExpected = "0"
			} // app down returns managed borrows; fixture removes management natives
			cleanupEnv := []string{"SFC_MANAGED_TUN_CLEANUP=" + path, "SFC_TEST_EXPECT_GONE=" + networkExpected}
			if cleanupStopped[n] || !containerMode && ownersStopped {
				cleanupEnv = append(cleanupEnv, "SFC_TEST_OWNED_DEPENDENTS_STOPPED=1")
			}
			b, e := run(n, cleanupEnv, self, "-test.run=^TestManagedTunnelCleanupHelper$", "-test.v")
			if e != nil {
				t.Error("owned cleanup", n, e, string(b))
				clean = false
			}
		}
		if ns != nil && before[0] != nil {
			for n := range before {
				after := snapshot(n)
				if !bytes.Equal(before[n], after) {
					t.Error("namespace baseline differs", n, string(before[n]), string(after))
					clean = false
				}
			}
		}
		if firewallMode {
			saveRouteNativeSnapshots(t, manifest, rawBefore, rawLast)
		}
		for n, original := range forwarding {
			if original != "" {
				if b, e := run(n, nil, "sysctl", "-w", "net.ipv4.ip_forward="+original); e != nil {
					t.Error("restore owned namespace forwarding", n, e, string(b))
					clean = false
				}
				if b, e := run(n, nil, "sysctl", "-n", "net.ipv4.ip_forward"); e != nil || strings.TrimSpace(string(b)) != original {
					t.Error("owned namespace forwarding read-back differs", n, e)
					clean = false
				}
			}
		}
		for n, original := range forwarding6 {
			if original == "" {
				continue
			}
			if b, err := run(n, nil, "sysctl", "-w", "net.ipv6.conf.all.forwarding="+original); err != nil {
				t.Error("restore owned IPv6 forwarding", err, string(b))
				clean = false
			}
			if b, err := run(n, nil, "sysctl", "-n", "net.ipv6.conf.all.forwarding"); err != nil || strings.TrimSpace(string(b)) != original {
				t.Error("owned IPv6 forwarding read-back differs", n, err)
				clean = false
			}
		}
		if link, e := netlink.LinkByName("mda0"); e == nil {
			if e = netlink.LinkDel(link); e != nil {
				t.Error(e)
				clean = false
			}
		}
		for _, proc := range engines {
			proc.stop(t, false)
		}
		for _, proc := range containerds {
			proc.stop(t, false)
		}
		holder.stop(t, false)
		if ns != nil {
			_ = ns.Close()
		}
		if mnt != nil {
			_ = mnt.Close()
		}
		for _, path := range []string{filepath.Join(root, "node-b.log"), filepath.Join(root, "engine-0/engine.log"), filepath.Join(root, "engine-1/engine.log"), filepath.Join(root, "echo-0.log"), filepath.Join(root, "echo-1.log")} {
			if raw, e := os.ReadFile(path); e == nil {
				lines := bytes.Split(raw, []byte{'\n'})
				if len(lines) > 40 {
					lines = lines[len(lines)-40:]
				}
				t.Log(filepath.Base(path), string(bytes.Join(lines, []byte{'\n'})))
			}
		}
		if clean && !t.Failed() {
			_ = os.RemoveAll(root)
		} else {
			t.Log("preserved original recovery state", root)
		}
	})
	// Cleanup is registered before the first namespace/veth or native effect.
	holder = startSystemProcess(t, ctx, filepath.Join(root, "holder.log"), []string{self, "-test.run=^TestSystemNamespaceHolder$", "-test.v"}, []string{"SFC_R5_NAMESPACE_HOLDER=1"}, &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL})
	for {
		b, _ := os.ReadFile(holder.log)
		if bytes.Contains(b, []byte("r5-private-ns-ready")) {
			break
		}
		select {
		case err := <-holder.done:
			holder.cmd = nil
			t.Fatal("private namespace holder exited", err, string(b))
		default:
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	ns, e = os.Open(fmt.Sprintf("/proc/%d/ns/net", holder.cmd.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	mnt, e = os.Open(fmt.Sprintf("/proc/%d/ns/mnt", holder.cmd.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	mntPath = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), mnt.Fd())
	nsPath = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), ns.Fd())
	if e = netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "mda0"}, PeerName: "mdb0"}); e != nil {
		t.Fatal(e)
	}
	link, e := netlink.LinkByName("mdb0")
	if e != nil {
		t.Fatal(e)
	}
	if e = netlink.LinkSetNsFd(link, int(ns.Fd())); e != nil {
		t.Fatal(e)
	}
	for n, name := range []string{"mda0", "mdb0"} {
		for _, args := range [][]string{{"ip", "link", "set", "lo", "up"}, {"ip", "address", "add", fmt.Sprintf("192.0.2.%d/30", n+1), "dev", name}, {"ip", "link", "set", name, "up", "mtu", "1500"}} {
			if b, e := run(n, nil, args...); e != nil {
				t.Fatal(e, string(b))
			}
		}
	}
	for n := 0; n < 2; n++ {
		for {
			b, e := run(n, nil, "ip", "-j", "-6", "addr")
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Contains(b, []byte("tentative")) {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		engRoot := filepath.Join(root, fmt.Sprintf("engine-%d", n))
		if e = os.MkdirAll(engRoot, 0700); e != nil {
			t.Fatal(e)
		}
		conf := filepath.Join(engRoot, "daemon.json")
		if e = os.WriteFile(conf, []byte(`{"features":{"containerd-snapshotter":false}}`), 0600); e != nil {
			t.Fatal(e)
		}
		sockets[n] = filepath.Join(engRoot, "docker.sock")
		args := []string{"dockerd", "--config-file", conf, "--host", "unix://" + sockets[n], "--data-root", filepath.Join(engRoot, "data"), "--exec-root", filepath.Join(engRoot, "exec"), "--pidfile", filepath.Join(engRoot, "docker.pid"), "--storage-driver", "vfs", "--bridge", "none", "--iptables=false", "--ip6tables=false", "--ip-forward=false", "--ip-masq=false", "--userland-proxy=false", "--shutdown-timeout", "3", "--log-level", "error"}
		if firewallMode {
			for i, value := range args {
				if value == "--iptables=false" {
					args[i] = "--iptables=true"
				}
				if value == "--ip6tables=false" {
					args[i] = "--ip6tables=true"
				}
			}
		}
		if containerMode {
			containerdConfig := filepath.Join(engRoot, "containerd.toml")
			containerdSocket := filepath.Join(engRoot, "containerd.sock")
			toml := fmt.Sprintf("version = 3\nroot = %q\nstate = %q\ndisabled_plugins = [\"io.containerd.cri.v1.images\", \"io.containerd.cri.v1.runtime\"]\n[grpc]\naddress = %q\n", filepath.Join(engRoot, "containerd-root"), filepath.Join(engRoot, "containerd-state"), containerdSocket)
			if e = os.WriteFile(containerdConfig, []byte(toml), 0600); e != nil {
				t.Fatal(e)
			}
			containerdArgs := []string{"containerd", "--config", containerdConfig, "--log-level", "error"}
			if n == 1 {
				containerdArgs = append([]string{"nsenter", "--net=" + nsPath, "--mount=" + mntPath, "--"}, containerdArgs...)
			}
			containerds[n] = startSystemProcess(t, ctx, filepath.Join(engRoot, "containerd.log"), containerdArgs, nil, &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL})
			args = append(args, "--containerd", containerdSocket, "--containerd-namespace", tag+fmt.Sprintf("-%d", n), "--containerd-plugins-namespace", tag+fmt.Sprintf("-plugins-%d", n))
		}
		if n == 1 {
			args = append([]string{"nsenter", "--net=" + nsPath, "--mount=" + mntPath, "--"}, args...)
		}
		if containerMode {
			args = append(args, "--insecure-registry", "192.0.2.0/24")
		}
		engines[n] = startSystemProcess(t, ctx, filepath.Join(engRoot, "engine.log"), args, nil, &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL})
		for {
			b, err := run(n, nil, "docker", "--host", "unix://"+sockets[n], "info", "--format", "{{.ID}} {{.ServerVersion}}")
			if err == nil {
				t.Logf("independent Engine%d=%s", n, b)
				break
			}
			select {
			case err := <-engines[n].done:
				engines[n].cmd = nil
				log, _ := os.ReadFile(engines[n].log)
				t.Fatal("private Engine exited", err, string(log))
			default:
			}
			select {
			case <-ctx.Done():
				t.Fatal("private Engine socket", ctx.Err())
			case <-time.After(30 * time.Millisecond):
			}
		}
		if containerMode {
			b, e := run(n, nil, "sysctl", "-n", "net.ipv4.ip_forward")
			if e != nil || strings.TrimSpace(string(b)) != "0" && strings.TrimSpace(string(b)) != "1" {
				t.Fatal("owned namespace forwarding baseline", e)
			}
			forwarding[n] = strings.TrimSpace(string(b))
			if b, e := run(n, nil, "sysctl", "-w", "net.ipv4.ip_forward=1"); e != nil {
				t.Fatal(e, string(b))
			}
			b, e = run(n, nil, "sysctl", "-n", "net.ipv6.conf.all.forwarding")
			if e != nil || strings.TrimSpace(string(b)) != "0" && strings.TrimSpace(string(b)) != "1" {
				t.Fatal("owned IPv6 forwarding baseline", e)
			}
			forwarding6[n] = strings.TrimSpace(string(b))
		}
		if firewallMode {
			// Docker initializes its persistent, empty POSTROUTING hook on
			// the first bridge, rather than at daemon startup. Establish that
			// Engine baseline before comparing Seafield Cluster's resource lifecycle.
			name := tag + "-driver-baseline"
			id := ""
			t.Cleanup(func() {
				if id != "" {
					if b, err := run(n, nil, "docker", "--host", "unix://"+sockets[n], "network", "rm", id); err != nil {
						t.Error("private Engine driver baseline rollback", err, string(b))
					}
				}
			})
			args := []string{"docker", "--host", "unix://" + sockets[n], "network", "create", "--driver", "bridge", "--subnet", "198.19.85.240/28", "--label", "org.sfc.test-owner=" + tag}
			if option.managedDNSRuntime {
				args = append(args, "--ipv6", "--subnet", "fd42:6d79:ffff::/64")
			}
			args = append(args, name)
			b, err := run(n, nil, args...)
			if err != nil {
				t.Fatal("private Engine driver baseline create", err, string(b))
			}
			id = strings.TrimSpace(string(b))
			if len(id) != 64 {
				t.Fatal("private Engine driver baseline missing original ID")
			}
			if b, err = run(n, nil, "docker", "--host", "unix://"+sockets[n], "network", "rm", id); err != nil {
				t.Fatal("private Engine driver baseline remove", err, string(b))
			}
			t.Logf("private Engine%d initialized bridge driver and removed original bootstrap network %s", n, id)
			id = ""
		}
		before[n] = snapshot(n)
		rawBefore[n] = bytes.Clone(rawLast[n])
	}
	admin, e := identity.Create(filepath.Join(root, "admin"))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(admin.Private)
	for n, id := range []string{"node-a", "node-b"} {
		configs[n] = filepath.Join(root, id+".yaml")
		text := fmt.Sprintf("version: 1\nnode:\n id: %s\n listen: '192.0.2.%d:44101'\n state_dir: %q\n identity_dir: %q\nmodules:\n network: {enabled: true}\n workload: {enabled: false}\n ingress: {enabled: false}\n", id, n+1, filepath.Join(root, fmt.Sprintf("state-%d", n)), filepath.Join(root, fmt.Sprintf("key-%d", n)))
		writeTestEngine(t, configs[n], "unix://"+sockets[n])
		text = strings.Replace(text, "\nmodules:", "\n management_socket: "+fmt.Sprintf("%q", filepath.Join(root, id+".sock"))+"\nmodules:", 1)
		if containerMode {
			text = strings.Replace(text, "workload: {enabled: false}", "workload: {enabled: true}", 1)
			// App routes use the node's external gateway listeners.
			if option.replicaTopology && n == 0 {
				text = strings.Replace(text, "ingress: {enabled: false}", "ingress: {enabled: true, gateways: {external: {enabled: true, addresses: [192.0.2.1], ports: [18080], listeners: [{id: http, address: '192.0.2.1:18080'}]}}}", 1)
			}
			if sqlMode && n == 1 {
				text = strings.Replace(text, "ingress: {enabled: false}", "ingress: {enabled: true, gateways: {external: {enabled: true, addresses: [192.0.2.2], ports: [8080, 8443], listeners: [{id: http, address: '192.0.2.2:8080'}, {id: https, address: '192.0.2.2:8443', tls: true, http3: true}]}}}", 1)
			}
		}
		if e = os.WriteFile(configs[n], []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
	}
	cfg, e := loadTestNode(configs[0])
	if e != nil {
		t.Fatal(e)
	}
	var vault *vaultfixture.Vault
	var gitSource *gitfixture.Fixture
	if sqlMode {
		_, _ = systemCertificate(t, root)
		vault = vaultfixture.Open(t)
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("SQL provider credential requires the finite scenario deadline")
		}
		// A two-lifecycle SQL scenario can legitimately exceed the short
		// fixture's old five-minute token. Provision credentials for this
		// original finite deadline plus cleanup, without renewing at failures.
		installManagedVault(t, &cfg, root, vault, time.Until(deadline)+30*time.Second)
	}
	if option.gitSQL {
		gitSource = gitfixture.OpenAt(t, "192.0.2.1:0")
		credential := gitSource.Credential(root, "tenant", "git-read")
		cfg.GitCredentials = []config.GitCredential{credential}
		remoteConfig, err := loadTestNode(configs[1])
		if err != nil {
			t.Fatal(err)
		}
		if len(remoteConfig.GitCredentials) != 0 {
			t.Fatal("fixture already has Git credentials")
		}
		raw, err := os.ReadFile(configs[1])
		if err != nil {
			t.Fatal(err)
		}
		var document, credentials yaml.Node
		if err = yaml.Unmarshal(raw, &document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
			t.Fatal("original node YAML", err)
		}
		mapping := document.Content[0]
		for i := 0; i < len(mapping.Content); i += 2 {
			if mapping.Content[i].Value == "git_credentials" {
				t.Fatal("duplicate Git credentials in fixture")
			}
		}
		if err = credentials.Encode([]config.GitCredential{credential}); err != nil {
			t.Fatal(err)
		}
		// Module.Body is an input-only decoded representation. Preserve the
		// original module mappings rather than serializing that Go structure.
		mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "git_credentials"}, &credentials)
		raw, err = yaml.Marshal(&document)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(configs[1], raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = loadTestNode(configs[1]); err != nil {
			t.Fatal("prepared Git node config", err)
		}
	}
	init, e := Initialize(ctx, cfg, admin.Public, "init-managed-tunnels")
	if e != nil {
		t.Fatal(e)
	}
	a, e = Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.InstallConfiguration(ctx); e != nil {
		t.Fatal(e)
	}
	clusterID := init.Installation.Root.Cluster
	policy := a.controlPolicy
	proof, e := identity.Ephemeral()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(proof.Private)
	source := sfcp.Peer{ID: "node-a", Endpoint: "192.0.2.1:44101", Policy: sfcp.Policy{Key: sfcp.Identity(a.Identity.Public), Respond: true}}
	mesh, e := sfcp.NewTransport(proof, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return source, k == source.Key })
	if e != nil {
		t.Fatal(e)
	}
	defer mesh.Close()
	user := userauth.Client{Cluster: clusterID, Self: proof, Mesh: mesh, Peers: []sfcp.Peer{source}}
	reply, e := user.Enroll(ctx, source, control.Enrollment{Schema: 1, RequestID: "native-admin", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}, admin.Private)
	if e != nil || reply.Result == nil || reply.Result.Code != state.Applied {
		t.Fatal("actual enrollment", e)
	}
	session, e := user.Login(ctx, source, "admin", admin.Private)
	if e != nil {
		t.Fatal(e)
	}
	recordedOperations := map[string]control.UserOperation{}
	recordedResults := map[string]state.Result{}
	attempt := func(id, action string, expected uint64, payload any) state.Result {
		t.Helper()
		raw, _ := control.ChangeBytes(action, "admin", expected, payload)
		var ch control.Change
		_ = json.Unmarshal(raw, &ch)
		op, e := user.Prepare(ctx, source, session, id, ch)
		if e != nil {
			t.Fatal(id, action, e)
		}
		reply, e := user.Operation(ctx, source, op, false)
		if e != nil || reply.Result == nil {
			t.Fatal(id, action, e, reply.Result)
		}
		recordedOperations[id], recordedResults[id] = op, *reply.Result
		return *reply.Result
	}
	change := func(id, action string, expected uint64, payload any) {
		t.Helper()
		if result := attempt(id, action, expected, payload); result.Code != state.Applied {
			t.Fatal(id, action, result)
		}
	}
	var lastReadCause string
	read := func() cluster.View {
		t.Helper()
		for {
			v, err := a.Engine().Read(ctx, true)
			if err == nil {
				return v
			}
			if !option.gitSQL || !errors.Is(err, raft.ErrNotLeader) && !errors.Is(err, raft.ErrLeadershipLost) && !errors.Is(err, cluster.ErrRecovering) {
				t.Fatal(err)
			}
			// This N2 fixture cannot assume the original process stays leader.
			// Obtain an actual authenticated latest quorum proof, then wait for
			// that committed index locally. Preserve Local=true: this is a
			// follower's assertion view, never a native/management admission.
			query, cancel := context.WithTimeout(ctx, 2*time.Second)
			proof, proofErr := cluster.CallManagement(query, a.Mesh, a.Identity, clusterID, source, cluster.ManagementRequest{Method: "status", Latest: true})
			if proofErr == nil && !proof.Local && proof.CommandIndex > 0 {
				v, proofErr = a.Engine().ReadAtLeast(query, proof.CommandIndex)
				if proofErr == nil {
					cancel()
					if proof.Node != "node-a" {
						t.Log("latest quorum proof from current control", proof.Node, "committed", proof.CommandIndex)
					}
					return v
				}
			}
			cancel()
			cause := fmt.Sprint(err, "/", proofErr)
			if cause != lastReadCause {
				t.Log("original latest read awaiting current quorum", cause)
				lastReadCause = cause
			}
			select {
			case <-ctx.Done():
				t.Fatal("current quorum read", ctx.Err(), cause)
			case <-time.After(40 * time.Millisecond):
			}
		}
	}
	wait := func(label string, check func() bool) {
		t.Helper()
		for !check() {
			select {
			case err := <-daemonDone:
				// This is the original owned handle, not a management timeout.
				// Its Wait result has been consumed; cleanup must not wait twice.
				daemon = nil
				if raw, readErr := os.ReadFile(filepath.Join(root, "node-b.log")); readErr == nil {
					if len(raw) > 8192 {
						raw = raw[len(raw)-8192:]
					}
					t.Log("original node-b daemon exit log", string(raw))
				}
				t.Fatal(label, "original node-b daemon exited", err)
			case <-ctx.Done():
				a.mu.RLock()
				err := a.moduleError
				a.mu.RUnlock()
				t.Fatal(label, ctx.Err(), err)
			case <-time.After(40 * time.Millisecond):
			}
		}
	}
	bKey, e := identity.Create(filepath.Join(root, "key-1"))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(bKey.Private)
	change("invite-b", "invite-node", 0, control.NodeInvitation{Peer: config.Peer{ID: "node-b", Key: bKey.Actor(), Endpoint: "192.0.2.2:44101"}, JoinID: "join-native-b"})
	inv, e := user.NodeInvitation(ctx, source, session, "node-b")
	if e != nil {
		t.Fatal(e)
	}
	invFile := filepath.Join(root, "invitation.json")
	raw, _ := json.Marshal(inv)
	_ = os.WriteFile(invFile, raw, 0600)
	if b, e := run(1, nil, append(append([]string{filepath.Join(products, "sfcd"), "--config", configs[1]}, sfcdEngineFlags(configs[1])...), "join", "--cluster", hex.EncodeToString(clusterID[:]), "--source-public-key", a.Identity.Actor(), "--invitation", invFile)...); e != nil {
		t.Fatal("actual join", e, string(b))
	}
	startB := func() {
		t.Helper()
		log, e := os.OpenFile(filepath.Join(root, "node-b.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		prefix := []string{"--net=" + nsPath}
		if containerMode {
			prefix = append(prefix, "--mount="+mntPath)
		}
		daemon = exec.Command("nsenter", append(append(append(prefix, "--", filepath.Join(products, "sfcd"), "--config", configs[1]), sfcdEngineFlags(configs[1])...), "run")...)
		daemon.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		daemon.Stdout, daemon.Stderr = log, log
		if e = daemon.Start(); e != nil {
			t.Fatal(e)
		}
		daemonDone = make(chan error, 1)
		cmd := daemon
		go func() { e := cmd.Wait(); _ = log.Close(); daemonDone <- e }()
	}
	startB()
	cutB := func(stopped func()) {
		t.Helper()
		if daemon == nil || daemon.Process == nil {
			t.Fatal("original node-b daemon handle required")
		}
		owned := daemon
		bConfig, err := loadTestNode(configs[1])
		if err != nil {
			t.Fatal("original daemon socket configuration", err)
		}
		if bConfig.Node.ManagementSocket != filepath.Join(root, "node-b.sock") {
			t.Fatal("process-cut recovery must own its private socket path")
		}
		originalSocket, err := captureOwnedDaemonSocket(bConfig.Node.ManagementSocket, owned.Process.Pid)
		if err != nil {
			t.Fatal("original daemon socket ownership before cut", err)
		}
		defer originalSocket.close()
		paused := true
		t.Cleanup(func() {
			if paused {
				_ = owned.Process.Signal(syscall.SIGCONT)
			}
		})
		if err := owned.Process.Signal(syscall.SIGSTOP); err != nil {
			t.Fatal(err)
		}
		for {
			raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", owned.Process.Pid))
			if err != nil {
				t.Fatal("owned node-b stopped state", err)
			}
			stoppedState := false
			for _, line := range strings.Split(string(raw), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[0] == "State:" && fields[1] == "T" {
					stoppedState = true
				}
			}
			if stoppedState {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("owned node-b SIGSTOP", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		stopped()
		if err := owned.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		err = <-daemonDone
		daemon = nil
		paused = false
		var exit *exec.ExitError
		if ctx.Err() != nil || !errors.As(err, &exit) {
			t.Fatal("owned node-b expected explicit SIGKILL", err, ctx.Err())
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatal("owned node-b did not exit by SIGKILL", err)
		}
		if err := originalSocket.removeAfterKill(owned); err != nil {
			t.Fatal("explicit original daemon socket recovery", err)
		}
		t.Log("explicit operator recovery: original socket peer PID/UID and inode verified before SIGSTOP; same socket removed only after original SIGKILL/Wait, product stale-path refusal unchanged")
	}
	wait("joined node", func() bool {
		d, e := policy.Members(read().State)
		v, ok := d.Entry("node-b")
		return e == nil && ok && membership.FullMember(v)
	})
	if option.gitSQL {
		d, err := policy.Members(read().State)
		entry, found := d.Entry("node-b")
		if err != nil || !found || entry.Peer.Voter {
			t.Fatal("original SQL non-voter before explicit promotion", err)
		}
		change("e7-promote-sql-control", "promote-node", entry.Revision, control.NodeSelection{ID: "node-b"})
		wait("actual SQL N2/Q2 configuration", func() bool {
			installed, err := a.Engine().InstalledConfiguration(ctx, true)
			if err != nil || len(installed.Configuration.Servers) != 2 {
				return false
			}
			for _, server := range installed.Configuration.Servers {
				if server.Suffrage != raft.Voter {
					return false
				}
			}
			return true
		})
	}
	owners = [2]string{a.owner, engine.Owner(clusterID, bKey.Public)}
	raw, _ = json.Marshal(map[string]any{"schema": 1, "cluster": clusterID, "owners": owners, "configs": configs, "state_root": root, "engine_sockets": sockets, "namespace_paths": []string{current, nsPath}, "cidr": "198.19.80.0/23"})
	if e = os.WriteFile(manifest, raw, 0644); e != nil {
		t.Fatal(e)
	}
	change("tenant", "create-tenant", 0, control.TenantID{ID: "tenant"})
	if sqlMode {
		storeFileCertificate(t, ctx, user, source, session, change, filepath.Join(root, "cert.pem"), filepath.Join(root, "private.pem"))
	}
	catalog, _ := policy.Catalog(read().State)
	tenant, _ := catalog.Tenant("tenant")
	change("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a", "node-b"}))
	for _, node := range []string{"node-a", "node-b"} {
		for _, scope := range []string{"", "tenant"} {
			limit := tenancy.NodeLimit{Tenant: scope, Node: node, Capacity: workload.Resources{CPU: 2e9, Memory: 256 << 20}, Networks: 4, MaxConsumers: 8, PacketQueuePackets: 32, PacketQueueBytes: 128 << 10}
			if firewallMode {
				limit.Networks, limit.MaxConsumers = 8, 32
			}
			if sqlMode {
				// Normal 128KiB SQL bodies need roughly 107 MTU1280 packets.
				// Explicit node quota includes SFCP framing/ACK headroom;
				// the smaller queue's overload evidence remains separate.
				limit.PacketQueuePackets = 128
				limit.PacketQueueBytes = 256 << 10
				limit.Capacity.Memory = 1 << 30
				limit.MaxIngressInstances = 2
				limit.MaxIngressListeners = 4
				if option.moveSQL {
					limit.MaxIngressListeners = 6 // original two plus four declared target listeners
				}
				limit.MaxIngressRequests = 4
				limit.MaxIngressConnections = 16
				limit.IngressBufferBytes = 256 << 10
			}
			if option.replicaTopology {
				limit.MaxIngressInstances, limit.MaxIngressListeners = 1, 1
				limit.MaxIngressRequests, limit.MaxIngressConnections = 4, 16
				limit.IngressBufferBytes = 256 << 10
			}
			change("quota/"+scope+"/"+node, "set-node-quota", 0, limit)
		}
	}
	if option.nodeDrain {
		testManagedNodeDrain(t, ctx, a, root, products, configs, sockets, read, change, wait, run)
		normal = true
		return
	}
	if option.replicaTopology {
		testManagedReplicaTopology(t, ctx, a, root, products, configs, sockets, read, change, wait, func() { stop(&daemon, daemonDone) }, startB)
		normal = true
		return
	}
	if option.managedDNSRuntime {
		if option.identityDNSClosure {
			testCurrentIdentityDNSClosure(t, ctx, a, root, products, configs, sockets, manifest, read, change, wait, run)
		} else {
			testManagedDNSRuntime(t, ctx, a, root, products, configs, sockets, manifest, read, change, attempt, wait, daemon.Process.Pid, run)
		}
		wait("DNS product restores both native topology/isolation baselines before rollback", func() bool {
			for n := range before {
				if !bytes.Equal(before[n], snapshot(n)) {
					return false
				}
			}
			return true
		})
		normal = true
		return
	}
	if option.crossTenantRoute {
		var identityChecks []func(func())
		if option.identityTraffic {
			identityChecks = append(identityChecks, prepareTrafficIdentityRotations(t, ctx, a, root, configs[1], manifest, read, change, wait))
		}
		testManagedCrossTenantRoutes(t, ctx, a, root, products, configs, sockets, manifest, read, change, wait, func() { stop(&daemon, daemonDone) }, startB, run, option.routeFaults, option.routeDiscovery, identityChecks...)
		wait("route product restores both native topology/isolation baselines before rollback", func() bool {
			for n := range before {
				if !bytes.Equal(before[n], snapshot(n)) {
					return false
				}
			}
			return true
		})
		normal = true
		return
	}
	if sqlMode {
		testManagedTwoNodeSQL(t, ctx, a, root, products, configs, sockets, manifest, user, source, session, read, change, wait, func() { stop(&daemon, daemonDone) }, startB, cutB, vault, gitSource, withRestore, option.dns, option.dnsOnly, option.moveSQL)
		normal = true
		return
	}
	profile, file, home := filepath.Join(root, "client.yaml"), filepath.Join(root, "app.yaml"), filepath.Join(root, "home")
	_ = os.Mkdir(home, 0700)
	_ = os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%s', endpoint: '192.0.2.1:44101', voter: true}\n", clusterID, a.Identity.Actor())), 0600)
	doc := "name: app\nservices:\n"
	for n, alias := range []string{"alpha", "beta"} {
		for j, node := range []string{"node-a", "node-b"} {
			octet := (n*2 + j) * 16
			doc += fmt.Sprintf(" %s%d:\n  image: docker.io/library/php@sha256:%s\n  cpus: 0.1\n  mem_limit: 16m\n  networks: {%s: {ipv4_address: 198.19.80.%d}}\n  x-sfc: {node: %s}\n", alias, j, strings.Repeat("a", 64), alias, octet+2, node)
		}
	}
	doc += "networks:\n"
	management := "schema: 1\ntenant: tenant\nchanges:\n"
	for n, alias := range []string{"alpha", "beta"} {
		if option.managedNetwork {
			doc += fmt.Sprintf(" %s: {external: true, name: %s}\n", alias, alias)
			management += fmt.Sprintf(" - id: %s\n   action: create-tun-network\n   expected: %d\n   payload:\n    Tenant: tenant\n    Name: %s\n    Members:\n     - Node: node-a\n       Pools: [{ID: pool, Prefix: 198.19.80.%d/28, Gateway: 198.19.80.%d, MTU: 1280}]\n       Addresses: [198.19.81.%d/32]\n     - Node: node-b\n       Pools: [{ID: pool, Prefix: 198.19.80.%d/28, Gateway: 198.19.80.%d, MTU: 1280}]\n       Addresses: [198.19.81.%d/32]\n", alias, n, alias, n*32, n*32+1, n*2+1, n*32+16, n*32+17, n*2+2)
		} else {
			doc += fmt.Sprintf(" %s:\n  x-sfc:\n   mtu: 1280\n   pools:\n    node-a: {cidr: 198.19.80.%d/28, gateway: 198.19.80.%d}\n    node-b: {cidr: 198.19.80.%d/28, gateway: 198.19.80.%d}\n   tunnel_addresses: {node-a: 198.19.81.%d/32, node-b: 198.19.81.%d/32}\n", alias, n*32, n*32+1, n*32+16, n*32+17, n*2+1, n*2+2)
		}
	}
	_ = os.WriteFile(file, []byte(doc), 0600)
	cli := func(args ...string) []byte {
		t.Helper()
		b, diagnostic, e := runManagedCLICommand(ctx, filepath.Join(products, "sfc"), home, profile, args, nil)
		if e != nil {
			t.Fatal("prebuilt CLI", args, e, string(diagnostic), string(b))
		}
		return b
	}
	cli("wallet", "init")
	cli("login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin/key.pem"))
	managementSources := map[string]state.Object{}
	if option.managedNetwork {
		applyManagementChanges(t, root, "prepare-networks", []byte(management), func(args ...string) { cli(args...) })
		managementSources = read().State.Objects("control/network-sources/")
		if len(managementSources) != 8 {
			t.Fatal("two logical networks did not atomically publish eight native sources", len(managementSources))
		}
	}
	tunnelKey := func(alias, node string) string {
		if option.managedNetwork {
			return "control/network-sources/tun/tenant/" + alias + "/" + node
		}
		return deployment.ResourceKey("tunnel", "tenant", "app", alias+"/"+node)
	}
	cli("compose", "up", "--tenant", "tenant", "--operation", "rollout", "-f", file, "--no-input")
	tunnelKeys := []string{}
	for _, alias := range []string{"alpha", "beta"} {
		for _, node := range []string{"node-a", "node-b"} {
			tunnelKeys = append(tunnelKeys, tunnelKey(alias, node))
		}
	}
	observed := func() bool {
		apps, e := policy.Apps(read().State)
		if e != nil {
			return false
		}
		ex, ok := apps.Execution("tenant", "app")
		if !ok {
			return false
		}
		for _, sourceKey := range tunnelKeys {
			key := sourceKey
			if option.managedNetwork {
				parts := strings.Split(sourceKey, "/")
				key = deployment.ResourceKey("network-ref", "tenant", "app", parts[4]+"/"+parts[5])
			}
			stage, ok := ex.Stage(key)
			if !ok || stage.Observation == nil || !stage.Observation.Applied || stage.Observation.Native == "" {
				return false
			}
		}
		return true
	}
	wait("four real managed TUN observations", observed)
	observeB := func(key string) (ModuleObservation, error) {
		current, known := a.resourcePeerForKey(ctx, bKey.Public)
		if !known {
			return ModuleObservation{}, sfcp.ErrAdmission
		}
		reply, e := cluster.CallManagement(ctx, a.Mesh, a.commandIdentity(), clusterID, current, cluster.ManagementRequest{Method: "observe", Key: key, Latest: false})
		var v ModuleObservation
		if e == nil {
			e = json.Unmarshal(reply.Data, &v)
		}
		return v, e
	}
	oldB := map[string]ModuleObservation{}
	for _, alias := range []string{"alpha", "beta"} {
		key := tunnelKey(alias, "node-b")
		var v ModuleObservation
		wait("remote native observation", func() bool {
			var e error
			v, e = observeB(key)
			return e == nil && v.Ready && v.Tunnel != nil && v.Tunnel.PacketUsers == 1
		})
		oldB[key] = v
	}
	startEchoes := func() {
		for n := 0; n < 2; n++ {
			addresses := "198.19.81.1,198.19.81.3"
			if n == 1 {
				addresses = "198.19.81.2,198.19.81.4"
			}
			log, _ := os.Create(filepath.Join(root, fmt.Sprintf("echo-%d.log", n)))
			cmd := exec.Command(self, "-test.run=^TestManagedTunnelUDPHelper$")
			if n == 1 {
				cmd = exec.Command("nsenter", "--net="+nsPath, "--", self, "-test.run=^TestManagedTunnelUDPHelper$")
			}
			cmd.Env = append(os.Environ(), "SFC_MANAGED_UDP=echo", "SFC_MANAGED_UDP_ADDRESSES="+addresses)
			cmd.Stdout, cmd.Stderr = log, log
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			echoes = append(echoes, cmd)
			echoDone = append(echoDone, done)
			go func() { e := cmd.Wait(); _ = log.Close(); done <- e }()
		}
		for n := 0; n < 2; n++ {
			path := filepath.Join(root, fmt.Sprintf("echo-%d.log", n))
			wait("kernel echo ready", func() bool { b, _ := os.ReadFile(path); return bytes.Contains(b, []byte("managed kernel UDP ready")) })
		}
	}
	startEchoes()
	probe := func() {
		t.Helper()
		for n, addresses := range []string{"198.19.81.2,198.19.81.4", "198.19.81.1,198.19.81.3"} {
			b, e := run(n, []string{"SFC_MANAGED_UDP=probe", "SFC_MANAGED_UDP_ADDRESSES=" + addresses}, self, "-test.run=^TestManagedTunnelUDPHelper$", "-test.v")
			if e != nil {
				delivered, dropped := a.Mesh.PacketCounts()
				t.Log("local SFCP packets delivered/dropped", delivered, dropped)
				for node := 0; node < 2; node++ {
					for _, args := range [][]string{{"ip", "-j", "-s", "link"}, {"ip", "-j", "route", "show", "table", "all"}, {"cat", "/proc/net/snmp"}} {
						out, err := run(node, nil, args...)
						t.Log("failed UDP native", node, args, err, string(out))
					}
				}
				t.Fatal("both actual native planes", n, e, string(b))
			}
		}
	}
	probe()
	t.Log("initial bidirectional UDP on both logical networks passed")
	if option.identityTraffic {
		prepareTrafficIdentityRotations(t, ctx, a, root, configs[1], manifest, read, change, wait)(func() {
			wait("original four TUN planes restored on current identity transport", func() bool {
				for _, alias := range []string{"alpha", "beta"} {
					local, err := a.tunnel.Observe(tunnelKey(alias, "node-a"))
					remote, remoteErr := observeB(tunnelKey(alias, "node-b"))
					if err != nil || remoteErr != nil || local.PacketUsers != 1 || remote.Tunnel == nil || remote.Tunnel.PacketUsers != 1 || !remote.Ready {
						return false
					}
					original := oldB[tunnelKey(alias, "node-b")]
					if remote.NativeID != original.NativeID || remote.Journal.Applied != original.Journal.Applied || remote.Journal.LastID != original.Journal.LastID {
						t.Fatal("identity switch replaced original native TUN or operation")
					}
				}
				return true
			})
			probe()
		})
	}
	resources, _ := policy.Resources(read().State)
	limit, _ := resources.Quotas.Limit("", "node-a")
	oldLimit := limit
	rev := limit.Revision
	limit.Revision = 0
	limit.PacketQueuePackets, limit.PacketQueueBytes = 0, 0
	change("pause-packets", "set-node-quota", rev, limit)
	wait("local packet users zero", func() bool {
		for _, alias := range []string{"alpha", "beta"} {
			v, _ := a.tunnel.Observe(tunnelKey(alias, "node-a"))
			if v.PacketUsers != 0 {
				return false
			}
		}
		return true
	})
	resources, _ = policy.Resources(read().State)
	limit, _ = resources.Quotas.Limit("", "node-a")
	oldLimit.Revision = 0
	change("restore-packets", "set-node-quota", limit.Revision, oldLimit)
	wait("local original planes restored", func() bool {
		for _, alias := range []string{"alpha", "beta"} {
			if a.tunnel.Ready(tunnelKey(alias, "node-a")) != nil {
				return false
			}
		}
		return true
	})
	if e = a.Engine().Snapshot(ctx); e != nil {
		t.Fatal(e)
	}
	oldA := map[string]TunnelObservation{}
	for _, alias := range []string{"alpha", "beta"} {
		key := tunnelKey(alias, "node-a")
		oldA[key], e = a.tunnel.Observe(key)
		if e != nil {
			t.Fatal(e)
		}
	}
	eventCursors := map[string]string{}
	if option.managedNetwork {
		for _, kind := range []string{"tunnel-down", "tunnel-up"} {
			page, err := user.EventsPage(ctx, source, session, eventlog.Query{Tenant: "tenant", Node: "node-a", Kind: kind, Limit: 100})
			if err != nil {
				t.Fatal("original tunnel event cursor", err)
			}
			eventCursors[kind] = page.Cursor
		}
	}
	stop(&daemon, daemonDone)
	if option.managedNetwork {
		var reconnectTarget eventlog.Target
		wait("actual stopped peer emits each logical TUN outage", func() bool {
			page, err := user.EventsPage(ctx, source, session, eventlog.Query{Tenant: "tenant", Node: "node-a", Kind: "tunnel-down", After: eventCursors["tunnel-down"], Limit: 100})
			if err != nil {
				return false
			}
			found := map[string]bool{}
			for _, item := range page.Items {
				if item.Target.Tenant != "tenant" || item.Scope != "tenant" || item.Target.PairID != "node-a/node-b" {
					t.Fatal("tunnel outage lost current tenant/network pair", item)
				}
				found[item.Target.Network] = true
				if item.Target.Network == "alpha" {
					reconnectTarget = item.Target
				}
			}
			return found["alpha"] && found["beta"]
		})
		from, to, ok := strings.Cut(reconnectTarget.PairID, "/")
		if !ok || reconnectTarget.Node != from && reconnectTarget.Node != to {
			t.Fatal("outage does not identify an installed member pair", reconnectTarget)
		}
		peer := from
		if reconnectTarget.Node == from {
			peer = to
		}
		var plan control.TunnelPlan
		if json.Unmarshal(cli("mesh", "reconnect", "--node", reconnectTarget.Node, "--peer", peer, "--preview"), &plan) != nil || !plan.Valid() || plan.PairID != reconnectTarget.PairID || plan.Node != reconnectTarget.Node {
			t.Fatal("actual outage event cannot select current reconnect plan", plan)
		}
	}
	startB()
	for key, old := range oldB {
		wait("same DB/native/pin restart", func() bool {
			now, e := observeB(key)
			return e == nil && now.Ready && now.Tunnel != nil && !maps.Equal(now.Tunnel.Connections, old.Tunnel.Connections) && now.NativeID == old.NativeID && now.Journal.Pins["packet-plane"] == old.Journal.Pins["packet-plane"] && now.Journal.LastID == old.Journal.LastID
		})
	}
	wait("local new packet planes after remote restart", func() bool {
		for key, old := range oldA {
			now, err := a.tunnel.Observe(key)
			if err != nil || now.PacketUsers != 1 || maps.Equal(now.Connections, old.Connections) {
				return false
			}
		}
		return true
	})
	if option.managedNetwork {
		wait("actual rejoined peer emits each logical TUN recovery", func() bool {
			page, err := user.EventsPage(ctx, source, session, eventlog.Query{Tenant: "tenant", Node: "node-a", Kind: "tunnel-up", After: eventCursors["tunnel-up"], Limit: 100})
			if err != nil {
				return false
			}
			found := map[string]bool{}
			for _, item := range page.Items {
				if item.Target.Tenant != "tenant" || item.Scope != "tenant" || item.Target.PairID != "node-a/node-b" {
					t.Fatal("tunnel recovery lost tenant/network pair", item)
				}
				found[item.Target.Network] = true
			}
			return found["alpha"] && found["beta"]
		})
		var events eventlog.Page
		if json.Unmarshal(cli("events", "--tenant", "tenant", "--node", "node-a", "--kind", "tunnel-up", "--since", eventCursors["tunnel-up"], "--limit", "100"), &events) != nil || len(events.Items) < 2 {
			t.Fatal("actual CLI tunnel network events missing")
		}
		verifyNativeTunnelEventReader(t, ctx, a, root, source, read, change, eventCursors)
	}
	probe()
	t.Log("restarted bidirectional UDP on both logical networks passed")
	for n := range echoes {
		stop(&echoes[n], echoDone[n])
	}
	cli("compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "down")
	wait("original TUN/Bridge retirement", func() bool {
		shared := read().State
		apps, e := policy.Apps(shared)
		if e != nil {
			return false
		}
		i, ok := apps.Inventory("tenant", "app")
		r, exists := i.Operation("rollout")
		if !ok || !exists || r.Status != "Retired" || !i.Quiescent() || len(i.Claims()) == 0 {
			return false
		}
		// FinishRetirement removes its transient target list. The original
		// operation and removed claims are the durable completion evidence.
		// This metadata-only app has no workload health-verification timestamp;
		// CompletedAt is not the retirement receipt or borrow-return proof.
		for _, claim := range i.Claims() {
			if !claim.Removed || shared.Object(claim.Step.Key).Present {
				return false
			}
		}
		return true
	})
	if option.managedNetwork {
		for key, original := range managementSources {
			if read().State.Object(key) != original {
				t.Fatal("app down changed its borrowed management source", key)
			}
			if strings.Contains(key, "/tun/") {
				if strings.HasSuffix(key, "/node-a") {
					record, err := a.tunnel.manager.View(key)
					if err != nil || len(record.Consumers) != 1 || record.Consumers["packet-plane"].Generation != original.Generation {
						t.Fatal("local app TUN pin was not returned", key, err)
					}
				} else {
					observation, err := observeB(key)
					if err != nil || !observation.Ready || len(observation.Journal.Pins) != 1 || observation.Journal.Pins["packet-plane"].Generation != original.Generation {
						t.Fatal("remote app TUN pin was not returned", key, err)
					}
				}
			} else if strings.HasSuffix(key, "/node-a") {
				record, err := a.network.View(key)
				if err != nil || len(record.Consumers) != 0 || !record.State.Applied.Present {
					t.Fatal("local borrowed Bridge not preserved/returned", key, err)
				}
			} else {
				observation, err := observeB(key)
				if err != nil || !observation.Ready || len(observation.Journal.Pins) != 0 {
					t.Fatal("remote borrowed Bridge not preserved/returned", key, err)
				}
			}
		}
		t.Log("app down returned the four app borrows and preserved all eight management sources/native resources")
		observe := func(node, key string) (ModuleObservation, error) {
			if node == "node-b" {
				return observeB(key)
			}
			raw, err := a.observeManaged(ctx, key, read())
			var observation ModuleObservation
			if err == nil {
				err = json.Unmarshal(raw, &observation)
			}
			return observation, err
		}
		stopEchoes := func() {
			for n := range echoes {
				stop(&echoes[n], echoDone[n])
			}
		}
		replay := func(id string) {
			t.Helper()
			op, known := recordedOperations[id]
			if !known {
				t.Fatal("missing original management operation", id)
			}
			before := read().State
			for _, method := range []string{"result", "resume"} {
				var reply userauth.Reply
				var err error
				if method == "result" {
					reply, err = user.Result(ctx, source, session, op)
				} else {
					reply, err = user.Resume(ctx, source, session, op)
				}
				if err != nil || reply.Result == nil || *reply.Result != recordedResults[id] {
					t.Fatal("original management receipt after same DB restart", method, id, err, reply.Result)
				}
			}
			after := read().State
			if before.Object(control.ResourcesKey) != after.Object(control.ResourcesKey) || before.Object(control.AppsKey) != after.Object(control.AppsKey) {
				t.Fatal("original result/resume reapplied the network transition")
			}
		}
		if option.identityTraffic {
			stopEchoes()
			retireTrafficIdentityNetworks(t, policy, read, change, wait, observe)
		} else {
			verifyManagedTUNReconfiguration(t, policy, read, attempt, wait, observe, startEchoes, stopEchoes, probe, func() { stop(&daemon, daemonDone) }, startB, func() { stop(&daemon, daemonDone); startB() }, replay)
		}
	} else {
		for _, key := range tunnelKeys {
			if read().State.Object(key).Present {
				t.Fatal("retired TUN still shared", key)
			}
		}
	}
	wait("product restores both native topology/isolation baselines before rollback", func() bool {
		for n := range before {
			if !bytes.Equal(before[n], snapshot(n)) {
				return false
			}
		}
		return true
	})
	normal = true
	t.Log("actual CLI up/down, one parent Runtime and one product daemon in two native namespaces; two logical networks/four TUNs, real Bridge SDK effects, bidirectional kernel UDP1280B, runtime packet zero/restore, same node DB/native/pin restart, original retirement; two independent private Docker Engines; no task/image/SQL/Ingress readiness claim")
}
