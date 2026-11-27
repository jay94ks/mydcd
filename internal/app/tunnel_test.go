// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
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

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/vishvananda/netlink"
)

// The helper is an actual kernel UDP service/client. It never reads TUN or
// implements packet forwarding; both daemon packet planes must carry the IP.
func TestTunnelUDPHelper(t *testing.T) {
	mode := os.Getenv("SFC_TUN_HELPER")
	if mode == "" {
		t.Skip("isolated daemon TUN fixture only")
	}
	addresses := strings.Split(os.Getenv("SFC_TUN_ADDRESSES"), ",")
	if len(addresses) != 2 {
		t.Fatal("two explicit addresses required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	if mode == "echo" {
		errs := make(chan error, 2)
		for i, address := range addresses {
			af := "udp4"
			if i == 1 {
				af = "udp6"
			}
			c, err := net.ListenUDP(af, &net.UDPAddr{IP: net.ParseIP(address), Port: 53001})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			go func() {
				b := make([]byte, 2048)
				for {
					n, from, e := c.ReadFromUDP(b)
					if e != nil {
						errs <- e
						return
					}
					if _, e = c.WriteToUDP(b[:n], from); e != nil {
						errs <- e
						return
					}
				}
			}()
		}
		fmt.Println("dual-stack kernel UDP echo ready")
		select {
		case <-ctx.Done():
			return
		case err := <-errs:
			t.Fatal(err)
		}
	}
	if mode != "probe" {
		t.Fatal("unknown helper mode")
	}
	for i, address := range addresses {
		af, header := "udp4", 20
		if i == 1 {
			af, header = "udp6", 40
		}
		c, err := net.DialUDP(af, nil, &net.UDPAddr{IP: net.ParseIP(address), Port: 53001})
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{0x71}, 1280-header-8)
		if err = c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			c.Close()
			t.Fatal(err)
		}
		if _, err = c.Write(payload); err != nil {
			c.Close()
			t.Fatal(err)
		}
		b := make([]byte, 2048)
		n, err := c.Read(b)
		c.Close()
		if err != nil || !bytes.Equal(payload, b[:n]) {
			t.Fatal("actual remote kernel UDP", af, n, err)
		}
		t.Logf("actual %s 1280B IP to %s and kernel echo return", af, address)
	}
}

func TestRealBoundaryDaemonTunnelPathsAndRetirement(t *testing.T) {
	host := os.Getenv("SFC_KERNEL_HOST_NETNS")
	tag := os.Getenv("SFC_KERNEL_TEST_OWNER")
	bin := os.Getenv("SFC_TUNNEL_PRODUCTS")
	if host == "" || tag == "" || bin == "" {
		t.Skip("requires isolated namespace, explicit products/owner and rollback prestate")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || current == host || os.Geteuid() != 0 {
		t.Fatal("refusing namespace mutation", host, current, err)
	}
	for _, name := range []string{"sfc", "sfcd"} {
		if _, err = os.Stat(filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	t.Cleanup(cancel)
	outerSnapshot := func() []byte {
		t.Helper()
		view := map[string]json.RawMessage{}
		for name, args := range map[string][]string{"links": {"ip", "-j", "link"}, "routes4": {"ip", "-j", "-4", "route", "show", "table", "all"}, "routes6": {"ip", "-j", "-6", "route", "show", "table", "all"}, "nft": {"nft", "-j", "list", "ruleset"}} {
			c, stop := context.WithTimeout(context.Background(), 3*time.Second)
			b, e := exec.CommandContext(c, args[0], args[1:]...).Output()
			stop()
			if e != nil {
				t.Fatal(e)
			}
			view[name] = b
		}
		b, _ := json.Marshal(view)
		return b
	}
	outerBefore := outerSnapshot()
	t.Logf("outer prestate=%s", outerBefore)
	t.Cleanup(func() {
		after := outerSnapshot()
		if !bytes.Equal(outerBefore, after) {
			t.Errorf("outer namespace not restored\nbefore=%s\nafter=%s", outerBefore, after)
		}
	})
	root := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]*identity.Identity, 3)
	for i := range keys {
		keys[i], err = identity.Create(filepath.Join(root, fmt.Sprint("key-", i)))
		if err != nil {
			t.Fatal(err)
		}
	}
	clusterID := shaCluster(tag)
	owners := []string{desired.Owner(clusterID, keys[0].Public), desired.Owner(clusterID, keys[1].Public)}
	peers := fmt.Sprintf("    - {id: a, key: '%s', endpoint: '192.0.2.1:44101', voter: false}\n    - {id: b, key: '%s', endpoint: '192.0.2.2:44102', voter: true}\n", keys[0].Actor(), keys[1].Actor())
	configs := make([]string, 2)
	for i, id := range []string{"a", "b"} {
		text := fmt.Sprintf("version: 1\ncommon:\n  cluster: '%x'\n  admin: '%s'\n  peers:\n%snode:\n  id: %s\n  state_dir: '%s'\n  identity_dir: '%s'\n  listen: '192.0.2.%d:%d'\n  bootstrap: %t\nmodules:\n  network: {enabled: true}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n", clusterID, keys[2].Actor(), peers, id, filepath.Join(root, "state-"+id), filepath.Join(root, fmt.Sprint("key-", i)), i+1, 44101+i, i == 1)
		configs[i] = filepath.Join(root, id+".yaml")
		if err = os.WriteFile(configs[i], []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	client := filepath.Join(root, "client.yaml")
	text := fmt.Sprintf("version: 1\ncluster: '%x'\nidentity_dir: '%s'\npeers:\n%s", clusterID, filepath.Join(root, "key-2"), strings.ReplaceAll(peers, "    -", "  -"))
	if err = os.WriteFile(client, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("outer=%s host=%s cluster=%x native owners=%q", current, host, clusterID, owners)
	names := []string{"dca0", "dcb0"}
	ns := make([]*os.File, 2)
	nsPath := make([]string, 2)
	daemons := make([]*exec.Cmd, 2)
	done := make([]chan error, 2)
	logs := make([]string, 2)
	echoes := make([]*exec.Cmd, 2)
	echoDone := make([]chan error, 2)
	var normal bool
	stopProcess := func(cmd **exec.Cmd, ch chan error) {
		if *cmd == nil {
			return
		}
		_ = (*cmd).Process.Signal(syscall.SIGCONT)
		_ = (*cmd).Process.Signal(syscall.SIGTERM)
		select {
		case e := <-ch:
			if e != nil && !t.Failed() {
				t.Error("child exit", e)
			}
		case <-time.After(8 * time.Second):
			_ = (*cmd).Process.Kill()
			<-ch
			t.Error("child Stop/Wait exceeded bound")
		}
		*cmd = nil
	}
	runNS := func(i int, args ...string) ([]byte, error) {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		return exec.CommandContext(c, "nsenter", append([]string{"--net=" + nsPath[i], "--"}, args...)...).CombinedOutput()
	}
	snapshot := func(i int) []byte {
		t.Helper()
		m := map[string]json.RawMessage{}
		for name, args := range map[string][]string{"links": {"ip", "-j", "link"}, "routes4": {"ip", "-j", "-4", "route", "show", "table", "all"}, "routes6": {"ip", "-j", "-6", "route", "show", "table", "all"}, "nft": {"nft", "-j", "list", "ruleset"}} {
			b, e := runNS(i, args...)
			if e != nil {
				t.Fatalf("namespace snapshot %s: %v %s", name, e, b)
			}
			m[name] = b
		}
		b, _ := json.Marshal(m)
		return b
	}
	baseline := make([][]byte, 2)
	// All cleanup is registered before the first child namespace/veth exists.
	t.Cleanup(func() {
		for i := range echoes {
			stopProcess(&echoes[i], echoDone[i])
		}
		for i := range daemons {
			stopProcess(&daemons[i], done[i])
		}
		for i := range ns {
			if ns[i] == nil {
				continue
			}
			if out, e := runNS(i, "ip", "link", "set", "dev", names[i], "mtu", "1500"); e != nil {
				t.Error("underlay rollback", e, string(out))
			}
			if normal && len(baseline[i]) > 0 {
				if after := snapshot(i); !bytes.Equal(baseline[i], after) {
					t.Errorf("namespace %d native baseline differs\nbefore=%s\nafter=%s", i, baseline[i], after)
				}
			}
		}
		// Compare both baselines before releasing either veth namespace.
		for i := range ns {
			if ns[i] != nil {
				if e := ns[i].Close(); e != nil {
					t.Error(e)
				}
				ns[i] = nil
			}
		}
		all, _ := filepath.Glob(filepath.Join(root, "*.log"))
		for _, path := range all {
			b, _ := os.ReadFile(path)
			t.Logf("child %s: %s", filepath.Base(path), b)
		}
	})
	start := func(i int, fresh bool) {
		t.Helper()
		logs[i] = filepath.Join(root, fmt.Sprintf("daemon-%d-%d.log", i, time.Now().UnixNano()))
		log, e := os.Create(logs[i])
		if e != nil {
			t.Fatal(e)
		}
		var cmd *exec.Cmd
		if fresh {
			cmd = exec.CommandContext(ctx, "sh", append(append([]string{"-c", "kill -STOP $$; exec \"$@\"", "sfc-netns", filepath.Join(bin, "sfcd"), "--config", configs[i]}, sfcdEngineFlags(configs[i])...), "run")...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
		} else {
			cmd = exec.CommandContext(ctx, "nsenter", append(append([]string{"--net=" + nsPath[i], "--", filepath.Join(bin, "sfcd"), "--config", configs[i]}, sfcdEngineFlags(configs[i])...), "run")...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		}
		cmd.Stdout, cmd.Stderr = log, log
		if e = cmd.Start(); e != nil {
			log.Close()
			t.Fatal(e)
		}
		daemons[i] = cmd
		done[i] = make(chan error, 1)
		go func() { e := cmd.Wait(); log.Close(); done[i] <- e }()
		if fresh {
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				b, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
				if e == nil && strings.Contains(string(b), "State:\tT") {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("child namespace setup", ctx.Err())
				case <-tick.C:
				}
			}
			ns[i], e = os.Open(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid))
			if e != nil {
				t.Fatal(e)
			}
			nsPath[i] = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), ns[i].Fd())
		}
	}
	start(0, true)
	start(1, true)
	if err = netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: names[0]}, PeerName: names[1]}); err != nil {
		t.Fatal(err)
	}
	for i, name := range names {
		link, e := netlink.LinkByName(name)
		if e != nil {
			t.Fatal(e)
		}
		if e = netlink.LinkSetNsFd(link, int(ns[i].Fd())); e != nil {
			t.Fatal(e)
		}
		for _, args := range [][]string{{"ip", "link", "set", "dev", "lo", "up"}, {"ip", "addr", "add", fmt.Sprintf("192.0.2.%d/30", i+1), "dev", name}, {"ip", "link", "set", "dev", name, "mtu", "1500", "up"}} {
			if out, e := runNS(i, args...); e != nil {
				t.Fatal("underlay setup", e, string(out))
			}
		}
	}
	for i := range ns {
		// Wait for the fixture's asynchronous link-local DAD before baseline.
		tick := time.NewTicker(20 * time.Millisecond)
		for {
			out, e := runNS(i, "ip", "-j", "-6", "addr", "show", "dev", names[i])
			if e != nil {
				tick.Stop()
				t.Fatal(e, string(out))
			}
			if !bytes.Contains(out, []byte("tentative")) {
				break
			}
			select {
			case <-ctx.Done():
				tick.Stop()
				t.Fatal("underlay DAD", ctx.Err())
			case <-tick.C:
			}
		}
		tick.Stop()
		baseline[i] = snapshot(i)
		t.Logf("node %d namespace=%s baseline=%s", i, nsPath[i], baseline[i])
		if err = daemons[i].Process.Signal(syscall.SIGCONT); err != nil {
			t.Fatal(err)
		}
	}
	cli := func(peer string, args ...string) (cluster.ManagementReply, error) {
		call, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		argv := []string{"--net=" + nsPath[0], "--", filepath.Join(bin, "sfc"), "--config", client, "--peer", peer, "--timeout", "3s"}
		argv = append(argv, args...)
		cmd := exec.CommandContext(call, "nsenter", argv...)
		out, e := cmd.Output()
		var reply cluster.ManagementReply
		if len(out) > 0 {
			if d := json.Unmarshal(out, &reply); d != nil {
				return reply, fmt.Errorf("CLI decode: %w: %s", d, out)
			}
		}
		return reply, e
	}
	wait := func(what string, predicate func() bool) {
		t.Helper()
		tick := time.NewTicker(80 * time.Millisecond)
		defer tick.Stop()
		for {
			if predicate() {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("timeout: " + what)
			case <-tick.C:
				for i := range daemons {
					if daemons[i] != nil {
						select {
						case e := <-done[i]:
							daemons[i] = nil
							b, _ := os.ReadFile(logs[i])
							t.Fatalf("daemon %d exited: %v %s", i, e, b)
						default:
						}
					}
				}
			}
		}
	}
	wait("replicated leader", func() bool { reply, e := cli("b", "status"); return e == nil && reply.Code == "ok" })
	sequence := 0
	submit := func(key string, value any, expected uint64, remove bool) state.Result {
		t.Helper()
		sequence++
		c := state.Command{Actor: keys[2].Actor(), Epoch: 1, RequestID: fmt.Sprint("tunnel-", sequence), Key: key, Expected: expected, Delete: remove}
		if !remove {
			b, e := json.Marshal(value)
			if e != nil {
				t.Fatal(e)
			}
			c.Value = string(b)
		}
		b, e := state.EncodeCommand(c)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(root, fmt.Sprint("command-", sequence))
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		reply, e := cli("b", "submit", path)
		if e != nil || reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
			t.Fatalf("commit %s: %+v %v", key, reply, e)
		}
		return reply.Committed.Result
	}
	observe := func(i int) (ModuleObservation, error) {
		reply, e := cli(string(rune('a'+i)), "observe", desired.TunnelPrefix+string(rune('a'+i)))
		var o ModuleObservation
		if e == nil {
			e = json.Unmarshal(reply.Data, &o)
		}
		return o, e
	}
	for i, id := range []string{"a", "b"} {
		submit(desired.NodePrefix+id, desired.NodeSpec{Schema: 1, Owner: owners[i], CPU: 1_000_000_000, Memory: 128 << 20, MaxEndpoints: 4, MaxConsumers: 4, PacketQueuePackets: 8, PacketQueueBytes: 16 << 10}, 0, false)
	}
	specs := []network.TunnelSpec{
		{Schema: 1, Owner: owners[0], Network: "daemon-boundary", MTU: 1280, RouteMetric: 100, Addresses: []netip.Prefix{netip.MustParsePrefix("10.249.25.1/32"), netip.MustParsePrefix("fd00:249:25::1/128")}, Routes: []netip.Prefix{netip.MustParsePrefix("10.249.25.2/32"), netip.MustParsePrefix("fd00:249:25::2/128")}},
		{Schema: 1, Owner: owners[1], Network: "daemon-boundary", MTU: 1280, RouteMetric: 100, Addresses: []netip.Prefix{netip.MustParsePrefix("10.249.25.2/32"), netip.MustParsePrefix("fd00:249:25::2/128")}, Routes: []netip.Prefix{netip.MustParsePrefix("10.249.25.1/32"), netip.MustParsePrefix("fd00:249:25::1/128")}},
	}
	results := make([]state.Result, 2)
	results[0] = submit(desired.TunnelPrefix+"a", specs[0], 0, false)
	wait("first intent preserved but unavailable", func() bool { o, e := observe(0); return e == nil && !o.Ready && o.Revision == results[0].Revision })
	results[1] = submit(desired.TunnelPrefix+"b", specs[1], 0, false)
	var original [2]ModuleObservation
	wait("both actual TUN packet planes", func() bool {
		for i := range original {
			o, e := observe(i)
			if e != nil || !o.Ready {
				return false
			}
			original[i] = o
		}
		return true
	})
	for i, o := range original {
		t.Logf("node %d TUN ready: %s", i, mustJSON(o))
	}
	indexes := make([]int, 2)
	for i, o := range original {
		out, e := runNS(i, "ip", "-j", "link", "show", "dev", o.NativeID)
		var links []struct {
			IfIndex int `json:"ifindex"`
		}
		if e != nil || json.Unmarshal(out, &links) != nil || len(links) != 1 {
			t.Fatal("original TUN ifindex", e, string(out))
		}
		indexes[i] = links[0].IfIndex
	}
	for i := range echoes {
		log, e := os.Create(filepath.Join(root, fmt.Sprint("echo-", i, ".log")))
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.CommandContext(ctx, "nsenter", "--net="+nsPath[i], "--", self, "-test.run=^TestTunnelUDPHelper$", "-test.v", "-test.timeout=70s")
		cmd.Env = append(os.Environ(), "SFC_TUN_HELPER=echo", "SFC_TUN_ADDRESSES="+specs[i].Addresses[0].Addr().String()+","+specs[i].Addresses[1].Addr().String())
		cmd.Stdout, cmd.Stderr = log, log
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if e = cmd.Start(); e != nil {
			log.Close()
			t.Fatal(e)
		}
		echoes[i] = cmd
		echoDone[i] = make(chan error, 1)
		go func() { e := cmd.Wait(); log.Close(); echoDone[i] <- e }()
		wait("actual dual-stack UDP listener", func() bool { b, _ := os.ReadFile(log.Name()); return bytes.Contains(b, []byte("echo ready")) })
	}
	probe := func(i int) {
		t.Helper()
		other := 1 - i
		cmd := exec.CommandContext(ctx, "nsenter", "--net="+nsPath[i], "--", self, "-test.run=^TestTunnelUDPHelper$", "-test.v", "-test.timeout=10s")
		cmd.Env = append(os.Environ(), "SFC_TUN_HELPER=probe", "SFC_TUN_ADDRESSES="+specs[other].Addresses[0].Addr().String()+","+specs[other].Addresses[1].Addr().String())
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("node %d actual packet plane: %v %s", i, e, out)
		}
		t.Logf("node %d remote UDP: %s", i, out)
	}
	probe(0)
	probe(1)
	if out, e := runNS(0, "ip", "link", "set", "dev", names[0], "mtu", "1300"); e != nil {
		t.Fatal(e, string(out))
	}
	wait("real underlay decrease closes admission", func() bool {
		o, e := observe(0)
		return e == nil && !o.Ready && o.NativeID == original[0].NativeID && o.Tunnel != nil && o.Tunnel.PacketUsers == 0
	})
	if out, e := runNS(0, "ip", "link", "set", "dev", names[0], "mtu", "1500"); e != nil {
		t.Fatal(e, string(out))
	}
	wait("fresh path admission after underlay restore", func() bool {
		for i := range original {
			o, e := observe(i)
			if e != nil || !o.Ready || o.Tunnel == nil || o.Tunnel.PacketUsers != 1 || maps.Equal(o.Tunnel.Connections, original[i].Tunnel.Connections) {
				return false
			}
		}
		return true
	})
	probe(0)
	// Preserve the namespace and service sockets while the original daemon/DB
	// is stopped. Restart only that executable in the same native namespace.
	stopProcess(&daemons[0], done[0])
	start(0, false)
	wait("same DB and original TUN/pin", func() bool {
		o, e := observe(0)
		return e == nil && o.Ready && o.NativeID == original[0].NativeID && o.Journal.Consumers == 1 && o.Journal.Pins["packet-plane"] == original[0].Journal.Pins["packet-plane"] && o.Journal.Applied == original[0].Journal.Applied
	})
	out, e := runNS(0, "ip", "-j", "link", "show", "dev", original[0].NativeID)
	var links []struct {
		IfIndex int `json:"ifindex"`
	}
	if e != nil || json.Unmarshal(out, &links) != nil || len(links) != 1 || links[0].IfIndex != indexes[0] {
		t.Fatal("restart replaced native TUN", e, string(out), indexes[0])
	}
	probe(1)
	for i := range echoes {
		stopProcess(&echoes[i], echoDone[i])
	}
	for i, id := range []string{"a", "b"} {
		drain := specs[i]
		drain.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{byte(i + 1)}}
		d := submit(desired.TunnelPrefix+id, drain, results[i].Revision, false)
		var gone ModuleObservation
		wait("packet settlement and original native absence "+id, func() bool {
			o, e := observe(i)
			gone = o
			return e == nil && o.Ready && len(o.Retirement) > 0 && o.Journal.Consumers == 0
		})
		var released network.TunnelSpec
		if err = json.Unmarshal(gone.Retirement, &released); err != nil {
			t.Fatal(err)
		}
		r := submit(desired.TunnelPrefix+id, released, d.Revision, false)
		submit(desired.TunnelPrefix+id, nil, r.Revision, true)
	}
	for i := range daemons {
		stopProcess(&daemons[i], done[i])
	}
	normal = true
	t.Log("actual two native namespaces/daemons and CLI CAS; signed bilateral paths; dual-stack1280B UDP; underlay MTU decrease/restore; same DB/native/pin restart; packet settlement, signed Gone and kernel retirement")
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func shaCluster(tag string) [32]byte {
	return sha256.Sum256([]byte("sfc-native-tunnel-test-1:" + tag))
}
