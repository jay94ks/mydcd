// SPDX-License-Identifier: Apache-2.0

package clusterfixture

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/config"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// A child node listens on this MyDCP port in its own namespace.
const childPort = "7443"

// childEnv names the spec file of a child node process; packageEnv marks
// the test process that Main moved into its own namespace.
const (
	childEnv   = "MYDC_CLUSTERFIXTURE_CHILD"
	packageEnv = "MYDC_CLUSTERFIXTURE_NAMESPACE"
)

// Main runs the test package; in a child node process it runs that node
// instead. A package that uses NewIsolated calls it from TestMain.
//
// As root, the package's tests run in a fresh network namespace of their
// own (Main runs the test binary again there): what node-0 leaves in the
// kernel (TUN devices, routes, nftables rules, bridges) goes away with it,
// and test packages running at once never meet.
func Main(m *testing.M) {
	if spec := os.Getenv(childEnv); spec != "" {
		if err := runChild(spec); err != nil {
			fmt.Fprintln(os.Stderr, "clusterfixture child:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		os.Exit(m.Run())
	}
	if os.Getenv(packageEnv) == "" {
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Env = append(os.Environ(), packageEnv+"=1")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
		signal.Ignore(syscall.SIGINT)
		err := cmd.Run()
		if exit, ok := err.(*exec.ExitError); ok {
			os.Exit(exit.ExitCode())
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "clusterfixture: test namespace:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if err := ownNamespace(); err != nil {
		fmt.Fprintln(os.Stderr, "clusterfixture: test namespace:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// ownNamespace finishes a new network namespace for this process: private
// mounts with /sys showing its links, and loopback up.
func ownNamespace() error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("private mounts: %w", err)
	}
	if err := unix.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		return fmt.Errorf("sysfs: %w", err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(lo)
}

// hostNet is a bridge in the test's namespace with an address per node:
// node-0 (in the test process) uses the bridge's own, each child a veth.
type hostNet struct {
	bridge string
	prefix netip.Prefix
}

func newHostNet() (*hostNet, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	// A random /24 of the shared address space and a random name, so test
	// packages running at once do not meet.
	n := &hostNet{bridge: "cf" + hex.EncodeToString(b[:]), prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64 + b[0]&63, b[1], 0}), 24)}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = n.bridge
	link := &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkAdd(link); err != nil {
		return nil, err
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: n.address(0).AsSlice(), Mask: net.CIDRMask(24, 32)}}
	if err := netlink.AddrAdd(link, addr); err != nil {
		n.close()
		return nil, err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		n.close()
		return nil, err
	}
	return n, nil
}

// address is node i's address: .1 for node-0, .(10+i) for a child.
func (n *hostNet) address(i int) netip.Addr {
	a := n.prefix.Addr().As4()
	a[3] = 1
	if i > 0 {
		a[3] = byte(10 + i)
	}
	return netip.AddrFrom4(a)
}

func (n *hostNet) close() {
	if link, err := netlink.LinkByName(n.bridge); err == nil {
		_ = netlink.LinkDel(link)
	}
}

// connect joins the namespace of process pid to the bridge as node i: a
// veth whose inside end is eth0 with the node's address.
func (n *hostNet) connect(pid, i int) error {
	bridge, err := netlink.LinkByName(n.bridge)
	if err != nil {
		return err
	}
	outside, inside := n.bridge+"h"+strconv.Itoa(i), n.bridge+"c"+strconv.Itoa(i)
	attrs := netlink.NewLinkAttrs()
	attrs.Name, attrs.MasterIndex = outside, bridge.Attrs().Index
	veth := &netlink.Veth{LinkAttrs: attrs, PeerName: inside}
	if err = netlink.LinkAdd(veth); err != nil {
		return err
	}
	peer, err := netlink.LinkByName(inside)
	if err == nil {
		err = netlink.LinkSetNsPid(peer, pid)
	}
	if err == nil {
		err = netlink.LinkSetUp(veth)
	}
	if err != nil {
		return err
	}
	ns, err := netns.GetFromPid(pid)
	if err != nil {
		return err
	}
	h, err := netlink.NewHandleAt(ns)
	_ = ns.Close()
	if err != nil {
		return err
	}
	defer h.Close()
	if peer, err = h.LinkByName(inside); err != nil {
		return err
	}
	if err = h.LinkSetName(peer, "eth0"); err == nil {
		err = h.AddrAdd(peer, &netlink.Addr{IPNet: &net.IPNet{IP: n.address(i).AsSlice(), Mask: net.CIDRMask(24, 32)}})
	}
	if err == nil {
		err = h.LinkSetUp(peer)
	}
	return err
}

// childSpec is what a child node process needs to join.
type childSpec struct {
	Config     config.Node
	Invitation membership.Invitation
	Cluster    [32]byte
	Source     [32]byte
}

// childReady is the child's one line on stdout once it serves.
type childReady struct {
	Key   [32]byte
	Error string `json:",omitempty"`
}

// startChild runs node i as a child process in a new network namespace:
// the namespace is joined to the bridge and the node's engine makes its
// bridges there before the node opens; then the node joins and serves.
func (c *Cluster) startChild(n *Node, i int, inv membership.Invitation) {
	c.t.Helper()
	raw, err := json.Marshal(childSpec{Config: n.Config, Invitation: inv, Cluster: c.ID, Source: c.Nodes[0].Key})
	if err != nil {
		c.t.Fatal(err)
	}
	spec := filepath.Join(filepath.Dir(n.Socket), "child.json")
	if err = os.WriteFile(spec, raw, 0o600); err != nil {
		c.t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"="+spec)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		c.t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		c.t.Fatal("child", n.ID, err)
	}
	n.child, n.stdin = cmd, stdin
	if err = c.net.connect(cmd.Process.Pid, i); err != nil {
		c.t.Fatal("child network", n.ID, err)
	}
	n.Engine.UseHost("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/ns/net")
	if _, err = stdin.Write([]byte("go\n")); err != nil {
		c.t.Fatal("child", n.ID, err)
	}
	lines := make(chan childReady, 1)
	go func() {
		var r childReady
		line, err := bufio.NewReader(stdout).ReadBytes('\n')
		if err == nil {
			err = json.Unmarshal(line, &r)
		}
		if err != nil && r.Error == "" {
			r.Error = "no ready line: " + err.Error()
		}
		lines <- r
	}()
	select {
	case r := <-lines:
		if r.Error != "" {
			c.t.Fatal("child", n.ID, r.Error)
		}
		n.Key = r.Key
	case <-c.ctx.Done():
		c.t.Fatal("child", n.ID, c.ctx.Err())
	}
	c.register(n)
}

// stopChild closes the child's stdin (it closes its node and exits) and
// kills it if it does not exit soon.
func stopChild(n *Node) {
	cmd := n.child
	_ = n.stdin.Close()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

// runChild is a child node process: it waits for its namespace to be
// joined, joins the cluster, serves its management socket and reports its
// key, then runs until stdin closes.
func runChild(spec string) error {
	if err := ownNamespace(); err != nil {
		return err
	}
	raw, err := os.ReadFile(spec)
	if err != nil {
		return err
	}
	var s childSpec
	if err = json.Unmarshal(raw, &s); err != nil {
		return err
	}
	in := bufio.NewReader(os.Stdin)
	if _, err = in.ReadString('\n'); err != nil {
		return err
	}
	ready := json.NewEncoder(os.Stdout)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	r, _, err := app.Join(ctx, s.Config, s.Invitation, s.Cluster, s.Source)
	if err == nil {
		if err = r.Mesh.ListenUnix(s.Config.Node.ManagementSocket); err != nil {
			_ = r.Close()
		}
	}
	if err != nil {
		_ = ready.Encode(childReady{Error: "join: " + err.Error()})
		return err
	}
	if err = ready.Encode(childReady{Key: r.Identity.Public}); err != nil {
		_ = r.Close()
		return err
	}
	_, _ = in.ReadString('\n') // until the test closes stdin
	return r.Close()
}
