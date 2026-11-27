// SPDX-License-Identifier: Apache-2.0

package enginefake

import (
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strconv"
	"syscall"

	apinetwork "github.com/moby/moby/api/types/network"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Docker makes a kernel bridge for each bridge network and a network
// namespace for each running container, joined to its bridges by veth
// links; sfcd reads both back (bridge type, MTU, gateways; routes inside
// the container's namespace, named by its PID and sandbox key). With UseHost
// the fake does the same (needs root): bridges live in its namespace (the
// node's namespace; empty is the test's own), and a running container's
// namespace belongs to a holder process that sleeps until the container
// stops.

// UseHost turns host mode on: bridges go into the network namespace at
// netns (a path such as /proc/<pid>/ns/net; empty is the test's own). It
// may be called while the engine serves.
func (e *Engine) UseHost(netns string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.host, e.hostNetNS = true, netns
}

// sandbox is a running container's namespace: its holder process.
type sandbox struct {
	cmd *exec.Cmd
	// links counts the container's interfaces (eth0, eth1, ...).
	links int
}

// hostHandle is a netlink handle in the node's namespace. Close it.
func (e *Engine) hostHandle() (*netlink.Handle, error) {
	if e.hostNetNS == "" {
		return netlink.NewHandle()
	}
	ns, err := netns.GetFromPath(e.hostNetNS)
	if err != nil {
		return nil, err
	}
	defer ns.Close()
	return netlink.NewHandleAt(ns)
}

// createBridgeLink makes n's kernel bridge, up, with each pool's gateway.
func (e *Engine) createBridgeLink(n *netw) error {
	h, err := e.hostHandle()
	if err != nil {
		return err
	}
	defer h.Close()
	name := n.Options["com.docker.network.bridge.name"]
	if n.Driver == sfcDriver && len(n.Name) >= 12 {
		// Seafield's sfc driver takes the device name from sfcd's create
		// hook (purpose 36), which names it "md" + the network name's last
		// 12 characters (network.BridgeDeviceName); the fake asks no hook
		// and uses that name directly.
		name = "md" + n.Name[len(n.Name)-12:]
	}
	if name == "" {
		name = "br-" + n.ID[:12]
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	if mtu, err := strconv.Atoi(n.Options["com.docker.network.driver.mtu"]); err == nil && mtu > 0 {
		attrs.MTU = mtu
	}
	link := &netlink.Bridge{LinkAttrs: attrs}
	if err := h.LinkAdd(link); err != nil {
		if _, found := h.LinkByName(name); found == nil {
			// Another engine in this namespace may own it, so it is not removed.
			return fmt.Errorf("enginefake: host bridge %s already exists (left by a test process that died? remove it with: ip link del %s): %w", name, name, err)
		}
		return err
	}
	n.HostLink = name
	for _, c := range n.IPAM.Config {
		if !c.Subnet.IsValid() {
			continue
		}
		gw := c.Gateway
		if !gw.IsValid() {
			gw = c.Subnet.Masked().Addr().Next()
		}
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: gw.AsSlice(), Mask: net.CIDRMask(c.Subnet.Bits(), gw.BitLen())}}
		if err := h.AddrAdd(link, addr); err != nil {
			_ = h.LinkDel(link)
			return err
		}
	}
	if err := h.LinkSetUp(link); err != nil {
		_ = h.LinkDel(link)
		return err
	}
	return nil
}

func (e *Engine) deleteBridgeLink(n *netw) {
	if n.HostLink == "" {
		return
	}
	if h, err := e.hostHandle(); err == nil {
		if link, err := h.LinkByName(n.HostLink); err == nil {
			_ = h.LinkDel(link)
		}
		h.Close()
	}
	n.HostLink = ""
}

// startSandbox gives running c its namespace and joins it to each of its
// bridge networks. The caller holds e.mu.
func (e *Engine) startSandbox(c *ctr) error {
	cmd := exec.Command("sleep", "infinity")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return err
	}
	c.sandbox = &sandbox{cmd: cmd}
	ch, err := c.sandbox.handle()
	if err != nil {
		e.stopSandbox(c)
		return err
	}
	defer ch.Close()
	if lo, err := ch.LinkByName("lo"); err == nil {
		_ = ch.LinkSetUp(lo)
	}
	names := make([]string, 0, len(c.Networks))
	for name := range c.Networks {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if err := e.connectSandbox(c, e.lookupNetwork(name), c.Networks[name]); err != nil {
			e.stopSandbox(c)
			return err
		}
	}
	return nil
}

func (s *sandbox) pid() int { return s.cmd.Process.Pid }

func (s *sandbox) key() string { return "/proc/" + strconv.Itoa(s.pid()) + "/ns/net" }

func (s *sandbox) handle() (*netlink.Handle, error) {
	ns, err := netns.GetFromPath(s.key())
	if err != nil {
		return nil, err
	}
	defer ns.Close()
	return netlink.NewHandleAt(ns)
}

// connectSandbox joins running c's namespace to n's bridge: a veth whose
// container end is eth<N> with the endpoint's address (the first one also
// carries the default route, as Docker sets). The caller holds e.mu.
func (e *Engine) connectSandbox(c *ctr, n *netw, es *apinetwork.EndpointSettings) error {
	if c.sandbox == nil || n == nil || n.HostLink == "" || es == nil || !es.IPAddress.Is4() {
		return nil
	}
	ip := net.IPNet{IP: es.IPAddress.AsSlice(), Mask: net.CIDRMask(es.IPPrefixLen, 32)}
	var gw net.IP
	if es.Gateway.IsValid() {
		gw = es.Gateway.AsSlice()
	}
	h, err := e.hostHandle()
	if err != nil {
		return err
	}
	defer h.Close()
	bridge, err := h.LinkByName(n.HostLink)
	if err != nil {
		return err
	}
	index := c.sandbox.links
	host, peer := "ve"+c.ID[:10]+strconv.Itoa(index), "vc"+c.ID[:10]+strconv.Itoa(index)
	attrs := netlink.NewLinkAttrs()
	attrs.Name, attrs.MasterIndex, attrs.MTU = host, bridge.Attrs().Index, bridge.Attrs().MTU
	if err = h.LinkAdd(&netlink.Veth{LinkAttrs: attrs, PeerName: peer}); err != nil {
		return err
	}
	c.sandbox.links++
	inner, err := h.LinkByName(peer)
	if err == nil {
		err = h.LinkSetNsPid(inner, c.sandbox.pid())
	}
	if err == nil {
		err = h.LinkSetUp(&netlink.Veth{LinkAttrs: attrs})
	}
	if err != nil {
		return err
	}
	ch, err := c.sandbox.handle()
	if err != nil {
		return err
	}
	defer ch.Close()
	if inner, err = ch.LinkByName(peer); err != nil {
		return err
	}
	name := "eth" + strconv.Itoa(index)
	if err = ch.LinkSetName(inner, name); err == nil {
		err = ch.AddrAdd(inner, &netlink.Addr{IPNet: &ip})
	}
	if err == nil {
		err = ch.LinkSetUp(inner)
	}
	if err == nil && index == 0 && gw != nil {
		err = ch.RouteAdd(&netlink.Route{LinkIndex: inner.Attrs().Index, Gw: gw})
	}
	return err
}

// stopSandbox ends c's namespace; its veth links go with it. The caller
// holds e.mu.
func (e *Engine) stopSandbox(c *ctr) {
	if c.sandbox == nil {
		return
	}
	_ = c.sandbox.cmd.Process.Kill()
	_ = c.sandbox.cmd.Wait()
	c.sandbox = nil
}

// sandboxOf is the running container's PID and sandbox key for inspect.
func (c *ctr) sandboxOf() (int, string) {
	if c.sandbox == nil {
		return 0, ""
	}
	return c.sandbox.pid(), c.sandbox.key()
}
