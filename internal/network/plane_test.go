// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/vishvananda/netlink"
)

// This helper runs only inside the guarded kernel test's anonymous netns. The
// opposite endpoint is an actual QUIC peer running an IP/UDP echo fixture, not
// a second native kernel or a full daemon/service test.
func tunnelMYDCPRoundTrip(t *testing.T, ctx context.Context, device PacketIO, spec TunnelSpec) {
	t.Helper()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	wasUp := lo.Attrs().Flags&net.FlagUp != 0
	defer func() {
		if !wasUp {
			if err := netlink.LinkSetDown(lo); err != nil {
				t.Error(err)
			}
		}
	}()
	if err = netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cluster := [32]byte{7}
	nid := NetworkID(cluster, spec.Network)
	peers := map[mydcp.Identity]mydcp.Peer{mydcp.Identity(a.Public): {ID: "a", Policy: mydcp.Policy{Key: mydcp.Identity(a.Public), Member: true, Tunnel: true}}, mydcp.Identity(b.Public): {ID: "b", Policy: mydcp.Policy{Key: mydcp.Identity(b.Public), Member: true, Tunnel: true}}}
	lookup := func(key mydcp.Identity) (mydcp.Peer, bool) { p, ok := peers[key]; return p, ok }
	client, err := mydcp.NewTransport(a, cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := mydcp.NewTransport(b, cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	scope := []byte("kernel-boundary:source=1:generation=1:dual-stack")
	var pathMu sync.Mutex
	var remote PacketPeer
	if err = server.OnPath(func(_ context.Context, _ *mydcp.Session, got []byte, mtu int) error {
		if !bytes.Equal(got, scope) || mtu != 1280 {
			return ErrPolicy
		}
		return nil
	}, func(s *mydcp.Session, p mydcp.PathPair) error {
		pathMu.Lock()
		remote = PacketPeer{Session: s, Path: p}
		pathMu.Unlock()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var endpoints []Endpoint
	for i := range spec.Addresses {
		local, target := spec.Addresses[i].Addr(), spec.Routes[i].Addr()
		endpoints = append(endpoints, Endpoint{Owner: a.Public, Network: nid, ID: EndpointID(cluster, spec.Network, "a", "tun-a", 1, local), Address: local}, Endpoint{Owner: b.Public, Network: nid, ID: EndpointID(cluster, spec.Network, "b", "tun-b", 1, target), Address: target})
	}
	policy, err := NewPacketPolicy(endpoints)
	if err != nil {
		t.Fatal(err)
	}
	if err = server.OnPacket(func(s *mydcp.Session, f mydcp.Frame) error {
		if policy.Inbound(b.Public, a.Public, nid, [16]byte(f.Fields[2].Value), 1280, f.Fields[3].Value) != nil {
			return ErrPolicy
		}
		pathMu.Lock()
		current := remote
		pathMu.Unlock()
		if current.Session != s || !s.PathCurrent(current.Path) {
			return ErrPolicy
		}
		packet := append([]byte(nil), f.Fields[3].Value...)
		header, source, target := 20, 12, 16
		if packet[0]>>4 == 6 {
			header, source, target = 40, 8, 24
		}
		old := append([]byte(nil), packet[source:target]...)
		copy(packet[source:target], packet[target:target+target-source])
		copy(packet[target:target+target-source], old)
		port := append([]byte(nil), packet[header:header+2]...)
		copy(packet[header:header+2], packet[header+2:header+4])
		copy(packet[header+2:header+4], port)
		destination, err := policy.Outbound(b.Public, nid, 1280, packet)
		if err != nil {
			return err
		}
		return s.SendPacket(ctx, mydcp.Frame{Purpose: mydcp.Packet, Kind: 1, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: b.Public[:]}, {Tag: 2, Required: true, Value: nid[:]}, {Tag: 3, Required: true, Value: destination.ID[:]}, {Tag: 4, Required: true, Value: packet}}})
	}); err != nil {
		t.Fatal(err)
	}
	var plane atomic.Pointer[PacketPlane]
	if err = client.OnPacket(func(s *mydcp.Session, f mydcp.Frame) error {
		p := plane.Load()
		if p == nil {
			return ErrPolicy
		}
		return p.Receive(s, f)
	}); err != nil {
		t.Fatal(err)
	}
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	target := peers[mydcp.Identity(b.Public)]
	target.Endpoint = server.Addr().String()
	session, err := client.Dial(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := session.ObservePath(ctx, scope, 1280)
	if err != nil {
		t.Fatal("real bilateral signed native path", err)
	}
	local, other := pair.Samples()
	for _, sample := range []mydcp.PathSample{local, other} {
		if len(sample.Signature) != ed25519.SignatureSize || sample.Budget.IPBytes < 1280 || sample.Budget.ObservedAt.IsZero() {
			t.Fatal("unsigned/native-unobserved path", sample)
		}
	}
	observation := func(s mydcp.PathSample) MTUObservation {
		return MTUObservation{From: hex.EncodeToString(s.From[:]), To: hex.EncodeToString(s.To[:]), Source: 1, Generation: 1, At: uint64(s.At), PathMTU: s.Budget.UDPBytes, Overhead: s.Budget.UDPBytes - s.Budget.IPBytes}
	}
	if err = AdmitMTU(1280, 1, 1, uint64(time.Now().UnixMilli()), 30_000, observation(local), observation(other)); err != nil {
		t.Fatal("reused bilateral MTU core", err)
	}
	p, err := NewPacketPlane(ctx, a.Public, nid, spec, device, PacketLimits{QueuePackets: 4, QueueBytes: 8192}, PacketPlan{Policy: policy, Peers: map[[32]byte]PacketPeer{b.Public: {Session: session, Path: pair}}})
	if err != nil {
		t.Fatal(err)
	}
	plane.Store(p)
	defer func() {
		if err := p.Stop(); err != nil {
			t.Error(err)
		}
	}()
	for i, af := range []string{"udp4", "udp6"} {
		local, remote := spec.Addresses[i].Addr(), spec.Routes[i].Addr()
		c, err := net.DialUDP(af, &net.UDPAddr{IP: net.IP(local.AsSlice())}, &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: 53001})
		if err != nil {
			t.Fatal(err)
		}
		header := 20
		if af == "udp6" {
			header = 40
		}
		payload := bytes.Repeat([]byte{0x73}, 1280-header-8)
		if err = c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			c.Close()
			t.Fatal(err)
		}
		if _, err = c.Write(payload); err != nil {
			c.Close()
			t.Fatal(err)
		}
		reply := make([]byte, 2048)
		n, err := c.Read(reply)
		c.Close()
		if err != nil || !bytes.Equal(reply[:n], payload) {
			t.Fatal("native TUN -> signed-path MYDCP -> echo -> native UDP", af, n, err, p.Err())
		}
	}
	if err = p.Stop(); err != nil {
		t.Fatal("packet reader/writer settlement", err)
	}
	if used := p.bytes.Load(); used != 0 {
		t.Fatal("packet queue survived Stop", used)
	}
	if !session.PathCurrent(pair) {
		t.Fatal("packet Stop closed transport-owned connection")
	}
	if err = device.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err = device.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual dual-stack 1280B kernel UDP/TUN over two authenticated QUIC peers; signed native IP budgets=%d/%d; product packet Stop joined read/write and returned queue bytes", local.Budget.IPBytes, other.Budget.IPBytes)
}
