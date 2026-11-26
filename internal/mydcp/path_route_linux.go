// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"
)

// This is local connection provenance, never a permission or a remote MTU
// observation. Capture it before native discovery, including on connections
// first used for Raft/reporting rather than a TUN admission.
type nativeRoute struct {
	Link, MTU               int
	Remote, Source, Gateway string
}

func readNativeRoute(address net.Addr) (nativeRoute, error) {
	udp, ok := address.(*net.UDPAddr)
	if !ok {
		return nativeRoute{}, ErrAdmission
	}
	a := udp.AddrPort().Addr().Unmap()
	routes, err := netlink.RouteGet(net.IP(a.AsSlice()))
	if err != nil {
		return nativeRoute{}, err
	}
	if len(routes) != 1 {
		return nativeRoute{}, errors.New("ambiguous native MYDCP route")
	}
	r := routes[0]
	l, err := netlink.LinkByIndex(r.LinkIndex)
	if err != nil {
		return nativeRoute{}, err
	}
	if l.Attrs().Flags&net.FlagUp == 0 {
		return nativeRoute{}, errors.New("native MYDCP route is down")
	}
	mtu := l.Attrs().MTU
	if r.MTU > 0 {
		mtu = min(mtu, r.MTU)
	}
	return nativeRoute{Link: r.LinkIndex, MTU: mtu, Remote: a.String(), Source: r.Src.String(), Gateway: r.Gw.String()}, nil
}

func (p *connectionPath) bindRoute(address net.Addr) error {
	r, err := readNativeRoute(address)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.route = r
	return nil
}

// NativeRouteCurrent is read only. The owner decides when to retire a stale
// connection; no packet, management command, or resource effect is retried here.
func (s *Session) NativeRouteCurrent() (bool, error) {
	if s.conn == nil || s.path == nil {
		return false, ErrAdmission
	}
	current, err := readNativeRoute(s.RemoteAddr())
	if err != nil {
		return false, err
	}
	s.path.mu.Lock()
	original := s.path.route
	s.path.mu.Unlock()
	return current == original, nil
}
