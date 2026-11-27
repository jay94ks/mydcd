// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"syscall"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ServiceBinding is a read-back of an ORIGINAL pinned Bridge, not a desired
// interface name. It cannot be constructed outside this package. Callers keep
// the Bridge consumer until all sockets and their requests have stopped.
type ServiceBinding struct {
	manager   *Manager
	lease     BridgeLease
	namespace [32]byte
	name      string
	index     int
}

func serviceNamespace() ([32]byte, error) {
	s, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		return [32]byte{}, err
	}
	return serviceNamespaceInfo(s)
}

func serviceNamespaceInfo(s os.FileInfo) ([32]byte, error) {
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok {
		return [32]byte{}, engine.ErrOwnership
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256([]byte(fmt.Sprintf("sfc-network-namespace-1/%s/%d/%d", boot, st.Dev, st.Ino))), nil
}

func (m *Manager) ServiceBinding(ctx context.Context, lease BridgeLease) (*ServiceBinding, error) {
	l, err := m.InspectConsumer(ctx, lease.Key, lease.Consumer, lease.Pin.Generation)
	if err != nil || l.Pin != lease.Pin || l.NetworkID != lease.NetworkID || l.NetworkName != lease.NetworkName {
		return nil, errors.Join(err, engine.ErrOwnership)
	}
	r, err := m.View(l.Key)
	if err != nil {
		return nil, err
	}
	id, err := m.driver.Engine.Identity("bridge", l.Key, r.State.Applied)
	if err != nil {
		return nil, err
	}
	name := bridgeDeviceName(id)
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	ns, err := serviceNamespace()
	if err != nil {
		return nil, err
	}
	return &ServiceBinding{m, l, ns, name, link.Attrs().Index}, nil
}

func (b *ServiceBinding) Namespace() [32]byte { return b.namespace }
func (b *ServiceBinding) Interface() string   { return b.name }
func (b *ServiceBinding) Index() int          { return b.index }
func (b *ServiceBinding) Lease() BridgeLease {
	l := b.lease
	l.Spec.Pools = slices.Clone(l.Spec.Pools)
	l.Spec.Lifecycle.Proof = slices.Clone(l.Spec.Lifecycle.Proof)
	return l
}

func (b *ServiceBinding) Check(ctx context.Context) error {
	_, err := b.checkedNetwork(ctx)
	return err
}

func (b *ServiceBinding) checkedNetwork(ctx context.Context) (client.NetworkInspectResult, error) {
	if b == nil || b.manager == nil {
		return client.NetworkInspectResult{}, engine.ErrOwnership
	}
	ns, err := serviceNamespace()
	if err != nil || ns != b.namespace {
		return client.NetworkInspectResult{}, errors.Join(err, engine.ErrOwnership)
	}
	l, inspected, err := b.manager.inspectConsumerNetwork(ctx, b.lease.Key, b.lease.Consumer, b.lease.Pin.Generation)
	if err != nil || l.Pin != b.lease.Pin || l.NetworkID != b.lease.NetworkID {
		return client.NetworkInspectResult{}, errors.Join(err, engine.ErrOwnership)
	}
	link, err := netlink.LinkByName(b.name)
	if err != nil || link.Attrs().Index != b.index || link.Type() != "bridge" {
		return client.NetworkInspectResult{}, errors.Join(err, engine.ErrOwnership)
	}
	// The removed second SDK call also observed cancellation. Preserve that
	// boundary after the kernel read, before consuming endpoint metadata.
	return inspected, ctx.Err()
}

// SocketControl binds the socket to the proven local Bridge. There is no
// wildcard/device fallback, SO_REUSEPORT or takeover of an existing listener.
func (b *ServiceBinding) SocketControl(ctx context.Context, gateway netip.Addr) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		if err := b.Check(ctx); err != nil {
			return err
		}
		found := false
		for _, p := range b.lease.Spec.Pools {
			found = found || p.Gateway == gateway
		}
		if !found || !gateway.IsValid() || gateway.IsUnspecified() {
			return engine.ErrOwnership
		}
		var inner error
		err := raw.Control(func(fd uintptr) {
			inner = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, b.name)
		})
		return errors.Join(err, inner)
	}
}

// HasEndpoint joins packet provenance to an actual Engine endpoint after the
// workload owner has verified the original immutable container and generation.
func (b *ServiceBinding) HasEndpoint(ctx context.Context, nativeID string, address netip.Addr) error {
	// Endpoint membership and Bridge ownership come from the same checked
	// SDK response, rather than a second read of the same network.
	n, err := b.checkedNetwork(ctx)
	if err != nil {
		return err
	}
	e, ok := n.Network.Containers[nativeID]
	if !ok || e.EndpointID == "" || address.IsUnspecified() || !address.IsValid() {
		return engine.ErrOwnership
	}
	for _, raw := range []string{e.IPv4Address.String(), e.IPv6Address.String()} {
		if p, err := netip.ParsePrefix(raw); err == nil && p.Addr() == address {
			return nil
		}
	}
	return engine.ErrOwnership
}
