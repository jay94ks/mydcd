// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var ErrKernelOwnership = errors.New("TUN, route or nft ownership/readback mismatch")

// TunnelSpec is committed input, not a set of host defaults. Addresses are
// explicit local addresses; Routes are remote overlay prefixes through TUN.
type TunnelSpec struct {
	Schema         uint8
	Owner, Network string
	MTU            int
	RouteMetric    int
	Addresses      []netip.Prefix
	Routes         []netip.Prefix
	Lifecycle      schema.Lifecycle
	RoutePolicy    *PacketRoutePolicy `json:",omitempty"`
}

func DecodeTunnel(value string) (TunnelSpec, error) {
	s, err := schema.Decode[TunnelSpec]([]byte(value))
	if err != nil || s.Schema != 1 || s.Owner == "" || s.Network == "" || s.MTU < 1280 || s.MTU > 65535 || s.RouteMetric < 1 || s.RouteMetric > 2147483647 || len(s.Addresses) > 32 || len(s.Routes) == 0 && s.RoutePolicy != nil || len(s.Routes) > 64 || !s.Lifecycle.Valid() {
		return s, ErrPolicy
	}
	if s.RoutePolicy != nil && !s.RoutePolicy.valid(s) {
		return s, ErrPolicy
	}
	for _, list := range [][]netip.Prefix{s.Addresses, s.Routes} {
		previous := ""
		for _, p := range list {
			a := p.Addr()
			if !p.IsValid() || a.Is4In6() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsLinkLocalUnicast() || p.Bits() == 0 || p.String() <= previous {
				return s, ErrPolicy
			}
			previous = p.String()
		}
	}
	for i, p := range s.Routes {
		if p != p.Masked() {
			return s, ErrPolicy
		}
		for _, q := range s.Routes[:i] {
			if p.Overlaps(q) {
				return s, ErrPolicy
			}
		}
	}
	for _, p := range s.Addresses {
		if p.Bits() != p.Addr().BitLen() {
			return s, ErrPolicy
		}
	}
	return s, nil
}

type tunnelIdentity struct{ name, alias, table string }
type tunnelFile struct {
	identity tunnelIdentity
	file     *os.File
}
type tunnelIO struct{ file *os.File }

func (f tunnelIO) Read(b []byte) (int, error)         { return f.file.Read(b) }
func (f tunnelIO) Write(b []byte) (int, error)        { return f.file.Write(b) }
func (f tunnelIO) SetReadDeadline(t time.Time) error  { return f.file.SetReadDeadline(t) }
func (f tunnelIO) SetWriteDeadline(t time.Time) error { return f.file.SetWriteDeadline(t) }

// PacketIO lends access without transferring FD close ownership to a consumer.
type PacketIO interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// TunnelDriver owns its FDs in the process network namespace. Normal Close
// detaches FDs and leaves persistent kernel objects for the original journal.
type TunnelDriver struct {
	Owner  string
	mu     sync.Mutex
	files  map[string]tunnelFile
	closed bool
}

// TunnelDeviceName reuses the exact native identity without creating a device.
func TunnelDeviceName(key string, generation uint64, spec TunnelSpec) (string, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	_, id, err := (&TunnelDriver{Owner: spec.Owner}).parameters(key, reconcile.Operation{Target: reconcile.Resource{Generation: generation, Present: true, Spec: string(raw)}})
	return id.name, err
}

func (d *TunnelDriver) parameters(key string, op reconcile.Operation) (TunnelSpec, tunnelIdentity, error) {
	s, err := DecodeTunnel(op.Target.Spec)
	if err != nil || d.Owner == "" || s.Owner != d.Owner || key == "" || len(key) > 512 || op.Target.Generation == 0 || !op.Target.Present {
		return s, tunnelIdentity{}, ErrKernelOwnership
	}
	name := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", d.Owner, key, op.Target.Generation)))
	full := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", d.Owner, key, op.Target.Generation, stableTunnelSpec(s))))
	return s, tunnelIdentity{fmt.Sprintf("mt%x", name[:6]), fmt.Sprintf("mydc-tun-1:%x", full), fmt.Sprintf("mydc_%x", full)}, nil
}

// stableTunnelSpec is the part of a spec that names its native identity.
// Without a route policy the remote route set is left out: a TUN network
// member joining or leaving changes only its peers' routes and firewall
// accept rules in place, under the same device (devel/design/node-apps.md
// 3.1). A route policy binds its routes into the identity as before.
func stableTunnelSpec(s TunnelSpec) string {
	if s.RoutePolicy == nil {
		s.Routes = nil
	}
	raw, _ := json.Marshal(s)
	return string(raw)
}

// InPlace: only the remote route set differs, so the device, its address and
// every consumer's pin stay; reconcile may apply it while the plane runs.
func (d *TunnelDriver) InPlace(applied, target reconcile.Resource) bool {
	a, errA := DecodeTunnel(applied.Spec)
	b, errB := DecodeTunnel(target.Spec)
	return errA == nil && errB == nil && a.RoutePolicy == nil && b.RoutePolicy == nil && applied.Generation == target.Generation && stableTunnelSpec(a) == stableTunnelSpec(b)
}

func missingLink(err error) bool {
	var missing netlink.LinkNotFoundError
	return errors.As(err, &missing)
}
func ownTunnel(link netlink.Link, id tunnelIdentity) bool {
	tun, ok := link.(*netlink.Tuntap)
	return ok && tun.Mode == netlink.TUNTAP_MODE_TUN && !tun.NonPersist && link.Attrs().Name == id.name && link.Attrs().Alias == id.alias
}
func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
func routeFor(link netlink.Link, p netip.Prefix, s TunnelSpec) netlink.Route {
	scope := netlink.SCOPE_LINK
	if p.Addr().Is6() {
		// Linux IPv6 route scope is universe even for a direct device route;
		// next-hop reachability is represented separately from the scope byte.
		scope = netlink.SCOPE_UNIVERSE
	}
	return netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixNet(p), Table: routeTable(s), Protocol: unix.RTPROT_STATIC, Scope: scope, Type: unix.RTN_UNICAST, MTU: s.MTU, Priority: s.RouteMetric}
}
func sameRoute(a, b netlink.Route) bool {
	return a.LinkIndex == b.LinkIndex && a.Dst != nil && b.Dst != nil && a.Dst.String() == b.Dst.String() && a.Table == b.Table && a.Protocol == b.Protocol && a.Scope == b.Scope && a.Type == b.Type && a.MTU == b.MTU && a.Gw.Equal(b.Gw) && a.Priority == b.Priority && len(a.MultiPath) == 0
}
func routeState(link netlink.Link, p netip.Prefix, s TunnelSpec) (bool, error) {
	want := routeFor(link, p, s)
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Dst: want.Dst, Table: want.Table}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return false, err
	}
	for _, r := range routes {
		if !sameRoute(r, want) {
			return false, fmt.Errorf("%w: route %s wanted %s observed %s", ErrKernelOwnership, p, want.String(), r.String())
		}
	}
	if len(routes) > 1 {
		return false, ErrKernelOwnership
	}
	return len(routes) == 1, nil
}

// staleTunnelRoutes lists this TUN's own routes (its table, the exact shape
// routeFor writes) whose prefix the spec no longer has: a peer that left.
// Kernel routes and routes in other tables are not this owner's to judge here;
// any other route of its table on the device is foreign.
func staleTunnelRoutes(link netlink.Link, s TunnelSpec) ([]netlink.Route, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{LinkIndex: link.Attrs().Index, Table: routeTable(s)}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	var stale []netlink.Route
	for _, r := range routes {
		if r.Protocol == unix.RTPROT_KERNEL || r.Dst == nil {
			continue
		}
		p, ok := netip.AddrFromSlice(r.Dst.IP)
		ones, _ := r.Dst.Mask.Size()
		if !ok {
			return nil, ErrKernelOwnership
		}
		prefix := netip.PrefixFrom(p.Unmap(), ones)
		if slices.Contains(s.Routes, prefix) {
			continue
		}
		if !sameRoute(r, routeFor(link, prefix, s)) {
			return nil, ErrKernelOwnership
		}
		stale = append(stale, r)
	}
	return stale, nil
}

// pruneTunnelRoutes removes the routes of peers that left the network. The
// firewall has already been narrowed to the new route set.
func pruneTunnelRoutes(link netlink.Link, s TunnelSpec) error {
	stale, err := staleTunnelRoutes(link, s)
	if err != nil {
		return err
	}
	for i := range stale {
		if err = netlink.RouteDel(&stale[i]); err != nil {
			return err
		}
	}
	return nil
}

func (d *TunnelDriver) attach(key string, id tunnelIdentity, fresh bool) error {
	if old, ok := d.files[key]; ok {
		if old.identity != id {
			return ErrKernelOwnership
		}
		return nil
	}
	flags := netlink.TUNTAP_NO_PI | netlink.TUNTAP_ONE_QUEUE
	if fresh {
		flags |= netlink.TUNTAP_TUN_EXCL
	}
	tun := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: id.name}, Mode: netlink.TUNTAP_MODE_TUN, Flags: flags, Queues: 1}
	if err := netlink.LinkAdd(tun); err != nil {
		return err
	}
	if len(tun.Fds) != 1 {
		for _, f := range tun.Fds {
			_ = f.Close()
		}
		return ErrKernelOwnership
	}
	if d.files == nil {
		d.files = make(map[string]tunnelFile)
	}
	d.files[key] = tunnelFile{id, tun.Fds[0]}
	if fresh {
		// Failure before the alias is installed remains uncertain. Recovery
		// never adopts an unlabelled device merely because its name matches.
		return netlink.LinkSetAlias(tun, id.alias)
	}
	return nil
}
func (d *TunnelDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	return d.run(ctx, key, op, true)
}
func (d *TunnelDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	return d.run(ctx, key, op, false)
}

// Inspect reads an already applied TUN without attaching an FD, repairing
// addresses/routes/firewall, or issuing link updates. Recovery remains the
// journal owner's responsibility; an absent/partial object is never created.
func (d *TunnelDriver) Inspect(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return reconcile.EffectUnknown, os.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return reconcile.EffectUnknown, err
	}
	if op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, reconcile.ErrOperation
	}
	s, id, err := d.parameters(key, op)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	outcome, err := d.inspect(s, id, reconcile.Apply)
	if canceled := ctx.Err(); canceled != nil {
		return reconcile.EffectUnknown, errors.Join(err, canceled)
	}
	return outcome, err
}

func (d *TunnelDriver) run(ctx context.Context, key string, op reconcile.Operation, create bool) (reconcile.Outcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return reconcile.EffectUnknown, os.ErrClosed
	}
	s, id, err := d.parameters(key, op)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if err = ctx.Err(); err != nil {
		return reconcile.EffectUnknown, err
	}
	link, err := netlink.LinkByName(id.name)
	if err != nil && !missingLink(err) {
		return reconcile.EffectUnknown, err
	}
	if err == nil && !ownTunnel(link, id) {
		return reconcile.EffectUnknown, ErrKernelOwnership
	}
	selectorRule, selectorGuard, selectorErr := inspectRouteSelector(s, link)
	if selectorErr != nil {
		return reconcile.EffectUnknown, selectorErr
	}
	if create && op.Kind == reconcile.Apply && link == nil && (selectorRule || selectorGuard) {
		return reconcile.EffectUnknown, ErrKernelOwnership
	}
	if op.Kind == reconcile.Remove {
		if _, _, firewallErr := lookupTunnelFirewallEither(s, id); firewallErr != nil {
			return reconcile.EffectUnknown, firewallErr
		}
		if link != nil {
			// Reject foreign routes attached to this link before LinkDel can
			// remove them implicitly. Kernel-generated address routes are local.
			routes, routeErr := netlink.RouteListFiltered(netlink.FAMILY_ALL,
				&netlink.Route{LinkIndex: link.Attrs().Index, Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
			if routeErr != nil {
				return reconcile.EffectUnknown, routeErr
			}
			for _, r := range routes {
				if r.Protocol == unix.RTPROT_KERNEL {
					continue
				}
				found := false
				for _, p := range s.Routes {
					found = found || sameRoute(r, routeFor(link, p, s))
				}
				if !found {
					return reconcile.EffectUnknown, ErrKernelOwnership
				}
			}
			if err = netlink.LinkDel(link); err != nil {
				return reconcile.EffectUnknown, err
			}
		}
		// Keep the firewall until the device and its routes are gone. A
		// partial retirement must never leave an unguarded live TUN.
		if err = removeTunnelFirewall(s, id); err != nil {
			return reconcile.EffectUnknown, err
		}
		if err = removeRouteSelector(s); err != nil {
			return reconcile.EffectUnknown, err
		}
		if f, ok := d.files[key]; ok {
			if err = f.file.Close(); err != nil {
				return reconcile.EffectUnknown, err
			}
			delete(d.files, key)
		}
	} else if op.Kind == reconcile.Apply {
		if link == nil && !create {
			return reconcile.EffectUnknown, nil
		}
		if err = d.attach(key, id, link == nil); err != nil {
			return reconcile.EffectUnknown, err
		}
		link, err = netlink.LinkByName(id.name)
		if err != nil || !ownTunnel(link, id) {
			return reconcile.EffectUnknown, errors.Join(err, ErrKernelOwnership)
		}
		if err = netlink.LinkSetMTU(link, s.MTU); err != nil {
			return reconcile.EffectUnknown, err
		}
		if err = routeSourceValidation(s, id, true); err != nil {
			return reconcile.EffectUnknown, err
		}
		addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return reconcile.EffectUnknown, err
		}
		for _, p := range s.Addresses {
			present := false
			for _, a := range addresses {
				present = present || a.IPNet.String() == prefixNet(p).String()
			}
			if !present {
				address := &netlink.Addr{IPNet: prefixNet(p)}
				if p.Addr().Is6() {
					// TUN is point-to-point: no multicast neighbour discovery or
					// Ethernet DAD is used for its explicit local identity.
					address.Flags = unix.IFA_F_NODAD
				}
				if err = netlink.AddrAdd(link, address); err != nil {
					return reconcile.EffectUnknown, err
				}
			}
		}
		if err = ensureRouteSelector(s, link); err != nil {
			return reconcile.EffectUnknown, err
		}
		if err = ensureTunnelFirewall(s, id); err != nil {
			return reconcile.EffectUnknown, err
		}
		if err = netlink.LinkSetUp(link); err != nil {
			return reconcile.EffectUnknown, err
		}
		for _, p := range s.Routes {
			present, err := routeState(link, p, s)
			if err != nil {
				return reconcile.EffectUnknown, err
			}
			if !present {
				r := routeFor(link, p, s)
				if err = netlink.RouteAdd(&r); err != nil {
					return reconcile.EffectUnknown, err
				}
			}
		}
		if err = pruneTunnelRoutes(link, s); err != nil {
			return reconcile.EffectUnknown, err
		}
	} else {
		return reconcile.EffectUnknown, reconcile.ErrOperation
	}
	return d.inspect(s, id, op.Kind)
}

func (d *TunnelDriver) inspect(s TunnelSpec, id tunnelIdentity, kind reconcile.Kind) (reconcile.Outcome, error) {
	link, err := netlink.LinkByName(id.name)
	if missingLink(err) && kind == reconcile.Remove {
		_, table, firewallErr := lookupTunnelFirewallEither(s, id)
		present := table != nil
		if firewallErr == nil && !present {
			rule, guard, selectorErr := inspectRouteSelector(s, nil)
			if selectorErr != nil || rule || guard {
				return reconcile.EffectUnknown, errors.Join(selectorErr, ErrKernelOwnership)
			}
			return reconcile.EffectApplied, nil
		}
		return reconcile.EffectUnknown, firewallErr
	}
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if !ownTunnel(link, id) || link.Attrs().MTU != s.MTU || link.Attrs().Flags&net.FlagUp == 0 || kind != reconcile.Apply {
		return reconcile.EffectUnknown, ErrKernelOwnership
	}
	if hasRouteSelector(s) {
		if err := routeSourceValidation(s, id, false); err != nil {
			return reconcile.EffectUnknown, err
		}
		rule, guard, selectorErr := inspectRouteSelector(s, link)
		if selectorErr != nil || !rule || !guard {
			return reconcile.EffectUnknown, errors.Join(selectorErr, ErrKernelOwnership)
		}
	}
	addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	for _, p := range s.Addresses {
		found := false
		for _, a := range addresses {
			found = found || a.IPNet.String() == prefixNet(p).String()
		}
		if !found {
			return reconcile.EffectUnknown, ErrKernelOwnership
		}
	}
	for _, a := range addresses {
		found := a.IP.IsLinkLocalUnicast()
		for _, p := range s.Addresses {
			found = found || a.IPNet.String() == prefixNet(p).String()
		}
		if !found {
			return reconcile.EffectUnknown, ErrKernelOwnership
		}
	}
	for _, p := range s.Routes {
		present, err := routeState(link, p, s)
		if err != nil || !present {
			return reconcile.EffectUnknown, errors.Join(err, ErrKernelOwnership)
		}
	}
	if stale, err := staleTunnelRoutes(link, s); err != nil || len(stale) != 0 {
		return reconcile.EffectUnknown, errors.Join(err, ErrKernelOwnership)
	}
	present, err := inspectTunnelFirewall(s, id)
	if err != nil || !present {
		return reconcile.EffectUnknown, errors.Join(err, ErrKernelOwnership)
	}
	return reconcile.EffectApplied, nil
}

// AppliedAbsent proves loss of a completed local kernel effect, never the
// outcome of an in-flight Apply. Same-named or partial native state is denied.
func (d *TunnelDriver) AppliedAbsent(ctx context.Context, key string, resource reconcile.Resource) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false, os.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s, id, err := d.parameters(key, reconcile.Operation{Target: resource})
	if err != nil {
		return false, err
	}
	link, err := netlink.LinkByName(id.name)
	if err == nil {
		if !ownTunnel(link, id) {
			return false, ErrKernelOwnership
		}
		outcome, err := d.inspect(s, id, reconcile.Apply)
		if err != nil || outcome != reconcile.EffectApplied {
			return false, errors.Join(err, ErrKernelOwnership)
		}
		return false, nil
	}
	if !missingLink(err) {
		return false, err
	}
	if _, held := d.files[key]; held {
		return false, ErrKernelOwnership
	}
	outcome, err := d.inspect(s, id, reconcile.Remove)
	if err != nil || outcome != reconcile.EffectApplied {
		return false, errors.Join(err, ErrKernelOwnership)
	}
	for _, prefix := range s.Routes {
		rows, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Dst: prefixNet(prefix), Table: routeTable(s)}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
		if err != nil || len(rows) != 0 {
			return false, errors.Join(err, ErrKernelOwnership)
		}
	}
	return true, ctx.Err()
}

func (d *TunnelDriver) PacketIO(key string, r reconcile.Resource) (PacketIO, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, os.ErrClosed
	}
	s, id, err := d.parameters(key, reconcile.Operation{Target: r})
	if err != nil {
		return nil, err
	}
	if outcome, err := d.inspect(s, id, reconcile.Apply); err != nil || outcome != reconcile.EffectApplied {
		return nil, errors.Join(err, ErrKernelOwnership)
	}
	if err = d.attach(key, id, false); err != nil {
		return nil, err
	}
	return tunnelIO{d.files[key].file}, nil
}
func (d *TunnelDriver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	var errs []error
	for key, f := range d.files {
		errs = append(errs, f.file.Close())
		delete(d.files, key)
	}
	return errors.Join(errs...)
}

type TunnelManager struct {
	journal   *reconcile.Journal
	driver    *TunnelDriver
	admission *Manager
}
type TunnelLease struct {
	Key, Consumer string
	Pin           reconcile.Lease
	IO            PacketIO
}

func OpenTunnelManager(path, owner string) (*TunnelManager, error) {
	return openTunnelManager(path, owner, nil)
}

func OpenTunnelManagerWithAdmission(path, owner string, admission *Manager) (*TunnelManager, error) {
	if admission == nil {
		return nil, ErrPolicy
	}
	return openTunnelManager(path, owner, admission)
}

func openTunnelManager(path, owner string, admission *Manager) (*TunnelManager, error) {
	if owner == "" {
		return nil, ErrKernelOwnership
	}
	j, err := reconcile.OpenJournal(path)
	if err != nil {
		return nil, err
	}
	if admission != nil {
		if err := admission.enrolTunnel(j, owner); err != nil {
			_ = j.Close()
			return nil, err
		}
	}
	return &TunnelManager{journal: j, driver: &TunnelDriver{Owner: owner}, admission: admission}, nil
}
func (m *TunnelManager) Desired(key string, revision, generation uint64, spec *TunnelSpec, capacity int) error {
	d := reconcile.Desired{Revision: revision, Retiring: generation}
	if spec != nil {
		b, err := json.Marshal(spec)
		if err != nil {
			return err
		}
		if _, err = DecodeTunnel(string(b)); err != nil {
			return err
		}
		d.Retiring = 0
		d.Resource = reconcile.Resource{Generation: generation, Spec: string(b), Present: true}
	}
	return m.journal.Desired(key, d, capacity)
}
func (m *TunnelManager) Step(ctx context.Context, key string) error {
	if err := m.journal.RestoreApplied(ctx, key, m.driver); err != nil {
		return err
	}
	return m.journal.Step(ctx, key, m.driver)
}
func (m *TunnelManager) Acquire(key, consumer string, generation uint64) (TunnelLease, error) {
	return m.AcquireContext(context.Background(), key, consumer, generation)
}

func (m *TunnelManager) AcquireContext(ctx context.Context, key, consumer string, generation uint64) (TunnelLease, error) {
	if consumer != "packet-plane" {
		return TunnelLease{}, reconcile.ErrLease
	}
	pin, err := m.borrow(ctx, key, consumer, generation)
	if err != nil {
		return TunnelLease{}, err
	}
	r, err := m.journal.Read(key)
	if err != nil {
		return TunnelLease{}, err
	}
	io, err := m.driver.PacketIO(key, r.State.Applied)
	return TunnelLease{key, consumer, pin, io}, err
}
func (m *TunnelManager) Return(l TunnelLease) error {
	return m.journal.Return(l.Key, l.Consumer, l.Pin)
}

// BorrowDependency pins the native path without lending its packet FD. An
// uncertain readback preserves the durable reference for the original owner.
func (m *TunnelManager) BorrowDependency(ctx context.Context, key, consumer string, generation uint64) (reconcile.Lease, error) {
	if !strings.HasPrefix(consumer, "ingress/") && !strings.HasPrefix(consumer, "network-reference/") {
		return reconcile.Lease{}, reconcile.ErrLease
	}
	pin, err := m.borrow(ctx, key, consumer, generation)
	if err != nil {
		return pin, err
	}
	_, err = m.Inspect(ctx, key)
	return pin, err
}

func (m *TunnelManager) borrow(ctx context.Context, key, consumer string, generation uint64) (reconcile.Lease, error) {
	if m.admission != nil {
		return m.admission.borrowFrom(ctx, m.journal, "tunnel", key, consumer, generation)
	}
	return m.journal.Borrow(key, consumer, generation)
}
func (m *TunnelManager) View(key string) (reconcile.Record, error) { return m.journal.Read(key) }
func (m *TunnelManager) Keys() []string                            { return m.journal.Keys() }
func (m *TunnelManager) Inspect(ctx context.Context, key string) (string, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return "", err
	}
	if r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource {
		return "", reconcile.ErrPending
	}
	return m.inspect(ctx, key, r.State.Applied, reconcile.Apply)
}
func (m *TunnelManager) inspect(ctx context.Context, key string, resource reconcile.Resource, kind reconcile.Kind) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	d := m.driver
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return "", os.ErrClosed
	}
	s, id, err := d.parameters(key, reconcile.Operation{Target: resource})
	if err != nil {
		return "", err
	}
	outcome, err := d.inspect(s, id, kind)
	if err != nil || outcome != reconcile.EffectApplied {
		return "", errors.Join(err, ErrKernelOwnership)
	}
	return id.name, nil
}
func (m *TunnelManager) Gone(ctx context.Context, key string, revision, generation uint64, spec TunnelSpec) (bool, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return false, err
	}
	if generation == 0 || revision == 0 || r.State.GenerationFloor != generation || r.State.Desired.Revision < revision || r.State.Pending != nil || r.State.Applied.Present || r.State.Desired.Present || len(r.Consumers) != 0 {
		return false, nil
	}
	spec.Lifecycle = schema.Lifecycle{}
	b, err := json.Marshal(spec)
	if err != nil {
		return false, err
	}
	_, err = m.inspect(ctx, key, reconcile.Resource{Present: true, Generation: generation, Spec: string(b)}, reconcile.Remove)
	return err == nil, err
}
func (m *TunnelManager) Close() error {
	return errors.Join(m.journal.Close(), m.driver.Close())
}
