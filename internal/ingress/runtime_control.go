// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type ControlDrain struct {
	Revision            uint64
	Draining            bool
	StartedAt, Deadline uint64
}
type RuntimeControl struct {
	Tenant, App, Node, Route string
	Balance                  *Balance
	Revision                 uint64
	Drain                    *ControlDrain
}

// SetRuntimeControls installs a derived view of the authoritative management
// checkpoint. It owns no deployment, container, listener or independent log.
func (m *Manager) SetRuntimeControls(revision uint64, controls []RuntimeControl) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || revision < m.controlRevision {
		return ErrRoute
	}
	if revision == m.controlRevision && m.controlsInitialized {
		return nil
	}
	if len(controls) > 8192 {
		return ErrRoute
	}
	for _, c := range controls {
		if c.Balance != nil && c.Balance.Validate() != nil || c.Drain != nil && c.Drain.Draining && (c.Drain.StartedAt == 0 || c.Drain.Deadline < c.Drain.StartedAt) {
			return ErrRoute
		}
	}
	var owned []RuntimeControl
	if err := json.Unmarshal([]byte(marshal(controls)), &owned); err != nil {
		return err
	}
	m.controls = owned
	m.controlRevision = revision
	m.controlsInitialized = true
	for _, i := range m.instances {
		i.mu.Lock()
		i.applyRuntimeControlsLocked()
		i.mu.Unlock()
	}
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	for _, g := range m.gateways {
		g.mu.Lock()
		g.rebuildLocked()
		g.mu.Unlock()
	}
	return nil
}

// Traffic hold modes (the owned VPS catalog's TrafficHolds values).
const (
	HoldExclude   = "exclude"
	HoldLowWeight = "low-weight"
)

// SetTrafficHolds installs the committed owned VPS traffic holds, node name
// to mode. An exclude hold leaves the node's backends out unless nothing else
// can serve the route; a low-weight hold gives them a small share. Requests in
// flight keep their backend.
func (m *Manager) SetTrafficHolds(holds map[string]string) {
	owned := make(map[string]string, len(holds))
	for node, mode := range holds {
		if mode == HoldExclude || mode == HoldLowWeight {
			owned[node] = mode
		}
	}
	m.trafficHolds.Store(&owned)
}

// holdSelection marks the selection's backends on held nodes.
func (m *Manager) holdSelection(q *Selection) {
	holds := m.trafficHolds.Load()
	if holds == nil || len(*holds) == 0 {
		return
	}
	for id, b := range q.Backends {
		switch (*holds)[b.Node] {
		case HoldExclude:
			if q.Avoid == nil {
				q.Avoid = map[string]bool{}
			}
			q.Avoid[id] = true
		case HoldLowWeight:
			if q.Light == nil {
				q.Light = map[string]bool{}
			}
			q.Light[id] = true
		}
	}
}

func (i *instance) applyRuntimeControlsLocked() {
	for _, timer := range i.controlTimers {
		timer.Stop()
	}
	i.controlTimers = nil
	i.controlBalances = map[string]Balance{}
	i.controlBackendDrains = map[string]ControlDrain{}
	i.controlDrain = ControlDrain{}
	for _, c := range i.manager.controls {
		if c.Tenant != i.record.Spec.Tenant || c.App != i.record.Spec.App {
			continue
		}
		if c.Balance != nil {
			i.controlBalances[c.Route] = *c.Balance
		}
		if c.Drain != nil {
			d := *c.Drain
			old, exists := i.controlBackendDrains[c.Node]
			if !exists || d.Revision > old.Revision {
				i.controlBackendDrains[c.Node] = d
			}
			if (c.Node == "" || c.Node == i.manager.node) && d.Revision > i.controlDrain.Revision {
				i.controlDrain = d
			}
		}
	}
	i.controlDraining.Store(i.controlDrain.Draining)
	for _, d := range i.controlBackendDrains {
		if !d.Draining {
			continue
		}
		delay := time.Until(time.Unix(int64(d.Deadline), 0))
		if delay < 0 {
			delay = 0
		}
		i.controlTimers = append(i.controlTimers, time.AfterFunc(delay, func() {
			i.mu.Lock()
			defer i.mu.Unlock()
			now := uint64(time.Now().Unix())
			for _, flow := range i.flows {
				if i.controlDrain.Draining && now >= i.controlDrain.Deadline || i.backendControlExpired(flow.target.Backend, now) {
					flow.cancel()
				}
			}
		}))
	}
}
func (i *instance) backendControl(node string) ControlDrain {
	d := i.controlBackendDrains[""]
	if one, ok := i.controlBackendDrains[node]; ok && one.Revision > d.Revision {
		d = one
	}
	return d
}
func (i *instance) backendControlExpired(id string, now uint64) bool {
	for _, s := range i.record.Spec.Services {
		for _, b := range s.Backends {
			if b.ID == id {
				d := i.backendControl(b.Node)
				return d.Draining && now >= d.Deadline
			}
		}
	}
	return false
}
func (i *instance) controlledRoutes(s Spec) Spec {
	if len(i.controlBalances) == 0 {
		return s
	}
	s.Routes = slices.Clone(s.Routes)
	for at := range s.Routes {
		if balance, ok := i.controlBalances[s.Routes[at].ID]; ok {
			s.Routes[at].Balance = &balance
		}
	}
	return s
}

// ValidateLocalGateways is an adapter observation. Callers sign its exact
// configuration before proposing a management change; the Raft reducer never
// enumerates interfaces or depends on another machine's clock.
func ValidateLocalGateways(c GatewayConfiguration) error {
	if c.Validate() != nil || len(c.External.AllowedSources) != 0 {
		return ErrRoute
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	local := map[netip.Addr]bool{}
	var loopback []netip.Prefix
	for _, address := range addresses {
		if p, e := netip.ParsePrefix(address.String()); e == nil {
			local[p.Addr().Unmap()] = true
			if p.Addr().IsLoopback() {
				loopback = append(loopback, p.Masked())
			}
		}
	}
	for _, g := range []Gateway{c.External, c.Local} {
		for _, a := range g.Addresses {
			present := local[a]
			if a.IsLoopback() {
				for _, p := range loopback {
					present = present || p.Contains(a)
				}
			}
			if !present {
				return errors.New("INGRESS_ADDRESS_NOT_LOCAL")
			}
		}
	}
	return nil
}
func (m *Manager) GatewayConfiguration() (GatewayConfiguration, uint64, string) {
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	return NormalizeGatewayConfiguration(m.gatewayConfiguration), m.gatewayRevision, m.gatewayError
}

// UpdateGateways keeps identical physical listeners. The HTTP/HTTP3 SDKs
// retire changed listeners gracefully; app instances and container owners are
// untouched. A failed bind is retained as an unapplied desired revision.
func (m *Manager) UpdateGateways(ctx context.Context, c GatewayConfiguration, revision uint64) error {
	c = NormalizeGatewayConfiguration(c)
	if err := ValidateLocalGateways(c); err != nil {
		m.gatewayMu.Lock()
		m.gatewayError = "INGRESS_ADDRESS_OR_CONFIGURATION_INVALID"
		m.gatewayMu.Unlock()
		return err
	}
	m.gatewaySerial.Lock()
	defer m.gatewaySerial.Unlock()
	m.gatewayMu.Lock()
	if revision < m.gatewayRevision {
		m.gatewayMu.Unlock()
		return ErrRoute
	}
	if revision == m.gatewayRevision && revision > 0 && marshal(c) != marshal(m.gatewayConfiguration) {
		m.gatewayMu.Unlock()
		return ErrRoute
	}
	if marshal(c) == marshal(m.gatewayConfiguration) && m.gatewayError == "" && len(m.gatewayRetirements) == 0 {
		m.gatewayRevision = revision
		m.gatewayError = ""
		m.gatewayMu.Unlock()
		return nil
	}
	old := m.gateways
	wanted := map[string]*sharedGateway{}
	retiring := []*sharedGateway{}
	for _, pair := range []struct {
		kind    string
		gateway Gateway
	}{{"external", c.External}, {"local", c.Local}} {
		g := pair.gateway
		if !g.Enabled {
			continue
		}
		sources := slices.Clone(g.AllowedSources)
		if pair.kind == "local" && len(sources) == 0 {
			for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
				sources = append(sources, netip.MustParsePrefix(p))
			}
			for _, a := range m.gatewayClusterAddresses {
				sources = append(sources, netip.PrefixFrom(a, a.BitLen()))
			}
		}
		for _, l := range g.Listeners {
			if previous := old[l.ID]; previous != nil && previous.kind == pair.kind && previous.definition == l {
				previous.mu.Lock()
				previous.allowed = sources
				previous.mu.Unlock()
				wanted[l.ID] = previous
			} else {
				wanted[l.ID] = &sharedGateway{manager: m, kind: pair.kind, definition: l, allowed: sources, bindings: map[string]gatewayBinding{}}
			}
		}
	}
	for id, g := range old {
		if wanted[id] != g {
			retiring = append(retiring, g)
		}
	}
	// Remove routing admission first; requests that already hold a binding keep
	// their original instance/backend lease until SDK shutdown completes.
	for _, g := range retiring {
		g.mu.Lock()
		g.bindings = map[string]gatewayBinding{}
		g.rebuildLocked()
		g.mu.Unlock()
	}
	m.gatewayRetirements = append(m.gatewayRetirements, retiring...)
	retiring = slices.Clone(m.gatewayRetirements)
	m.gateways = wanted
	m.gatewayClasses = map[netip.Addr]string{}
	for _, a := range c.External.Addresses {
		m.gatewayClasses[a] = "external"
	}
	for _, a := range c.Local.Addresses {
		m.gatewayClasses[a] = "local"
	}
	m.gatewayMu.Unlock()
	for _, g := range retiring {
		if err := g.shutdown(ctx); err != nil {
			m.gatewayMu.Lock()
			m.gatewayError = "GATEWAY_SHUTDOWN_FAILED"
			m.gatewayMu.Unlock()
			return err
		}
	}
	m.gatewayMu.Lock()
	m.gatewayRetirements = nil
	m.gatewayMu.Unlock()
	// Bindings are derived from still-owned instances under the same lock order
	// as ordinary reconciliation. No retired app or foreign listener is adopted.
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, i := range m.instances {
		i.mu.Lock()
		if !i.record.Gone && !i.record.Spec.Lifecycle.Drain {
			for _, l := range i.record.Spec.Listeners {
				if l.Shared != "" {
					m.gatewayMu.Lock()
					enabled := m.gateways[l.Shared] != nil
					m.gatewayMu.Unlock()
					if !enabled {
						continue
					}
					if err := m.attachShared(i, i.record.Spec, l); err != nil {
						i.mu.Unlock()
						m.gatewayMu.Lock()
						m.gatewayError = "GATEWAY_BINDING_FAILED"
						m.gatewayMu.Unlock()
						return err
					}
				}
			}
		}
		i.mu.Unlock()
	}
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	for _, g := range m.gateways {
		g.mu.Lock()
		if g.listener == nil {
			if err := g.startLocked(); err != nil {
				g.mu.Unlock()
				m.gatewayError = "GATEWAY_LISTEN_FAILED"
				return err
			}
		}
		g.mu.Unlock()
	}
	m.gatewayConfiguration = c
	m.gatewayRevision = revision
	m.gatewayError = ""
	return nil
}
func (g *sharedGateway) shutdown(ctx context.Context) error {
	g.mu.Lock()
	server, qs, listener, packet := g.server, g.quic, g.listener, g.packet
	g.mu.Unlock()
	var err error
	if server != nil {
		err = server.Shutdown(ctx)
	} else if listener != nil {
		err = listener.Close()
	}
	if qs != nil {
		err = errors.Join(err, qs.Shutdown(ctx))
	}
	if err != nil {
		return err
	}
	if packet != nil {
		_ = packet.Close()
	}
	g.workers.Wait()
	if g.inherited != nil {
		g.inherited.workers.Wait()
	}
	g.mu.Lock()
	g.server, g.quic, g.listener, g.packet = nil, nil, nil, nil
	g.mu.Unlock()
	return nil
}

// NormalizeGatewayConfiguration owns all returned slices and fixes the order
// of set-like address/port/source/listener declarations before node signing.
func NormalizeGatewayConfiguration(c GatewayConfiguration) GatewayConfiguration {
	normalize := func(g Gateway) Gateway {
		g.Addresses = slices.Clone(g.Addresses)
		g.Ports = slices.Clone(g.Ports)
		g.AllowedSources = slices.Clone(g.AllowedSources)
		g.Listeners = slices.Clone(g.Listeners)
		slices.SortFunc(g.Addresses, func(a, b netip.Addr) int { return a.Compare(b) })
		slices.Sort(g.Ports)
		slices.SortFunc(g.AllowedSources, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
		slices.SortFunc(g.Listeners, func(a, b Listener) int { return strings.Compare(a.ID, b.ID) })
		return g
	}
	c.External, c.Local = normalize(c.External), normalize(c.Local)
	return c
}
