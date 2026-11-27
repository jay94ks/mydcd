// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"errors"
	"hash/fnv"
	"net/netip"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// Network change and retirement in the fake, with the real payload types and
// the tenancy.Networks rules that the web can check: plan (reserved) → drain
// (draining) → fence (fenced, owner closure) → commit, or cancel while
// reserved; reconfigure-tun-network needs every member fenced, and an empty
// target retires the group (DNS must be off). join-tun-network adds one
// server while no member changes; leave-tun-network removes one drained
// server on its closure (the last one deletes the network). Fence and leave take
// the owner's signed closure from NetworkClosure (REQ-33 mock,
// fake_network_backup.go); Fake.FenceNetworkChange skips that in tests.

// fakeServerAddress stands for a server's address in the system range's
// server block (sfcd reserves the real one; the fake derives one).
func fakeServerAddress(node string) netip.Prefix {
	h := fnv.New32a()
	h.Write([]byte(node))
	v := 0x0afef000 + 1 + h.Sum32()%4094 // 10.254.240.0/20
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), 32)
}

// fakeMember builds a member row and its tenancy.Network source.
func fakeMember(tenant, name, node, kind string, pool tenancy.Subnet, tunnel netip.Prefix, rev uint64) NetworkMember {
	id := name
	src := tenancy.Network{Tenant: tenant, ID: id, Node: node, Owner: fakeNodeKey(node), Generation: rev, Revision: rev, Pools: []tenancy.Subnet{pool}}
	m := NetworkMember{Node: node, ID: id, CIDR: pool.Prefix.String(), Generation: rev, Revision: rev}
	if kind == "tun" {
		src.ID = name + "-" + node
		src.Logical = name
		m.ID = src.ID
		if tunnel.IsValid() {
			src.TunnelAddresses = []netip.Prefix{tunnel}
			m.Tunnel = tunnel.Addr().String()
		}
	}
	m.Source = src
	return m
}

// fixtureMembers fills Members of fixture network rows (pool "main", the
// first host as gateway, MTU 1500, the server's fake address).
func fixtureMembers(rows []ResourceEntry) {
	for i := range rows {
		n := rows[i].Network
		if n == nil || len(n.Members) > 0 {
			continue
		}
		row := *n
		prefix, err := netip.ParsePrefix(n.CIDR)
		if err != nil {
			continue
		}
		for j, node := range n.Nodes {
			// each server of a fixture TUN network gets its own /24
			p := prefix
			if n.Kind == "tun" && j > 0 {
				a := p.Addr().As4()
				a[2] += byte(j)
				p = netip.PrefixFrom(netip.AddrFrom4(a), p.Bits())
			}
			tunnel := fakeServerAddress(node)
			pool := tenancy.Subnet{ID: "main", Prefix: p, Gateway: p.Addr().Next(), MTU: 1500}
			row.Members = append(row.Members, fakeMember(rows[i].Tenant, n.Name, node, n.Kind, pool, tunnel, n.Revision))
		}
		rows[i].Network = &row
	}
}

// networkRow finds a tenant network row and returns a copy to change.
func (w *world) networkRow(tenant, name string) (int, *Network) {
	i := slices.IndexFunc(w.resources, func(e ResourceEntry) bool {
		return e.Tenant == tenant && e.Network != nil && e.Network.Name == name
	})
	if i < 0 {
		return -1, nil
	}
	row := *w.resources[i].Network
	row.Members = slices.Clone(row.Members)
	for j := range row.Members {
		if c := row.Members[j].Change; c != nil {
			cc := *c
			row.Members[j].Change = &cc
		}
		row.Members[j].Source.Pools = slices.Clone(row.Members[j].Source.Pools)
	}
	return i, &row
}

// memberByID finds the network row and member holding member network id.
func (w *world) memberByID(tenant, id string) (int, *Network, int) {
	for i, e := range w.resources {
		if e.Tenant != tenant || e.Network == nil {
			continue
		}
		for j, m := range e.Network.Members {
			if m.ID == id {
				_, row := w.networkRow(tenant, e.Network.Name)
				return i, row, j
			}
		}
	}
	return -1, nil, -1
}

func activeChange(c *NetworkChange) bool {
	return c != nil && c.Phase != string(tenancy.ChangeCommitted) && c.Phase != string(tenancy.ChangeCancelled)
}

func (c *fakeConn) applyNetworkChange(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	switch ch.Action {
	case ActionPlanNetworkChange:
		var q control.NetworkChangePlan
		if decodePayload(ch.Payload, &q) != nil || q.Change == "" || q.Target.Tenant != q.Tenant || q.Target.ID != q.ID || len(q.Target.Pools) == 0 {
			return errors.New("payload")
		}
		// tenancy.validDefinition: the target is a definition, not a stored
		// row; control.planNetworkChange: Owner empty or the target node's key.
		if t := q.Target; t.Generation != 0 || t.Revision != 0 || t.Draining || t.PendingChange != 0 || t.Owner != ([32]byte{}) && t.Owner != fakeNodeKey(t.Node) {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		i, row, j := w.memberByID(q.Tenant, q.ID)
		if i < 0 {
			return errCAS
		}
		m := &row.Members[j]
		if m.Revision != ch.Expected || m.Draining || activeChange(m.Change) || q.Target.Logical != m.Source.Logical {
			return errCAS
		}
		m.Change = &NetworkChange{ID: q.Change, Generation: next, Revision: next, TargetRevision: next, Phase: string(tenancy.ChangeReserved),
			TargetCIDR: q.Target.Pools[0].Prefix.String(), MetadataOnly: true}
		m.Revision, m.Source.Revision, m.Source.PendingChange = next, next, next
		w.pendingTargets()[q.Tenant+"/"+q.ID] = q.Target
		w.resources[i].Network = row
		w.netRev = next
		return nil

	case ActionDrainNetwork:
		var q control.NetworkSelection
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		i, row, j := w.memberByID(q.Tenant, q.ID)
		if i < 0 {
			return errCAS
		}
		m := &row.Members[j]
		if m.Revision != ch.Expected || m.Draining {
			return errCAS
		}
		m.Draining, m.Revision, m.Source.Draining, m.Source.Revision = true, next, true, next
		if m.Change != nil && m.Change.Phase == string(tenancy.ChangeReserved) {
			m.Change.Phase, m.Change.Revision = string(tenancy.ChangeDraining), next
		}
		w.resources[i].Network = row
		w.netRev = next
		return nil

	case ActionCancelNetworkChange:
		var q control.NetworkChangeCancel
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		i, row, j := w.memberByID(q.Tenant, q.ID)
		if i < 0 {
			return errCAS
		}
		m := &row.Members[j]
		if m.Change == nil || m.Change.Generation != q.Generation || m.Change.Revision != ch.Expected || m.Change.Phase != string(tenancy.ChangeReserved) || !q.Candidate.Empty() {
			return errCAS
		}
		m.Change.Phase, m.Change.Revision = string(tenancy.ChangeCancelled), next
		m.Source.PendingChange = 0
		delete(w.pendingTargets(), q.Tenant+"/"+q.ID)
		w.resources[i].Network = row
		w.netRev = next
		return nil

	case ActionFenceNetworkChange:
		// the owner's signed closure: NetworkClosure
		return c.applyFenceNetworkChange(op, actor, next)

	case ActionCommitNetworkChange:
		var q control.NetworkChangeCommit
		if decodePayload(ch.Payload, &q) != nil || len(q.Members) == 0 {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		i, row := w.networkRow(q.Tenant, q.Network)
		if i < 0 || row.Kind != "tun" || ch.Expected != w.netRev {
			return errCAS
		}
		changed := 0
		for _, v := range q.Members {
			j := slices.IndexFunc(row.Members, func(m NetworkMember) bool { return m.ID == v.ID })
			if j < 0 || v.Tenant != q.Tenant {
				return errCAS
			}
			m := &row.Members[j]
			if m.Change == nil || m.Change.Phase != string(tenancy.ChangeFenced) || m.Change.Generation != v.Generation || m.Change.Revision != v.Revision {
				return errCAS
			}
			changed++
		}
		if changed != len(q.Members) {
			return errCAS
		}
		for _, v := range q.Members {
			j := slices.IndexFunc(row.Members, func(m NetworkMember) bool { return m.ID == v.ID })
			m := &row.Members[j]
			m.CIDR = m.Change.TargetCIDR
			m.Change.Phase, m.Change.Revision = string(tenancy.ChangeCommitted), next
			m.Draining, m.Revision, m.Generation = false, next, next
			if t, ok := w.pendingTargets()[q.Tenant+"/"+v.ID]; ok {
				m.Source.Pools = slices.Clone(t.Pools)
				delete(w.pendingTargets(), q.Tenant+"/"+v.ID)
			}
			m.Source.Draining, m.Source.Revision, m.Source.Generation, m.Source.PendingChange = false, next, next, 0
		}
		row.CIDR = row.Members[0].CIDR
		row.Revision = next
		w.resources[i].Network = row
		w.netRev = next
		return nil

	case ActionReconfigureTUN:
		var q control.NetworkReconfigure
		if decodePayload(ch.Payload, &q) != nil || q.Target.Members == nil || len(q.Members) == 0 {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Target.Tenant) {
			return errForbidden
		}
		i, row := w.networkRow(q.Target.Tenant, q.Target.Name)
		if i < 0 || row.Kind != "tun" || ch.Expected != w.netRev || len(q.Members) != len(row.Members) {
			return errCAS
		}
		for _, v := range q.Members {
			j := slices.IndexFunc(row.Members, func(m NetworkMember) bool { return m.ID == v.ID })
			if j < 0 {
				return errCAS
			}
			m := row.Members[j]
			if m.Change == nil || m.Change.Phase != string(tenancy.ChangeFenced) || m.Change.Generation != v.Generation || m.Change.Revision != v.Revision {
				return errCAS
			}
		}
		if len(q.Target.Members) == 0 {
			if row.DNS != nil && row.DNS.Enabled {
				return errors.New("dns enabled")
			}
			w.resources = slices.Delete(w.resources, i, i+1)
			w.netRev = next
			return nil
		}
		row.Members, row.Nodes = nil, nil
		for _, tm := range q.Target.Members {
			if len(tm.Pools) == 0 || len(tm.Addresses) != 0 {
				return errors.New("payload")
			}
			row.Members = append(row.Members, fakeMember(q.Target.Tenant, q.Target.Name, tm.Node, "tun", tm.Pools[0], fakeServerAddress(tm.Node), next))
			row.Nodes = append(row.Nodes, tm.Node)
		}
		row.CIDR, row.Revision = row.Members[0].CIDR, next
		w.resources[i].Network = row
		w.netRev = next
		return nil

	case ActionJoinTUN:
		var q control.NetworkJoin
		if decodePayload(ch.Payload, &q) != nil || len(q.Member.Pools) == 0 || len(q.Member.Addresses) != 0 {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		i, row := w.networkRow(q.Tenant, q.Name)
		if i < 0 || row.Kind != "tun" || ch.Expected != w.netRev || slices.Contains(row.Nodes, q.Member.Node) {
			return errCAS
		}
		for _, t := range tenancy.NetworkToggles() {
			if !tenancy.ToggleAllowed(t, slices.Contains(row.Toggles, t), len(row.Members)+1) {
				return errors.New("toggle refuses the join")
			}
		}
		for _, m := range row.Members {
			if m.Draining || activeChange(m.Change) {
				return errors.New("member changing")
			}
		}
		row.Members = append(slices.Clone(row.Members), fakeMember(q.Tenant, q.Name, q.Member.Node, "tun", q.Member.Pools[0], fakeServerAddress(q.Member.Node), next))
		row.Nodes = append(slices.Clone(row.Nodes), q.Member.Node)
		row.Revision = next
		w.resources[i].Network = row
		w.netRev = next
		return nil

	case ActionSetNetworkToggle:
		var q control.NetworkToggleSet
		if decodePayload(ch.Payload, &q) != nil || !slices.Contains(tenancy.NetworkToggles(), q.Toggle) {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		i, row := w.networkRow(q.Tenant, q.Name)
		if i < 0 || row.Kind != "tun" || ch.Expected != w.netRev || slices.Contains(row.Toggles, q.Toggle) == q.On {
			return errCAS
		}
		if !tenancy.ToggleAllowed(q.Toggle, q.On, len(row.Members)) {
			return errors.New("toggle not allowed")
		}
		row.Toggles = slices.DeleteFunc(slices.Clone(row.Toggles), func(t tenancy.NetworkToggle) bool { return t == q.Toggle })
		if q.On {
			row.Toggles = append(row.Toggles, q.Toggle)
			slices.Sort(row.Toggles)
		}
		row.Members = slices.Clone(row.Members)
		for j := range row.Members {
			row.Members[j].Source.Toggles = slices.Clone(row.Toggles)
		}
		row.Revision = next
		w.resources[i].Network = row
		w.netRev = next
		return nil

	case ActionLeaveTUN:
		var p NetworkClosure
		if decodePayload(ch.Payload, &p) != nil || p.Tenant == "" {
			return errors.New("payload")
		}
		if !w.canManage(actor, p.Tenant) {
			return errForbidden
		}
		i, row, j := w.memberByID(p.Tenant, p.Network)
		if i < 0 || row.Members[j].Revision != ch.Expected || row.Members[j].Source.Logical == "" || !row.Members[j].Draining {
			return errCAS
		}
		// sfcd: the last member leaving deletes the network; its DNS must
		// be off first.
		last := len(row.Members) == 1
		if last && row.DNS != nil && row.DNS.Enabled {
			return errCAS
		}
		m := row.Members[j]
		if activeChange(m.Change) || !w.memberClosureOK(p.Tenant, m, p) {
			return errors.New("closure")
		}
		if last {
			w.resources = slices.Delete(w.resources, i, i+1)
			w.netRev = next
			return nil
		}
		row.Members = slices.Delete(slices.Clone(row.Members), j, j+1)
		row.Nodes = slices.DeleteFunc(slices.Clone(row.Nodes), func(n string) bool { return n == m.Node })
		row.CIDR, row.Revision = row.Members[0].CIDR, next
		w.resources[i].Network = row
		w.netRev = next
		return nil
	}
	return errors.New("action")
}

// pendingTargets keeps planned targets by tenant/member id.
func (w *world) pendingTargets() map[string]tenancy.Network {
	if w.netTargets == nil {
		w.netTargets = map[string]tenancy.Network{}
	}
	return w.netTargets
}

// FenceNetworkChange moves a draining change to fenced without a closure, as
// fence-network-change with NetworkClosure's proof would.
func (f *Fake) FenceNetworkChange(tenant, name, node string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.w
	i, row := w.networkRow(tenant, name)
	if i < 0 {
		return errors.New("no network")
	}
	j := slices.IndexFunc(row.Members, func(m NetworkMember) bool { return m.Node == node })
	if j < 0 || row.Members[j].Change == nil || row.Members[j].Change.Phase != string(tenancy.ChangeDraining) {
		return errors.New("not draining")
	}
	w.root++
	row.Members[j].Change.Phase, row.Members[j].Change.Revision = string(tenancy.ChangeFenced), w.root
	w.resources[i].Network = row
	w.netRev = w.root
	return nil
}
