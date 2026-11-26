// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"errors"
	"path"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// applySharedCreate models the creation of tenant shared resources with the
// real payload types: a TUN network and its managed DNS, a managed or node-fixed volume and a
// Vault object. Only the list rows change; addresses, native volumes and
// secret values are not modeled. f.mu is held.
func (c *fakeConn) applySharedCreate(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	switch ch.Action {
	case ActionCreateTUNNetwork:
		var v tenancy.TUNDefinition
		if decodePayload(ch.Payload, &v) != nil || v.Name == "" || len(v.Members) == 0 || len(v.Members) > 32 {
			return errors.New("payload")
		}
		if !w.canManage(actor, v.Tenant) {
			return errForbidden
		}
		if ch.Expected != w.netRev || slices.ContainsFunc(w.resources, func(e ResourceEntry) bool {
			return e.Tenant == v.Tenant && e.Network != nil && e.Network.Name == v.Name
		}) {
			return errCAS
		}
		row := &Network{Name: v.Name, Kind: "tun", Revision: next}
		for _, m := range v.Members {
			if m.Node == "" || len(m.Pools) == 0 || len(m.Addresses) == 0 || slices.Contains(row.Nodes, m.Node) {
				return errors.New("payload")
			}
			row.Nodes = append(row.Nodes, m.Node)
			row.Members = append(row.Members, fakeMember(v.Tenant, v.Name, m.Node, "tun", m.Pools[0], m.Addresses[0], next))
			row.Members[len(row.Members)-1].Source.Toggles = slices.Clone(v.Toggles)
		}
		for _, t := range tenancy.NetworkToggles() {
			if !tenancy.ToggleAllowed(t, slices.Contains(v.Toggles, t), len(v.Members)) {
				return errors.New("toggle not allowed")
			}
		}
		row.Toggles = slices.Clone(v.Toggles)
		row.CIDR = v.Members[0].Pools[0].Prefix.String()
		w.resources = append(w.resources, ResourceEntry{Key: v.Tenant + "/network/" + v.Name, Tenant: v.Tenant, Network: row})
		w.netRev = next
		return nil

	case ActionConfigureNetworkDNS:
		// mydcd: managed DNS exists only for TUN (logical) networks; Expected
		// is the policy object's revision (0 for the first one).
		var v services.ManagedDNSDefinition
		if decodePayload(ch.Payload, &v) != nil || v.Schema != 1 || v.Policy.Upstreams == nil {
			return errors.New("payload")
		}
		if !w.canManage(actor, v.Tenant) {
			return errForbidden
		}
		i := slices.IndexFunc(w.resources, func(e ResourceEntry) bool {
			return e.Tenant == v.Tenant && e.Network != nil && e.Network.Name == v.Network
		})
		if i < 0 || w.resources[i].Network.Kind != "tun" {
			return errors.New("not a tun network")
		}
		n := w.resources[i].Network
		cur := uint64(0)
		if n.DNS != nil {
			cur = n.DNS.Revision
		}
		if ch.Expected != cur {
			return errCAS
		}
		// a new row value: pages already handed out keep the old pointer
		row := *n
		row.DNS = dnsView(v.Policy, next)
		// the fake's resolver is each member's pool gateway
		row.Members = slices.Clone(row.Members)
		for j := range row.Members {
			row.Members[j].Resolver = ""
			if p := row.Members[j].Source.Pools; v.Policy.Enabled && len(p) > 0 && p[0].Gateway.IsValid() {
				row.Members[j].Resolver = p[0].Gateway.String()
				row.DNS.Resolvers = append(row.DNS.Resolvers, p[0].Gateway.String()+":53")
			}
		}
		ready := v.Policy.Enabled
		row.DNS.Ready, row.DNS.State = &ready, "stopped"
		if ready {
			row.DNS.State = "ready"
		}
		w.resources[i].Network = &row
		return nil

	case ActionBeginVolumeCreate, ActionRegisterFixedVolume:
		row := volumeRow{Revision: next, Retain: true}
		if ch.Action == ActionBeginVolumeCreate {
			var q control.VolumeCreate
			if decodePayload(ch.Payload, &q) != nil || q.Scope.ID == "" || q.Node == "" {
				return errors.New("payload")
			}
			row.Tenant, row.Name, row.Kind, row.Node, row.CapacityBytes, row.App = q.Scope.Tenant, q.Scope.ID, "shared", q.Node, q.CapacityBytes, q.Scope.App
			if q.Scope.Cluster != w.cluster {
				return errors.New("cluster")
			}
		} else {
			var q control.VolumeFixedRegister
			if decodePayload(ch.Payload, &q) != nil || q.Scope.ID == "" || !q.Scope.TenantManaged() {
				return errors.New("payload")
			}
			if q.Scope.Cluster != w.cluster {
				return errors.New("cluster")
			}
			ok := slices.ContainsFunc(w.nodeStorage, func(r FixtureStorageRoot) bool {
				return r.Node == q.Node && r.ID == q.Storage && r.Generation == q.RootGeneration && !r.Draining && slices.Contains(r.Tenants, q.Scope.Tenant)
			})
			if !ok {
				return errors.New("storage root")
			}
			row.Tenant, row.Name, row.Kind, row.Node, row.Storage, row.CapacityBytes = q.Scope.Tenant, q.Scope.ID, "fixed", q.Node, q.Storage, q.CapacityBytes
		}
		if !w.canManage(actor, row.Tenant) {
			return errForbidden
		}
		row.Key = row.Tenant + "/" + row.Name
		if ch.Expected != 0 || slices.ContainsFunc(w.volumes, func(v volumeRow) bool { return v.Key == row.Key }) {
			return errCAS
		}
		w.volumes = append(w.volumes, row)
		w.fillVolumeSources()
		return nil

	case ActionVaultCreate:
		var v control.VaultObject
		if decodePayload(ch.Payload, &v) != nil || v.Object.ID == "" || v.Object.Parent == "" {
			return errors.New("payload")
		}
		if !w.canManageRealm(actor, v.Realm) {
			return errForbidden
		}
		if v.Realm == "" && !slices.ContainsFunc(w.vault, func(e VaultView) bool { return e.Realm == "" && e.ID == v.Object.Parent && e.Kind == "group" }) {
			return errCAS // no cluster Vault yet, or no such parent group
		}
		p := path.Join(v.Object.Parent, v.Object.ID)
		if ch.Expected != w.vaultRev[v.Realm] || slices.ContainsFunc(w.vault, func(e VaultView) bool { return e.Realm == v.Realm && e.Path == p }) {
			return errCAS
		}
		row := VaultView{Realm: v.Realm, Path: p, Kind: "group", Revision: next}
		if v.Object.Kind == secrets.Secret {
			row.Kind, row.Profile, row.Keys = "object", v.Object.Reference.Profile, slices.Clone(v.Object.Reference.Keys)
		}
		w.vault = append(w.vault, row)
		w.fillVaultIDs()
		w.vaultRev[v.Realm] = next
		return nil
	}
	return errors.New("action")
}

// dnsView is the row form of a managed DNS policy.
func dnsView(p services.ManagedDNSPolicy, rev uint64) *NetworkDNS {
	d := &NetworkDNS{Zone: p.Zone, Enabled: p.Enabled, Revision: rev, Upstreams: []string{}, TTL: p.TTL, NegativeTTL: p.NegativeTTL, Reverse: p.Reverse, Policy: p, Resolvers: []string{}, State: "unknown"}
	d.Policy.Upstreams = slices.Clone(p.Upstreams)
	d.Policy.Transports = slices.Clone(p.Transports)
	for _, u := range p.Upstreams {
		d.Upstreams = append(d.Upstreams, u.String())
	}
	return d
}
