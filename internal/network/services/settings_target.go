// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

type SettingKind string

const (
	SettingDNS     SettingKind = "dns"
	SettingNetwork SettingKind = "network"
)

// NativeScope identifies the exact local namespace and original interface.
// The real adapter obtains these from its owned namespace/ifindex journal;
// caller text or a desired network name alone is not native provenance.
type NativeScope struct {
	Namespace [32]byte
	Interface string
}
type settingBinding struct {
	Native    NativeScope
	Listeners []network.Listener
	Prefixes  []netip.Prefix
	Exclusive bool
}

// SettingsTarget can only be built from current typed product policy. It has no
// side effects; native preparation and admission remain separate transitions.
type SettingsTarget struct {
	kind                             SettingKind
	key                              string
	revision                         uint64
	source                           Source
	instance                         [32]byte
	enabled                          bool
	binding                          settingBinding
	dns                              *dnsProjection
	network                          *tenancy.Network
	changeGeneration, targetRevision uint64
}

func (t SettingsTarget) Key() string       { return t.key }
func (t SettingsTarget) Revision() uint64  { return t.revision }
func (t SettingsTarget) Kind() SettingKind { return t.kind }
func ownSettingsTarget(t SettingsTarget) SettingsTarget {
	t.binding.Listeners = slices.Clone(t.binding.Listeners)
	t.binding.Prefixes = slices.Clone(t.binding.Prefixes)
	if t.dns != nil {
		p := ownProjection(*t.dns)
		t.dns = &p
	}
	if t.network != nil {
		n := *t.network
		n.Pools = slices.Clone(n.Pools)
		t.network = &n
	}
	return t
}
func validNativeScope(s NativeScope) bool {
	return s.Namespace != ([32]byte{}) && len(s.Interface) > 0 && len(s.Interface) <= 256 && !strings.ContainsAny(s.Interface, "\x00\r\n")
}
func bindingBytes(b settingBinding) []byte { raw, _ := json.Marshal(b); return raw }
func bindingEqual(a, b settingBinding) bool {
	return string(bindingBytes(a)) == string(bindingBytes(b))
}
func bindingConflicts(a, b settingBinding) bool {
	if a.Native.Namespace != b.Native.Namespace {
		return false
	}
	if a.Exclusive && b.Exclusive && a.Native.Interface == b.Native.Interface {
		return true
	}
	for _, x := range a.Listeners {
		for _, y := range b.Listeners {
			if network.ListenerConflict(x, y) {
				return true
			}
		}
	}
	for _, x := range a.Prefixes {
		for _, y := range b.Prefixes {
			if x.Overlaps(y) {
				return true
			}
		}
	}
	return false
}
func (t SettingsTarget) hash() [32]byte {
	raw, _ := json.Marshal(targetSnapshot(t))
	return sha256.Sum256(append([]byte("sfc-settings-target-1\x00"), raw...))
}
func settingsDNS(c access.Catalog, n tenancy.Networks, a Authority, actor string, cfg DNSConfig, scope NativeScope) (SettingsTarget, error) {
	p, e := buildDNS(c, n, a, actor, cfg)
	if !cfg.Enabled {
		p, e = buildRetiringDNS(c, n, a, actor, cfg)
	}
	if e != nil || !validNativeScope(scope) {
		return SettingsTarget{}, ErrLease
	}
	ref, ok := referenceForProjection(a, p)
	if cfg.Enabled && (!ok || ref.DesiredSource != cfg.Source || ref.DesiredHash != projectionHash(p)) {
		return SettingsTarget{}, ErrLease
	}
	t := SettingsTarget{kind: SettingDNS, key: "dns/" + dnsKey(cfg.Tenant, cfg.ID), revision: cfg.Source, source: p.Local, instance: ref.ID, enabled: cfg.Enabled, dns: &p, binding: settingBinding{Native: scope}}
	if cfg.Enabled {
		for _, protocol := range []uint8{6, 17} {
			t.binding.Listeners = append(t.binding.Listeners, network.Listener{ID: generationText(uint64(protocol)), Owner: poolOwner(p.Local), Generation: 1, Address: p.Local.Gateway, Port: 53, Protocol: protocol})
		}
	}
	return t, nil
}
func DNSSettings(c access.Catalog, n tenancy.Networks, a Authority, actor string, cfg DNSConfig, scope NativeScope) (SettingsTarget, error) {
	return settingsDNS(c, n, a, actor, cfg, scope)
}

// NetworkSettings builds either current network ownership or the exact staged
// target. A candidate may prepare while Reserved but cannot serve before CAS.
func NetworkSettings(c access.Catalog, n tenancy.Networks, a Authority, actor, tenant, id string, candidate bool, scope NativeScope) (SettingsTarget, error) {
	v, ok := n.Network(tenant, id)
	generation, revision := v.Generation, v.Revision
	var change, target uint64
	if candidate {
		ch, exists := n.Change(tenant, id)
		if !exists || ch.Phase == tenancy.ChangeCancelled {
			return SettingsTarget{}, ErrLease
		}
		v = ch.Target
		generation = ch.Generation
		revision = ch.TargetRevision
		change, target = ch.Generation, ch.TargetRevision
		ok = true
	}
	if !ok || n.Cluster() != a.cluster || !validNativeScope(scope) || len(v.Pools) == 0 || c.Authorize(actor, tenant, access.ManageNetwork, v.Node) != nil {
		return SettingsTarget{}, ErrLease
	}
	v.PendingChange = 0
	s := Source{a.cluster, tenant, id, v.Pools[0].ID, v.Node, v.Owner, generation, v.Pools[0].Prefix, v.Pools[0].Gateway, v.Pools[0].MTU}
	raw, _ := json.Marshal(struct {
		Source Source
		Change uint64
		Target uint64
	}{s, change, target})
	inst := sha256.Sum256(raw)
	t := SettingsTarget{kind: SettingNetwork, key: "network/" + serviceKey(tenant, id), revision: revision, source: s, instance: inst, enabled: !v.Draining, network: &v, changeGeneration: change, targetRevision: target, binding: settingBinding{Native: scope, Exclusive: true}}
	for _, p := range v.Pools {
		t.binding.Prefixes = append(t.binding.Prefixes, p.Prefix)
	}
	return t, nil
}
func (t SettingsTarget) live(c access.Catalog, n tenancy.Networks, a Authority, exact bool) bool {
	if a.cluster != t.source.Cluster || n.Cluster() != a.cluster || !t.enabled {
		return false
	}
	switch t.kind {
	case SettingDNS:
		if t.dns == nil || !freshDNSProjection(c, n, a, *t.dns) {
			return false
		}
		ref, ok := referenceForProjection(a, *t.dns)
		return ok && ref.ID == t.instance && (!exact || ref.DesiredSource == t.revision && ref.DesiredHash == projectionHash(*t.dns))
	case SettingNetwork:
		v, ok := n.Network(t.source.Tenant, t.source.Network)
		if !ok || v.Draining || !settingNodeAllowed(c, v.Tenant, v.Node) {
			return false
		}
		if t.changeGeneration != 0 {
			ch, ok := n.Change(v.Tenant, v.ID)
			return ok && ch.Generation == t.changeGeneration && ch.TargetRevision == t.targetRevision && ch.Phase == tenancy.ChangeCommitted && v.Generation == ch.Committed.Generation && v.Owner == t.source.Owner
		}
		return v.Generation == t.source.NetworkGeneration && v.Revision == t.revision && v.Owner == t.source.Owner
	}
	return false
}
func settingNodeAllowed(c access.Catalog, tenant, node string) bool {
	t, ok := c.Tenant(tenant)
	return ok && t.Enabled && t.Phase == access.TenantActive && slices.Contains(t.AllowedNodes, node)
}
func (t SettingsTarget) preparable(c access.Catalog, n tenancy.Networks, a Authority) bool {
	if t.source.Cluster != a.cluster || n.Cluster() != a.cluster || t.enabled && !settingNodeAllowed(c, t.source.Tenant, t.source.Node) || !t.enabled && t.kind != SettingDNS && !settingNodeAllowed(c, t.source.Tenant, t.source.Node) {
		return false
	}
	switch t.kind {
	case SettingDNS:
		if t.dns == nil || !freshDNSProjection(c, n, a, *t.dns) {
			return false
		}
		if !t.enabled {
			return true
		}
		ref, ok := referenceForProjection(a, *t.dns)
		return ok && ref.ID == t.instance && ref.DesiredSource == t.revision && ref.DesiredHash == projectionHash(*t.dns)
	case SettingNetwork:
		if t.changeGeneration != 0 {
			ch, ok := n.Change(t.source.Tenant, t.source.Network)
			return ok && ch.Generation == t.changeGeneration && ch.TargetRevision == t.targetRevision && ch.Phase != tenancy.ChangeCancelled && ch.Target.Owner == t.source.Owner
		}
		v, ok := n.Network(t.source.Tenant, t.source.Network)
		return ok && v.Generation == t.source.NetworkGeneration && v.Revision == t.revision && v.Owner == t.source.Owner
	}
	return false
}
