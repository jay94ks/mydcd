// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
)

// This metadata binds the one management policy to an exact local owner and
// native dependency. It is neither a second policy store nor a Ready report.
type ManagedDNSOwnerSource struct {
	Node                             string
	Bridge                           deployment.ObjectRef
	MaxConnections, RequestTimeoutMS int
}

func dnsOwnerOrder(row AppDNSOwner) string {
	if row.Managed != nil {
		return row.Source.Key + "\x00" + row.Config.Network + "\x00" + row.Config.Pool
	}
	return row.Source.Key
}

// No app identity or supplied configuration/commit fact is accepted here.
// Root/source CAS, epoch and the deterministic digest bind this pure metadata
// projection. Re-reading after an unknown reply does not start a native effect.
type NetworkDNSProgress struct {
	Schema                        uint8
	Kind                          string
	Cluster, Reporter, Digest     [32]byte
	Source                        deployment.ObjectRef
	Expected, Epoch, RootRevision uint64
	At                            uint64                   `json:",omitempty"`
	Close                         *services.ReferenceClose `json:",omitempty"`
	Signature                     []byte
}

func NetworkDNSProgressBytes(r NetworkDNSProgress) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-network-dns-progress-1\x00"), raw...)
}

func (r NetworkDNSProgress) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: AppsKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func networkDNSReportValue(raw []byte) bool {
	var head struct{ Kind string }
	return json.Unmarshal(raw, &head) == nil && head.Kind == "network-dns"
}

func (p Policy) networkDNSProgress(s state.State, cmd state.Command) (NetworkDNSProgress, error) {
	var r NetworkDNSProgress
	if cmd.Kind != state.ModuleReport || cmd.Key != AppsKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Kind != "network-dns" || r.Cluster != p.Cluster || r.Reporter == ([32]byte{}) || r.Digest == ([32]byte{}) || r.Epoch != s.ModuleEpoch() || r.RootRevision != cmd.Expected || !ed25519.Verify(ed25519.PublicKey(r.Reporter[:]), NetworkDNSProgressBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	if r.Close == nil && r.At != 0 || r.Close != nil && (r.At == 0 || r.At > math.MaxInt64) {
		return r, ErrCatalog
	}
	original, err := r.Command()
	if err != nil || original != cmd {
		return r, ErrCatalog
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(r.Reporter) {
		return r, ErrCatalog
	}
	object := s.Object(r.Source.Key)
	if !object.Present || r.Source.Generation == 0 || object.Generation != r.Source.Generation || object.Revision != r.Source.Revision || !strings.HasPrefix(r.Source.Key, services.ManagedDNSPrefix) {
		return r, ErrCatalog
	}
	return r, nil
}

func (p Policy) managedDNSProjection(s state.State, projection ResourceProjection, key string) (appDNSGroup, ManagedDNSSource, error) {
	apps, err := p.Apps(s)
	if err != nil {
		return appDNSGroup{}, ManagedDNSSource{}, err
	}
	return p.managedDNSProjectionFromApps(s, apps, projection, key)
}

func (p Policy) managedDNSProjectionFromApps(s state.State, apps Apps, projection ResourceProjection, key string) (appDNSGroup, ManagedDNSSource, error) {
	sources, err := p.ManagedDNS(s)
	if err != nil {
		return appDNSGroup{}, ManagedDNSSource{}, err
	}
	source, found := sources[key]
	if !found || !projection.Compatible {
		return appDNSGroup{}, source, ErrCatalog
	}
	definition := source.Definition
	catalog, err := p.Catalog(s)
	if err != nil {
		return appDNSGroup{}, source, err
	}
	// Placement withdrawal fences serving on the whole logical view, whose
	// current admission already requires every member. Keep the declared
	// source untouched and settle its original owner instances as disabled.
	if definition.Policy.Enabled {
		tenant, found := catalog.Tenant(definition.Tenant)
		members, err := projection.Resources.Networks.TUNSources(definition.Tenant, definition.Network)
		if !found || err != nil {
			return appDNSGroup{}, source, ErrCatalog
		}
		for _, member := range members {
			if !slices.Contains(tenant.AllowedNodes, member.Network.Node) {
				definition.Policy.Enabled = false
				break
			}
		}
	}
	group := appDNSGroup{Managed: true, Tenant: definition.Tenant, Network: definition.Network}
	if apps.network != nil {
		for _, original := range apps.network.Groups {
			if dnsGroupKey(original) != dnsGroupKey(group) || len(original.Owners) == 0 {
				continue
			}
			object := s.Object(key)
			frozen := true
			for _, row := range original.Owners {
				frozen = frozen && !row.Config.Enabled && row.Source == (deployment.ObjectRef{Key: key, Generation: object.Generation, Revision: object.Revision})
			}
			if frozen && (!definition.Policy.Enabled || managedDNSLiveReferences(apps, key)) {
				// Permission restoration also waits for every original close.
				// Neither a Task/name change nor a new source version resets it.
				return original, source, nil
			}
		}
	}
	authority, err := projection.addressAuthority(p.Cluster)
	if err != nil {
		return group, source, err
	}
	registrations, err := p.managedDNSRegistrationsFromApps(s, apps, projection, definition, nil)
	if err != nil {
		return group, source, err
	}
	plans, err := definition.RetainedPlans(catalog, projection.Resources.Networks, authority, source.Principal, 1, 1, registrations)
	if err != nil {
		return group, source, err
	}
	object := s.Object(key)
	for _, plan := range plans {
		bridge, exists := projection.ManagedSources[plan.BridgeKey]
		if !exists || bridge.Bridge == nil || bridge.Network.Owner != plan.Owner || bridge.Network.Node != plan.Node || bridge.Network.ID != plan.Config.Network {
			return group, source, ErrCatalog
		}
		if plan.Config.Enabled {
			owner, err := p.nodeOwner(s, plan.Node)
			if err != nil || !p.ownsResource(s, owner, plan.Owner) {
				return group, source, ErrCatalog
			}
		}
		dep := s.Object(plan.BridgeKey)
		if !dep.Present || dep.Generation == 0 || dep.Revision < dep.Generation {
			return group, source, ErrCatalog
		}
		meta := &ManagedDNSOwnerSource{Node: plan.Node, Bridge: deployment.ObjectRef{Key: plan.BridgeKey, Generation: dep.Generation, Revision: dep.Revision}, MaxConnections: plan.MaxConnections, RequestTimeoutMS: plan.RequestTimeoutMS}
		group.Owners = append(group.Owners, AppDNSOwner{Managed: meta, Source: deployment.ObjectRef{Key: key, Generation: object.Generation, Revision: object.Revision}, Config: plan.Config})
	}
	slices.SortFunc(group.Owners, func(a, b AppDNSOwner) int { return strings.Compare(dnsOwnerOrder(a), dnsOwnerOrder(b)) })
	group.Digest = appDNSDigest(group.Owners)
	return group, source, nil
}

func managedDNSGroupEnabled(group appDNSGroup) bool {
	for _, owner := range group.Owners {
		if owner.Config.Enabled {
			return true
		}
	}
	return false
}

func (p Policy) managedGroupReporter(s state.State, projection ResourceProjection, g appDNSGroup, owner [32]byte) bool {
	for _, row := range g.Owners {
		if row.Managed != nil && p.ownsResource(s, owner, projection.ManagedSources[row.Managed.Bridge.Key].Network.Owner) {
			return true
		}
	}
	return false
}

// ManagedDNSUpdates is a controller hint over an immutable current snapshot.
// The reducer independently derives the entire group at the actual commit.
func (p Policy) ManagedDNSUpdates(s state.State, owner [32]byte) ([]NetworkDNSProgress, error) {
	sources, err := p.ManagedDNS(s)
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, nil
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return nil, err
	}
	projection, err := p.projectResourcesFromApps(s, apps)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(sources))
	for key := range sources {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	local := map[string]bool{}
	for _, network := range projection.Resources.Networks.AllNetworks() {
		if p.ownsResource(s, owner, network.Owner) && network.Logical != "" {
			local[services.ManagedDNSKey(network.Tenant, network.Logical)] = true
		}
	}
	var out []NetworkDNSProgress
	for _, key := range keys {
		if !local[key] {
			continue
		}
		group, _, err := p.managedDNSProjectionFromApps(s, apps, projection, key)
		if err != nil {
			return nil, err
		}
		if !managedDNSGroupEnabled(group) && !managedDNSLiveReferences(apps, key) {
			continue
		}
		if !p.managedGroupReporter(s, projection, group, owner) {
			continue
		}
		expected := uint64(0)
		changed := true
		if apps.network != nil {
			expected = apps.network.Revision
			for _, old := range apps.network.Groups {
				if dnsGroupKey(old) == dnsGroupKey(group) {
					changed = old.Digest != group.Digest
					break
				}
			}
		}
		if !changed {
			continue
		}
		object := s.Object(key)
		out = append(out, NetworkDNSProgress{Schema: 1, Kind: "network-dns", Cluster: p.Cluster, Reporter: owner, Digest: group.Digest, Source: deployment.ObjectRef{Key: key, Generation: object.Generation, Revision: object.Revision}, Expected: expected, Epoch: s.ModuleEpoch(), RootRevision: s.Object(AppsKey).Revision})
	}
	return out, nil
}

func (p Policy) reduceNetworkDNSProgress(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.networkDNSProgress(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	apps, err := p.Apps(s)
	if err != nil {
		return nil, state.Invalid
	}
	expected := uint64(0)
	if apps.network != nil {
		expected = apps.network.Revision
	}
	if r.Expected != expected {
		return nil, state.ConditionFailed
	}
	if r.Close != nil {
		updated, err := p.closeManagedDNS(s, apps, r)
		if err != nil {
			return nil, state.ConditionFailed
		}
		return p.appsCheckpoint(s, updated)
	}
	projection, err := p.projectResourcesFromApps(s, apps)
	if err != nil {
		return nil, state.Invalid
	}
	group, source, err := p.managedDNSProjectionFromApps(s, apps, projection, r.Source.Key)
	if err != nil || group.Digest != r.Digest {
		return nil, state.ConditionFailed
	}
	if !managedDNSGroupEnabled(group) && !managedDNSLiveReferences(apps, r.Source.Key) {
		return nil, state.ConditionFailed
	}
	allowed := false
	for _, row := range group.Owners {
		if row.Managed != nil && p.ownsResource(s, r.Reporter, projection.ManagedSources[row.Managed.Bridge.Key].Network.Owner) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, state.Forbidden
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	return p.publishDNSGroup(s, catalog, projection, source.Principal, apps, group)
}

func (p Policy) closeManagedDNS(s state.State, apps Apps, r NetworkDNSProgress) (Apps, error) {
	if apps.network == nil || r.Close == nil || !p.ownsResource(s, r.Reporter, r.Close.Owner) {
		return apps, ErrCatalog
	}
	sources, err := p.ManagedDNS(s)
	if err != nil {
		return apps, err
	}
	_, exists := sources[r.Source.Key]
	if !exists {
		return apps, ErrCatalog
	}
	for _, group := range apps.network.Groups {
		if !group.Managed || group.Digest != r.Digest {
			continue
		}
		for _, row := range group.Owners {
			if row.Managed == nil || row.Reference != r.Close.Consumer || row.Source.Key != r.Source.Key || row.Source.Generation != r.Source.Generation {
				continue
			}
			if r.Close.Target == ([32]byte{}) && row.Config.Enabled {
				return apps, ErrCatalog
			}
			// ObserveReferenceClose validates the ORIGINAL consumer/generation/
			// lifetime/fence and owner signature. Current account revocation or
			// a newer view cannot erase that outstanding settlement dependency.
			n := *apps.network
			n.Authority, err = n.Authority.ObserveReferenceClose(*r.Close, int64(r.At))
			if err != nil {
				return apps, err
			}
			if n.Authority.Revision() == apps.network.Authority.Revision() {
				return apps, ErrCatalog
			}
			apps.network = &n
			return apps, nil
		}
	}
	return apps, ErrCatalog
}

// ManagedDNSClosure binds positive original local facts to the current root.
// It does not infer closure from absent observation, a disabled setting or a
// metadata count; the existing Authority verifies the complete signed receipt.
func (p Policy) ManagedDNSClosure(s state.State, owner [32]byte, proof services.ReferenceClose, at uint64) (NetworkDNSProgress, error) {
	apps, err := p.Apps(s)
	if err != nil || apps.network == nil {
		return NetworkDNSProgress{}, ErrCatalog
	}
	for _, group := range apps.network.Groups {
		if !group.Managed {
			continue
		}
		for _, row := range group.Owners {
			if row.Managed == nil || row.Reference != proof.Consumer {
				continue
			}
			o := s.Object(row.Source.Key)
			copy := proof
			copy.Signature = slices.Clone(proof.Signature)
			r := NetworkDNSProgress{Schema: 1, Kind: "network-dns", Cluster: p.Cluster, Reporter: owner, Digest: group.Digest, Source: deployment.ObjectRef{Key: row.Source.Key, Generation: o.Generation, Revision: o.Revision}, Expected: apps.network.Revision, Epoch: s.ModuleEpoch(), RootRevision: s.Object(AppsKey).Revision, At: at, Close: &copy}
			if at == 0 || at > math.MaxInt64 || !o.Present || o.Generation != row.Source.Generation {
				return r, ErrCatalog
			}
			if _, err := p.closeManagedDNS(s, apps, r); err != nil {
				return r, err
			}
			return r, nil
		}
	}
	return NetworkDNSProgress{}, ErrCatalog
}
