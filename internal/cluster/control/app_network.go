// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// One embedded checkpoint shares Apps' existing FSM/DB transaction. It is not
// a second allocator, log or independent DNS source of truth.
type appNetworkState struct {
	Revision  uint64
	Authority services.Authority
	Groups    []appDNSGroup
}
type appNetworkDisk struct {
	Schema    uint8
	Cluster   [32]byte
	Revision  uint64
	Authority json.RawMessage
	Groups    []appDNSGroup
}
type appDNSGroup struct {
	Managed              bool `json:",omitempty"`
	Tenant, App, Network string
	// Source/Serial survive positive owner archival. An empty Owners slice
	// is only the stable scope's public version floor, never native authority.
	Source uint64
	Serial uint32
	Digest [32]byte
	Owners []AppDNSOwner
}

// AppDNSOwner is committed public input for exactly one native owner. Source
// is the original DNS Goal; Config's source/serial is a shared projection, not
// a local publication counter or native-ready report.
type AppDNSOwner struct {
	Managed   *ManagedDNSOwnerSource `json:",omitempty"`
	Source    deployment.ObjectRef
	Config    services.DNSConfig
	Reference [32]byte
}

func dnsGroupKey(g appDNSGroup) string {
	if g.Managed {
		return g.Tenant + "/@managed/" + g.Network
	}
	return g.Tenant + "/" + g.App + "/" + g.Network
}
func appDNSDigest(owners []AppDNSOwner) [32]byte {
	owners = slices.Clone(owners)
	for i := range owners {
		owners[i].Config.Source, owners[i].Config.Serial = 0, 0
		owners[i].Reference = [32]byte{}
	}
	raw, _ := json.Marshal(owners)
	return sha256.Sum256(raw)
}
func dnsServiceID(tenant, app, alias string) string {
	h := sha256.Sum256([]byte(tenant + "/" + app + "/" + alias))
	return "d" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:]))
}

func (n appNetworkState) encode() ([]byte, error) {
	if n.Revision == 0 || len(n.Groups) > 1024 {
		return nil, ErrCatalog
	}
	raw, err := n.Authority.Encode()
	if err != nil {
		return nil, err
	}
	if err := n.validateGroups(); err != nil {
		return nil, err
	}
	return json.Marshal(appNetworkDisk{1, n.Authority.Cluster(), n.Revision, raw, n.Groups})
}

// Authority decoding validates its own canonical bytes and signatures. Keep
// the outer cross-references shared with Encode without encoding that same
// already-validated Authority a second time on every committed-state read.
func (n appNetworkState) validateGroups() error {
	if n.Revision == 0 || len(n.Groups) > 1024 {
		return ErrCatalog
	}
	for i, g := range n.Groups {
		if g.Source == 0 || g.Source > n.Revision || g.Digest != appDNSDigest(g.Owners) || len(g.Owners) > 64 || !g.Managed && len(g.Owners) > 16 || g.Managed && g.App != "" || i > 0 && dnsGroupKey(n.Groups[i-1]) >= dnsGroupKey(g) {
			return ErrCatalog
		}
		for j, owner := range g.Owners {
			c, ok := n.Authority.ReferenceConsumer(owner.Reference)
			cfg := owner.Config
			sourceKey := deployment.ResourceKey("dns", g.Tenant, g.App, g.Network+"/"+c.Local.Node)
			serviceID := dnsServiceID(g.Tenant, g.App, g.Network)
			if g.Managed {
				sourceKey = services.ManagedDNSKey(g.Tenant, g.Network)
				serviceID = services.ManagedDNSServiceID(g.Tenant, g.Network, cfg.Pool)
				if owner.Managed == nil || owner.Managed.Node != c.Local.Node || owner.Managed.Bridge.Generation == 0 || owner.Managed.Bridge.Revision < owner.Managed.Bridge.Generation || owner.Managed.Bridge.Key != (tenancy.SourceIdentity{Kind: "bridge", Tenant: g.Tenant, Network: g.Network, Node: c.Local.Node}).Key() || owner.Managed.MaxConnections < 1 || owner.Managed.MaxConnections > 4096 || owner.Managed.RequestTimeoutMS < 1 || owner.Managed.RequestTimeoutMS > 60000 {
					return ErrCatalog
				}
			} else if owner.Managed != nil {
				return ErrCatalog
			}
			if !ok || owner.Source.Generation == 0 || owner.Source.Revision < owner.Source.Generation || sourceKey == "" || owner.Source.Key != sourceKey || cfg.Tenant != g.Tenant || cfg.ID != serviceID || cfg.Network != c.Local.Network || cfg.Pool != c.Local.Pool || cfg.Source != g.Source || cfg.Serial != g.Serial || c.DesiredSource != g.Source || c.Serial != g.Serial || j > 0 && dnsOwnerOrder(g.Owners[j-1]) >= dnsOwnerOrder(owner) {
				return ErrCatalog
			}
		}
	}
	return nil
}

func decodeAppNetwork(raw []byte, cluster [32]byte) (*appNetworkState, error) {
	var disk appNetworkDisk
	if len(raw) > maxAppCheckpoint || canonical(raw, &disk) != nil || disk.Schema != 1 || disk.Cluster != cluster {
		return nil, ErrCatalog
	}
	authority, err := services.DecodeAuthority(disk.Authority)
	if err != nil || authority.Cluster() != cluster {
		return nil, ErrCatalog
	}
	n := &appNetworkState{Revision: disk.Revision, Authority: authority, Groups: disk.Groups}
	// canonical(raw, &disk) proved the outer representation; DecodeAuthority
	// proved Authority == its canonical encoding. Only group invariants remain.
	if err := n.validateGroups(); err != nil {
		return nil, err
	}
	return n, nil
}

// The typed Authority is immutable: transitions clone before writes and its
// accessors own mutable output. Only Groups contains mutable control metadata.
// The caller already decoded/validated this Apps value; copying is not another
// checkpoint decode, authority grant, or signature-validation boundary.
func (n appNetworkState) owned() (*appNetworkState, error) {
	if n.Authority.Cluster() == ([32]byte{}) || n.validateGroups() != nil {
		return nil, ErrCatalog
	}
	raw, err := json.Marshal(n.Groups)
	var groups []appDNSGroup
	if err != nil || json.Unmarshal(raw, &groups) != nil {
		return nil, ErrCatalog
	}
	return &appNetworkState{Revision: n.Revision, Authority: n.Authority, Groups: groups}, nil
}

// NetworkDNS returns owned committed configuration and the SAME Authority.
// Reads grant no socket/native permission; owners still need current quorum,
// typed original Bridge provenance and the local Settings/query journals.
func (a Apps) NetworkDNS(owner [32]byte) (services.Authority, []AppDNSOwner, bool) {
	if a.network == nil {
		return services.Authority{}, nil, false
	}
	n, err := a.network.owned()
	if err != nil {
		return services.Authority{}, nil, false
	}
	var out []AppDNSOwner
	for _, g := range n.Groups {
		for _, row := range g.Owners {
			ref, _ := n.Authority.ReferenceConsumer(row.Reference)
			if ref.Local.Owner == owner {
				out = append(out, row)
			}
		}
	}
	return n.Authority, out, true
}

// DNSProjectionNeeded is a controller hint over the same immutable input. The
// signed reducer independently derives/rechecks everything at commit; this
// read never grants authority or emits denied reports just to poll readiness.
func (a Apps) DNSProjectionNeeded(s state.State, projection ResourceProjection, tenant, app, key string) (bool, error) {
	entry, found := a.entries[appKey(tenant, app)]
	e, active := entry.Inventory.Execution()
	if !found || !active {
		return false, ErrCatalog
	}
	group, err := appDNSProjection(s, e, projection, key)
	if err != nil {
		return false, err
	}
	if a.network != nil {
		for _, old := range a.network.Groups {
			if dnsGroupKey(old) == dnsGroupKey(group) {
				return old.Digest != group.Digest, nil
			}
		}
	}
	return true, nil
}

func (p Policy) reduceAppDNS(s state.State, r AppProgress, apps Apps, entry appEntry, e deployment.Execution) (map[string][]byte, state.Code) {
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	if _, retiring := entry.Inventory.Retirement(); retiring || e.Status() == "Paused" || e.Status() == "Stopping" || e.Status() == "Closed" || e.Status() == "Failed" || p.authorizeAppStep(s, c, entry, e, r.Key) != nil {
		return nil, state.Forbidden
	}
	stage, ok := e.Stage(r.Key)
	o := s.Object(r.Key)
	if !ok || stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied || !o.Present || o.Value != stage.Command.Value || o.Generation != stage.Result.Generation || o.Revision != stage.Result.Revision {
		return nil, state.ConditionFailed
	}
	projection, err := p.ProjectResources(s)
	if err != nil || !projection.Compatible {
		return nil, state.Invalid
	}
	g, ok := projection.Goals[r.Key]
	if !ok || g.Goal.Kind != "dns" || !p.ownsResource(s, r.Reporter, g.Goal.Owner) || g.Goal.Lifecycle != nil {
		return nil, state.Forbidden
	}
	group, err := appDNSProjection(s, e, projection, r.Key)
	if err != nil {
		return nil, state.ConditionFailed
	}
	return p.publishDNSGroup(s, c, projection, entry.Origin.Session.User, apps, group)
}

func (p Policy) publishDNSGroup(s state.State, c access.Catalog, projection ResourceProjection, actor string, apps Apps, group appDNSGroup) (map[string][]byte, state.Code) {
	var err error
	var n appNetworkState
	if apps.network != nil {
		n = *apps.network
		n.Groups = slices.Clone(n.Groups)
	} else {
		n.Authority, err = services.NewAuthority(p.Cluster, projection.Addresses)
		if err != nil {
			return nil, state.Invalid
		}
	}
	index := slices.IndexFunc(n.Groups, func(old appDNSGroup) bool { return dnsGroupKey(old) == dnsGroupKey(group) })
	if index >= 0 && n.Groups[index].Digest == group.Digest {
		return nil, state.ConditionFailed
	}
	if n.Revision == ^uint64(0) || index < 0 && len(n.Groups) >= 1024 || index >= 0 && n.Groups[index].Serial == ^uint32(0) {
		return nil, state.ConditionFailed
	}
	n.Revision++
	group.Source, group.Serial = n.Revision, 1
	if index >= 0 {
		group.Serial = n.Groups[index].Serial + 1
	}
	n.Authority, err = n.Authority.SyncPools(projection.Resources.Networks)
	if err != nil {
		return nil, state.ConditionFailed
	}
	book := projection.Addresses.Checkpoint()
	n.Authority, err = n.Authority.ResizeAddresses(book.Capacity)
	if err != nil {
		return nil, state.ConditionFailed
	}
	pools := map[string]network.Pool{}
	for _, pool := range book.Pools {
		pools[pool.ID] = pool
	}
	for _, allocation := range book.Allocations {
		n.Authority, err = n.Authority.WithCommittedStaticAllocation(allocation, pools[allocation.Pool].Network)
		if err != nil {
			return nil, state.ConditionFailed
		}
	}
	for i := range group.Owners {
		row := &group.Owners[i]
		row.Config.Source, row.Config.Serial = group.Source, group.Serial
		local, found := projection.Resources.Networks.Network(group.Tenant, row.Config.Network)
		if !found || !group.Managed && len(local.Pools) != 1 {
			return nil, state.Invalid
		}
		subnetIndex := slices.IndexFunc(local.Pools, func(pool tenancy.Subnet) bool { return pool.ID == row.Config.Pool })
		if subnetIndex < 0 {
			return nil, state.Invalid
		}
		subnet := local.Pools[subnetIndex]
		source := services.Source{Cluster: p.Cluster, Tenant: group.Tenant, Network: local.ID, Pool: subnet.ID, Node: local.Node, Owner: local.Owner, NetworkGeneration: local.Generation, Prefix: subnet.Prefix, Gateway: subnet.Gateway, MTU: subnet.MTU}
		var ref services.ReferenceConsumer
		n.Authority, ref, err = n.Authority.GrantDNSInstance(c, projection.Resources.Networks, actor, n.Authority.DNSReferenceGeneration(group.Tenant, row.Config.ID, source), row.Config)
		if err != nil {
			return nil, state.ConditionFailed
		}
		row.Reference = ref.ID
	}
	if index < 0 {
		n.Groups = append(n.Groups, group)
	} else {
		n.Groups[index] = group
	}
	slices.SortFunc(n.Groups, func(a, b appDNSGroup) int { return strings.Compare(dnsGroupKey(a), dnsGroupKey(b)) })
	apps.network = &n
	return p.appsCheckpoint(s, apps)
}

// appDNSProjection derives names only from exact committed Task Goals of the
// accepted execution. Future tasks may be absent; no generation/address is
// predicted. A later committed Task produces a new shared serial/hot view.
func appDNSProjection(s state.State, e deployment.Execution, projection ResourceProjection, key string) (appDNSGroup, error) {
	scope := e.Scope()
	prefix := strings.TrimSuffix(deployment.ResourceKey("dns", scope.Tenant, scope.App, "root"), "root")
	parts := strings.Split(strings.TrimPrefix(key, prefix), "/")
	if !strings.HasPrefix(key, prefix) || len(parts) != 2 {
		return appDNSGroup{}, ErrCatalog
	}
	alias := parts[0]
	group := appDNSGroup{Tenant: scope.Tenant, App: scope.App, Network: alias}
	var declaration deployment.DNSDeclaration
	for _, step := range e.Steps() {
		if step.Kind != "dns" || step.Key != deployment.ResourceKey("dns", scope.Tenant, scope.App, alias+"/"+step.Node) {
			continue
		}
		stage, found := e.Stage(step.Key)
		obj := s.Object(step.Key)
		goal, known := projection.Goals[step.Key]
		if !found || stage.Result == nil || stage.Command == nil || stage.Result.Code != state.Applied || !known || !obj.Present || obj.Value != stage.Command.Value || obj.Revision != stage.Result.Revision || obj.Generation != stage.Result.Generation || goal.Goal.Lifecycle != nil {
			continue
		}
		var cfg deployment.DNSDeclaration
		if canonical(goal.Goal.Config, &cfg) != nil || !cfg.Enabled {
			return group, ErrCatalog
		}
		if len(group.Owners) != 0 && !bytes.Equal(marshalDNSDeclaration(declaration), marshalDNSDeclaration(cfg)) {
			return group, ErrCatalog
		}
		declaration = cfg
		localID := deployment.PoolID(scope.Tenant, scope.App, alias, step.Node)
		local, found := projection.Resources.Networks.Network(scope.Tenant, localID)
		if !found || local.Owner != step.Owner || local.Node != step.Node || local.Draining {
			return group, ErrCatalog
		}
		config := services.DNSConfig{Tenant: scope.Tenant, ID: dnsServiceID(scope.Tenant, scope.App, alias), Network: localID, Pool: "pool", Enabled: true, Reverse: cfg.Reverse, Zone: cfg.Zone, TTL: cfg.TTL, NegativeTTL: cfg.NegativeTTL, QuerySeconds: uint32((cfg.Limits.Timeout+999)/1000) + 1, MaxQueries: cfg.Limits.Inflight, MaxCacheEntries: cfg.Limits.Cache, MaxResponseBytes: 4096}
		if cfg.Forward.Enabled {
			for _, upstream := range cfg.Forward.Upstreams {
				addr, err := netip.ParseAddrPort(upstream)
				if err != nil {
					ip, parseErr := netip.ParseAddr(upstream)
					if parseErr != nil {
						return group, err
					}
					addr = netip.AddrPortFrom(ip, 53)
				}
				config.Upstreams = append(config.Upstreams, addr)
			}
		}
		group.Owners = append(group.Owners, AppDNSOwner{Source: deployment.ObjectRef{Key: step.Key, Generation: obj.Generation, Revision: obj.Revision}, Config: config})
	}
	if len(group.Owners) == 0 {
		return group, ErrCatalog
	}
	for _, record := range declaration.Records {
		found := false
		for _, step := range e.Steps() {
			if step.Kind == "task" && dnsTaskMatches(record.Task, step.Key, scope) {
				found = true
			}
		}
		if !found {
			return group, ErrCatalog
		}
	}
	var members []string
	for _, row := range group.Owners {
		members = append(members, row.Config.Network)
	}
	slices.Sort(members)
	var names []services.DNSName
	for _, step := range e.Steps() {
		if step.Kind != "task" {
			continue
		}
		stage, _ := e.Stage(step.Key)
		obj := s.Object(step.Key)
		goal, found := projection.Goals[step.Key]
		if !found || stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied || !obj.Present || obj.Value != stage.Command.Value || obj.Generation != stage.Result.Generation || obj.Revision != stage.Result.Revision || goal.Goal.Lifecycle != nil {
			continue
		}
		var task deployment.ComposeService
		if canonical(goal.Goal.Config, &task) != nil {
			return group, ErrCatalog
		}
		if _, attached := task.Networks[alias]; !attached {
			continue
		}
		instance, identityErr := deployment.TaskInstanceForKey(scope.Tenant, scope.App, step.Key, task)
		if identityErr != nil {
			return group, identityErr
		}
		service := instance.Service
		var labels []string
		if len(declaration.Records) == 0 {
			labels = []string{service}
		}
		for _, record := range declaration.Records {
			if dnsTaskMatches(record.Task, step.Key, scope) {
				labels = append(labels, record.Name)
			}
		}
		for family := 0; family < 2; family++ {
			endpoint := step.Key + "/" + alias + "/" + strconv.Itoa(family)
			alloc, held := projection.Addresses.Allocation(endpoint)
			if !held || alloc.Generation != obj.Generation {
				continue
			}
			for _, label := range labels {
				names = append(names, services.DNSName{Name: label, Endpoint: endpoint, Generation: alloc.Generation})
			}
		}
	}
	for i := range group.Owners {
		group.Owners[i].Config.Members = slices.Clone(members)
		group.Owners[i].Config.Names = slices.Clone(names)
	}
	slices.SortFunc(group.Owners, func(a, b AppDNSOwner) int { return strings.Compare(a.Source.Key, b.Source.Key) })
	group.Digest = appDNSDigest(group.Owners)
	return group, nil
}

func marshalDNSDeclaration(v deployment.DNSDeclaration) []byte { raw, _ := json.Marshal(v); return raw }

func dnsTaskMatches(target, key string, scope deployment.AppScope) bool {
	id, err := deployment.ResourceIDFromKey("task", scope.Tenant, scope.App, key)
	if err != nil {
		return false
	}
	service, _, _ := strings.Cut(id, "/")
	return target == service || target == key || target == "workload/task/"+scope.App+"/"+service
}
