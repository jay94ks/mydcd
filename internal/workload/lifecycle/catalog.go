// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/schema"
)

const maxCatalogNames = 1024
const maxCatalogVersions = 4096
const maxCatalogUses = 4096

type ScriptVersion struct {
	Revision        uint64
	Source          SourceFact
	Active, Deleted bool
}

type ScriptRecord struct {
	Tenant, Name string
	Revision     uint64 // mutation CAS/floor, distinct from immutable source revision
	Versions     []ScriptVersion
}

// Use is an app binding or build job pin, never a per-probe Raft mutation.
// Release requires the same accepted reference; adapters prove native closure.
type Use struct {
	Tenant, ID, Kind, Principal, Node string
	Owner, Parent                     [32]byte
	PolicyRevision                    uint64
	Scripts                           []NamedReference
	Sources                           []SourceFact `json:",omitempty"`
}

type catalogRecord struct {
	Publications map[string][32]byte `json:",omitempty"`
	Schema       uint8
	Cluster      [32]byte
	Revision     uint64
	Scripts      map[string]ScriptRecord
	Policies     map[string][]TenantPolicy
	Uses         map[string]Use
	Builds       map[string]BuildJob `json:",omitempty"`
}

type Catalog struct{ d catalogRecord }

func catalogKey(tenant, name string) string { return tenant + "/" + name }

func NewCatalog(cluster [32]byte) (Catalog, error) {
	if cluster == ([32]byte{}) {
		return Catalog{}, ErrContract
	}
	return Catalog{catalogRecord{Schema: 1, Cluster: cluster, Scripts: map[string]ScriptRecord{}, Policies: map[string][]TenantPolicy{}, Uses: map[string]Use{}}}, nil
}

func (c Catalog) Cluster() [32]byte { return c.d.Cluster }
func (c Catalog) Revision() uint64  { return c.d.Revision }
func (c Catalog) Quiescent() bool   { return len(c.d.Uses) == 0 }

func (c Catalog) Tenants() []string {
	ids := make([]string, 0, len(c.d.Policies))
	for tenant := range c.d.Policies {
		ids = append(ids, tenant)
	}
	slices.Sort(ids)
	return ids
}

func ownScript(r ScriptRecord) ScriptRecord {
	r.Versions = slices.Clone(r.Versions)
	for i := range r.Versions {
		r.Versions[i].Source = r.Versions[i].Source.Clone()
	}
	return r
}
func ownUse(u Use) Use {
	u.Scripts = slices.Clone(u.Scripts)
	u.Sources = ownFacts(u.Sources)
	return u
}
func (c Catalog) clone() Catalog {
	d := c.d
	d.Publications = maps.Clone(d.Publications)
	d.Scripts = maps.Clone(d.Scripts)
	for k, r := range d.Scripts {
		d.Scripts[k] = ownScript(r)
	}
	d.Policies = maps.Clone(d.Policies)
	for tenant, versions := range d.Policies {
		d.Policies[tenant] = slices.Clone(versions)
		for i := range d.Policies[tenant] {
			d.Policies[tenant][i] = d.Policies[tenant][i].Clone()
		}
	}
	d.Uses = maps.Clone(d.Uses)
	for k, u := range d.Uses {
		d.Uses[k] = ownUse(u)
	}
	d.Builds = maps.Clone(d.Builds)
	for k, j := range d.Builds {
		d.Builds[k] = j.Clone()
	}
	return Catalog{d}
}

func (c Catalog) Script(tenant, name string) (ScriptRecord, bool) {
	r, ok := c.d.Scripts[catalogKey(tenant, name)]
	return ownScript(r), ok
}

func (c Catalog) Policy(tenant string, revision uint64) (TenantPolicy, bool) {
	versions := c.d.Policies[tenant]
	if revision == 0 && len(versions) > 0 {
		return versions[len(versions)-1].Clone(), true
	}
	for _, p := range versions {
		if p.Revision == revision {
			return p.Clone(), true
		}
	}
	return TenantPolicy{}, false
}

func (c Catalog) Records(tenant string) []ScriptRecord {
	var result []ScriptRecord
	for _, r := range c.d.Scripts {
		if tenant == "" || r.Tenant == tenant {
			result = append(result, ownScript(r))
		}
	}
	slices.SortFunc(result, func(a, b ScriptRecord) int {
		return strings.Compare(catalogKey(a.Tenant, a.Name), catalogKey(b.Tenant, b.Name))
	})
	return result
}

func (c Catalog) Sources(tenant string) []NamedSource {
	var sources []NamedSource
	for _, r := range c.Records(tenant) {
		for _, v := range r.Versions {
			d := v.Source.ContentDigest()
			sources = append(sources, NamedSource{Tenant: r.Tenant, Ref: NamedReference{r.Name, v.Revision}, Digest: hex.EncodeToString(d[:]), SDK: v.Source.SDK, Active: v.Active && !v.Deleted})
		}
	}
	return sources
}

func (c Catalog) version(tenant string, ref NamedReference) (ScriptVersion, bool) {
	r, ok := c.d.Scripts[catalogKey(tenant, ref.Name)]
	if !ok {
		return ScriptVersion{}, false
	}
	for _, v := range r.Versions {
		if v.Revision == ref.Revision {
			v.Source = v.Source.Clone()
			return v, true
		}
	}
	return ScriptVersion{}, false
}

func (c Catalog) used(tenant string, ref NamedReference) bool {
	for _, u := range c.d.Uses {
		if u.Tenant == tenant && slices.Contains(u.Scripts, ref) {
			return true
		}
	}
	return false
}

func (c Catalog) advance() (Catalog, error) {
	if c.d.Schema != 1 || c.d.Cluster == ([32]byte{}) || c.d.Revision == ^uint64(0) {
		return c, ErrContract
	}
	n := c.clone()
	n.d.Revision++
	return n, nil
}

func (c Catalog) PutScript(users access.Catalog, actor string, expected uint64, tenant, id string, source SourceFact) (Catalog, error) {
	if users.Authorize(actor, tenant, access.ManageServices, "") != nil {
		return c, access.ErrDenied
	}
	policy, configured := c.Policy(tenant, 0)
	if !configured || !policy.AllowsSource(source) {
		return c, ErrReference
	}
	r := c.d.Scripts[catalogKey(tenant, id)]
	if !name(id) || source.Verify() != nil || source.Cluster != c.d.Cluster || source.Tenant != tenant || r.Revision != expected || expected == ^uint64(0) || len(r.Versions) >= 128 || r.Revision == 0 && len(c.d.Scripts) >= maxCatalogNames {
		return c, ErrContract
	}
	n, err := c.advance()
	if err != nil {
		return c, err
	}
	r = ownScript(r)
	r.Tenant, r.Name, r.Revision = tenant, id, expected+1
	r.Versions = append(r.Versions, ScriptVersion{Revision: r.Revision, Source: source.Clone(), Active: true})
	n.d.Scripts[catalogKey(tenant, id)] = r
	if err := n.rememberPublication(source); err != nil {
		return c, err
	}
	if n.Validate() != nil {
		return c, ErrContract
	}
	return n, nil
}

func (c Catalog) RetireScript(users access.Catalog, actor string, expected uint64, tenant string, ref NamedReference, remove bool) (Catalog, error) {
	if users.AuthorizeCleanup(actor, tenant, access.ManageServices) != nil {
		return c, access.ErrDenied
	}
	r, ok := c.d.Scripts[catalogKey(tenant, ref.Name)]
	if !ok || r.Revision != expected || expected == ^uint64(0) {
		return c, ErrContract
	}
	i := slices.IndexFunc(r.Versions, func(v ScriptVersion) bool { return v.Revision == ref.Revision })
	if i < 0 || r.Versions[i].Deleted || remove && (r.Versions[i].Active || c.used(tenant, ref)) {
		return c, ErrPending
	}
	n, err := c.advance()
	if err != nil {
		return c, err
	}
	r = ownScript(r)
	r.Revision++
	r.Versions[i].Active = false
	r.Versions[i].Deleted = remove
	n.d.Scripts[catalogKey(tenant, ref.Name)] = r
	return n, nil
}

func (c Catalog) SetPolicy(users access.Catalog, actor string, expected uint64, policy TenantPolicy) (Catalog, error) {
	if users.Authorize(actor, policy.Tenant, access.ManageServices, "") != nil {
		return c, access.ErrDenied
	}
	old, _ := c.Policy(policy.Tenant, 0)
	if policy.Revision != 0 || old.Revision != expected || expected == ^uint64(0) || len(c.d.Policies[policy.Tenant]) >= 128 {
		return c, ErrContract
	}
	policy.Revision = expected + 1
	if policy.Validate() != nil {
		return c, ErrContract
	}
	for _, node := range policy.Build.Nodes {
		if users.Authorize(actor, policy.Tenant, access.ManageServices, node) != nil {
			return c, access.ErrDenied
		}
		if _, err := users.CheckImageRef(actor, policy.Tenant, node, policy.Build.Image); err != nil {
			return c, err
		}
	}
	n, err := c.advance()
	if err != nil {
		return c, err
	}
	n.d.Policies[policy.Tenant] = append(n.d.Policies[policy.Tenant], policy.Clone())
	if n.Validate() != nil {
		return c, ErrContract
	}
	return n, nil
}

func validUse(u Use) bool {
	return name(u.Tenant) && name(u.ID) && name(u.Principal) && name(u.Node) && u.Owner != ([32]byte{}) && u.Parent != ([32]byte{}) && (u.Kind == "app-binding" || u.Kind == "build-job") && u.Selection().Validate() == nil
}

func sameUse(a, b Use) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(aa, bb)
}

// AdmissionPolicy keeps an accepted policy identity only while the current
// enabled policy has exactly the same settings. Sequence restoration alone
// changes neither authority nor an immutable app/build recipe.
func (c Catalog) AdmissionPolicy(tenant string, revision uint64) (TenantPolicy, bool) {
	accepted, aok := c.Policy(tenant, revision)
	current, cok := c.Policy(tenant, 0)
	if revision == 0 || !aok || !cok || !accepted.Enabled || !current.Enabled {
		return TenantPolicy{}, false
	}
	current.Revision = accepted.Revision
	left, err := json.Marshal(accepted)
	right, currentErr := json.Marshal(current)
	if err != nil || currentErr != nil || !bytes.Equal(left, right) {
		return TenantPolicy{}, false
	}
	return accepted, true
}

// Reserve is called only inside the accepted app/build FSM transition after
// authenticating its grant. Caller strings are not permission receipts.
func (c Catalog) Reserve(u Use) (Catalog, error) {
	if u.Kind == "build-job" {
		return c, ErrReference
	}
	return c.reserve(u)
}
func (c Catalog) reserve(u Use) (Catalog, error) {
	if !validUse(u) {
		return c, ErrContract
	}
	key := catalogKey(u.Tenant, u.ID)
	if _, used := c.d.Builds[key]; used {
		return c, ErrPending
	}
	if old, ok := c.d.Uses[key]; ok {
		if sameUse(old, u) {
			return c, nil
		}
		return c, ErrPending
	}
	p, ok := c.AdmissionPolicy(u.Tenant, u.PolicyRevision)
	if !ok || u.Kind == "build-job" && len(p.Build.Nodes) == 0 || len(c.d.Uses) >= maxCatalogUses {
		return c, ErrReference
	}
	for _, f := range u.Sources {
		if f.Cluster != c.d.Cluster || f.Tenant != u.Tenant || !p.AllowsSource(f) {
			return c, ErrReference
		}
	}
	if u.Kind == "build-job" && !slices.Contains(p.Build.Nodes, u.Node) {
		return c, ErrReference
	}
	for _, ref := range u.Scripts {
		v, ok := c.version(u.Tenant, ref)
		if !ok || !v.Active || v.Deleted || !p.AllowsSource(v.Source) {
			return c, ErrReference
		}
	}
	n, err := c.advance()
	if err != nil {
		return c, err
	}
	n.d.Uses[key] = ownUse(u)
	for _, f := range u.Sources {
		if err := n.rememberPublication(f); err != nil {
			return c, err
		}
	}
	for _, ref := range u.Scripts {
		v, _ := n.version(u.Tenant, ref)
		if err := n.rememberPublication(v.Source); err != nil {
			return c, err
		}
	}
	return n, nil
}

// Release is a terminal accepted-use transition, not cancellation inference.
// Current source policy/retirement may forbid new uses without blocking this.
func (c Catalog) Release(u Use) (Catalog, error) {
	if u.Kind == "build-job" {
		return c, ErrPending
	}
	for _, j := range c.d.Builds {
		if j.Phase != "closed" && j.Intent.Tenant == u.Tenant && j.Intent.AppUse == u.Digest() {
			return c, ErrPending
		}
	}
	return c.release(u)
}
func (c Catalog) release(u Use) (Catalog, error) {
	key := catalogKey(u.Tenant, u.ID)
	old, ok := c.d.Uses[key]
	if !ok || !validUse(u) || !sameUse(old, u) {
		return c, ErrReference
	}
	n, err := c.advance()
	if err != nil {
		return c, err
	}
	delete(n.d.Uses, key)
	return n, nil
}

func (c Catalog) Validate() error {
	if c.d.Schema != 1 || c.d.Cluster == ([32]byte{}) || c.d.Scripts == nil || c.d.Policies == nil || c.d.Uses == nil || len(c.d.Scripts) > maxCatalogNames || len(c.d.Policies) > 1024 || len(c.d.Uses) > maxCatalogUses {
		return ErrContract
	}
	count := 0
	for key, r := range c.d.Scripts {
		if !name(r.Tenant) || len(c.d.Policies[r.Tenant]) == 0 || !name(r.Name) || key != catalogKey(r.Tenant, r.Name) || r.Revision == 0 || len(r.Versions) == 0 || len(r.Versions) > 128 {
			return ErrContract
		}
		var last uint64
		for _, v := range r.Versions {
			if v.Revision <= last || v.Revision > r.Revision || v.Source.Verify() != nil || v.Source.Cluster != c.d.Cluster || v.Source.Tenant != r.Tenant || v.Deleted && v.Active {
				return ErrContract
			}
			last = v.Revision
			count++
		}
	}
	for tenant, versions := range c.d.Policies {
		if !name(tenant) || len(versions) == 0 || len(versions) > 128 {
			return ErrContract
		}
		var last uint64
		for _, p := range versions {
			if p.Validate() != nil || p.Tenant != tenant || p.Revision <= last {
				return ErrContract
			}
			last = p.Revision
			count++
		}
	}
	if count > maxCatalogVersions || c.d.Revision == 0 && count != 0 {
		return ErrContract
	}
	for key, u := range c.d.Uses {
		if !validUse(u) || key != catalogKey(u.Tenant, u.ID) {
			return ErrContract
		}
		if _, ok := c.Policy(u.Tenant, u.PolicyRevision); !ok {
			return ErrContract
		}
		for _, f := range u.Sources {
			if f.Cluster != c.d.Cluster || f.Tenant != u.Tenant {
				return ErrContract
			}
		}
		for _, ref := range u.Scripts {
			if v, ok := c.version(u.Tenant, ref); !ok || v.Deleted {
				return ErrContract
			}
		}
	}
	if err := c.validatePublications(); err != nil {
		return err
	}
	return c.validateBuildJobs()
}

func (c Catalog) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(c.d)
}

func DecodeCatalog(raw []byte) (Catalog, error) {
	d, err := schema.Decode[catalogRecord](raw)
	if err != nil {
		return Catalog{}, ErrContract
	}
	c := Catalog{d}
	if c.Validate() != nil {
		return Catalog{}, ErrContract
	}
	return c, nil
}
