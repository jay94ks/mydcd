// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
)

type Use struct {
	Purpose                                      string `json:",omitempty"`
	Tenant, User, App, Deployment, Service, Node string
	RequesterKey, NodeKey                        [32]byte
	Sources                                      []string
	// RegistrySources names the Sources read only to pull images. Only they
	// may select a RegistryShared object; an app input selecting one fails.
	RegistrySources []string `json:",omitempty"`
}
type PolicyRef struct {
	ID                                     string
	Generation, PolicyRevision, AuthPolicy uint64
}
type NodeScope struct {
	ID  string
	Key [32]byte
}
type Target struct {
	Purpose          string      `json:"purpose,omitempty"`
	Cluster          [32]byte    `json:"cluster_id"`
	Realm            string      `json:"vault_tenant_id"`
	Tenant           string      `json:"tenant_id"`
	User             string      `json:"user_id"`
	UserPolicy       uint64      `json:"user_policy_ref"`
	MembershipPolicy uint64      `json:"membership_policy_ref"`
	RequesterKey     [32]byte    `json:"requester_public_key"`
	App              string      `json:"app_id"`
	Deployment       string      `json:"deployment_id"`
	Group            string      `json:"group_id"`
	Path             []PolicyRef `json:"ancestor_policy_refs"`
	Services         []string    `json:"consumer_service_ids"`
	Nodes            []NodeScope `json:"permitted_nodes"`
	Actions          [2]string   `json:"actions"`
	Scope            string      `json:"scope"`
	ApprovalID       string      `json:"approval_id"`
	IssuerPolicy     uint64      `json:"issuer_policy_ref"`
}

const namespaceScope = "selected-secrets-in-group-namespace"

const PurposeRegistrySource = "registry-source"
const PurposeImageBuild = "image-build"

func validPurpose(p string) bool {
	return p == "" || p == PurposeRegistrySource || p == PurposeImageBuild
}
func targetActions(p string) [2]string {
	if p == PurposeImageBuild {
		return [2]string{"resolve", "build"}
	}
	if p == PurposeRegistrySource {
		return [2]string{"resolve", "registry"}
	}
	return [2]string{"resolve", "mount"}
}

type Leaf struct {
	Secret                            string
	Generation, MetadataRevision      uint64
	Reference                         Reference
	SourcePosition, ExpansionPosition int
}
type UsePlan struct {
	Use          Use
	Leaves       []Leaf
	Gates        []string
	Dependencies []Dependency
}
type Dependency struct {
	ID                         string
	Generation, PolicyRevision uint64
}

// BatchPlan is public metadata, not permission to fetch values. The current
// approval registry and policy must be checked before provider reads/consumption.
type BatchPlan struct {
	Uses     []UsePlan
	Required []Target
}

func ownUse(u Use) Use {
	u.Sources = slices.Clone(u.Sources)
	u.RegistrySources = slices.Clone(u.RegistrySources)
	return u
}

// ClusterConsumer reports a cluster-owned registry source reader's use: no
// workspace, registry-source purpose, authorized by system administration.
func (u Use) ClusterConsumer() bool { return u.Tenant == "" && u.Purpose == PurposeRegistrySource }

// registryShared reports whether a path crosses a RegistryShared Group.
func (t Tree) registryShared(path []Object) bool {
	if t.tenant != "" {
		return false
	}
	for _, o := range path {
		if o.ACL.RegistryShared {
			return true
		}
	}
	return false
}
func ownTarget(t Target) Target {
	t.Path = slices.Clone(t.Path)
	t.Services = slices.Clone(t.Services)
	t.Nodes = slices.Clone(t.Nodes)
	return t
}
func ownLeaf(l Leaf) Leaf             { l.Reference.Keys = slices.Clone(l.Reference.Keys); return l }
func nodeScopeKey(n NodeScope) string { return n.ID + "/" + hex.EncodeToString(n.Key[:]) }
func (t Tree) allowed(c access.Catalog, u Use, path []Object) bool {
	if !validPurpose(u.Purpose) {
		return false
	}
	if !identifier(u.User) || !identifier(u.App) || !identifier(u.Deployment) || !identifier(u.Service) || !identifier(u.Node) || u.RequesterKey == ([32]byte{}) || u.NodeKey == ([32]byte{}) {
		return false
	}
	shared := t.registryShared(path)
	if u.ClusterConsumer() {
		// A cluster source reader belongs to no workspace: only a system
		// administrator binds it, and only RegistryShared secrets serve it.
		if t.tenant != "" || !shared || !c.SystemAllowed(u.User) {
			return false
		}
	} else if !identifier(u.Tenant) || c.Authorize(u.User, u.Tenant, access.Deploy, u.Node) != nil {
		return false
	} else if t.tenant != "" && t.tenant != u.Tenant || t.tenant == "" && !shared && !slices.Contains(t.objects[t.root].ACL.TenantGrants, u.Tenant) {
		return false
	}
	for _, o := range path {
		a := o.ACL
		if o.Status != Active || slices.Contains(a.DenyUsers, u.User) || slices.Contains(a.DenyServices, u.Service) || len(a.Users) > 0 && !slices.Contains(a.Users, u.User) || len(a.Services) > 0 && !slices.Contains(a.Services, u.Service) {
			return false
		}
	}
	return true
}
func (t Tree) policies(group string) ([]PolicyRef, error) {
	path, err := t.path(group)
	if err != nil {
		return nil, err
	}
	var refs []PolicyRef
	for _, o := range path {
		if o.Kind != Group || o.Status != Active {
			return nil, ErrPolicy
		}
		refs = append(refs, PolicyRef{o.ID, o.Generation, o.PolicyRevision, o.AuthPolicy})
	}
	return refs, nil
}
func (t Tree) target(c access.Catalog, u Use, group string) (Target, error) {
	o, ok := t.objects[group]
	if !ok || o.Kind != Group || !o.Protected || o.Status != Active {
		return Target{}, ErrPolicy
	}
	refs, err := t.policies(group)
	if err != nil {
		return Target{}, err
	}
	user, _ := c.User(u.User)
	m, _ := c.Membership(u.Tenant, u.User)
	return Target{Purpose: u.Purpose, Cluster: t.cluster, Realm: t.tenant, Tenant: u.Tenant, User: u.User, UserPolicy: user.Revision, MembershipPolicy: m.Revision, RequesterKey: u.RequesterKey, App: u.App, Deployment: u.Deployment, Group: group, Path: refs, Services: []string{u.Service}, Nodes: []NodeScope{{ID: u.Node, Key: u.NodeKey}}, Actions: targetActions(u.Purpose), Scope: namespaceScope}, nil
}
func sameBase(a, b Use) bool {
	return a.Purpose == b.Purpose && a.Tenant == b.Tenant && a.User == b.User && a.App == b.App && a.Deployment == b.Deployment && a.RequesterKey == b.RequesterKey
}

// Plan expands metadata only. It validates every selected object/ancestor,
// including overwritten sources, before returning any usable plan. Sources and
// group Entries retain order; only the required password-group set is deduped.
func (t Tree) Plan(c access.Catalog, uses []Use) (BatchPlan, error) {
	if len(uses) < 1 || len(uses) > 256 {
		return BatchPlan{}, ErrPolicy
	}
	var result BatchPlan
	required := map[string]Target{}
	for _, input := range uses {
		u := ownUse(input)
		if !sameBase(uses[0], u) || len(u.Sources) < 1 || len(u.Sources) > 256 {
			return BatchPlan{}, ErrPolicy
		}
		p := UsePlan{Use: u}
		gates := map[string]bool{}
		dependencies := map[string]Dependency{}
		visits := 0
		var visit func(string, int, bool) error
		visit = func(id string, position int, registry bool) error {
			visits++
			if visits > 16384 {
				return ErrPolicy
			}
			path, err := t.path(id)
			if err != nil {
				return err
			}
			if !t.allowed(c, u, path) || t.registryShared(path) && !registry {
				return access.ErrDenied
			}
			for _, o := range path {
				dependencies[o.ID] = Dependency{o.ID, o.Generation, o.PolicyRevision}
				if o.Kind == Group && o.Protected {
					gates[o.ID] = true
				}
			}
			o := path[len(path)-1]
			if o.Kind == Group {
				for _, child := range o.Entries {
					if err = visit(child, position, registry); err != nil {
						return err
					}
				}
			} else {
				p.Leaves = append(p.Leaves, Leaf{Secret: o.ID, Generation: o.Generation, MetadataRevision: o.Revision, Reference: o.Reference, SourcePosition: position, ExpansionPosition: len(p.Leaves)})
			}
			return nil
		}
		for _, id := range u.RegistrySources {
			if !slices.Contains(u.Sources, id) {
				return BatchPlan{}, ErrPolicy
			}
		}
		for i, id := range u.Sources {
			if err := visit(id, i, slices.Contains(u.RegistrySources, id)); err != nil {
				return BatchPlan{}, err
			}
		}
		for id := range gates {
			p.Gates = append(p.Gates, id)
		}
		slices.Sort(p.Gates)
		for _, d := range dependencies {
			p.Dependencies = append(p.Dependencies, d)
		}
		slices.SortFunc(p.Dependencies, func(a, b Dependency) int { return strings.Compare(a.ID, b.ID) })
		for _, id := range p.Gates {
			g, err := t.target(c, u, id)
			if err != nil {
				return BatchPlan{}, err
			}
			old, exists := required[id]
			if !exists {
				required[id] = g
			} else {
				if !slices.Contains(old.Services, u.Service) {
					old.Services = append(old.Services, u.Service)
				}
				node := NodeScope{u.Node, u.NodeKey}
				if !slices.Contains(old.Nodes, node) {
					old.Nodes = append(old.Nodes, node)
				}
				required[id] = old
			}
		}
		result.Uses = append(result.Uses, p)
	}
	for _, v := range required {
		slices.Sort(v.Services)
		slices.SortFunc(v.Nodes, func(a, b NodeScope) int { return strings.Compare(nodeScopeKey(a), nodeScopeKey(b)) })
		result.Required = append(result.Required, ownTarget(v))
	}
	slices.SortFunc(result.Required, func(a, b Target) int { return strings.Compare(a.Group, b.Group) })
	return result, nil
}

// Fetched contains transient private provider values. It must never be encoded
// into Tree, an approval, command/result, public plan, log or Snapshot.
type Fetched struct {
	Secret    string
	Reference Reference
	Values    map[string][]byte
}
type Provenance struct {
	Secret                            string
	ProviderRevision                  uint64
	SourcePosition, ExpansionPosition int
}
type Keyset struct {
	Values     map[string][]byte
	Provenance map[string]Provenance
}

// Merge is a private-staging operation after current authorization of ALL
// leaves/gates. It validates all exact revisions/keys before producing output.
// The caller publishes one consumer generation only after complete staging.
func validateFetched(plan UsePlan, values []Fetched, maxBytes int) (map[string]Fetched, error) {
	if maxBytes <= 0 || len(values) > maxObjects {
		return nil, ErrPolicy
	}
	byID := map[string]Fetched{}
	total := 0
	for _, v := range values {
		if _, dup := byID[v.Secret]; dup {
			return nil, ErrPolicy
		}
		byID[v.Secret] = v
		for _, data := range v.Values {
			if len(data) > maxBytes-total {
				return nil, ErrPolicy
			}
			total += len(data)
		}
	}
	needed := map[string]bool{}
	for _, leaf := range plan.Leaves {
		v, ok := byID[leaf.Secret]
		if !ok || !sameReference(v.Reference, leaf.Reference) || len(v.Values) != len(leaf.Reference.Keys) {
			return nil, ErrPolicy
		}
		for _, k := range leaf.Reference.Keys {
			if _, ok = v.Values[k]; !ok {
				return nil, ErrPolicy
			}
		}
		needed[leaf.Secret] = true
	}
	if len(needed) != len(byID) {
		return nil, ErrPolicy
	}
	return byID, nil
}

// ValidateFetched checks exact leaves/references/keys and the total private
// byte budget without constructing a merged keyset or exposing values.
func ValidateFetched(plan UsePlan, values []Fetched, maxBytes int) error {
	_, err := validateFetched(plan, values, maxBytes)
	return err
}

func Merge(plan UsePlan, values []Fetched, maxBytes int) (Keyset, error) {
	byID, err := validateFetched(plan, values, maxBytes)
	if err != nil {
		return Keyset{}, err
	}
	result := Keyset{Values: map[string][]byte{}, Provenance: map[string]Provenance{}}
	for _, leaf := range plan.Leaves {
		v := byID[leaf.Secret]
		for _, k := range leaf.Reference.Keys {
			result.Values[k] = bytes.Clone(v.Values[k])
			result.Provenance[k] = Provenance{leaf.Secret, leaf.Reference.Revision, leaf.SourcePosition, leaf.ExpansionPosition}
		}
	}
	return result, nil
}
func sameReference(a, b Reference) bool {
	return a.Profile == b.Profile && a.Object == b.Object && a.Revision == b.Revision && slices.Equal(a.Keys, b.Keys)
}
func sameTarget(a, b Target) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}
