// SPDX-License-Identifier: Apache-2.0

// Package access is the deterministic user/tenant policy core. Authentication,
// clocks, credential verification and durable publication belong to adapters.
package access

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

var (
	ErrInvalid  = errors.New("invalid account or tenant policy")
	ErrDenied   = errors.New("access denied")
	ErrConflict = errors.New("policy revision conflict")
)

type Method string

const (
	Password   Method = "password"
	PrivateKey Method = "private-key"
	Token      Method = "token"
)

// Credential contains only public metadata and protected-backend references.
// Password/token verification material must never be placed in this record.
type Credential struct {
	ID          string
	Method      Method
	PublicKey   [32]byte
	VerifierRef string
	Enabled     bool
	Label       string            `json:",omitempty"`
	Operations  []string          `json:",omitempty"`
	OneTime     bool              `json:",omitempty"`
	VolumeFiles []VolumeFileGrant `json:",omitempty"`
}

// Nil keeps the original schema1 bytes. An explicit empty ceiling means deny
// all, so only that case must override omitempty through every JSON boundary.
func (c Credential) MarshalJSON() ([]byte, error) {
	type wire Credential
	if c.VolumeFiles == nil || len(c.VolumeFiles) != 0 {
		return json.Marshal(wire(c))
	}
	return json.Marshal(struct {
		wire
		VolumeFiles []VolumeFileGrant
	}{wire: wire(c), VolumeFiles: c.VolumeFiles})
}

type User struct {
	ID, Username         string
	Revision             uint64
	Enabled, SystemAdmin bool
	Credentials          []Credential
	AutomationOnly       bool `json:",omitempty"`
	// Operations: the account's action ceiling (set-account-scope), on top
	// of every credential's own ceiling. Nil = no account ceiling. A system
	// administrator has none, so the installation keeps a usable admin.
	Operations []string `json:",omitempty"`
}
type Role string

const (
	Manager Role = "manager"
	Viewer  Role = "viewer"
)

type Membership struct {
	Tenant, User string
	Role         Role
	Revision     uint64
	Enabled      bool
}
type Tenant struct {
	ID           string
	Revision     uint64
	Enabled      bool
	Phase        TenantPhase
	Retirement   *TenantRetirement
	AllowedNodes []string
	ImageSources []TrustRule
}
type Action string

const (
	Read           Action = "read"
	CallService    Action = "call-service"
	ManageNetwork  Action = "network"
	Deploy         Action = "deploy"
	ManageSecrets  Action = "secrets"
	ManageVolumes  Action = "volumes"
	ManageRoutes   Action = "routes"
	ManageServices Action = "network-services"
	ManageCD       Action = "cd"
	ManageRegistry Action = "registry"
	ManageTrust    Action = "image-trust"
	ManageMembers  Action = "members"
)

const maxRecords = 4096

// Catalog is immutable. Every transition returns an owned candidate which the
// caller must persist atomically with its request result before publication.
type Catalog struct {
	volumeFiles []VolumeFileFolderGrant
	revision    uint64
	anchor      [32]byte
	users       map[string]User
	tenants     map[string]Tenant
	members     map[string]Membership
	revocations map[string]Revocation
	nodeCLI     NodeCLIPolicy
	nodeKeys    map[[32]byte]bool // borrowed membership context, never checkpointed
}

func New(anchor [32]byte) (Catalog, error) {
	if anchor == ([32]byte{}) {
		return Catalog{}, ErrInvalid
	}
	return Catalog{anchor: anchor, users: map[string]User{}, tenants: map[string]Tenant{}, members: map[string]Membership{}, revocations: map[string]Revocation{}}, nil
}
func (c Catalog) Revision() uint64             { return c.revision }
func (c Catalog) AwaitingAdmin() bool          { return c.anchor != ([32]byte{}) }
func (c Catalog) Counts() (users, tenants int) { return len(c.users), len(c.tenants) }
func (c Catalog) User(id string) (User, bool) {
	u, ok := c.users[id]
	u.Credentials = ownCredentials(u.Credentials)
	return u, ok
}

// Username resolves the exact canonical login name to an owned public record.
// It does not authenticate a credential or grant any node/member permission.
func (c Catalog) Username(name string) (User, bool) {
	if !username(name) {
		return User{}, false
	}
	for _, u := range c.users {
		if u.Username == name {
			return c.User(u.ID)
		}
	}
	return User{}, false
}
func (c Catalog) Tenant(id string) (Tenant, bool) { t, ok := c.tenants[id]; return ownTenant(t), ok }

// Tenants is the complete owned FSM view. External callers must apply their
// own current authorization; VisibleTenants remains the user listing boundary.
func (c Catalog) Tenants() []Tenant {
	var out []Tenant
	for _, tenant := range c.tenants {
		out = append(out, ownTenant(tenant))
	}
	slices.SortFunc(out, func(a, b Tenant) int { return strings.Compare(a.ID, b.ID) })
	return out
}
func ownTenant(t Tenant) Tenant {
	t.AllowedNodes = slices.Clone(t.AllowedNodes)
	t.ImageSources = slices.Clone(t.ImageSources)
	if t.Retirement != nil {
		r := ownRetirement(*t.Retirement)
		t.Retirement = &r
	}
	return t
}
func memberKey(tenant, user string) string { return tenant + "/" + user }
func (c Catalog) Membership(tenant, user string) (Membership, bool) {
	m, ok := c.members[memberKey(tenant, user)]
	return m, ok
}
func identifier(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return true
}
func username(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '.' || b == '_') {
			return false
		}
	}
	return true
}
func validUser(u User) bool {
	if !identifier(u.ID) || !username(u.Username) || len(u.Credentials) > 64 || !ValidCredentialOperations(u.Operations) || u.SystemAdmin && u.Operations != nil {
		return false
	}
	// An ordinary account can await its first credential. It cannot log in,
	// and cannot serve as the installation's usable administrator.
	if len(u.Credentials) == 0 {
		return !u.SystemAdmin
	}
	seen, keys, enabled := map[string]bool{}, map[[32]byte]bool{}, 0
	for _, v := range u.Credentials {
		if !identifier(v.ID) || seen[v.ID] || !validCredentialLabel(v.Label) || !ValidCredentialOperations(v.Operations) || !validVolumeFileGrants(v.VolumeFiles) || !validVolumeFileCredential(v) || v.OneTime && v.Method != Token || u.AutomationOnly && v.Enabled && v.Method != PrivateKey {
			return false
		}
		seen[v.ID] = true
		switch v.Method {
		case PrivateKey:
			if v.PublicKey == ([32]byte{}) || keys[v.PublicKey] || v.VerifierRef != "" {
				return false
			}
			keys[v.PublicKey] = true
		case Password, Token:
			if v.PublicKey != ([32]byte{}) || len(v.VerifierRef) < 1 || len(v.VerifierRef) > 256 || strings.ContainsAny(v.VerifierRef, "\x00\r\n") {
				return false
			}
		default:
			return false
		}
		if v.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		return false
	}
	raw, err := json.Marshal(PublicUserOf(u))
	return err == nil && len(raw) <= 96<<10
}
func (c Catalog) clone() (Catalog, error) {
	if c.users == nil || c.tenants == nil || c.members == nil || c.revocations == nil || c.revision == ^uint64(0) {
		return c, ErrInvalid
	}
	n := Catalog{revision: c.revision + 1, anchor: c.anchor, users: map[string]User{}, tenants: map[string]Tenant{}, members: map[string]Membership{}, revocations: map[string]Revocation{}}
	n.volumeFiles = slices.Clone(c.volumeFiles)
	n.nodeCLI = c.nodeCLI
	// WithNodeKeys owns this immutable context; no transition mutates its map.
	n.nodeKeys = c.nodeKeys
	for k, v := range c.users {
		v.Credentials = ownCredentials(v.Credentials)
		v.Operations = slices.Clone(v.Operations)
		n.users[k] = v
	}
	for k, v := range c.tenants {
		n.tenants[k] = ownTenant(v)
	}
	for k, v := range c.members {
		n.members[k] = v
	}
	for k, v := range c.revocations {
		n.revocations[k] = v
	}
	return n, nil
}

// Enroll consumes the installation's administrator-enrollment anchor. It never
// creates a tenant, image policy or operating resource as a side effect.
func (c Catalog) Enroll(provenKey [32]byte, u User) (Catalog, error) {
	if !c.AwaitingAdmin() || provenKey != c.anchor {
		return c, ErrDenied
	}
	if len(c.users) != 0 || !validUser(u) || !u.Enabled || !u.SystemAdmin || u.Revision != 0 {
		return c, ErrInvalid
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	u.Revision = n.revision
	u.Credentials = ownCredentials(u.Credentials)
	u.Operations = slices.Clone(u.Operations)
	slices.Sort(u.Operations)
	n.users[u.ID] = u
	n.anchor = [32]byte{}
	return n, nil
}
func (c Catalog) SystemAllowed(actor string) bool {
	u, ok := c.users[actor]
	return ok && u.Enabled && u.SystemAdmin
}
func (c Catalog) Authorize(actor, tenant string, action Action, node string) error {
	return c.authorize(actor, tenant, action, node, false)
}

// AuthorizeCleanup only authorizes settlement of original resources/operations.
// Consumers must not use it for new creates, dispatches or permission grants.
// An old node grant is unnecessary for removing an already owned resource.
func (c Catalog) AuthorizeCleanup(actor, tenant string, action Action) error {
	return c.authorize(actor, tenant, action, "", true)
}
func (c Catalog) authorize(actor, tenant string, action Action, node string, cleanup bool) error {
	u, ok := c.users[actor]
	if !ok || !u.Enabled {
		return ErrDenied
	}
	t, ok := c.tenants[tenant]
	if !ok || !t.Enabled || t.Phase == TenantDeleted || t.Phase == TenantRetiring && action != Read && !cleanup {
		return ErrDenied
	}
	switch action {
	case Read, CallService, ManageNetwork, Deploy, ManageSecrets, ManageVolumes, ManageRoutes, ManageServices, ManageCD, ManageRegistry, ManageTrust, ManageMembers:
	default:
		return ErrDenied
	}
	if node != "" && !slices.Contains(t.AllowedNodes, node) {
		return ErrDenied
	}
	if u.SystemAdmin {
		return nil
	}
	m, ok := c.members[memberKey(tenant, actor)]
	if !ok || !m.Enabled || m.Role != Manager && !(m.Role == Viewer && action == Read) {
		return ErrDenied
	}
	return nil
}

// PutUser requires a currently authenticated system administrator, not a role
// string supplied by a YAML file or by an unverified client payload.
func (c Catalog) PutUser(actor string, expected uint64, u User) (Catalog, error) {
	if !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	return c.replaceUser(expected, u)
}

// replaceUser retains one validation/publication boundary for administrator
// full-account replacement and strictly scoped self-credential edits.
func (c Catalog) replaceUser(expected uint64, u User) (Catalog, error) {
	old := c.users[u.ID]
	if expected != old.Revision {
		return c, ErrConflict
	}
	if !validUser(u) || u.Revision != 0 || len(c.users) >= maxRecords && old.ID == "" {
		return c, ErrInvalid
	}
	for id, v := range c.users {
		if id != u.ID && v.Username == u.Username {
			return c, ErrConflict
		}
	}
	if old.Enabled && old.SystemAdmin && (!u.Enabled || !u.SystemAdmin) {
		admins := 0
		for _, v := range c.users {
			if v.Enabled && v.SystemAdmin {
				admins++
			}
		}
		if admins < 2 {
			return c, ErrDenied
		}
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	u.Revision = n.revision
	u.Credentials = ownCredentials(u.Credentials)
	u.Operations = slices.Clone(u.Operations)
	slices.Sort(u.Operations)
	n.users[u.ID] = u
	// New account revisions invalidate every prior signed session. Only then is
	// it safe to reclaim that account's individual revocation tombstones.
	for id, r := range n.revocations {
		if r.User == u.ID {
			delete(n.revocations, id)
		}
	}
	if n.ValidateNodeCLI() != nil {
		return c, ErrDenied
	}
	return n, nil
}
func (c Catalog) CreateTenant(actor, id string, expected uint64) (Catalog, error) {
	if !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	if !identifier(id) || expected != 0 || len(c.tenants) >= maxRecords {
		return c, ErrInvalid
	}
	if _, ok := c.tenants[id]; ok {
		return c, ErrConflict
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	n.tenants[id] = Tenant{ID: id, Revision: n.revision, Enabled: true, Phase: TenantActive, ImageSources: []TrustRule{{Registry: "docker.io", Repository: "**"}}}
	return n, nil
}
func (c Catalog) SetNodes(actor, tenant string, expected uint64, nodes []string) (Catalog, error) {
	if !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	t, ok := c.tenants[tenant]
	if !ok || t.Phase != TenantActive {
		return c, ErrDenied
	}
	if t.Revision != expected {
		return c, ErrConflict
	}
	nodes = slices.Clone(nodes)
	slices.Sort(nodes)
	for i, node := range nodes {
		if !identifier(node) || i > 0 && node == nodes[i-1] {
			return c, ErrInvalid
		}
	}
	if len(nodes) > maxRecords {
		return c, ErrInvalid
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	t.AllowedNodes = nodes
	t.Revision = n.revision
	n.tenants[tenant] = ownTenant(t)
	return n, nil
}
func (c Catalog) SetMembership(actor string, expected uint64, m Membership) (Catalog, error) {
	if c.Authorize(actor, m.Tenant, ManageMembers, "") != nil {
		old, exists := c.members[memberKey(m.Tenant, m.User)]
		if m.Enabled || !exists || m.Role != old.Role || c.AuthorizeCleanup(actor, m.Tenant, ManageMembers) != nil {
			return c, ErrDenied
		}
	}
	if _, ok := c.users[m.User]; !ok {
		return c, ErrDenied
	}
	k := memberKey(m.Tenant, m.User)
	old := c.members[k]
	if expected != old.Revision {
		return c, ErrConflict
	}
	if m.Revision != 0 || m.Role != Manager && m.Role != Viewer || len(c.members) >= maxRecords && old.Revision == 0 {
		return c, ErrInvalid
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	m.Revision = n.revision
	n.members[k] = m
	return n, nil
}
func (c Catalog) SetTrust(actor, tenant string, expected uint64, rules []TrustRule) (Catalog, error) {
	if c.Authorize(actor, tenant, ManageTrust, "") != nil {
		return c, ErrDenied
	}
	t := c.tenants[tenant]
	if expected != t.Revision {
		return c, ErrConflict
	}
	rules, err := CanonicalTrust(rules)
	if err != nil {
		return c, err
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	t.ImageSources = rules
	t.Revision = n.revision
	n.tenants[tenant] = ownTenant(t)
	return n, nil
}

// VisibleTenants returns owned, sorted records, including implicit admin scope.
func (c Catalog) VisibleTenants(actor string) []Tenant {
	var result []Tenant
	for id, t := range c.tenants {
		if c.Authorize(actor, id, Read, "") == nil {
			result = append(result, ownTenant(t))
		}
	}
	slices.SortFunc(result, func(a, b Tenant) int { return strings.Compare(a.ID, b.ID) })
	return result
}

type catalogRecord struct {
	VolumeFiles []VolumeFileFolderGrant `json:",omitempty"`
	Schema      uint8
	Revision    uint64
	Anchor      [32]byte
	Users       []User
	Tenants     []Tenant
	Members     []Membership
	Revocations []Revocation
	NodeCLI     *NodeCLIPolicy `json:",omitempty"`
}

func (c Catalog) Encode() ([]byte, error) {
	r := catalogRecord{Schema: 1, Revision: c.revision, Anchor: c.anchor, VolumeFiles: slices.Clone(c.volumeFiles)}
	if c.nodeCLI.Revision != 0 {
		policy := c.nodeCLI
		r.NodeCLI = &policy
	}
	for _, v := range c.users {
		v.Credentials = ownCredentials(v.Credentials)
		slices.SortFunc(v.Credentials, func(a, b Credential) int { return strings.Compare(a.ID, b.ID) })
		r.Users = append(r.Users, v)
	}
	for _, v := range c.tenants {
		r.Tenants = append(r.Tenants, ownTenant(v))
	}
	for _, v := range c.members {
		r.Members = append(r.Members, v)
	}
	slices.SortFunc(r.Users, func(a, b User) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(r.Tenants, func(a, b Tenant) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(r.Members, func(a, b Membership) int {
		return strings.Compare(memberKey(a.Tenant, a.User), memberKey(b.Tenant, b.User))
	})
	for _, v := range c.revocations {
		r.Revocations = append(r.Revocations, v)
	}
	slices.SortFunc(r.Revocations, func(a, b Revocation) int {
		return strings.Compare(memberKey(a.User, a.Session), memberKey(b.User, b.Session))
	})
	return json.Marshal(r)
}

// Decode validates canonical snapshots before making their policy available.
func Decode(b []byte) (Catalog, error) {
	var r catalogRecord
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || r.Schema != 1 || len(r.Users) > maxRecords || len(r.Tenants) > maxRecords || len(r.Members) > maxRecords || len(r.Revocations) > maxRecords || len(r.VolumeFiles) > maxRecords {
		return Catalog{}, ErrInvalid
	}
	c := Catalog{revision: r.Revision, anchor: r.Anchor, users: map[string]User{}, tenants: map[string]Tenant{}, members: map[string]Membership{}, revocations: map[string]Revocation{}}
	if r.NodeCLI != nil {
		if r.NodeCLI.Revision == 0 {
			return Catalog{}, ErrInvalid
		}
		c.nodeCLI = *r.NodeCLI
	}
	names := map[string]bool{}
	admins := 0
	for _, u := range r.Users {
		if !validUser(u) || u.Revision == 0 || u.Revision > c.revision || names[u.Username] {
			return Catalog{}, ErrInvalid
		}
		if _, exists := c.users[u.ID]; exists {
			return Catalog{}, ErrInvalid
		}
		names[u.Username] = true
		c.users[u.ID] = u
		if u.Enabled && u.SystemAdmin {
			admins++
		}
	}
	for _, t := range r.Tenants {
		if !identifier(t.ID) || t.Revision == 0 || t.Revision > c.revision || len(t.AllowedNodes) > maxRecords || !validRetirement(t) {
			return Catalog{}, ErrInvalid
		}
		if _, exists := c.tenants[t.ID]; exists {
			return Catalog{}, ErrInvalid
		}
		for i, node := range t.AllowedNodes {
			if !identifier(node) || i > 0 && node <= t.AllowedNodes[i-1] {
				return Catalog{}, ErrInvalid
			}
		}
		trust, err := CanonicalTrust(t.ImageSources)
		if err != nil || !slices.Equal(trust, t.ImageSources) {
			return Catalog{}, ErrInvalid
		}
		c.tenants[t.ID] = t
	}
	for _, m := range r.Members {
		t, tenant := c.tenants[m.Tenant]
		_, user := c.users[m.User]
		k := memberKey(m.Tenant, m.User)
		if !tenant || t.Phase == TenantDeleted || !user || m.Role != Manager && m.Role != Viewer || m.Revision == 0 || m.Revision > c.revision {
			return Catalog{}, ErrInvalid
		}
		if _, exists := c.members[k]; exists {
			return Catalog{}, ErrInvalid
		}
		c.members[k] = m
	}
	for _, v := range r.Revocations {
		u, exists := c.users[v.User]
		k := memberKey(v.User, v.Session)
		if !exists || !identifier(v.Session) || v.AccountRevision != u.Revision || v.Revision == 0 || v.Revision > c.revision {
			return Catalog{}, ErrInvalid
		}
		if _, exists := c.revocations[k]; exists {
			return Catalog{}, ErrInvalid
		}
		c.revocations[k] = v
	}
	lastFile := ""
	for _, g := range r.VolumeFiles {
		if !g.valid() || g.Revision == 0 || g.Revision > c.revision || g.key() <= lastFile {
			return Catalog{}, ErrInvalid
		}
		if _, ok := c.tenants[g.Tenant]; !ok {
			return Catalog{}, ErrInvalid
		}
		if _, ok := c.users[g.User]; !ok {
			return Catalog{}, ErrInvalid
		}
		c.volumeFiles = append(c.volumeFiles, g)
		lastFile = g.key()
	}

	if c.ValidateNodeCLI() != nil {
		return Catalog{}, ErrInvalid
	}
	if c.AwaitingAdmin() {
		if c.revision != 0 || len(c.users)+len(c.tenants)+len(c.members)+len(c.revocations)+len(c.volumeFiles) != 0 {
			return Catalog{}, ErrInvalid
		}
	} else if admins == 0 {
		return Catalog{}, ErrInvalid
	}
	canonical, err := c.Encode()
	if err != nil || !bytes.Equal(canonical, b) {
		return Catalog{}, ErrInvalid
	}
	return c, nil
}
