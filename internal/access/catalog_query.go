// SPDX-License-Identifier: Apache-2.0

package access

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"sort"
	"strings"
)

// PublicCredential deliberately has no protected verifier reference. Field
// names and public-key encoding match the existing credential detail API.
type PublicCredential struct {
	VolumeFiles []VolumeFileGrant `json:",omitempty"`
	ID          string
	Method      Method
	PublicKey   [32]byte
	Enabled     bool
	Label       string   `json:",omitempty"`
	Operations  []string `json:",omitempty"`
	OneTime     bool     `json:",omitempty"`
}

// Preserve the same nil/empty distinction as the stored credential without
// adding a field to historical nil or changing nonempty schema1 encoding.
func (c PublicCredential) MarshalJSON() ([]byte, error) {
	type wire PublicCredential
	if c.VolumeFiles == nil || len(c.VolumeFiles) != 0 {
		return json.Marshal(wire(c))
	}
	return json.Marshal(struct {
		wire
		VolumeFiles []VolumeFileGrant
	}{wire: wire(c), VolumeFiles: c.VolumeFiles})
}

type PublicUser struct {
	ID, Username         string
	Revision             uint64
	Enabled, SystemAdmin bool
	Credentials          []PublicCredential
	AutomationOnly       bool     `json:",omitempty"`
	Operations           []string `json:",omitempty"`
}

type TenantMember struct {
	User, Username string
	Revision       uint64
	Role           Role
	Enabled        bool
	AccountEnabled bool
	Implicit       bool
	Actions        []Action
}

const catalogPageSize = 32
const catalogPageBytes = 96 << 10

// Cursor binds both independent page positions to one immutable catalog and
// one query scope. It is not authority: callers must reauthorize every page.
type catalogCursor struct {
	Revision uint64
	Scope    string
	User     string
	Node     string
}

func (c Catalog) queryCursor(scope, raw string) (catalogCursor, error) {
	value := catalogCursor{Revision: c.revision, Scope: scope}
	if raw == "" {
		return value, nil
	}
	if len(raw) > 512 {
		return value, ErrInvalid
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	var parsed catalogCursor
	if err != nil || json.Unmarshal(data, &parsed) != nil || parsed.Scope != scope ||
		(parsed.User == "" && parsed.Node == "") || parsed.User != "" && !identifier(parsed.User) || parsed.Node != "" && !identifier(parsed.Node) {
		return value, ErrInvalid
	}
	canonical, _ := json.Marshal(parsed)
	if base64.RawURLEncoding.EncodeToString(canonical) != raw {
		return value, ErrInvalid
	}
	if parsed.Revision != c.revision {
		return value, ErrConflict
	}
	return parsed, nil
}

func (p catalogCursor) encode() string {
	raw, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// PublicUserOf returns only an owned public projection, never verifier references.
func PublicUserOf(u User) PublicUser {
	row := PublicUser{ID: u.ID, Username: u.Username, Revision: u.Revision, Enabled: u.Enabled, SystemAdmin: u.SystemAdmin, AutomationOnly: u.AutomationOnly, Operations: slices.Clone(u.Operations)}
	for _, v := range u.Credentials {
		row.Credentials = append(row.Credentials, PublicCredential{ID: v.ID, Method: v.Method, PublicKey: v.PublicKey, Enabled: v.Enabled, Label: v.Label, Operations: slices.Clone(v.Operations), OneTime: v.OneTime, VolumeFiles: ownVolumeFileGrants(v.VolumeFiles)})
	}
	slices.SortFunc(row.Credentials, func(a, b PublicCredential) int { return strings.Compare(a.ID, b.ID) })
	return row
}

// UsersPage returns owned public records, including disabled users and keys so
// administrators can manage them. Verification references never cross this API.
func (c Catalog) UsersPage(actor, after string) ([]PublicUser, string, error) {
	if !c.SystemAllowed(actor) {
		return nil, "", ErrDenied
	}
	cursor, err := c.queryCursor("users", after)
	if err != nil || cursor.Node != "" {
		if err == nil {
			err = ErrInvalid
		}
		return nil, "", err
	}
	ids := make([]string, 0, len(c.users))
	for id := range c.users {
		if id > cursor.User {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	rows := []PublicUser{}
	used := 0
	for _, id := range ids {
		row := PublicUserOf(c.users[id])
		data, _ := json.Marshal(row)
		if len(rows) >= catalogPageSize || used+len(data) > catalogPageBytes {
			if len(rows) == 0 {
				return nil, "", ErrInvalid
			}
			return rows, cursor.encode(), nil
		}
		rows, used, cursor.User = append(rows, row), used+len(data), id
	}
	return rows, "", nil
}

var tenantMemberActions = []Action{Read, CallService, ManageNetwork, Deploy, ManageSecrets, ManageVolumes, ManageRoutes, ManageServices, ManageCD, ManageRegistry, ManageTrust, ManageMembers}

// TenantMembersPage pages members and tenant-wide allowed nodes together. Large
// node allowlists must not make a single authenticated response unbounded.
func (c Catalog) TenantMembersPage(actor, tenant, after string) ([]TenantMember, []string, string, error) {
	if c.Authorize(actor, tenant, ManageMembers, "") != nil {
		return nil, nil, "", ErrDenied
	}
	cursor, err := c.queryCursor("tenant-members/"+tenant, after)
	if err != nil {
		return nil, nil, "", err
	}
	ids := []string{}
	for id, u := range c.users {
		_, explicit := c.members[memberKey(tenant, id)]
		if id > cursor.User && (explicit || u.SystemAdmin && u.Enabled) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	rows := []TenantMember{}
	for _, id := range ids[:min(len(ids), catalogPageSize)] {
		u := c.users[id]
		m, explicit := c.members[memberKey(tenant, id)]
		row := TenantMember{User: id, Username: u.Username, Revision: m.Revision, Role: m.Role, Enabled: m.Enabled, AccountEnabled: u.Enabled, Implicit: !explicit && u.SystemAdmin, Actions: []Action{}}
		if u.SystemAdmin && u.Enabled {
			row.Role, row.Enabled = Manager, true
		}
		for _, action := range tenantMemberActions {
			if c.Authorize(id, tenant, action, "") == nil {
				row.Actions = append(row.Actions, action)
			}
		}
		rows, cursor.User = append(rows, row), id
	}
	nodes := []string{}
	moreNodes := false
	for _, node := range c.tenants[tenant].AllowedNodes {
		if node <= cursor.Node {
			continue
		}
		if len(nodes) == catalogPageSize {
			moreNodes = true
			break
		}
		nodes, cursor.Node = append(nodes, node), node
	}
	next := ""
	if len(ids) > len(rows) || moreNodes {
		next = cursor.encode()
	}
	return rows, nodes, next, nil
}
