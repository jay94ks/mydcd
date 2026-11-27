// SPDX-License-Identifier: Apache-2.0

package access

import (
	"path"
	"slices"
	"strings"
)

// VolumeFileGrant is a credential ceiling, not a role. It bounds file
// operations under one tenant Volume prefix; it cannot create/move a Volume.
// The empty App selects a tenant-registered Volume, never all app Volumes.
type VolumeFileGrant struct {
	Tenant, App, Volume, Prefix string
	Operations                  []string
}

func ValidVolumeFilePath(name string, prefix bool) bool {
	if len(name) == 0 || len(name) > 1024 || strings.ContainsAny(name, "\\\x00\r\n") || strings.HasPrefix(name, "/") {
		return false
	}
	if prefix {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || name == "." || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || strings.HasPrefix(part, ".sfc-file-") {
			return false
		}
	}
	return true
}

func validVolumeFileGrants(grants []VolumeFileGrant) bool {
	if len(grants) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, g := range grants {
		key := g.Tenant + "/" + g.App + "/" + g.Volume + "/" + g.Prefix
		if !identifier(g.Tenant) || g.App != "" && !identifier(g.App) || !identifier(g.Volume) || !ValidVolumeFilePath(g.Prefix, true) || !strings.HasSuffix(g.Prefix, "/") || len(g.Operations) < 1 || len(g.Operations) > 4 || seen[key] {
			return false
		}
		seen[key] = true
		opSeen := map[string]bool{}
		for _, op := range g.Operations {
			if op != "volume-file-put" && op != "volume-file-get" && op != "volume-file-list" && op != "volume-file-delete" || opSeen[op] {
				return false
			}
			opSeen[op] = true
		}
	}
	return true
}
func ownVolumeFileGrants(in []VolumeFileGrant) []VolumeFileGrant {
	out := slices.Clone(in)
	for i := range out {
		out[i].Operations = slices.Clone(out[i].Operations)
		slices.Sort(out[i].Operations)
	}
	return out
}
func equalVolumeFileGrants(a, b []VolumeFileGrant) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Tenant != y.Tenant || x.App != y.App || x.Volume != y.Volume || x.Prefix != y.Prefix || !slices.Equal(x.Operations, y.Operations) {
			return false
		}
	}
	return true
}

// AuthorizeVolumeFile verifies the current session, node allocation and typed
// operation ceiling. Credential and approval ceilings narrow both ordinary
// manager authority and a current manager-issued folder grant.
func (c Catalog) AuthorizeVolumeFile(s Session, cluster [32]byte, issuer Issuer, at int64, tenant, app, volume, name, operation, node string) error {
	if !identifier(volume) || app != "" && !identifier(app) || !ValidVolumeFilePath(name, operation == "volume-file-list") || c.VerifySession(s, cluster, issuer, at) != nil || c.OperationAllowed(s, operation) != nil {
		return ErrDenied
	}
	u, ok := c.users[s.User]
	if !ok {
		return ErrDenied
	}
	matching := func(grants []VolumeFileGrant) bool {
		for _, g := range grants {
			if g.Tenant == tenant && g.App == app && g.Volume == volume && slices.Contains(g.Operations, operation) && strings.HasPrefix(name, g.Prefix) {
				return true
			}
		}
		return false
	}
	var source *Credential
	for i := range u.Credentials {
		if u.Credentials[i].ID == s.Credential && u.Credentials[i].Enabled {
			source = &u.Credentials[i]
		}
	}
	if source == nil {
		return ErrDenied
	}
	limited := source.VolumeFiles != nil
	if limited && !matching(source.VolumeFiles) {
		return ErrDenied
	}
	if s.Approval != nil {
		for _, approver := range u.Credentials {
			if approver.Enabled && approver.Method == PrivateKey && approver.PublicKey == s.Approval.PublicKey && approver.VolumeFiles != nil {
				if !matching(approver.VolumeFiles) {
					return ErrDenied
				}
				limited = true
			}
		}
	}
	if limited && c.AuthorizeSession(s, cluster, issuer, at, tenant, Read, node) != nil {
		return ErrDenied
	}
	if c.AuthorizeSession(s, cluster, issuer, at, tenant, ManageVolumes, node) == nil {
		return nil
	}
	for _, g := range c.volumeFiles {
		if g.User == s.User && g.Tenant == tenant && g.App == app && g.Volume == volume && strings.HasPrefix(name, g.Prefix) {
			return c.AuthorizeSession(s, cluster, issuer, at, tenant, Read, node)
		}
	}
	return ErrDenied
}

func validVolumeFileCredential(v Credential) bool {
	if v.VolumeFiles == nil {
		return true
	}
	if v.Operations == nil {
		return false
	}
	for _, op := range v.Operations {
		if op != "volume-file-put" && op != "volume-file-get" && op != "volume-file-list" && op != "volume-file-delete" {
			return false
		}
	}
	return true
}

// VolumeFileFolderGrant is a tenant manager's user-level delegation. It never
// edits a global credential; credential operation/path ceilings still apply.
type VolumeFileFolderGrant struct {
	Tenant, App, Volume, Prefix, User string
	Revision                          uint64
}

func (g VolumeFileFolderGrant) valid() bool {
	return identifier(g.Tenant) && identifier(g.User) && (g.App == "" || identifier(g.App)) && identifier(g.Volume) && ValidVolumeFilePath(g.Prefix, true) && strings.HasSuffix(g.Prefix, "/")
}
func (g VolumeFileFolderGrant) key() string {
	return g.Tenant + "/" + g.App + "/" + g.Volume + "/" + g.User + "/" + g.Prefix
}
func (c Catalog) SetVolumeFileGrant(actor string, expected uint64, g VolumeFileFolderGrant, revoke bool) (Catalog, error) {
	if expected != c.revision {
		return c, ErrConflict
	}
	if !g.valid() || g.Revision != 0 {
		return c, ErrInvalid
	}
	if c.Authorize(actor, g.Tenant, ManageVolumes, "") != nil || !revoke && c.Authorize(g.User, g.Tenant, Read, "") != nil {
		return c, ErrDenied
	}
	index := slices.IndexFunc(c.volumeFiles, func(old VolumeFileFolderGrant) bool { return old.key() == g.key() })
	if revoke && index < 0 {
		return c, ErrInvalid
	}
	if !revoke && index < 0 && len(c.volumeFiles) >= maxRecords {
		return c, ErrInvalid
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	if revoke {
		n.volumeFiles = slices.Delete(n.volumeFiles, index, index+1)
	} else {
		g.Revision = n.revision
		if index < 0 {
			n.volumeFiles = append(n.volumeFiles, g)
		} else {
			n.volumeFiles[index] = g
		}
	}
	slices.SortFunc(n.volumeFiles, func(a, b VolumeFileFolderGrant) int { return strings.Compare(a.key(), b.key()) })
	return n, nil
}

// VolumeFileGrants is an internal read projection. Tenant is always exact;
// empty user/app/volume selectors enumerate rows within that tenant only.
// These selector wildcards create no authorization or write-grant scope.
func (c Catalog) VolumeFileGrants(tenant, user, app, volume string) []VolumeFileFolderGrant {
	var out []VolumeFileFolderGrant
	for _, g := range c.volumeFiles {
		if g.Tenant == tenant && (user == "" || g.User == user) && (app == "" || g.App == app) && (volume == "" || g.Volume == volume) {
			out = append(out, g)
		}
	}
	return out
}
