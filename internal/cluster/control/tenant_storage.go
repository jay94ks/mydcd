// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

// TenantStorageRoot reveals only the selected tenant's root reference, never
// the physical root's full tenant ACL or unrelated native filesystem facts.
type TenantStorageRoot struct {
	Node, ID             string
	Generation, Revision uint64
	Draining, Allowed    bool
	Root                 nodestorage.Reference
}
type TenantStoragePage struct {
	Index, RootRevision, Revision uint64
	Items                         []TenantStorageRoot
	Next                          string `json:",omitempty"`
}

func tenantStorageAllowed(c access.Catalog, p Policy, session access.Session, at int64, tenant, node string) bool {
	return c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageVolumes, node) == nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, node) == nil
}
func tenantStorageSnapshot(s state.State, cluster [32]byte, tenant, node string) string {
	raw, _ := json.Marshal(struct {
		Cluster                        [32]byte
		Tenant, Node                   string
		Catalog, Members, Roots, Epoch uint64
	}{cluster, tenant, node, s.Object(CatalogKey).Revision, s.Object(MembersKey).Revision, s.Object(NodeStorageKey).Revision, s.ModuleEpoch()})
	digest := sha256.Sum256(append([]byte("sfc-tenant-storage-page-1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}
func (p Policy) TenantStoragePage(s state.State, session access.Session, at int64, tenant, node, after string) (TenantStoragePage, error) {
	page := TenantStoragePage{Index: s.Index(), RootRevision: s.Object(NodeStorageKey).Revision}
	current, err := p.Current(s)
	if err != nil {
		return page, err
	}
	p = current
	if !lifecycle.ValidID(tenant) || node != "" && !lifecycle.ValidID(node) || len(after) > 512 {
		return page, access.ErrInvalid
	}
	users, err := p.Catalog(s)
	if err != nil {
		return page, err
	}
	if !tenantStorageAllowed(users, p, session, at, tenant, node) {
		return page, access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil {
		return page, err
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return page, err
	}
	page.Revision = roots.Revision()
	snapshot := tenantStorageSnapshot(s, p.Cluster, tenant, node)
	last := ""
	if after != "" {
		prefix, key, ok := strings.Cut(after, ":")
		parts := strings.Split(key, "/")
		if !ok || prefix != snapshot || len(parts) != 2 || !lifecycle.ValidID(parts[0]) || !lifecycle.ValidID(parts[1]) {
			return page, access.ErrConflict
		}
		last = key
	}
	for _, root := range roots.Roots() {
		definition := root.Definition
		key := definition.Node + "/" + definition.ID
		if key <= last || node != "" && definition.Node != node || !definition.Allows(tenant) || !tenantStorageAllowed(users, p, session, at, tenant, definition.Node) {
			continue
		}
		owner, err := p.nodeOwner(s, definition.Node)
		if err != nil || owner != definition.Key || !members.MemberKey(owner) {
			continue
		}
		if len(page.Items) == 8 {
			previous := page.Items[len(page.Items)-1]
			page.Next = snapshot + ":" + previous.Node + "/" + previous.ID
			break
		}
		page.Items = append(page.Items, TenantStorageRoot{Node: definition.Node, ID: definition.ID, Generation: root.Generation, Revision: root.Revision, Draining: root.Draining, Allowed: true, Root: root.Reference(p.Cluster)})
	}
	return page, nil
}
