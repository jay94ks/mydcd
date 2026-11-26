// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// PublicReadQuery contains logical selectors only. A Name is a resource name,
// never a native/container ID, host path, provider path or signed capability.
type PublicReadQuery struct{ Name, App, Node string }

func PublicReadMethod(method string) bool {
	return slices.Contains([]string{"volume-file-grants", "volume-backup-limits", "network-closure", "network-users", "volume-users", "route-endpoints", "lifecycle-uses", "vault-approvals", "vault-usages", "volume-retained-sources", "image-trust"}, method)
}
func (q PublicReadQuery) Valid(method string) bool {
	for _, id := range []string{q.Name, q.App, q.Node} {
		if id != "" && !lifecycle.ValidID(id) {
			return false
		}
	}
	switch method {
	case "volume-backup-limits":
		return q.Name == "" && q.App == ""
	case "network-closure", "network-users", "lifecycle-uses", "vault-usages":
		return q.Name != "" && q.App == "" && q.Node == ""
	case "volume-file-grants":
		return q.Node == ""
	case "volume-users", "volume-retained-sources":
		return q.Name != "" && q.Node == ""
	case "vault-approvals":
		return q.Name == "" && q.Node == ""
	case "route-endpoints", "image-trust":
		return q == (PublicReadQuery{})
	}
	return false
}

type PublicResourceUser struct {
	Kind, Tenant, App, Deployment, Service, Standalone, Node, Task, Consumer string
	Generation, Revision                                                     uint64
	Desired, Observed                                                        string
	Writable                                                                 *bool `json:",omitempty"`
	ContainerPresent                                                         *bool `json:",omitempty"`
	EndpointPresent                                                          *bool `json:",omitempty"`
	Live                                                                     bool
}
type PublicBackupLimit struct {
	Tenant, Node                  string
	Revision, Bytes, StagingBytes uint64
	Count, StagingCount           uint32
	UsedBytes, UsedStagingBytes   uint64
	UsedCount, UsedStagingCount   uint32
	GlobalPresent, GlobalOriginal bool
	Original                      *OriginalVolumeLimit `json:",omitempty"`
}
type PublicLifecycleUse struct {
	ID, Kind, App, Service, Standalone, Node string
	Revision                                 uint64
}
type PublicRetainedSource struct {
	Scope             volumes.Scope
	Move, Node, State string
}
type PublicRouteEndpoint struct{ Tenant, Network, Node, Pool string }
type PublicImageTrustUse struct {
	Kind, App, Deployment, Service, Standalone, Node, Reference string
	Rules                                                       []int
}
type PublicFileGrant struct {
	Tenant, App, Volume, Prefix, User string
	Revision                          uint64
	AccountEnabled, VolumePresent     bool
	Operations                        []string
}

type PublicReadRow struct {
	FileGrant     *PublicFileGrant      `json:",omitempty"`
	Closure       *NetworkClosureStatus `json:",omitempty"`
	Key           string
	User          *PublicResourceUser     `json:",omitempty"`
	BackupLimit   *PublicBackupLimit      `json:",omitempty"`
	Lifecycle     *PublicLifecycleUse     `json:",omitempty"`
	Approval      *secrets.PublicApproval `json:",omitempty"`
	SecretUsage   *secrets.PublicUsage    `json:",omitempty"`
	Retained      *PublicRetainedSource   `json:",omitempty"`
	RouteEndpoint *PublicRouteEndpoint    `json:",omitempty"`
	Image         *PublicImageTrustUse    `json:",omitempty"`
}
type PublicReadPage struct {
	Schema                                               uint8
	Method, Tenant                                       string
	Index, RootRevision, CatalogRevision, TenantRevision uint64
	Rules                                                []access.TrustRule `json:",omitempty"`
	Rows                                                 []PublicReadRow
	Next                                                 string
	Total                                                int
}

func publicReadRoot(method string) string {
	switch method {
	case "network-closure", "network-users", "route-endpoints":
		return ResourcesKey
	case "volume-backup-limits", "volume-users", "volume-retained-sources":
		return VolumesKey
	case "lifecycle-uses":
		return LifecycleKey
	case "vault-approvals", "vault-usages":
		return VaultKey
	}
	return CatalogKey
}

func publicReadAction(method string) access.Action {
	switch method {
	case "network-closure":
		return access.ManageNetwork
	case "lifecycle-uses":
		return access.ManageServices
	case "vault-approvals", "vault-usages":
		return access.ManageSecrets
	}
	return access.Read
}
func (p Policy) PublicRead(s state.State, session access.Session, at int64, method, tenant string, q PublicReadQuery, after string) (PublicReadPage, error) {
	if !q.Valid(method) || !PublicReadMethod(method) || at <= 0 {
		return PublicReadPage{}, access.ErrInvalid
	}
	current, err := p.Current(s)
	if err != nil {
		return PublicReadPage{}, access.ErrDenied
	}
	p = current
	catalog, err := p.Catalog(s)
	if err != nil {
		return PublicReadPage{}, err
	}
	action := publicReadAction(method)
	if tenant == "" {
		action = access.ManageCluster
	}
	if method == "route-endpoints" {
		if !routeEndpointReader(catalog, p, session, at) {
			return PublicReadPage{}, access.ErrDenied
		}
	} else if tenant == "" {
		// Cluster administration is not tenant retirement cleanup. Keep its
		// existing system-admin + signed ManageCluster scope boundary.
		if catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
			return PublicReadPage{}, access.ErrDenied
		}
	} else if catalog.AuthorizeSessionCleanup(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, action) != nil && (method != "volume-file-grants" || catalog.AuthorizeSessionCleanup(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageVolumes) != nil) {
		return PublicReadPage{}, access.ErrDenied
	}
	if tenant == "" && method != "vault-approvals" && method != "vault-usages" && method != "volume-backup-limits" {
		return PublicReadPage{}, access.ErrDenied
	}
	page := PublicReadPage{Schema: 1, Method: method, Tenant: tenant, Index: s.Index(), RootRevision: s.Object(publicReadRoot(method)).Revision, CatalogRevision: s.Object(CatalogKey).Revision, Rows: []PublicReadRow{}}
	if t, ok := catalog.Tenant(tenant); ok && method != "route-endpoints" {
		page.TenantRevision = t.Revision
	}
	rows := []PublicReadRow{}
	switch method {
	case "volume-file-grants":
		var e error
		rows, e = p.publicFileGrants(s, catalog, session, at, tenant, q)
		if e != nil {
			return page, e
		}
	case "network-closure":
		if _, err := p.NetworkClosureRead(s, session, at, tenant, q.Name); err != nil {
			return page, err
		}
		rows = append(rows, PublicReadRow{Key: q.Name, Closure: &NetworkClosureStatus{State: "unreachable"}})
	case "volume-backup-limits":
		book, e := p.Volumes(s)
		if e != nil {
			return page, e
		}
		for _, limit := range book.BackupLimits() {
			if limit.Tenant != tenant || q.Node != "" && q.Node != limit.Node || tenant != "" && catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, limit.Node) != nil {
				continue
			}
			global := book.backupLimits[backupLimitKey("", limit.Node)]
			row := PublicBackupLimit{Tenant: tenant, Node: limit.Node, Revision: limit.Revision, Bytes: limit.Bytes, Count: limit.Count, StagingBytes: limit.StagingBytes, StagingCount: limit.StagingCount, GlobalPresent: global.Revision != 0, GlobalOriginal: global.Original != nil, Original: limit.Original}
			book.publicBackupUsage(tenant, limit.Node, &row)
			rows = append(rows, PublicReadRow{Key: limit.Node, BackupLimit: &row})
		}
	case "lifecycle-uses":
		book, e := p.Lifecycles(s)
		if e != nil {
			return page, e
		}
		apps, e := p.readOnlyApps(s)
		if e != nil {
			return page, e
		}
		for _, use := range book.Uses() {
			if use.Tenant != tenant {
				continue
			}
			for _, ref := range use.Scripts {
				if ref.Name != q.Name {
					continue
				}
				row := PublicLifecycleUse{ID: use.ID, Kind: use.Kind, Node: use.Node, Revision: ref.Revision}
				parentID := use.ID
				if job, ok := book.BuildJob(tenant, use.ID); ok && use.Kind == "build-job" {
					parentID = job.Intent.AppUseID
				}
				for _, binding := range apps.bindings.Live() {
					need := binding.Needs()
					if bound, ok := CheckerBindingUse(binding); ok && bound.ID == parentID {
						row.App, row.Service = need.Use.App, need.Use.Service
						if name, ok := apps.StandaloneName(tenant, row.App); ok {
							row.Standalone = name
							row.App = ""
						}
					}
				}
				rows = append(rows, PublicReadRow{Key: fmt.Sprintf("%s/%020d", use.ID, ref.Revision), Lifecycle: &row})
			}
		}
	case "vault-approvals", "vault-usages":
		vault, e := p.Vault(s)
		if e != nil {
			return page, e
		}
		tree, ok := vault.Trees[tenant]
		if !ok {
			return page, access.ErrDenied
		}
		apps, e := p.readOnlyApps(s)
		if e != nil {
			return page, e
		}
		if method == "vault-approvals" {
			for _, row := range vault.Approvals.PublicApprovals(tree, q.App) {
				r := row
				if name, ok := apps.StandaloneName(r.Tenant, r.App); ok {
					r.Standalone = name
					r.App = ""
				}
				rows = append(rows, PublicReadRow{Key: r.ID, Approval: &r})
			}
		} else {
			if _, ok := tree.Object(q.Name); !ok {
				return page, access.ErrDenied
			}
			for _, row := range vault.Approvals.PublicUsages(tree, q.Name) {
				r := row
				if name, ok := apps.StandaloneName(r.Tenant, r.App); ok {
					r.Standalone = name
					r.App = ""
				}
				rows = append(rows, PublicReadRow{Key: r.ID, SecretUsage: &r})
			}
		}
	case "volume-retained-sources":
		book, e := p.Volumes(s)
		if e != nil {
			return page, e
		}
		for _, entry := range book.entries {
			scope := entry.State.Scope()
			if scope.Tenant != tenant || scope.ID != q.Name || q.App != "" && scope.App != q.App {
				continue
			}
			for _, move := range entry.State.Moves() {
				if move.Phase != volumes.Completed {
					continue
				}
				status := "retained"
				if move.SourceDeletion != nil {
					status = "deleting"
					if move.SourceDeletion.Gone != nil {
						status = "removed"
					}
				}
				r := PublicRetainedSource{Scope: scope, Move: move.Binding.ID, Node: move.Binding.Source.Node, State: status}
				rows = append(rows, PublicReadRow{Key: scope.Key() + "/" + r.Move, Retained: &r})
			}
		}
	case "route-endpoints":
		resources, e := p.Resources(s)
		if e != nil {
			return page, e
		}
		// Discovery publishes only active explicitly named TUN members. Legacy
		// private Bridge IDs and every CIDR/owner/generation remain undisclosed.
		for _, network := range resources.Networks.AllNetworks() {
			if network.Tenant != tenant || network.Logical == "" || network.Draining || network.PendingChange != 0 || len(network.TunnelAddresses) == 0 {
				continue
			}
			for _, pool := range network.Pools {
				r := PublicRouteEndpoint{Tenant: tenant, Network: network.Logical, Node: network.Node, Pool: pool.ID}
				rows = append(rows, PublicReadRow{Key: network.Logical + "/" + network.Node + "/" + pool.ID, RouteEndpoint: &r})
			}
		}
	case "network-users", "volume-users", "image-trust":
		tasks, e := p.publicReadTasks(s, session, at, tenant)
		if e != nil {
			return page, e
		}
		if method == "image-trust" {
			t, _ := catalog.Tenant(tenant)
			page.Rules = slices.Clone(t.ImageSources)
			for _, task := range tasks {
				image, e := access.PinImage(task.Image)
				if e != nil {
					return page, e
				}
				if task.Kind == "" {
					task.Kind = "app-service"
				}
				r := PublicImageTrustUse{Kind: task.Kind, Standalone: task.Standalone, App: task.App, Deployment: task.Deployment, Service: task.Service, Node: task.Node, Reference: image.Reference, Rules: []int{}}
				for i, rule := range page.Rules {
					if _, ok := access.MatchImageTrust([]access.TrustRule{rule}, image.Registry, image.Repository); ok {
						r.Rules = append(r.Rules, i)
					}
				}
				rows = append(rows, PublicReadRow{Key: task.TaskID + fmt.Sprintf("/%020d", task.Generation), Image: &r})
			}
		} else if method == "network-users" {
			resources, e := p.Resources(s)
			if e != nil {
				return page, e
			}
			selected := map[string]map[string]bool{}
			for _, network := range resources.Networks.AllNetworks() {
				if network.Tenant != tenant || (network.ID != q.Name && network.Logical != q.Name) {
					continue
				}
				name := network.Logical
				if name == "" {
					name = network.ID
				}
				if selected[name] == nil {
					selected[name] = map[string]bool{}
				}
				selected[name][network.Node] = true
			}
			if len(selected) == 0 {
				return page, access.ErrDenied
			}
			for _, task := range tasks {
				for _, resource := range task.Resources {
					if resource.Kind == "network" && selected[resource.Name][task.Node] {
						r := publicTaskUser(task)
						rows = append(rows, PublicReadRow{Key: task.TaskID + fmt.Sprintf("/%020d", task.Generation), User: &r})
						break
					}
				}
			}
		} else {
			rows, e = p.publicVolumeUsers(s, tenant, q, tasks)
			if e != nil {
				return page, e
			}
		}
	}
	slices.SortFunc(rows, func(a, b PublicReadRow) int { return strings.Compare(a.Key, b.Key) })
	basisRaw, _ := json.Marshal(struct {
		Index          uint64
		User           string
		Session        [32]byte
		Scopes         []access.Scope
		Method, Tenant string
		Query          PublicReadQuery
	}{s.Index(), session.User, session.Key, session.Scopes, method, tenant, q})
	basis := sha256.Sum256(append([]byte("mydc-public-resource-read-1\x00"), basisRaw...))
	offset, e := taskCursor(after, basis)
	if e != nil {
		return page, e
	}
	if uint64(offset) > uint64(len(rows)) {
		return page, access.ErrInvalid
	}
	page.Total = len(rows)
	for _, row := range rows[offset:] {
		if len(page.Rows) == 8 {
			break
		}
		candidate := append(page.Rows, row)
		raw, _ := json.Marshal(candidate)
		if len(raw) > 96<<10 {
			if len(page.Rows) == 0 {
				return page, ErrCatalog
			}
			break
		}
		page.Rows = candidate
	}
	if int(offset)+len(page.Rows) < len(rows) {
		page.Next = nextTaskCursor(basis, offset+uint32(len(page.Rows)))
	}
	return page, nil
}
func routeEndpointReader(c access.Catalog, p Policy, s access.Session, at int64) bool {
	for _, tenant := range c.VisibleTenants(s.User) {
		if c.AuthorizeSession(s, p.Cluster, p.Issuer(s.Issuer), at, tenant.ID, access.ManageRoutes, "") == nil {
			return true
		}
	}
	return c.AuthorizeSession(s, p.Cluster, p.Issuer(s.Issuer), at, "", access.ManageCluster, "") == nil
}
func (p Policy) publicReadTasks(s state.State, session access.Session, at int64, tenant string) ([]TaskView, error) {
	rows := []TaskView{}
	after := ""
	for {
		page, err := p.TaskPage(s, session, at, TaskSelection{Tenant: tenant}, after)
		if err != nil {
			return nil, err
		}
		rows = append(rows, page.Tasks...)
		if page.Next == "" {
			return rows, nil
		}
		after = page.Next
	}
}
func publicTaskUser(task TaskView) PublicResourceUser {
	if task.Kind == "" {
		task.Kind = "app-service"
	}
	row := PublicResourceUser{Kind: task.Kind, Standalone: task.Standalone, Tenant: task.Tenant, App: task.App, Deployment: task.Deployment, Service: task.Service, Node: task.Node, Task: task.TaskID, Generation: task.Generation, Revision: task.Revision, Desired: task.Desired, Observed: task.Observed, Live: true}
	if task.Observed != "unknown" && task.EndpointPresent != nil {
		present := *task.EndpointPresent
		row.EndpointPresent = &present
	}
	if task.Observed == "running" || task.Observed == "exited" || task.Observed == "created" {
		v := true
		row.ContainerPresent = &v
	} else if task.Observed == "missing" {
		v := false
		row.ContainerPresent = &v
	}
	return row
}
func (p Policy) publicVolumeUsers(s state.State, tenant string, q PublicReadQuery, tasks []TaskView) ([]PublicReadRow, error) {
	book, err := p.Volumes(s)
	if err != nil {
		return nil, err
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return nil, err
	}
	rows := []PublicReadRow{}
	for _, entry := range book.entries {
		scope := entry.State.Scope()
		if scope.Tenant != tenant || scope.ID != q.Name || q.App != "" && scope.App != q.App {
			continue
		}
		for _, consumer := range entry.State.Consumers() {
			row := PublicResourceUser{Kind: "volume-operation", Tenant: tenant, Consumer: consumer.ID, Node: consumer.Owner.Node, Live: true}
			w := consumer.Writable
			row.Writable = &w
			for _, task := range tasks {
				binding, ok := apps.Binding(deployment.ObjectRef{Key: task.TaskID, Generation: task.Generation, Revision: task.Revision})
				if !ok {
					continue
				}
				for _, pin := range binding.Pins() {
					if pin.Scope == scope && pin.Consumer == consumer {
						row = publicTaskUser(task)
						row.Consumer = consumer.ID
						row.Writable = &w
					}
				}
			}
			rows = append(rows, PublicReadRow{Key: scope.Key() + "/" + consumer.ID + fmt.Sprintf("/%020d", consumer.Generation), User: &row})
		}
	}
	return rows, nil
}
func (v Volumes) publicBackupUsage(tenant, node string, out *PublicBackupLimit) {
	charge := func(scopeTenant, scopeNode string, bytes uint64, count uint32, staging bool) {
		if scopeNode != node || tenant != "" && scopeTenant != tenant {
			return
		}
		if staging {
			out.UsedStagingBytes += bytes
			out.UsedStagingCount += count
		} else {
			out.UsedBytes += bytes
			out.UsedCount += count
		}
	}
	for _, job := range v.backups {
		bytes, count := backupCharged(job)
		charge(job.Binding.Scope.Tenant, job.Binding.Source.Owner.Node, bytes, count, false)
	}
	for _, job := range v.restores {
		if v.restoreCharged(job) {
			charge(job.Binding.Target.Scope.Tenant, job.Binding.Target.Node, job.Binding.MaxBytes, 1, true)
		}
	}
	for _, job := range v.moves {
		_, move, ok := v.Move(job.Selection())
		if ok && movePending(move) {
			charge(job.Binding.Scope.Tenant, job.Binding.Source.Node, job.Binding.MaxBytes, 1, false)
			charge(job.Binding.Scope.Tenant, job.Binding.Target.Node, job.Binding.MaxBytes, 1, true)
		}
	}
}

// FileGrant rows project the RQ9 volume-file-grant/revoke reducer's existing
// Catalog.VolumeFileGrants state. Credential.VolumeFiles is a separate ceiling,
// never an independently issued tenant folder delegation or another grant DB.
// Empty user/app/volume are read selectors; the tenant is always exact. Current
// permissions and the shared page/cursor machinery remain in PublicRead.
func (p Policy) publicFileGrants(s state.State, c access.Catalog, session access.Session, at int64, tenant string, q PublicReadQuery) ([]PublicReadRow, error) {
	manager := c.AuthorizeSessionCleanup(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageVolumes) == nil
	userFilter := session.User
	if manager {
		userFilter = ""
	}
	book, err := p.Volumes(s)
	if err != nil {
		return nil, err
	}
	rows := []PublicReadRow{}
	for _, grant := range c.VolumeFileGrants(tenant, userFilter, q.App, q.Name) {
		// Recheck logical selectors before even reading the target account. Hidden
		// tenant/account rows must not affect payloads, keys, Total or pagination.
		if grant.Tenant != tenant || !manager && grant.User != session.User || q.Name != "" && grant.Volume != q.Name || q.App != "" && grant.App != q.App {
			continue
		}
		account, exists := c.User(grant.User)
		if !exists {
			return nil, ErrCatalog
		}
		entry, present := book.entries[(volumes.Scope{Tenant: tenant, App: grant.App, ID: grant.Volume}).Key()]
		present = present && !entry.State.Deleted()
		row := PublicFileGrant{Tenant: grant.Tenant, App: grant.App, Volume: grant.Volume, Prefix: grant.Prefix, User: grant.User, Revision: grant.Revision, AccountEnabled: account.Enabled, VolumePresent: present, Operations: []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}}
		key := grant.User + "/" + grant.App + "/" + grant.Volume + "/" + grant.Prefix
		rows = append(rows, PublicReadRow{Key: key, FileGrant: &row})
	}
	return rows, nil
}
