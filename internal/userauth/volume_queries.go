// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// VolumePageQuery selects one page of a tenant's volumes, backups or
// restores. An empty Tenant asks for the whole cluster (administrators).
type VolumePageQuery struct {
	Tenant string `json:",omitempty"`
	After  string `json:",omitempty"`
}

func (q VolumePageQuery) Valid() bool {
	return (q.Tenant == "" || lifecycle.ValidID(q.Tenant)) && len(q.After) <= 512
}

// VolumeRows is one page of the volumes book. Revision is the book's
// revision and RootRevision its root object's; pages of one list must share
// RootRevision. ModuleEpoch is the epoch a change built from the page uses.
type VolumeRows[T any] struct {
	Items        []T
	Next         string `json:",omitempty"`
	Revision     uint64
	RootRevision uint64
	ModuleEpoch  uint64
}

type (
	VolumesPage        = VolumeRows[control.VolumeView]
	VolumeBackupsPage  = VolumeRows[control.VolumeBackupView]
	VolumeRestoresPage = VolumeRows[control.VolumeRestoreView]
)

// VolumeArchivesPage is one page of Volume archives with the public
// recipient keys new packages are sealed to. Keys.Revision is what
// set-volume-archive-admin-key expects.
type VolumeArchivesPage struct {
	VolumeRows[control.VolumeArchiveView]
	Keys control.VolumeArchiveKeys
}

// VolumeQuery names one volume of a tenant.
type VolumeQuery struct {
	Tenant string
	Volume control.VolumeSelector
}

func (q VolumeQuery) Valid() bool { return lifecycle.ValidID(q.Tenant) && q.Volume.Valid() }

// VolumeUsageReply is the owner's measured usage of one volume, checked
// against the committed index it was read at.
type VolumeUsageReply struct {
	Usage        volumes.Usage
	Index        uint64
	RootRevision uint64
}

// VolumeBackupSourceReply is the owner's backup preflight for one volume;
// begin-volume-backup expects VolumeRevision and ModuleEpoch.
type VolumeBackupSourceReply struct {
	Source         control.VolumeBackupSource
	VolumeRevision uint64
	ModuleEpoch    uint64
	RootRevision   uint64
	Index          uint64
}

// VolumeFilePlanQuery asks for the plan of one volume file change.
type VolumeFilePlanQuery struct {
	Tenant string
	File   control.VolumeFileQuery
}

func (q VolumeFilePlanQuery) Valid() bool { return lifecycle.ValidID(q.Tenant) && q.File.Valid(false) }

// VolumeFileStatusQuery names one accepted volume file change.
type VolumeFileStatusQuery struct {
	Tenant string
	ID     string
}

func (q VolumeFileStatusQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && control.VolumeFileQuery{ID: q.ID}.Valid(true)
}

func (c Client) VolumePage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (VolumesPage, error) {
	return call(ctx, c, target, session, VolumesMethod, VolumePageQuery{Tenant: tenant, After: after})
}

func (c Client) VolumeBackupPage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (VolumeBackupsPage, error) {
	return call(ctx, c, target, session, VolumeBackupsMethod, VolumePageQuery{Tenant: tenant, After: after})
}

func (c Client) VolumeRestorePage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (VolumeRestoresPage, error) {
	return call(ctx, c, target, session, VolumeRestoresMethod, VolumePageQuery{Tenant: tenant, After: after})
}

func (c Client) VolumeArchivePage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, after string) (VolumeArchivesPage, error) {
	return call(ctx, c, target, session, VolumeArchivesMethod, VolumePageQuery{Tenant: tenant, After: after})
}

func (c Client) VolumeUsage(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, selector control.VolumeSelector) (VolumeUsageReply, error) {
	reply, _, err := c.VolumeUsageRoute(ctx, target, session, tenant, selector)
	return reply, err
}

// VolumeUsageRoute is VolumeUsage with the servers that answered and relayed.
func (c Client) VolumeUsageRoute(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, selector control.VolumeSelector) (VolumeUsageReply, Route, error) {
	reply, route, err := callRoute(ctx, c, target, session, VolumeUsageMethod, VolumeQuery{Tenant: tenant, Volume: selector})
	if err != nil {
		return VolumeUsageReply{}, Route{}, err
	}
	v := reply.Usage
	if v.Schema != 1 || v.Scope.Cluster != c.Cluster || v.Scope.Tenant != tenant || v.Scope.App != selector.App || v.Scope.ID != selector.ID || v.QuotaMode != "observe" || v.Snapshot || reply.Index == 0 || reply.RootRevision == 0 {
		return VolumeUsageReply{}, Route{}, sfcp.ErrAdmission
	}
	return reply, route, nil
}

func (c Client) VolumeBackupSource(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, q control.VolumeSelector) (VolumeBackupSourceReply, error) {
	reply, err := call(ctx, c, target, session, VolumeBackupSourceMethod, VolumeQuery{Tenant: tenant, Volume: q})
	if err != nil {
		return VolumeBackupSourceReply{}, err
	}
	if !reply.Source.Valid(c.Cluster, tenant, q) || reply.VolumeRevision == 0 || reply.ModuleEpoch == 0 || reply.RootRevision == 0 || reply.Index == 0 {
		return VolumeBackupSourceReply{}, sfcp.ErrAdmission
	}
	return reply, nil
}

func (c Client) VolumeFilePlan(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.VolumeFileQuery) (control.VolumeFilePlan, error) {
	plan, err := call(ctx, c, peer, session, VolumeFilePlanMethod, VolumeFilePlanQuery{Tenant: tenant, File: q})
	if err != nil {
		return control.VolumeFilePlan{}, err
	}
	if plan.Change.Scope.Cluster != c.Cluster || plan.Change.Scope.Tenant != tenant || plan.Change.Scope.App != q.App || plan.Change.Scope.ID != q.Volume || plan.Change.Path != q.Path || plan.Revision == 0 || !plan.Change.Valid(q.Method) {
		return control.VolumeFilePlan{}, sfcp.ErrAdmission
	}
	return plan, nil
}

func (c Client) VolumeFileStatus(ctx context.Context, peer sfcp.Peer, session access.Session, tenant, id string) (control.VolumeFileView, error) {
	status, err := call(ctx, c, peer, session, VolumeFileStatusMethod, VolumeFileStatusQuery{Tenant: tenant, ID: id})
	if err != nil {
		return control.VolumeFileView{}, err
	}
	if status.ID != id || status.Request.Scope.Cluster != c.Cluster || status.Request.Scope.Tenant != tenant {
		return control.VolumeFileView{}, sfcp.ErrAdmission
	}
	return status, nil
}

// authorizeVolumeRead allows Read on the tenant, or ManageCluster for the
// whole cluster (an empty tenant).
func (s Service) authorizeVolumeRead(view cluster.View, session access.Session, tenant string) (access.Catalog, bool) {
	c, err := s.Policy.Catalog(view.State)
	if err != nil {
		return access.Catalog{}, false
	}
	action := access.Read
	if tenant == "" {
		action = access.ManageCluster
	}
	return c, c.AuthorizeSession(session, s.Policy.Cluster, s.Policy.Issuer(session.Issuer), time.Now().Unix(), tenant, action, "") == nil
}

// volumeRows reads one page of the volumes book with page.
func volumeRows[T any](s Service, view cluster.View, session access.Session, q VolumePageQuery, page func(control.Volumes, access.Catalog, string, string, string) ([]T, string, error)) (VolumeRows[T], string) {
	c, ok := s.authorizeVolumeRead(view, session, q.Tenant)
	if !ok {
		return VolumeRows[T]{}, "denied"
	}
	v, err := s.Policy.Volumes(view.State)
	if err != nil {
		return VolumeRows[T]{}, "unavailable"
	}
	items, next, err := page(v, c, session.User, q.Tenant, q.After)
	if err != nil {
		return VolumeRows[T]{}, "denied"
	}
	if items == nil {
		items = []T{}
	}
	return VolumeRows[T]{Items: items, Next: next, Revision: v.Revision, RootRevision: view.State.Object(control.VolumesKey).Revision, ModuleEpoch: max(view.State.ModuleEpoch(), 1)}, "ok"
}

var (
	// VolumesMethod pages volumes with each owner's last periodic usage scan;
	// usage is an observation outside Raft and stays unknown when the
	// reports cannot be read.
	VolumesMethod = define(Method[VolumePageQuery, VolumesPage]{Name: "volumes"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q VolumePageQuery) (VolumesPage, string) {
		page, code := volumeRows(s, view, session, q, control.Volumes.Page)
		if code == "ok" && s.NodeObservations != nil && len(page.Items) != 0 {
			if reports, _, err := s.NodeObservations(ctx, view); err == nil {
				control.AttachVolumeUsage(page.Items, reports, uint64(time.Now().UnixMilli()))
			}
		}
		return page, code
	})
	VolumeBackupsMethod = define(Method[VolumePageQuery, VolumeBackupsPage]{Name: "volume-backups"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q VolumePageQuery) (VolumeBackupsPage, string) {
		return volumeRows(s, view, session, q, control.Volumes.BackupPage)
	})
	VolumeRestoresMethod = define(Method[VolumePageQuery, VolumeRestoresPage]{Name: "volume-restores"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q VolumePageQuery) (VolumeRestoresPage, string) {
		return volumeRows(s, view, session, q, control.Volumes.RestorePage)
	})
	VolumeArchivesMethod = define(Method[VolumePageQuery, VolumeArchivesPage]{Name: "volume-archives"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q VolumePageQuery) (VolumeArchivesPage, string) {
		rows, code := volumeRows(s, view, session, q, control.Volumes.ArchivePage)
		if code != "ok" {
			return VolumeArchivesPage{}, code
		}
		v, err := s.Policy.Volumes(view.State)
		if err != nil {
			return VolumeArchivesPage{}, "unavailable"
		}
		return VolumeArchivesPage{VolumeRows: rows, Keys: v.ArchiveKeys()}, "ok"
	})

	// VolumeUsageMethod asks the owner to measure one volume and answers only
	// when the volume is unchanged at a newer leader read.
	VolumeUsageMethod = define(Method[VolumeQuery, VolumeUsageReply]{Name: "volume-usage"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q VolumeQuery) (VolumeUsageReply, string) {
		if _, ok := s.authorizeVolumeRead(view, session, q.Tenant); !ok {
			return VolumeUsageReply{}, "denied"
		}
		if s.VolumeObserver == nil {
			return VolumeUsageReply{}, "unavailable"
		}
		ready, err := s.Policy.VolumeNative(view.State, session, time.Now().Unix(), q.Tenant, q.Volume)
		if err != nil {
			return VolumeUsageReply{}, "denied"
		}
		value, err := s.VolumeObserver(ctx, ready)
		if err != nil || !value.Matches(ready) {
			return VolumeUsageReply{}, "unavailable"
		}
		latest, err := s.Engine.Read(ctx, true)
		if err != nil || latest.Local {
			return VolumeUsageReply{}, "unavailable"
		}
		policy, err := s.Policy.Current(latest.State)
		if err != nil {
			return VolumeUsageReply{}, "unavailable"
		}
		current, err := policy.VolumeNative(latest.State, session, time.Now().Unix(), q.Tenant, q.Volume)
		a, _ := json.Marshal(ready)
		b, _ := json.Marshal(current)
		if err != nil || !bytes.Equal(a, b) {
			return VolumeUsageReply{}, "denied"
		}
		return VolumeUsageReply{Usage: value, Index: latest.State.Index(), RootRevision: latest.State.Object(control.VolumesKey).Revision}, "ok"
	})

	// VolumeBackupSourceMethod asks the owner for a backup preflight and
	// answers only when the volume's revision is unchanged at a newer read.
	VolumeBackupSourceMethod = define(Method[VolumeQuery, VolumeBackupSourceReply]{Name: "volume-backup-source"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q VolumeQuery) (VolumeBackupSourceReply, string) {
		if _, ok := s.authorizeVolumeRead(view, session, q.Tenant); !ok {
			return VolumeBackupSourceReply{}, "denied"
		}
		if s.VolumeSourceObserver == nil {
			return VolumeBackupSourceReply{}, "unavailable"
		}
		ready, err := s.Policy.VolumeNative(view.State, session, time.Now().Unix(), q.Tenant, q.Volume)
		if err != nil {
			return VolumeBackupSourceReply{}, "denied"
		}
		registry, err := s.Policy.Volumes(view.State)
		if err != nil {
			return VolumeBackupSourceReply{}, "denied"
		}
		before, ok := registry.Volume(ready.Spec.Scope)
		if !ok {
			return VolumeBackupSourceReply{}, "denied"
		}
		value, err := s.VolumeSourceObserver(ctx, ready)
		if err != nil || !value.Matches(ready) {
			return VolumeBackupSourceReply{}, "unavailable"
		}
		latest, err := s.Engine.Read(ctx, true)
		if err != nil || latest.Local {
			return VolumeBackupSourceReply{}, "unavailable"
		}
		policy, err := s.Policy.Current(latest.State)
		if err != nil {
			return VolumeBackupSourceReply{}, "denied"
		}
		current, err := policy.VolumeNative(latest.State, session, time.Now().Unix(), q.Tenant, q.Volume)
		if err != nil || !value.Matches(current) {
			return VolumeBackupSourceReply{}, "denied"
		}
		registry, err = policy.Volumes(latest.State)
		if err != nil {
			return VolumeBackupSourceReply{}, "denied"
		}
		after, ok := registry.Volume(current.Spec.Scope)
		if !ok || after.Revision() != before.Revision() {
			return VolumeBackupSourceReply{}, "denied"
		}
		return VolumeBackupSourceReply{Source: value, VolumeRevision: after.Revision(), ModuleEpoch: latest.State.ModuleEpoch(), RootRevision: latest.State.Object(control.VolumesKey).Revision, Index: latest.State.Index()}, "ok"
	})

	// The volume file plan and status check exact manager or folder-grant +
	// Read authority, credential ceilings and the selected volume and path
	// against the committed view before they expose a result.
	VolumeFilePlanMethod = define(Method[VolumeFilePlanQuery, control.VolumeFilePlan]{Name: "volume-file-plan"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q VolumeFilePlanQuery) (control.VolumeFilePlan, string) {
		plan, err := s.Policy.PlanVolumeFile(view.State, session, time.Now().Unix(), q.Tenant, q.File)
		if err != nil {
			return control.VolumeFilePlan{}, "denied"
		}
		return plan, "ok"
	})
	VolumeFileStatusMethod = define(Method[VolumeFileStatusQuery, control.VolumeFileView]{Name: "volume-file-status"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q VolumeFileStatusQuery) (control.VolumeFileView, string) {
		status, err := s.Policy.VolumeFileStatus(view.State, session, time.Now().Unix(), q.Tenant, control.VolumeFileQuery{ID: q.ID})
		if err != nil {
			return control.VolumeFileView{}, "denied"
		}
		return status, "ok"
	})
)
