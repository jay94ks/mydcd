// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (s Service) volumeBackupSource(ctx context.Context, view cluster.View, q Request, session access.Session) Reply {
	denied := Reply{Schema: 1, Code: "denied"}
	if s.VolumeSourceObserver == nil || q.VolumeSource == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	ready, err := s.Policy.VolumeNative(view.State, session, time.Now().Unix(), q.Tenant, *q.VolumeSource)
	if err != nil {
		return denied
	}
	registry, err := s.Policy.Volumes(view.State)
	if err != nil {
		return denied
	}
	before, ok := registry.Volume(ready.Spec.Scope)
	if !ok {
		return denied
	}
	value, err := s.VolumeSourceObserver(ctx, ready)
	if err != nil || !value.Matches(ready) {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	policy, err := s.Policy.Current(latest.State)
	if err != nil {
		return denied
	}
	current, err := policy.VolumeNative(latest.State, session, time.Now().Unix(), q.Tenant, *q.VolumeSource)
	if err != nil || !value.Matches(current) {
		return denied
	}
	registry, err = policy.Volumes(latest.State)
	if err != nil {
		return denied
	}
	after, ok := registry.Volume(current.Spec.Scope)
	if !ok || after.Revision() != before.Revision() {
		return denied
	}
	return Reply{Schema: 1, Code: "ok", Tenant: q.Tenant, RootRevision: latest.State.Object(control.CatalogKey).Revision, ModuleEpoch: latest.State.ModuleEpoch(), VolumesRootRevision: latest.State.Object(control.VolumesKey).Revision, VolumeRevision: after.Revision(), VolumeSource: &value, VolumeSourceIndex: latest.State.Index()}
}
func (c Client) VolumeBackupSource(ctx context.Context, target mydcp.Peer, session access.Session, tenant string, q control.VolumeSelector) (Reply, error) {
	if tenant == "" || !q.Valid() {
		return Reply{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, target, session, Request{Method: "volume-backup-source", Tenant: tenant, VolumeSource: &q})
	if err != nil {
		return reply, err
	}
	if reply.VolumeSource == nil || !reply.VolumeSource.Valid(c.Cluster, tenant, q) || reply.VolumeRevision == 0 || reply.ModuleEpoch == 0 || reply.VolumesRootRevision == 0 || reply.VolumeSourceIndex == 0 {
		return Reply{}, mydcp.ErrAdmission
	}
	return reply, nil
}
