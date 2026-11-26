// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (s Service) volumeUsage(ctx context.Context, view cluster.View, q Request, session access.Session) Reply {
	denied := Reply{Schema: 1, Code: "denied"}
	if s.VolumeObserver == nil || q.VolumeUsage == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	ready, err := s.Policy.VolumeNative(view.State, session, time.Now().Unix(), q.Tenant, *q.VolumeUsage)
	if err != nil {
		return denied
	}
	value, err := s.VolumeObserver(ctx, ready)
	if err != nil || !value.Matches(ready) {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	policy, err := s.Policy.Current(latest.State)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	current, err := policy.VolumeNative(latest.State, session, time.Now().Unix(), q.Tenant, *q.VolumeUsage)
	a, _ := json.Marshal(ready)
	b, _ := json.Marshal(current)
	if err != nil || !bytes.Equal(a, b) {
		return denied
	}
	return Reply{Schema: 1, Code: "ok", Tenant: q.Tenant, RootRevision: latest.State.Object(control.CatalogKey).Revision, VolumeUsage: &value, VolumeUsageIndex: latest.State.Index(), VolumesRootRevision: latest.State.Object(control.VolumesKey).Revision}
}

func (c Client) VolumeUsage(ctx context.Context, target mydcp.Peer, session access.Session, tenant string, selector control.VolumeSelector) (Reply, error) {
	if tenant == "" || !selector.Valid() {
		return Reply{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, target, session, Request{Method: "volume-usage", Tenant: tenant, VolumeUsage: &selector})
	if err != nil {
		return reply, err
	}
	v := reply.VolumeUsage
	if v == nil || v.Schema != 1 || v.Scope.Cluster != c.Cluster || v.Scope.Tenant != tenant || v.Scope.App != selector.App || v.Scope.ID != selector.ID || v.QuotaMode != "observe" || v.Snapshot || reply.VolumeUsageIndex == 0 || reply.VolumesRootRevision == 0 {
		return Reply{}, mydcp.ErrAdmission
	}
	return reply, nil
}

// volumeUsageRows adds each owner's last periodic usage scan to a `volumes`
// page. Usage is an observation outside Raft: when the reports cannot be
// read the rows stay unknown and the page still answers.
func (s Service) volumeUsageRows(ctx context.Context, view cluster.View, rows []control.VolumeView) {
	if s.NodeObservations == nil || len(rows) == 0 {
		return
	}
	reports, err := s.NodeObservations(ctx, view)
	if err != nil {
		return
	}
	control.AttachVolumeUsage(rows, reports, uint64(time.Now().UnixMilli()))
}
