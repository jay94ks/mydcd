// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/schema"
)

// advanceDeliveryController selects work only; accepted mutations, Unknown
// queries and native effects continue on the ordinary app owner/retirement loop.
func (r *Runtime) advanceDeliveryController(ctx context.Context, v cluster.View, apps control.Apps) (bool, error) {
	if !r.Engine().IsLeader() {
		return false, nil
	}
	for _, app := range apps.Records() {
		if app.CD == nil {
			continue
		}
		q := control.AppDeliveryWorkRequest{Tenant: app.Tenant, App: app.App, At: uint64(time.Now().Unix()), TargetCAS: true}
		// Local committed state is a scheduling preview, not source authority.
		preview, err := r.controlPolicy.AppDeliverySyncWork(v.State, r.Identity.Public, q)
		if err != nil || preview.Action == "" {
			continue
		}
		raw, _ := json.Marshal(q)
		reply, err := r.appCall(ctx, "app-delivery-sync-work", raw)
		if err != nil {
			return false, err
		}
		work, err := schema.Decode[control.AppDeliveryWork](reply.Data)
		if err != nil || work.Schema != 1 || work.Cluster != r.controlPolicy.Cluster || work.Reader != r.Identity.Public || work.Tenant != q.Tenant || work.App != q.App || work.Revision == 0 {
			return false, deployment.ErrInputs
		}
		if work.Action == "" {
			continue
		}
		if work.Target == nil || *work.Target == ([32]byte{}) {
			return false, deployment.ErrInputs
		}
		permit := control.AppDeliveryPermit{Scope: deployment.AppScope{Tenant: app.Tenant, App: app.App}, Revision: work.Revision, RootRevision: work.RootRevision, Epoch: work.Epoch, Target: work.Target}
		err = r.deliveryProgress(ctx, permit, control.AppDeliveryProgress{Action: work.Action, Choice: work.Choice})
		if err == errDeliverySourceCAS {
			return true, nil
		}
		return true, err
	}
	return false, nil
}
