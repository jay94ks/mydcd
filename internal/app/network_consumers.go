// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
)

// All fresh managed Bridge/TUN consumers (Task, reference, DNS, Ingress, packet plane)
// enter through this same Manager callback. The caller still needs its own
// service/Task permission: a Bridge budget is not authority to operate an app.
func (r *Runtime) networkConsumerBudget(ctx context.Context, key string, d reconcile.Desired) (network.ConsumerBudget, error) {
	budget, view, projection, err := r.networkConsumerPermit(ctx, key, d)
	if err != nil {
		return budget, err
	}
	if err := r.tenantIsolationAdmissionReady(view, projection); err != nil {
		return network.ConsumerBudget{}, err
	}
	return budget, nil
}

// Permission only; the consumer wrapper and first-create driver each verify
// their original native protection separately, without journal reentry.
func (r *Runtime) networkConsumerPermit(ctx context.Context, key string, d reconcile.Desired) (network.ConsumerBudget, cluster.View, control.ResourceProjection, error) {
	var view cluster.View
	var projection control.ResourceProjection
	if !d.Resource.Present || d.Revision == 0 || d.Resource.Generation == 0 {
		return network.ConsumerBudget{}, view, projection, mydcp.ErrAdmission
	}
	kind, owner := "bridge", ""
	if spec, err := network.DecodeBridge(d.Resource.Spec); err == nil && !spec.Lifecycle.Drain {
		owner = spec.Owner
	} else if spec, err := network.DecodeTunnel(d.Resource.Spec); err == nil && !spec.Lifecycle.Drain {
		kind, owner = "tunnel", spec.Owner
	}
	if owner != r.owner {
		return network.ConsumerBudget{}, view, projection, mydcp.ErrAdmission
	}
	ref := deployment.ObjectRef{Key: key, Revision: d.Revision, Generation: d.Resource.Generation}
	raw, err := json.Marshal(control.NativeRequest{Source: ref})
	if err != nil {
		return network.ConsumerBudget{}, view, projection, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reply, err := r.appCall(ctx, "app-native-permit", raw)
	if err != nil {
		return network.ConsumerBudget{}, view, projection, err
	}
	permit, err := schema.Decode[control.NativePermit](reply.Data)
	if err != nil || reply.Local || reply.Schema != 1 || reply.Code != "ok" || permit.Source != ref || permit.Owner != r.Identity.Public || permit.Kind != kind || permit.Spec != sha256.Sum256([]byte(d.Resource.Spec)) || permit.MaxConsumers < 1 || permit.MaxConsumers > 65536 {
		return network.ConsumerBudget{}, view, projection, mydcp.ErrAdmission
	}
	if permit.Consumers == nil || !permit.Consumers.Valid() || permit.Consumers.Scope.Owner != r.owner || permit.Consumers.Scope.Node != r.installation.record.Root.Self.ID || permit.MaxConsumers != min(permit.Consumers.NodeMaxConsumers, permit.Consumers.TenantMaxConsumers) {
		return network.ConsumerBudget{}, view, projection, mydcp.ErrAdmission
	}
	view, err = r.Engine().ReadAtLeast(ctx, reply.CommandIndex)
	if err != nil {
		return network.ConsumerBudget{}, view, projection, err
	}
	projection, err = r.controlPolicy.ProjectResources(view.State)
	if err != nil {
		return network.ConsumerBudget{}, view, projection, err
	}
	return *permit.Consumers, view, projection, nil
}
