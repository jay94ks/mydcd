// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func (r *Runtime) projectManagedDNS(ctx context.Context, v cluster.View) (bool, error) {
	if r.network == nil {
		return false, nil
	}
	updates, err := r.controlPolicy.ManagedDNSUpdates(v.State, r.Identity.Public)
	if err != nil || len(updates) == 0 {
		return false, err
	}
	// One whole logical network per original snapshot/root CAS. A subsequent
	// controller pass re-reads the root before considering another network.
	return true, r.sendNetworkDNSProgress(ctx, updates[0])
}

func (r *Runtime) sendNetworkDNSProgress(ctx context.Context, report control.NetworkDNSProgress) error {
	report.Reporter = r.commandIdentity().Public
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.NetworkDNSProgressBytes(report))
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "network-dns-progress", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil {
		return fmt.Errorf("network DNS progress has no original commit result")
	}
	switch reply.Committed.Result.Code {
	case state.Applied, state.ConditionFailed:
		// This is derived metadata, never a native effect or new Task. A CAS
		// loser simply re-reads the current root; an unknown reply likewise
		// cannot cause native dispatch or a second consumer allocation here.
		return nil
	default:
		return fmt.Errorf("network DNS progress rejected: %v", reply.Committed)
	}
}

// DNS projection joins the same app report/FSM path before workload native
// activation. It publishes committed configuration, never a socket/Ready fact.
func (r *Runtime) projectAppDNS(ctx context.Context, v cluster.View, apps control.Apps, projection control.ResourceProjection) (bool, error) {
	if r.network == nil {
		return false, nil
	}
	for _, app := range apps.Records() {
		i, found := apps.Inventory(app.Tenant, app.App)
		if !found {
			continue
		}
		if _, retiring := i.Retirement(); retiring {
			continue
		}
		e, active := i.Execution()
		if !active || e.Status() == "Paused" || e.Status() == "Stopping" || e.Status() == "Closed" || e.Status() == "Failed" {
			continue
		}
		for _, step := range e.Steps() {
			if step.Kind != "dns" || step.Owner != r.Identity.Public {
				continue
			}
			stage, found := e.Stage(step.Key)
			if !found || stage.Result == nil || stage.Result.Code != state.Applied {
				continue
			}
			changed, err := apps.DNSProjectionNeeded(v.State, projection, app.Tenant, app.App, step.Key)
			if err != nil {
				return false, err
			}
			if changed {
				return true, r.appProgress(ctx, v, app, "project-dns", step.Key, nil)
			}
		}
	}
	return false, nil
}
