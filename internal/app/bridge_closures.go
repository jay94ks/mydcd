// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

var errBridgeClosedRefused = errors.New("virtual bridge closed report refused")

// bridgeClosureOwed is the first closing bridge this server carries and has
// not reported closed yet.
func bridgeClosureOwed(networks tenancy.Networks, node string) (tenancy.VirtualBridge, bool) {
	for _, b := range networks.AllBridges() {
		if b.Phase != tenancy.BridgeClosing || !slices.Contains(networks.BridgeServers(b), node) {
			continue
		}
		if !slices.ContainsFunc(b.Closures, func(c tenancy.BridgeClosure) bool { return c.Node == node }) {
			return b, true
		}
	}
	return tenancy.VirtualBridge{}, false
}

// reconcileBridgeClosures sends at most one virtual-bridge-closed report per
// pass. A bridge has no native routes or rules yet, so there is nothing to
// remove before the report; the packet path adds that step.
func (r *Runtime) reconcileBridgeClosures(ctx context.Context, v cluster.View) error {
	if r.historicalOwner || !r.networkEnabled || r.installation == nil {
		return nil
	}
	node := r.installation.record.Root.Self.ID
	resources, err := r.controlPolicy.Resources(v.State)
	if err != nil {
		return err
	}
	b, owed := bridgeClosureOwed(resources.Networks, node)
	if !owed {
		return nil
	}
	closure := tenancy.BridgeClosure{Cluster: r.controlPolicy.Cluster, Owner: b.A.Tenant, ID: b.ID, Generation: b.Generation, Node: node, Key: r.Identity.Public}
	closure.Signature = ed25519.Sign(r.Identity.Private, tenancy.BridgeClosureBytes(closure))
	report := control.BridgeClosedReport{Schema: 1, Kind: "virtual-bridge-closed", Cluster: r.controlPolicy.Cluster, Reporter: r.Identity.Public,
		Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.ResourcesKey).Revision, Closure: closure}
	report.Signature = ed25519.Sign(r.Identity.Private, control.BridgeClosedReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "virtual-bridge-closed", raw)
	if err != nil {
		return err
	}
	switch {
	case reply.Committed == nil:
		return errBridgeClosedRefused
	case reply.Committed.Result.Code == state.ConditionFailed:
		return nil // the view moved meanwhile; the next pass reads again
	case reply.Committed.Result.Code != state.Applied:
		return errBridgeClosedRefused
	}
	return nil
}
