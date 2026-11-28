// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

var errNetworkLeaveRefused = errors.New("network leave report refused")

// drainedMembers are this server's drained workspace network members that
// are not in a planned change: a user removed them (drain-network) and they
// only wait for their native sources to go. A member drained for a planned
// change is fenced instead, and the system network leaves on its own steps
// (reconcileSystemNetwork).
func drainedMembers(networks tenancy.Networks, node string, owner [32]byte) []tenancy.Network {
	var out []tenancy.Network
	for _, m := range networks.AllNetworks() {
		if m.Node == node && m.Owner == owner && m.Tenant != "" && !m.System && m.Logical != "" && m.Draining && m.PendingChange == 0 {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tenant != out[j].Tenant {
			return out[i].Tenant < out[j].Tenant
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// reconcileNetworkLeaves sends at most one network-leave report per pass:
// the first drained member whose native sources are gone leaves on this
// server's own closure, so a network delete or a server removal finishes
// without the client that started it.
func (r *Runtime) reconcileNetworkLeaves(ctx context.Context, v cluster.View) error {
	if r.historicalOwner || !r.networkEnabled || r.network == nil || r.tunnel == nil || r.installation == nil {
		return nil
	}
	node := r.installation.record.Root.Self.ID
	resources, err := r.controlPolicy.Resources(v.State)
	if err != nil {
		return err
	}
	members := drainedMembers(resources.Networks, node, r.Identity.Public)
	if len(members) == 0 {
		return nil
	}
	projection, err := r.controlPolicy.ProjectResources(v.State)
	if err != nil {
		return err
	}
	for _, m := range members {
		closure, err := r.managedNetworkClosure(ctx, v, projection, m)
		if err != nil {
			return fmt.Errorf("network %s/%s: %w", m.Tenant, m.ID, err)
		}
		if closure == nil {
			continue // something still uses it
		}
		return r.publishNetworkLeave(ctx, v, m, *closure)
	}
	return nil
}

func (r *Runtime) publishNetworkLeave(ctx context.Context, v cluster.View, m tenancy.Network, closure tenancy.NetworkClosure) error {
	report := control.NetworkLeaveReport{Schema: 1, Kind: "network-leave", Cluster: r.controlPolicy.Cluster, Reporter: r.Identity.Public,
		Expected: m.Revision, Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.ResourcesKey).Revision, Closure: closure}
	report.Signature = ed25519.Sign(r.Identity.Private, control.NetworkLeaveReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "network-leave-report", raw)
	if err != nil {
		return err
	}
	switch {
	case reply.Committed == nil:
		return errNetworkLeaveRefused
	case reply.Committed.Result.Code == state.ConditionFailed:
		// Usually the view moved meanwhile and the next pass reads again
		// (for the last member: its DNS is still on). Said once.
		r.networkLeaves.refused(m)
		return nil
	case reply.Committed.Result.Code != state.Applied:
		return errNetworkLeaveRefused
	}
	log.Printf("network %s/%s: this server left (drained, nothing uses it)", m.Tenant, m.Logical)
	return nil
}

// networkLeaveProblem logs a leave the cluster refused as a condition
// failure once per member revision, not on every pass.
type networkLeaveProblem struct {
	mu   sync.Mutex
	last string
}

func (p *networkLeaveProblem) refused(m tenancy.Network) {
	key := fmt.Sprintf("%s/%s/%d", m.Tenant, m.ID, m.Revision)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last == key {
		return
	}
	p.last = key
	log.Printf("network %s/%s: leave refused at revision %d (condition failed; the last server leaves only once the network's DNS is off); retrying", m.Tenant, m.Logical, m.Revision)
}
