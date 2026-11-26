// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

var errSystemNetworkRefused = errors.New("system network report refused")

// systemNetworkStep is this server's next step on the system network
// (devel/design/node-apps.md 3.1), or "" when there is none: use when its
// node_apps and the recorded use differ, join while the network is used and
// this server is not a member, drain while it is unused, and leave once
// drained and its native sources are gone. users are the servers using it
// that are still in the cluster (control.Policy.SystemNetworkUsers).
func systemNetworkStep(networks tenancy.Networks, users []string, node string, want, work bool) (action string, member tenancy.Network) {
	members := networks.SystemMembers()
	i := slices.IndexFunc(members, func(m tenancy.Network) bool { return m.Node == node })
	if i >= 0 {
		member = members[i]
	}
	switch {
	case want != slices.Contains(networks.SystemPolicy().Users, node) && (!want || work):
		return "use", member
	case i >= 0 && member.Draining:
		return "leave", member
	case i >= 0 && len(users) == 0:
		return "drain", member
	case i < 0 && len(users) != 0 && work && !slices.ContainsFunc(members, func(m tenancy.Network) bool { return m.Draining || m.PendingChange != 0 }):
		return "join", member
	}
	return "", member
}

// reconcileSystemNetwork sends at most one system network report per pass.
func (r *Runtime) reconcileSystemNetwork(ctx context.Context, v cluster.View) error {
	if r.historicalOwner || !r.networkEnabled || r.network == nil || r.tunnel == nil || r.installation == nil {
		return nil
	}
	node := r.installation.record.Root.Self.ID
	resources, err := r.controlPolicy.Resources(v.State)
	if err != nil {
		return err
	}
	directory, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return err
	}
	networks := resources.Networks
	want := len(r.installation.config.NodeApps.Enabled()) > 0
	users := r.controlPolicy.SystemNetworkUsers(v.State, networks)
	action, member := systemNetworkStep(networks, users, node, want, directory.WorkKey(r.Identity.Public))
	report := control.SystemNetworkReport{Node: node, Action: action, On: action == "use" && want, Expected: networks.Revision()}
	switch action {
	case "":
		return nil
	case "use", "join":
		creates := action == "join" || report.On && len(networks.SystemMembers()) == 0
		if _, err := networks.NextSystemMember(node, r.Identity.Public); creates && err != nil {
			// The range has no free tunnel address or pool. Say so once
			// per networks revision instead of failing every pass.
			if r.systemNetworkFull.Swap(networks.Revision()) != networks.Revision() {
				log.Printf("system network: no free address in its range for node %s; widen it with mydc network system set-range", node)
			}
			return nil
		}
	case "drain":
		report.Expected = member.Revision
	case "leave":
		projection, err := r.controlPolicy.ProjectResources(v.State)
		if err != nil {
			return err
		}
		closure, err := r.managedNetworkClosure(ctx, v, projection, member)
		if err != nil || closure == nil {
			return err // native sources not gone yet
		}
		report.Expected, report.Closure = member.Revision, closure
	}
	return r.publishSystemNetwork(ctx, v, report)
}

func (r *Runtime) publishSystemNetwork(ctx context.Context, v cluster.View, report control.SystemNetworkReport) error {
	report.Schema, report.Cluster, report.Reporter = 1, r.controlPolicy.Cluster, r.Identity.Public
	report.Epoch, report.RootRevision = v.State.ModuleEpoch(), v.State.Object(control.ResourcesKey).Revision
	report.Signature = ed25519.Sign(r.Identity.Private, control.SystemNetworkReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "system-network-report", raw)
	if err != nil {
		return err
	}
	switch {
	case reply.Committed == nil:
		return errSystemNetworkRefused
	case reply.Committed.Result.Code == state.ConditionFailed:
		return nil // the view moved meanwhile; the next pass reads again
	case reply.Committed.Result.Code != state.Applied:
		return errSystemNetworkRefused
	}
	return nil
}
