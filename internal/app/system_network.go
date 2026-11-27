// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

var errSystemNetworkRefused = errors.New("system network report refused")

// systemNetworkStep is this server's next step on the system network
// (devel/design/cluster-apps.md 3.1), or "" when there is none: use when its
// cluster_apps and the recorded use differ, join while the network is used and
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
	want := len(r.installation.config.ClusterApps.Enabled()) > 0
	users := r.controlPolicy.SystemNetworkUsers(v.State, networks)
	work := directory.WorkKey(r.Identity.Public)
	action, member := systemNetworkStep(networks, users, node, want, work)
	report := control.SystemNetworkReport{Node: node, Action: action, On: action == "use" && want, Expected: networks.Revision()}
	// A step the cluster would refuse (no server quota, not a work server,
	// no free pool, ...) is not sent: its reason goes to the log once and
	// to the host report until it clears.
	block := ""
	creates := action == "join" || report.On && len(networks.SystemMembers()) == 0
	switch {
	case creates:
		block = r.controlPolicy.SystemNetworkBlock(v.State, node, r.Identity.Public)
	case want && !work && action == "" && !slices.Contains(networks.SystemPolicy().Users, node):
		block = "not-work-server"
	}
	r.systemNetwork.setBlock(node, block)
	if block != "" {
		return nil
	}
	switch action {
	case "":
		return r.claimClusterApps(ctx, v, networks, users, node)
	case "use", "join":
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
		// Usually the view moved meanwhile and the next pass reads again.
		// The same report refused again is not a race: say so once.
		r.systemNetwork.refused(report)
		return nil
	case reply.Committed.Result.Code != state.Applied:
		return errSystemNetworkRefused
	}
	return nil
}

// claimClusterApps sends at most one run report per pass: an app node.yaml
// turns on that no current user runs yet. An app another server runs is
// refused for the rest of this sfcd's life (clusterAppProblems.refuse).
func (r *Runtime) claimClusterApps(ctx context.Context, v cluster.View, networks tenancy.Networks, users []string, node string) error {
	for _, app := range r.installation.config.ClusterApps.Enabled() {
		if _, refused := r.clusterAppProblems.refusedBy(app); refused {
			continue
		}
		switch step, runner := clusterAppStep(networks, users, node, app); step {
		case "refuse":
			r.clusterAppProblems.refuse(app, runner)
		case "run":
			return r.publishSystemNetwork(ctx, v, control.SystemNetworkReport{Node: node, Action: "run", App: app, Expected: networks.Revision()})
		}
	}
	return nil
}

// clusterAppStep: what node does about app it turns on. "refuse" when
// another current user runs it (runner), "run" to claim it once node uses
// the network as a member that is not draining, "" otherwise (it runs it
// already, or it waits).
func clusterAppStep(networks tenancy.Networks, users []string, node, app string) (step, runner string) {
	if runner, ok := networks.ClusterAppRunner(app, users); ok {
		if runner != node {
			return "refuse", runner
		}
		return "", runner
	}
	member := slices.ContainsFunc(networks.SystemMembers(), func(m tenancy.Network) bool { return m.Node == node && !m.Draining })
	if member && slices.Contains(users, node) {
		return "run", ""
	}
	return "", ""
}

// systemNetworkProblem remembers what was last logged about this server's
// system network steps, so a blocked or refused step is logged once and
// not on every pass.
type systemNetworkProblem struct {
	mu      sync.Mutex
	block   string // SystemNetworkBlock reason, "" when none
	refusal string // last report refused as a condition failure
}

func (p *systemNetworkProblem) setBlock(node, block string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case block == p.block:
		return
	case block == "":
		log.Printf("system network: node %s is no longer blocked (was %s)", node, p.block)
	default:
		log.Printf("system network: node %s cannot join the system network: %s", node, block)
	}
	p.block = block
}

// blocked is the reason this server cannot join the system network now.
func (p *systemNetworkProblem) blocked() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.block
}

func (p *systemNetworkProblem) refused(report control.SystemNetworkReport) {
	key := fmt.Sprintf("%s/%s/%t/%d", report.Action, report.App, report.On, report.Expected)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.refusal == key {
		log.Printf("system network: %s report for node %s refused again at revision %d (condition failed); retrying", report.Action, report.Node, report.Expected)
	}
	p.refusal = key
}
