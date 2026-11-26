// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/moby/moby/client"
)

// installedTopology consumes the SDK configuration already checked against the
// durable FSM prefix by Engine.InstalledConfiguration. Directory entries supply
// authenticated keys, never a replacement voting configuration.
func installedTopology(installed cluster.InstalledConfiguration, directory membership.Directory) (lifecycle.Configuration, error) {
	c := lifecycle.Configuration{Index: installed.Index}
	if installed.Index == 0 || installed.AppliedIndex < installed.Index {
		return c, cluster.ErrRecovering
	}
	for _, server := range installed.Configuration.Servers {
		entry, exists := directory.Entry(string(server.ID))
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		if !exists || err != nil || entry.Peer.Endpoint != string(server.Address) || server.Suffrage != raft.Voter && server.Suffrage != raft.Nonvoter {
			return c, membership.ErrMember
		}
		c.Members = append(c.Members, lifecycle.Member{ID: entry.Peer.ID, Key: key, Voter: server.Suffrage == raft.Voter})
	}
	slices.SortFunc(c.Members, func(a, b lifecycle.Member) int { return strings.Compare(a.ID, b.ID) })
	return c, c.Validate()
}

// reconcileNodeLifecycle runs at the end of the existing native module pass on
// EVERY owner, not only the leader. It reports actual original closure or fresh
// readiness; normal app down/move/network drain perform the resource effects.
func (r *Runtime) reconcileNodeLifecycle(ctx context.Context, local cluster.View) error {
	if r.installation == nil || r.historicalOwner {
		return nil
	}
	directory, err := r.controlPolicy.Members(local.State)
	if err != nil || directory.Runtime == nil {
		return err
	}
	topology, err := directory.Topology()
	if err != nil {
		return err
	}
	node, found := topology.Node(r.installation.record.Root.Self.ID)
	if !found || node.Pending == nil || node.Closure != nil && node.Closure.ConfigurationIndex == topology.Configuration().Index {
		return nil
	}
	if node.Pending.Action == lifecycle.ForceRemove {
		return r.stopNodePacketPlanes()
	}
	if err := r.stopNodePacketPlanes(); err != nil {
		return err
	}
	// The same barriers used by shutdown keep already accepted provider/input
	// work from crossing a zero census. Never wait behind unbounded native IO.
	if !r.inputLife.TryLock() {
		return nil
	}
	defer r.inputLife.Unlock()
	if !r.vaultApprovalLife.TryLock() {
		return nil
	}
	defer r.vaultApprovalLife.Unlock()
	if !r.life.TryLock() {
		return nil
	}
	defer r.life.Unlock()
	if r.closed || ctx.Err() != nil {
		return ctx.Err()
	}
	reply, err := r.appCall(ctx, "node-runtime-work", []byte("{}"))
	if err != nil {
		return err
	}
	work, err := schema.Decode[control.NodeRuntimeWork](reply.Data)
	if err != nil || work.Schema != 1 || work.Cluster != r.controlPolicy.Cluster || work.Owner != r.Identity.Public || work.Node.Member.ID != node.Member.ID || work.Node.Member.Key != r.Identity.Public || work.Node.Pending == nil || *work.Node.Pending != *node.Pending || work.Index == 0 || work.Index != reply.CommandIndex || work.RootRevision == 0 {
		return membership.ErrMember
	}
	if !work.Activity.Empty() {
		return nil
	}
	view, err := r.Engine().ReadAtLeast(ctx, work.Index)
	if err != nil {
		return err
	}
	directory, err = r.controlPolicy.Members(view.State)
	if err != nil || directory.Revision != work.DirectoryRevision || view.State.Object(control.MembersKey).Revision != work.RootRevision || view.State.ModuleEpoch() != work.Epoch {
		return membership.ErrMember
	}
	activity, err := r.nodeLocalActivity(ctx)
	if err != nil || !activity.Empty() {
		return err
	}
	installed, err := r.Engine().InstalledConfiguration(ctx, false)
	if err != nil {
		return err
	}
	configuration, err := installedTopology(installed, directory)
	if err != nil || configuration.Index != work.ConfigurationIndex {
		return cluster.ErrRecovering
	}
	self, found := configuration.Member(node.Member.ID)
	if !found || self.Key != r.Identity.Public || r.installation.record.Root.Resume(work.Cluster, self) != nil {
		return membership.ErrMember
	}
	if work.Node.Pending.Action == lifecycle.Restore && r.docker != nil {
		if _, err := r.docker.API.Ping(ctx, client.PingOptions{}); err != nil {
			return err
		}
	}
	proof := lifecycle.Proof{Cluster: work.Cluster, Node: work.Node.Member.ID, Operation: work.Node.Pending.ID, Generation: work.Node.Generation, Revision: work.Node.Pending.Revision, ConfigurationIndex: work.ConfigurationIndex, Closed: work.Node.Pending.Action != lifecycle.Restore, Ready: work.Node.Pending.Action == lifecycle.Restore}
	proof.Signature = ed25519.Sign(r.Identity.Private, lifecycle.ProofBytes(proof))
	return r.memberReport(ctx, view, control.MemberReport{Action: "node-proof", Node: proof.Node, Expected: work.DirectoryRevision, Proof: &proof})
}

// Stopping packet IO does not return its durable reference or assert native
// Gone. Explicit existing drain/retirement still owns those transitions.
func (r *Runtime) stopNodePacketPlanes() error {
	if r.tunnel == nil {
		return nil
	}
	t := r.tunnel
	t.mu.Lock()
	instances := make([]*tunnelInstance, 0, len(t.instances)+len(t.routes))
	for _, instance := range t.instances {
		instances = append(instances, instance)
	}
	for _, instance := range t.routes {
		instances = append(instances, instance)
	}
	t.mu.Unlock()
	var failed error
	for _, instance := range instances {
		instance.mu.Lock()
		failed = errors.Join(failed, instance.stopPlane())
		instance.mu.Unlock()
	}
	return failed
}

// syncMemberConfiguration publishes only a changed, actually installed prefix.
// The same Directory checkpoint settles the original removal A2 atomically.
func (r *Runtime) syncMemberConfiguration(ctx context.Context) error {
	r.memberMu.Lock()
	defer r.memberMu.Unlock()
	view, d, err := r.members(ctx, false)
	if err != nil {
		return err
	}
	installed, err := r.Engine().InstalledConfiguration(ctx, false)
	if err != nil {
		return err
	}
	c, err := installedTopology(installed, d)
	if err != nil {
		return err
	}
	if d.Runtime != nil {
		topology, err := d.Topology()
		if err != nil {
			return err
		}
		previous := topology.Configuration()
		if previous.Index == c.Index && slices.Equal(previous.Members, c.Members) {
			return nil
		}
	}
	// An unchanged local prefix needs no quorum round trip on every idle tick.
	// A changed publication refreshes both inputs behind the normal barrier.
	view, d, err = r.members(ctx, true)
	if err != nil {
		return err
	}
	installed, err = r.Engine().InstalledConfiguration(ctx, true)
	if err != nil {
		return err
	}
	c, err = installedTopology(installed, d)
	if err != nil {
		return err
	}
	// Check locally before submitting, so a still-unobserved join never produces
	// a stream of rejected reports. The committed reducer repeats this check.
	updated, err := d.InstallConfiguration(c)
	if err != nil {
		return err
	}
	if updated.Revision == d.Revision {
		return nil
	}
	return r.memberReport(ctx, view, control.MemberReport{Action: "configuration", Node: r.installation.record.Root.Self.ID, Expected: d.Revision, Configuration: &c})
}

// advanceNodeRemoval grants exactly one RemoveServer invocation to the caller
// that commits Prepared -> Dispatched. A later leader/process only observes the
// same effect; absence, timeout and lost replies never authorize another call.
func (r *Runtime) advanceNodeRemoval(ctx context.Context, id string) error {
	r.memberMu.Lock()
	defer r.memberMu.Unlock()
	view, d, err := r.members(ctx, true)
	if err != nil {
		return err
	}
	op, exists := d.NodeOperation(id)
	if !exists || op.Action != lifecycle.Remove && op.Action != lifecycle.ForceRemove {
		return membership.ErrMember
	}
	if op.Job.Pending == nil {
		return nil
	}
	if op.Job.Pending.Phase != reconcile.Prepared {
		// The controller's configuration publication is the sole success path.
		// Unknown keeps its original SDK identity and durable target.
		if op.Job.Pending.Phase == reconcile.Dispatched {
			return r.memberReport(ctx, view, control.MemberReport{Action: "remove-unknown", Node: op.Node, Operation: op.ID, Expected: d.Revision})
		}
		return nil
	}
	topology, err := d.Topology()
	if err != nil {
		return err
	}
	node, exists := topology.Node(op.Node)
	if !exists || node.Pending == nil || node.Pending.ID != id || (op.Action == lifecycle.Remove && (node.Closure == nil || !node.Closure.Closed) || op.Action == lifecycle.ForceRemove && node.Retirement == nil) {
		return nil
	}
	if err := r.memberPolicy().CheckNodeEffect(view.State, id); err != nil {
		return err
	}
	installed, err := r.Engine().InstalledConfiguration(ctx, true)
	if err != nil {
		return err
	}
	configuration, err := installedTopology(installed, d)
	if err != nil {
		return err
	}
	if previous := topology.Configuration(); configuration.Index != previous.Index || !slices.Equal(configuration.Members, previous.Members) {
		return cluster.ErrRecovering
	}
	self := r.installation.record.Root.Self.ID
	if op.Node == self {
		// Transfer before the application Dispatch. If the successor cannot take
		// leadership, this original removal stays Prepared and sends no SDK effect.
		for _, member := range configuration.Members {
			if member.ID == self || !member.Voter || !topology.AdmitWork(member.ID) {
				continue
			}
			peer, found := d.Entry(member.ID)
			if found {
				return r.Engine().TransferLeadership(ctx, member.ID, peer.Peer.Endpoint)
			}
		}
		return errors.New("no active installed voter can receive leadership before node removal")
	}
	if _, err := d.DispatchRemoval(id, d.Revision, installed.Index, r.Identity.Public); err != nil {
		return err
	}
	if err := r.memberReport(ctx, view, control.MemberReport{Action: "remove-dispatch", Node: op.Node, Operation: id, Expected: d.Revision, ConfigurationIndex: installed.Index}); err != nil {
		return err
	}
	nativeErr := r.Engine().RemoveMember(ctx, op.Node, installed.Index)
	// A successful SDK future alone is not application completion. The next
	// installed prefix publication settles A2 and marks Removed atomically.
	if nativeErr != nil {
		return fmt.Errorf("%w: %v", cluster.ErrUnknown, nativeErr)
	}
	return nil
}
