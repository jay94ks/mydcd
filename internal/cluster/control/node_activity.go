// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// NodeActivity reads the existing shared owners and original reference sets.
// It never equates a withdrawn grant, expired ticket or unreachable peer with
// native closure. Kept Volume data and immutable script/cache bytes are not
// running work; their active writers/readers/builds are counted separately.
func (p Policy) NodeActivity(s state.State, owner [32]byte) (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(owner) {
		return activity, ErrCatalog
	}
	matches := func(key [32]byte) bool { return members.OwnsResource(owner, key) }
	builds, buildErr := p.ImageBuilds(s)
	if buildErr != nil {
		return activity, buildErr
	}
	for _, row := range builds.CachePrunes {
		q, err := row.Change()
		source, found := builds.Job(q.Tenant, row.Source)
		if err != nil || !found {
			return activity, ErrCatalog
		}
		if row.Pending() && matches(source.Run.Spec.Scope.Root.Key) {
			activity.Resources++
		}
	}
	for _, job := range builds.Jobs {
		if matches(job.Run.Spec.Scope.Root.Key) && !job.Run.Terminal() {
			activity.Resources++
		}
	}
	for _, r := range builds.Uploads {
		if matches(r.Scope.Root.Key) && r.Reclaimed == nil && (!r.Closed || !builds.ArtifactReferenced(r)) {
			activity.Resources++
		}
	}

	maintenance, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return activity, err
	}
	for _, row := range maintenance.Records {
		if row.Pending() && matches(row.Change.OwnerKey()) {
			activity.Resources++
		}
	}
	caches, err := p.ImageCacheJobs(s)
	if err != nil {
		return activity, err
	}
	for _, row := range caches.Records {
		if matches(row.Plan.Owner) && (row.State == "queued" || row.State == "running") {
			activity.Resources++
		}
	}
	tunnels, err := p.TunnelReconnections(s)
	if err != nil {
		return activity, err
	}
	for _, row := range tunnels.Records {
		if (matches(row.Plan.Owner) || matches(row.Plan.PeerKey)) && (row.State == "queued" || row.State == "running") {
			activity.Resources++
		}
	}
	jobs, err := p.Compactions(s)
	if err != nil {
		return activity, err
	}
	for _, record := range jobs.Records {
		for _, n := range record.Job.Nodes {
			if matches(n.Key) && (n.State == "queued" || n.State == "running") {
				activity.Resources++
			}
		}
	}
	apps, err := p.Apps(s)
	if err != nil {
		return activity, err
	}
	for _, app := range apps.entries {
		for _, row := range app.TaskRestarts {
			if matches(row.Plan.Container.Owner) && (row.Control == nil || !row.Control.Terminal()) {
				activity.Resources++
			}
		}
		for _, claim := range app.Inventory.Claims() {
			if matches(claim.Step.Owner) && !claim.Removed && claim.Step.Kind != "volume" {
				activity.Resources++
			}
		}
		if execution, found := app.Inventory.Execution(); found {
			for _, step := range execution.Steps() {
				stage, _ := execution.Stage(step.Key)
				if matches(step.Owner) && stage.Journal.Pending != nil {
					activity.Resources++
				}
			}
		}
	}
	for _, binding := range apps.bindings.Live() {
		if matches(binding.Needs().Use.NodeKey) {
			activity.Leases++
		}
	}
	resources, err := p.Resources(s)
	if err != nil {
		return activity, err
	}
	for _, reservation := range resources.Quotas.Reservations() {
		if matches(reservation.Owner) {
			activity.Leases++
		}
	}
	if apps.network != nil {
		for _, ref := range apps.network.Authority.ReferenceConsumers() {
			if matches(ref.Local.Owner) && ref.Closed == nil {
				activity.Leases++
				if ref.Route != nil {
					activity.Flows++
				}
			}
		}
	}
	v, err := p.Volumes(s)
	if err != nil {
		return activity, err
	}
	for _, file := range v.files {
		if file.Phase == "Reserved" && matches(file.Native.Owner.Key) {
			// A disconnected/unknown file effect keeps its original job in
			// addition to the exact shared consumer until signed positive close.
			activity.Resources++
		}
	}
	for _, volume := range v.entries {
		for _, consumer := range volume.State.Consumers() {
			if !matches(consumer.Owner.Key) {
				continue
			}
			if consumer.Writable {
				activity.Writers++
			} else {
				activity.Leases++
			}
		}
		for _, move := range volume.State.Moves() {
			if (matches(move.Binding.Source.Key) || matches(move.Binding.Target.Key)) && move.Phase != volumes.Completed && move.Phase != volumes.Cancelled {
				activity.Leases++
			}
		}
	}
	for _, backup := range v.backups {
		if matches(backup.Binding.Source.Owner.Key) && (backupPending(backup.Phase) || backup.Phase == "Deleting") {
			activity.Leases++
		}
	}
	for _, restore := range v.restores {
		if restorePending(restore.Phase) {
			backup, found := v.backups[backupKey(restore.Binding.Backup.Scope, restore.Binding.Backup.ID)]
			if !found {
				return activity, ErrCatalog
			}
			if matches(restore.Binding.Target.NodeKey) || matches(backup.Binding.Source.Owner.Key) {
				activity.Leases++
			}
		}
	}
	for _, creation := range v.creations {
		if matches(creation.Spec.NodeKey) && creation.Phase != "Ready" && creation.Phase != "Cancelled" && creation.Phase != "Unregistered" {
			activity.Resources++
		}
	}
	registries, err := p.Registries(s)
	if err != nil {
		return activity, err
	}
	external, sourceErr := p.ExternalRegistries(s)
	if sourceErr != nil {
		return activity, sourceErr
	}
	for _, entry := range external {
		if entry.Reader != nil && matches(entry.Reader.Owner) {
			activity.Leases++
		}
	}
	for _, entry := range registries.Entries() {
		if entry.Active != nil && matches(entry.Active.Owner) {
			activity.Resources++
		}
	}
	scripts, err := p.Lifecycles(s)
	if err != nil {
		return activity, err
	}
	for _, use := range scripts.Uses() {
		local := matches(use.Owner)
		for _, source := range use.Sources {
			local = local || matches(source.Owner)
		}
		for _, ref := range use.Scripts {
			record, found := scripts.Script(use.Tenant, ref.Name)
			if !found {
				continue
			}
			for _, version := range record.Versions {
				if version.Revision == ref.Revision {
					local = local || matches(version.Source.Owner)
				}
			}
		}
		if local {
			activity.CDJobs++
		}
	}
	for _, job := range scripts.BuildJobs() {
		if matches(job.Intent.Owner) && job.Phase != "closed" {
			activity.CDJobs++
		}
	}
	vault, err := p.Vault(s)
	if err != nil {
		return activity, err
	}
	for _, tree := range vault.Trees {
		activity.Leases += tree.PendingWrites(owner)
	}
	return activity, nil
}

// NodeRuntimeWork contains the current policy and SHARED blockers only. Native
// managers and local in-flight work must still be inspected by the owner.
type NodeRuntimeWork struct {
	Schema                                                            uint8
	Cluster, Owner                                                    [32]byte
	Node                                                              lifecycle.Node
	Activity                                                          lifecycle.Activity
	Index, Epoch, RootRevision, DirectoryRevision, ConfigurationIndex uint64
}

func (p Policy) NodeRuntimeWork(s state.State, owner [32]byte) (NodeRuntimeWork, error) {
	var work NodeRuntimeWork
	d, err := p.Members(s)
	if err != nil || !d.MemberKey(owner) {
		return work, ErrCatalog
	}
	topology, err := d.Topology()
	if err != nil {
		return work, err
	}
	for _, member := range topology.Configuration().Members {
		if member.Key != owner {
			continue
		}
		node, found := topology.Node(member.ID)
		if !found {
			return work, ErrCatalog
		}
		activity, err := p.NodeActivity(s, owner)
		if err != nil {
			return work, err
		}
		return NodeRuntimeWork{Schema: 1, Cluster: p.Cluster, Owner: owner, Node: node, Activity: activity, Index: s.Index(), Epoch: s.ModuleEpoch(), RootRevision: s.Object(MembersKey).Revision, DirectoryRevision: d.Revision, ConfigurationIndex: topology.Configuration().Index}, nil
	}
	return work, ErrCatalog
}
