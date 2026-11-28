// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type NodeDrainQuery struct{ Node, Operation string }

func (q NodeDrainQuery) Valid() bool {
	return lifecycle.ValidID(q.Node) && lifecycle.ValidID(q.Operation)
}

// ValidStatus permits selection of the node's latest relevant original drain.
// Planning and submission still require an explicitly named operation.
func (q NodeDrainQuery) ValidStatus() bool {
	return lifecycle.ValidID(q.Node) && (q.Operation == "" || lifecycle.ValidID(q.Operation))
}

type NodeDrainJob struct {
	AdditionalMoves                            []NodeDrainVolumeMove `json:",omitempty"`
	Move                                       *NodeDrainVolumeMove  `json:",omitempty"`
	CD                                         *AppCDMoveSource      `json:",omitempty"`
	Tenant, App, Deployment, Operation, Target string
	Expected                                   uint64
	Plan                                       [32]byte
	Services                                   []string
	Tasks                                      []deployment.ObjectRef
}
type NodeDrainPlan struct {
	At                                      int64
	Schema                                  uint8
	Node, Operation                         string
	Expected, RootRevision, AppsRoot, Index uint64
	Digest                                  [32]byte
	Needs                                   []volumes.NativeReady `json:",omitempty"`
	Jobs                                    []NodeDrainJob
	Tasks                                   []NodePlanTask
	Blockers                                []NodeBlocker
}
type NodeDrainVolumeMove struct {
	Expected  uint64
	Begin     VolumeMoveBegin
	Recipe    VolumeMoveRecipe
	Blueprint json.RawMessage
}

type NodeDrainChange struct {
	At            int64
	ID, Operation string
	LeaveBlocked  bool
	AppsRoot      uint64
	Plan          [32]byte
	Jobs          []NodeDrainJob
}
type NodeDrainStatus struct {
	Schema                 uint8
	Node, Operation, State string
	Total, Moved, Blocked  int
	Jobs                   []NodeDrainJobStatus
}
type NodeDrainJobStatus struct {
	Tenant, App, Operation, State string
	Total, Moved                  int
}

func drainAppOperation(operation, tenant, app string) string {
	digest := sha256.Sum256([]byte(operation + "\x00" + tenant + "\x00" + app))
	return "drain-" + hex.EncodeToString(digest[:12])
}
func drainPlanDigest(plan NodeDrainPlan) [32]byte {
	plan.Digest = [32]byte{}
	raw, _ := json.Marshal(plan)
	return sha256.Sum256(append([]byte("sfc-node-drain-plan-1\x00"), raw...))
}

func (p Policy) PlanNodeDrain(s state.State, session access.Session, at int64, q NodeDrainQuery) (NodeDrainPlan, error) {
	current, err := p.Current(s)
	if err != nil {
		return NodeDrainPlan{}, err
	}
	c, err := current.Catalog(s)
	if err != nil {
		return NodeDrainPlan{}, err
	}
	if !q.Valid() || c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return NodeDrainPlan{}, access.ErrDenied
	}
	return current.nodeDrainPlan(s, session, at, q)
}
func (p Policy) nodeDrainPlan(s state.State, session access.Session, at int64, q NodeDrainQuery, recipes ...VolumeMoveRecipe) (NodeDrainPlan, error) {
	removal, err := p.nodeRemovalPlan(s, q.Node)
	if err != nil {
		return NodeDrainPlan{}, err
	}
	members, err := p.Members(s)
	if err != nil {
		return NodeDrainPlan{}, err
	}
	out := NodeDrainPlan{At: at, Schema: 1, Node: q.Node, Operation: q.Operation, Expected: members.Cordon(q.Node).Revision, RootRevision: s.Object(MembersKey).Revision, AppsRoot: s.Object(AppsKey).Revision, Index: s.Index(), Tasks: removal.Tasks, Jobs: []NodeDrainJob{}, Blockers: []NodeBlocker{}}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return out, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return out, err
	}
	byApp := map[string][]int{}
	for index, task := range out.Tasks {
		key := appKey(task.Tenant, task.App)
		byApp[key] = append(byApp[key], index)
		out.Tasks[index].Movable = false
		if task.Reason != "STANDALONE_WRITABLE_LAYER_PRESENT" {
			out.Tasks[index].Reason = "NO_ELIGIBLE_TARGET"
		}
	}
	keys := make([]string, 0, len(byApp))
	for key := range byApp {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var queued []deployment.PlannedResource
	for _, key := range keys {
		entry := apps.entries[key]
		execution, active := entry.Inventory.Execution()
		indices := byApp[key]
		reason := ""
		if !active || execution.Status() != "Succeeded" || entry.Down != nil || entry.PendingSync != nil {
			reason = "ORIGINAL_OPERATION_PENDING"
		}
		if reason != "" {
			for _, i := range indices {
				out.Tasks[i].Reason = reason
			}
			continue
		}
		scope := entry.Inventory.Scope()
		ctx, e := p.appPlanningFromApps(s, session.User, scope.Tenant, apps)
		if e != nil {
			return out, e
		}
		ctx.Project, ctx.Deployment = scope.App, scope.Deployment
		ctx.Planned = append(ctx.Planned, queued...)
		for _, held := range queued {
			demand := held.Demand
			if demand.Need.CPU == 0 && demand.Need.Memory == 0 {
				continue
			}
			node, found := ctx.Nodes[demand.Node]
			if !found {
				continue
			}
			node.Used, e = addDemand(node.Used, demand.Need)
			if e != nil {
				return out, e
			}
			ctx.Nodes[demand.Node] = node
		}
		if entry.Delivery != nil {
			ctx.Actor = entry.Delivery.Principal()
			if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, scope.Tenant, access.ManageCD, "") != nil || c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, scope.Tenant, access.ManageCD, "") != nil {
				for _, i := range indices {
					out.Tasks[i].Reason = "CD_AUTHORITY_REQUIRED"
				}
				continue
			}
		}
		if node, ok := ctx.Nodes[q.Node]; ok {
			node.Draining = false
			ctx.Nodes[q.Node] = node
		}
		names := []string{}
		refs := []deployment.ObjectRef{}
		mounts := map[string]bool{}
		for _, i := range indices {
			task := out.Tasks[i]
			if task.Reason == "STANDALONE_WRITABLE_LAYER_PRESENT" {
				continue
			}
			resourceID, _ := deployment.ResourceIDFromKey("task", task.Tenant, task.App, task.Task)
			service, _, e := execution.Blueprint().TaskInput(resourceID)
			if e != nil {
				out.Tasks[i].Reason = "SOURCE_NOT_RETAINED"
				continue
			}
			blocked := ""
			if len(service.FixedVolumes) > 0 {
				blocked = "FIXED_VOLUME_PRESENT"
			}
			declared, known := execution.Blueprint().DeclaredService(task.Service)
			if !known {
				out.Tasks[i].Reason = "SOURCE_NOT_RETAINED"
				continue
			}
			for _, attachment := range declared.Networks {
				if attachment.IPv4 != "" || attachment.IPv6 != "" {
					blocked = "STATIC_ADDRESS_REPLAN_REQUIRED"
				}
			}
			if blocked != "" {
				out.Tasks[i].Reason = blocked
				continue
			}
			for _, mount := range service.Volumes {
				if mount.Type == "volume" {
					mounts[mount.Source] = true
				}
			}
			if !slices.Contains(names, task.Service) {
				names = append(names, task.Service)
			}
			refs = append(refs, deployment.ObjectRef{Key: task.Task, Generation: task.Generation, Revision: task.Revision})
		}
		if len(names) == 0 {
			continue
		}
		slices.Sort(names)
		groupVolumes := []registeredVolume{}
		witnesses := []VolumeMoveRecipe{}
		hasVolume := len(mounts) > 0
		if hasVolume {
			registry, e := p.Volumes(s)
			if e != nil {
				return out, e
			}
			volumeNames := make([]string, 0, len(mounts))
			for name := range mounts {
				volumeNames = append(volumeNames, name)
			}
			slices.Sort(volumeNames)
			ready := true
			for _, name := range volumeNames {
				volume := registry.entries[scope.Tenant+"/"+scope.App+"/"+name]
				if volume.Native.Verify() != nil || volume.Native.Fixed != nil || volume.Native.Owner.Node != q.Node || volume.CapacityBytes < 1024 {
					for _, i := range indices {
						out.Tasks[i].Reason = "VOLUME_SOURCE_OR_CAPACITY_REQUIRED"
					}
					ready = false
					break
				}
				var witness VolumeMoveRecipe
				for _, recipe := range recipes {
					if recipe.Schema == 1 && recipe.NativeBinding == VolumeNativeDigest(volume.Native) && recipe.Compatibility != ([32]byte{}) && recipe.Consumer.Writable && recipe.Consumer.Owner == volume.Native.Owner {
						for _, held := range volume.State.Consumers() {
							if held == recipe.Consumer {
								witness = recipe
							}
						}
					}
				}
				if witness.Schema != 1 {
					out.Needs = append(out.Needs, volume.Native)
					ready = false
				}
				groupVolumes = append(groupVolumes, volume)
				witnesses = append(witnesses, witness)
			}
			if !ready {
				for _, i := range indices {
					if out.Tasks[i].Reason == "NO_ELIGIBLE_TARGET" {
						out.Tasks[i].Reason = "SOURCE_RECIPE_UNAVAILABLE"
					}
				}
				continue
			}
		}

		candidates := make([]string, 0, len(ctx.Nodes))
		for id, node := range ctx.Nodes {
			if id != q.Node && !node.Draining {
				candidates = append(candidates, id)
			}
		}
		slices.Sort(candidates)
		for _, target := range candidates {
			operation := drainAppOperation(q.Operation, scope.Tenant, scope.App)
			job := NodeDrainJob{Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment, Operation: operation, Target: target, Expected: entry.Inventory.Revision(), Services: names, Tasks: refs}
			var plan deployment.Blueprint
			var compileErr error
			if hasVolume {
				placements := []deployment.VolumeMovePlacement{}
				moves := []NodeDrainVolumeMove{}
				active, _ := entry.Inventory.Active()
				for i, volume := range groupVolumes {
					owner, ownerRevision := volume.State.Owner()
					spec := volume.Native.Spec
					spec.Node = target
					spec.NodeKey = ctx.Nodes[target].Key
					id := operation
					if len(groupVolumes) > 1 {
						id = drainAppOperation(q.Operation, scope.Tenant, scope.App+"-"+volume.State.Scope().ID)
					}
					spec.Materialization = "m-" + id
					targetOwner, e := restoreTargetOwner(spec)
					if e != nil {
						compileErr = e
						break
					}
					placements = append(placements, deployment.VolumeMovePlacement{Scope: volume.State.Scope(), Source: owner, SourceOwnerRevision: ownerRevision, Target: targetOwner})
					moves = append(moves, NodeDrainVolumeMove{Expected: volume.State.Revision(), Recipe: witnesses[i], Begin: VolumeMoveBegin{Scope: volume.State.Scope(), ID: id, OwnerRevision: ownerRevision, Target: spec, Compatibility: witnesses[i].Compatibility, MaxBytes: volume.CapacityBytes, CapacityBytes: volume.CapacityBytes, MaxEntries: 100000, ExpiresAt: at + 86400, App: &VolumeMoveApp{Operation: active.ID, Revision: entry.Inventory.Revision(), Plan: active.Plan, Target: &VolumeMoveTargetApp{Upload: operation, Operation: operation}}}})
				}
				if compileErr != nil {
					continue
				}
				placement := placements[0]
				placement.Others = placements[1:]
				plan, compileErr = execution.Blueprint().RelocateVolumeNode(c, ctx, q.Node, target, names, placement)
				if compileErr == nil {
					artifact, e := plan.Encode()
					if e != nil {
						continue
					}
					for i := range moves {
						moves[i].Begin.App.Target.Plan = plan.Digest()
					}
					moves[0].Blueprint = artifact
					job.Move = &moves[0]
					job.AdditionalMoves = moves[1:]
				}

			} else {
				plan, compileErr = execution.Blueprint().RelocateNode(c, ctx, q.Node, target, names)
			}
			if compileErr != nil {
				continue
			}
			allowed := true
			for _, step := range plan.Steps() {
				if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, scope.Tenant, step.Action(), step.Node) != nil || entry.Delivery != nil && c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, scope.Tenant, step.Action(), step.Node) != nil {
					allowed = false
					break
				}
			}
			if !allowed {
				continue
			}
			job.Plan = plan.Digest()
			if entry.Delivery != nil {
				job.CD = &AppCDMoveSource{Registration: appRegistrationDigest(entry.Origin), Principal: entry.Delivery.Principal(), Requester: entry.Origin.Session.Key, PolicyRevision: entry.Delivery.PolicyRevision(), OverrideRevision: entry.Delivery.OverrideRevision(), Intent: plan.IntentDigest(), Input: plan.AppInputDigest()}
				if job.Move != nil {
					job.Move.Begin.App.CD = job.CD
					for i := range job.AdditionalMoves {
						job.AdditionalMoves[i].Begin.App.CD = job.CD
					}
				}
			}
			if job.Move == nil {
				replacement, e := entry.Inventory.ReplacementPlan(plan, false)
				if e != nil || replacement != nil && replacement.BlockedCode != "" {
					continue
				}
				submitter := "user/" + hex.EncodeToString(session.Key[:])
				if entry.Delivery != nil {
					identity, e := appExecutionOrigin(entry.Origin, entry.Sync, scope)
					if e != nil {
						return out, e
					}
					submitter = identity.Submitter
					delivery, e := entry.Delivery.StartRelocated(entry.Delivery.Revision(), c, ctx, plan, session.User, operation, submitter, s.ModuleEpoch())
					if e != nil {
						continue
					}
					entry.Delivery = &delivery
					entry.Inventory = delivery.Inventory()
				} else {
					inventory, e := entry.Inventory.Begin(job.Expected, c, ctx, plan, operation, submitter, s.ModuleEpoch(), false)
					if e != nil {
						continue
					}
					entry.Inventory = inventory
				}
				apps.entries[key] = entry
			}
			out.Jobs = append(out.Jobs, job)
			if job.Move != nil {
				demands, e := plan.ResourceDemands()
				if e != nil {
					return out, e
				}
				for _, demand := range demands {
					if current, exists := ctx.Current[demand.Key]; exists {
						if goal, e := deployment.DecodeGoalResources(p.Cluster, demand.Key, current); e == nil && demand.Matches(goal.Goal) {
							continue
						}
					}
					queued = append(queued, deployment.PlannedResource{Origin: plan.Digest(), Scope: plan.Scope(), Demand: demand})
				}
			}
			for _, i := range indices {
				if slices.Contains(names, out.Tasks[i].Service) {
					out.Tasks[i].Movable = true
					out.Tasks[i].Reason = ""
					out.Tasks[i].Target = target
				}
			}
			break
		}
	}

	for _, task := range out.Tasks {
		if !task.Movable {
			out.Blockers = append(out.Blockers, NodeBlocker{Code: task.Reason, Detail: task.Task})
		}
	}
	out.Digest = drainPlanDigest(out)
	return out, nil
}

func (p Policy) beginNodeDrain(s state.State, op UserOperation, cmd state.Command) (map[string][]byte, state.Code) {
	var q NodeDrainChange
	if canonical(op.Change.Payload, &q) != nil || q.At <= 0 || q.At > op.At || op.At-q.At > 30 || !lifecycle.ValidID(q.Operation) || !lifecycle.ValidID(q.ID) {
		return nil, state.Invalid
	}
	plan, err := p.nodeDrainPlan(s, op.Session, q.At, NodeDrainQuery{Node: q.ID, Operation: q.Operation}, drainRecipes(q.Jobs)...)
	if err != nil {
		return nil, state.Invalid
	}
	rawJobs, _ := json.Marshal(q.Jobs)
	plannedJobs, _ := json.Marshal(plan.Jobs)
	if q.AppsRoot != plan.AppsRoot || q.Plan != plan.Digest || op.Change.Expected != plan.Expected || string(rawJobs) != string(plannedJobs) {
		return nil, state.ConditionFailed
	}
	if !q.LeaveBlocked && len(plan.Blockers) > 0 {
		return nil, state.NodeTasksPresent
	}
	apps, err := p.Apps(s)
	if err != nil {
		return nil, state.Invalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	for _, job := range plan.Jobs {
		if job.Move != nil {
			continue
		}
		key := appKey(job.Tenant, job.App)
		entry := apps.entries[key]
		execution, found := entry.Inventory.Execution()
		if !found {
			return nil, state.ConditionFailed
		}
		ctx, err := p.appPlanningFromApps(s, op.Session.User, job.Tenant, apps)
		if err != nil {
			return nil, state.Invalid
		}
		ctx.Project, ctx.Deployment = job.App, job.Deployment
		if entry.Delivery != nil {
			ctx.Actor = entry.Delivery.Principal()
		}
		if node, found := ctx.Nodes[q.ID]; found {
			node.Draining = false
			ctx.Nodes[q.ID] = node
		}
		target, err := execution.Blueprint().RelocateNode(c, ctx, q.ID, job.Target, job.Services)
		if err != nil || target.Digest() != job.Plan {
			return nil, state.ConditionFailed
		}
		if entry.Delivery != nil {
			if job.CD == nil || !cdMoveSourceMatches(entry, job.CD, true) {
				return nil, state.ConditionFailed
			}
			identity, e := appExecutionOrigin(entry.Origin, entry.Sync, entry.Inventory.Scope())
			if e != nil {
				return nil, state.ConditionFailed
			}
			delivery, e := entry.Delivery.StartRelocated(entry.Delivery.Revision(), c, ctx, target, op.Session.User, job.Operation, identity.Submitter, cmd.Epoch)
			if e != nil {
				return nil, state.ConditionFailed
			}
			selected, ok := delivery.Selection()
			if !ok {
				return nil, state.ConditionFailed
			}
			choice := AppDeliveryChoice{Operation: selected.Operation, Candidate: selected.Candidate, Registration: appRegistrationDigest(entry.Origin)}
			proof := syncFromChoice(choice, selected, cmd.Epoch, &op, nil)
			proof.Local = ownLocalGrant(entry.Local)
			if proof.verify(entry.Origin, entry.Inventory.Scope()) != nil {
				return nil, state.ConditionFailed
			}
			entry.Delivery, entry.Inventory, entry.Sync = &delivery, delivery.Inventory(), proof
		} else {
			entry.Inventory, err = entry.Inventory.Begin(job.Expected, c, ctx, target, job.Operation, cmd.Actor, cmd.Epoch, false)
			if err != nil {
				return nil, state.ConditionFailed
			}
			entry.Origin = op
			entry.Sync = nil
		}

		entry.Down = nil
		entry.Compacted = nil
		apps.entries[key] = entry
	}
	appWrites, code := p.appsCheckpoint(s, apps, uint64(op.At))
	if code != state.Applied {
		return nil, code
	}
	d, err := p.Members(s)
	if err != nil {
		return nil, state.Invalid
	}
	origin, _ := json.Marshal(op)
	frozen, _ := json.Marshal(plan)
	d, err = d.BeginDrain(q.ID, q.Operation, op.Change.Expected, origin, frozen, uint32(len(drainRecipes(plan.Jobs))))
	if err != nil {
		return nil, state.ConditionFailed
	}
	writes, code := p.memberCheckpoint(s, d)
	if code != state.Applied {
		return nil, code
	}
	for key, value := range appWrites {
		writes[key] = value
	}
	return writes, state.Applied
}
func (p Policy) NodeDrainStatus(s state.State, session access.Session, at int64, q NodeDrainQuery) (NodeDrainStatus, error) {
	current, err := p.Current(s)
	if err != nil {
		return NodeDrainStatus{}, err
	}
	c, err := current.Catalog(s)
	if err != nil || !q.ValidStatus() || c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return NodeDrainStatus{}, access.ErrDenied
	}
	d, err := p.Members(s)
	if err != nil {
		return NodeDrainStatus{}, err
	}
	apps, err := p.Apps(s)
	if err != nil {
		return NodeDrainStatus{}, err
	}
	var latest *NodeDrainStatus
	// Directory append order is the committed acceptance order. Prefer the
	// newest in-progress original; otherwise keep the newest historical result.
	for i := len(d.Drains) - 1; i >= 0; i-- {
		drain := d.Drains[i]
		if drain.Node != q.Node || q.Operation != "" && drain.Operation != q.Operation {
			continue
		}
		out, err := current.nodeDrainStatus(s, apps, drain)
		if err != nil {
			return NodeDrainStatus{}, err
		}
		if q.Operation != "" || out.State == "Draining" {
			return out, nil
		}
		if latest == nil {
			latest = &out
		}
	}
	if latest != nil {
		return *latest, nil
	}
	return NodeDrainStatus{}, ErrNoNodeDrain
}

// ErrNoNodeDrain: the server has no drain (or none with that operation).
var ErrNoNodeDrain = errors.New("no such node drain")

func (p Policy) nodeDrainStatus(s state.State, apps Apps, drain membership.Drain) (NodeDrainStatus, error) {
	out := NodeDrainStatus{Schema: 1, Node: drain.Node, Operation: drain.Operation, State: "Draining", Jobs: []NodeDrainJobStatus{}}
	var plan NodeDrainPlan
	if canonical(drain.Plan, &plan) != nil {
		return out, ErrCatalog
	}
	out.Total = len(plan.Tasks)
	for _, task := range plan.Tasks {
		if !task.Movable {
			out.Blocked++
		}
	}
	for _, job := range plan.Jobs {
		row := NodeDrainJobStatus{Tenant: job.Tenant, App: job.App, Operation: job.Operation, State: "Queued", Total: len(job.Tasks)}
		if job.Move != nil {
			registry, e := p.Volumes(s)
			if e != nil {
				return out, e
			}
			if _, move, found := registry.Move(drainMoveSelection(job)); found {
				row.State = string(move.Phase)
			}
		}
		entry, found := apps.entries[appKey(job.Tenant, job.App)]
		if found {
			summary, exists := entry.Inventory.Operation(job.Operation)
			if exists {
				row.State = summary.Status
				if summary.Status == "Succeeded" {
					row.Moved = row.Total
				}
			}
		}
		out.Moved += row.Moved
		out.Jobs = append(out.Jobs, row)
	}
	if out.Moved+out.Blocked == out.Total {
		out.State = "Succeeded"
		if out.Blocked > 0 {
			out.State = "Partial"
		}
	}
	return out, nil
}
func validateDrainOrigin(raw []byte, node, operation string) bool {
	var op UserOperation
	var q NodeDrainChange
	return canonical(raw, &op) == nil && op.Change.Action == "drain-node" && canonical(op.Change.Payload, &q) == nil && q.ID == node && q.Operation == operation
}
func drainAppBegin(op UserOperation, scope deployment.AppScope) (AppBegin, error) {
	var q NodeDrainChange
	if canonical(op.Change.Payload, &q) != nil {
		return AppBegin{}, ErrCatalog
	}
	for _, job := range q.Jobs {
		if job.Tenant == scope.Tenant && job.App == scope.App && job.Deployment == scope.Deployment && job.Operation == drainAppOperation(q.Operation, job.Tenant, job.App) {
			return AppBegin{Tenant: job.Tenant, App: job.App, Deployment: job.Deployment, Operation: job.Operation}, nil
		}
	}
	return AppBegin{}, ErrCatalog
}
func (p Policy) admitNodeDrainPatch(s state.State, cmd state.Command, keys []string) bool {
	if strings.HasPrefix(cmd.Actor, "node/") {
		return p.admitDrainMovePatch(s, cmd, keys)
	}
	var op UserOperation
	if canonical([]byte(cmd.Value), &op) != nil || op.Change.Action != "drain-node" {
		return false
	}
	writes, code := p.reduceMembers(s, cmd)
	if code != state.Applied {
		return false
	}
	for _, key := range keys {
		if !checkpointPatchKey(writes, AppsKey, key) {
			return false
		}
	}
	return true
}
