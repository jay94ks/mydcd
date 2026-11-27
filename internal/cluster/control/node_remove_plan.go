// SPDX-License-Identifier: Apache-2.0

package control

import (
	"fmt"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"slices"
	"strings"
)

type NodeBlocker struct {
	Code   string
	Detail string `json:",omitempty"`
}
type NodePlanTask struct {
	Tenant, App, Service, Task, Node, Standalone string
	Target                                       string `json:",omitempty"`
	Generation, Revision                         uint64
	Movable                                      bool
	Reason                                       string `json:",omitempty"`
}
type NodePlanVolume struct {
	Tenant, App, ID, Move     string
	Generation, OwnerRevision uint64
	Fixed, Retained           bool
}
type NodePlanStorage struct {
	ID, Path                                string
	Generation, Revision, Volumes, Retained uint64
	Draining, Closed                        bool
}
type NodeRemovePlan struct {
	Schema                                                      uint8
	Node                                                        string
	Epoch, Expected, RootRevision, Index, ConfigurationIndex    uint64
	Removable                                                   bool
	Blockers                                                    []NodeBlocker
	VotersBefore, VotersAfter, QuorumAfter, FaultToleranceAfter int
	Tasks                                                       []NodePlanTask
	Storage                                                     []NodePlanStorage
	Volumes                                                     []NodePlanVolume
	Activity                                                    lifecycle.Activity
	PendingOperation                                            string `json:",omitempty"`
	NativeClosed                                                bool
}

func (p NodeRemovePlan) Rejection() state.Code { return nodeBlockerCode(p.Blockers) }
func (p *NodeRemovePlan) block(code state.Code, detail string) {
	name := state.RejectionReason(code)
	for _, b := range p.Blockers {
		if b.Code == name {
			return
		}
	}
	p.Blockers = append(p.Blockers, NodeBlocker{Code: name, Detail: detail})
}

func (p Policy) PlanNodeRemoval(s state.State, session access.Session, at int64, node string) (NodeRemovePlan, error) {
	current, err := p.Current(s)
	if err != nil {
		return NodeRemovePlan{}, err
	}
	c, err := current.Catalog(s)
	if err != nil {
		return NodeRemovePlan{}, err
	}
	if !lifecycle.ValidID(node) || c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return NodeRemovePlan{}, access.ErrDenied
	}
	return current.nodeRemovalPlan(s, node)
}

// nodeRemovalPlan is shared by the query and the actual removal reducer. It
// projects retained refs and never treats an empty/shared census as native Gone.
func (p Policy) nodeRemovalPlan(s state.State, node string) (NodeRemovePlan, error) {
	out := NodeRemovePlan{Schema: 1, Node: node, RootRevision: s.Object(MembersKey).Revision, Index: s.Index(), Blockers: []NodeBlocker{}, Tasks: []NodePlanTask{}, Storage: []NodePlanStorage{}}
	d, err := p.Members(s)
	if err != nil {
		return out, err
	}
	entry, exists := d.Entry(node)
	if !exists || !membership.FullMember(entry) {
		return out, access.ErrDenied
	}
	owner, err := identity.ParseKey(entry.CurrentPeer().Key)
	if err != nil {
		return out, err
	}
	shared, err := d.PlanNodeChange(node, true)
	if err != nil {
		return out, err
	}
	out.Expected, out.Epoch, out.ConfigurationIndex = shared.Expected, shared.Epoch, shared.ConfigurationIndex
	out.VotersBefore, out.VotersAfter, out.QuorumAfter, out.FaultToleranceAfter = shared.VotersBefore, shared.VotersAfter, shared.QuorumAfter, shared.FaultToleranceAfter
	out.PendingOperation = shared.PendingOperation
	for _, code := range shared.Blockers {
		out.Blockers = append(out.Blockers, NodeBlocker{Code: code})
	}
	if d.Runtime != nil {
		topology, err := d.Topology()
		if err != nil {
			return out, err
		}
		n, _ := topology.Node(node)
		out.NativeClosed = n.Closure != nil && n.Closure.Closed
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return out, err
	}
	seen := map[string]bool{}
	for _, entry := range apps.entries {
		candidates, err := acceptedTaskCandidates(s, apps, entry.Inventory.Scope(), entry.Inventory.Claims())
		if err != nil {
			return out, err
		}
		for _, candidate := range candidates {
			if !d.ResourceKeyForNode(node, candidate.goal.Owner) {
				continue
			}
			ref := candidate.ref
			id := fmt.Sprintf("%s/%d", ref.Key, ref.Generation)
			if seen[id] {
				continue
			}
			seen[id] = true
			goal := candidate.goal
			var service deployment.ComposeService
			if canonical(goal.Config, &service) != nil {
				return out, ErrCatalog
			}
			instance, e := deployment.TaskInstanceForKey(goal.Tenant, goal.App, ref.Key, service)
			if e != nil {
				return out, ErrCatalog
			}
			serviceName := instance.Service
			task := NodePlanTask{Tenant: goal.Tenant, App: goal.App, Service: serviceName, Node: node, Task: ref.Key, Generation: ref.Generation, Revision: ref.Revision, Reason: "EXPLICIT_APP_REPLAN_REQUIRED"}
			if entry.Standalone != nil {
				task.Standalone = entry.Standalone.Name
			}
			// A task with a fixed Volume cannot be relocated automatically. Even a
			// movable task requires the existing explicit app/Volume move operation.
			if binding, ok := apps.Binding(ref); ok {
				task.Movable = true
				for _, pin := range binding.Pins() {
					volumes, e := p.Volumes(s)
					if e != nil {
						return out, e
					}
					if registered, ok := volumes.entries[volumeKey(pin.Scope)]; ok && registered.Native.Fixed != nil {
						task.Movable = false
						task.Reason = "FIXED_VOLUME_PRESENT"
					}
				}
			}
			if entry.Standalone != nil && service.ReadOnly != nil && !*service.ReadOnly {
				task.Movable, task.Reason = false, "STANDALONE_WRITABLE_LAYER_PRESENT"
			}
			out.Tasks = append(out.Tasks, task)
		}
	}
	if len(out.Tasks) > 0 {
		out.block(state.NodeTasksPresent, "accepted Task sources still belong to this node")
	}
	volumes, err := p.Volumes(s)
	if err != nil {
		return out, err
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return out, err
	}
	for _, root := range roots.Roots() {
		if root.Definition.Node != node {
			continue
		}
		row := NodePlanStorage{ID: root.Definition.ID, Path: root.Definition.Path, Generation: root.Generation, Revision: root.Revision, Draining: root.Draining, Closed: root.Closed != nil}
		for _, v := range volumes.entries {
			current, _ := v.State.Owner()
			if d.ResourceKeyForNode(node, current.Key) && !v.State.Deleted() {
				if v.Native.Fixed != nil && v.Native.Fixed.Root.Root.ID == row.ID {
					row.Volumes++
				}
			}
		}
		out.Storage = append(out.Storage, row)
		if !row.Draining || !row.Closed || row.Volumes > 0 || row.Retained > 0 {
			out.block(state.NodeStorageNotDrained, "registered storage root or original data remains")
		}
	}
	for _, v := range volumes.entries {
		current, ownerRevision := v.State.Owner()
		scope := v.State.Scope()
		if d.ResourceKeyForNode(node, current.Key) && !v.State.Deleted() {
			out.Volumes = append(out.Volumes, NodePlanVolume{Tenant: scope.Tenant, App: scope.App, ID: scope.ID, Generation: scope.Generation, OwnerRevision: ownerRevision, Fixed: v.Native.Fixed != nil})
		}
		if d.ResourceKeyForNode(node, current.Key) && !v.State.Deleted() {
			if v.Native.Fixed != nil {
				out.block(state.NodeFixedVolumePresent, "node-fixed Volume must be explicitly unregistered; bytes are preserved")
			} else {
				out.block(state.NodeStorageNotDrained, "original Docker Volume data is still registered")
			}
		}
		for _, retained := range v.State.Retained() {
			if d.ResourceKeyForNode(node, retained.Owner.Key) {
				out.Volumes = append(out.Volumes, NodePlanVolume{Tenant: scope.Tenant, App: scope.App, ID: scope.ID, Generation: scope.Generation, OwnerRevision: retained.OwnerRevision, Retained: true, Move: retained.Move})
				out.block(state.NodeStorageNotDrained, "retained original Volume data must be explicitly settled")
			}
		}
	}
	out.Activity, err = p.NodeActivity(s, owner)
	if err != nil {
		return out, err
	}
	if !out.Activity.Empty() {
		out.block(state.NodeNativeUnsettled, "shared operations, writers, references or jobs remain")
	}
	slices.SortFunc(out.Tasks, func(a, b NodePlanTask) int { return strings.Compare(a.Task, b.Task) })
	slices.SortFunc(out.Storage, func(a, b NodePlanStorage) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(out.Volumes, func(a, b NodePlanVolume) int {
		return strings.Compare(fmt.Sprintf("%s/%s/%s/%d/%s", a.Tenant, a.App, a.ID, a.Generation, a.Move), fmt.Sprintf("%s/%s/%s/%d/%s", b.Tenant, b.App, b.ID, b.Generation, b.Move))
	})
	// Stable priorities make the original rejection reproducible, independent of
	// Go map iteration order and unrelated display row ordering.
	order := []string{"LAST_VOTER", "QUORUM_LOSS", "NODE_OPERATION_PENDING", "FIXED_VOLUME_PRESENT", "NODE_STORAGE_NOT_DRAINED", "TASKS_PRESENT", "NATIVE_UNSETTLED", "CONFIGURATION_NOT_INSTALLED"}
	slices.SortFunc(out.Blockers, func(a, b NodeBlocker) int { return slices.Index(order, a.Code) - slices.Index(order, b.Code) })
	out.Removable = len(out.Blockers) == 0
	return out, nil
}
