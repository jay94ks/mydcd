// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// RuntimeState stores the existing lifecycle core and A2 membership effects in
// the same Directory. It is not another roster or a second consensus protocol.
type RuntimeState struct {
	Topology   json.RawMessage
	Operations []NodeOperation
}
type NodeOperation struct {
	Node, ID                 string
	Action                   lifecycle.Action
	Generation, Epoch        uint64
	Origin                   json.RawMessage // original signed admin input, checked by control
	Authorization            json.RawMessage `json:",omitempty"` // explicit renewal; never replaces Origin
	Job                      reconcile.State // RemoveServer command; Present is the command, not node presence
	Source                   [32]byte
	BaseIndex, ObservedIndex uint64
}

func (d Directory) Topology() (lifecycle.Topology, error) {
	if d.Runtime == nil {
		return lifecycle.Topology{}, ErrMember
	}
	return lifecycle.Decode(d.Runtime.Topology)
}
func (d Directory) NodeOperation(id string) (NodeOperation, bool) {
	if d.Runtime != nil {
		for _, op := range d.Runtime.Operations {
			if op.ID == id {
				raw, _ := json.Marshal(op)
				var owned NodeOperation
				_ = json.Unmarshal(raw, &owned)
				return owned, true
			}
		}
	}
	return NodeOperation{}, false
}

// Quiescent guards expiry of request receipts, not node availability. A node
// may remain isolated after positive closure, but an unsettled lifecycle or
// SDK membership effect must retain its original signed request and A2 job.
func (d Directory) Quiescent() bool {
	for _, drain := range d.Drains {
		if drain.Pending > 0 {
			return false
		}
	}
	for _, rotation := range d.Rotations {
		if !rotation.Settled() {
			return false
		}
	}
	for _, entry := range d.Entries {
		if entry.Job.Pending != nil {
			return false
		}
	}
	if d.Runtime == nil {
		return true
	}
	topology, err := d.Topology()
	if err != nil {
		return false
	}
	for _, entry := range d.Entries {
		if node, exists := topology.Node(entry.Peer.ID); exists && node.Pending != nil {
			return false
		}
	}
	for _, operation := range d.Runtime.Operations {
		if operation.Job.Pending != nil {
			return false
		}
	}
	return true
}

func (d Directory) runtimeDispatched() bool {
	if d.Runtime != nil {
		for _, op := range d.Runtime.Operations {
			if op.Job.Pending != nil && op.Job.Pending.Phase != reconcile.Prepared {
				return true
			}
		}
	}
	return false
}
func (d Directory) keepTopology(t lifecycle.Topology) (Directory, error) {
	raw, err := t.Encode()
	if err != nil || d.Revision == ^uint64(0) {
		return d, ErrMember
	}
	n := clone(d)
	n.Revision++
	if n.Runtime == nil {
		n.Runtime = &RuntimeState{}
	}
	n.Runtime.Topology = raw
	return n, nil
}

// InstallConfiguration accepts only the adapter's actual durable Raft prefix.
// Its control caller authenticates that report; the lifecycle core prevents
// removal without original closure, and A2 prevents an untracked SDK effect.
func (d Directory) InstallConfiguration(c lifecycle.Configuration) (Directory, error) {
	if !d.writable() || c.Validate() != nil {
		return d, ErrMember
	}
	for _, member := range c.Members {
		e, exists := d.Entry(member.ID)
		key, err := identity.ParseKey(e.CurrentPeer().Key)
		if !exists || err != nil || key != member.Key {
			return d, ErrMember
		}
		voter := e.Peer.Voter
		if (e.Phase == Promoting || e.Phase == Demoting) && e.Job.Pending != nil && e.Job.Pending.Phase != reconcile.Prepared {
			voter = e.Phase == Promoting
		}
		if voter != member.Voter || e.NativeIndex > c.Index || !FullMember(e) && e.Phase != Learner && (e.Phase != Invited || e.Job.Pending == nil || e.Job.Pending.Phase == reconcile.Prepared) {
			return d, ErrMember
		}
	}
	var t lifecycle.Topology
	var err error
	if d.Runtime == nil {
		for _, e := range d.Entries {
			if FullMember(e) {
				if _, found := c.Member(e.Peer.ID); !found {
					return d, ErrMember
				}
			}
		}
		t, err = lifecycle.New(d.Cluster, c)
	} else {
		t, err = d.Topology()
		if err != nil {
			return d, err
		}
		for _, old := range t.Configuration().Members {
			if _, found := c.Member(old.ID); found {
				continue
			}
			node, _ := t.Node(old.ID)
			if node.Pending == nil {
				return d, ErrMember
			}
			op, exists := d.NodeOperation(node.Pending.ID)
			if !exists || op.Job.Pending == nil || op.Job.Pending.Phase == reconcile.Prepared || c.Index <= op.BaseIndex {
				return d, ErrMember
			}
		}
		previousRevision := t.Revision()
		t, err = t.CommitConfiguration(d.Cluster, c)
		if err == nil && t.Revision() == previousRevision {
			return d, nil
		}
	}
	if err != nil {
		return d, err
	}
	n, err := d.keepTopology(t)
	if err != nil {
		return d, err
	}
	for i, op := range n.Runtime.Operations {
		if op.Action != lifecycle.Remove && op.Action != lifecycle.ForceRemove || op.Job.Pending == nil {
			continue
		}
		if _, exists := c.Member(op.Node); exists {
			continue
		}
		job, err := reconcile.Settle(op.Job, op.Job.Pending.ID, reconcile.EffectApplied)
		if err != nil {
			return d, err
		}
		n.Runtime.Operations[i].Job, n.Runtime.Operations[i].ObservedIndex = job, c.Index
	}
	return n, nil
}
func (d Directory) BeginNode(node, id string, action lifecycle.Action, expected, epoch uint64, origin json.RawMessage) (Directory, error) {
	if action == lifecycle.ForceRemove {
		return d, ErrMember
	}
	return d.beginNode(node, id, action, expected, epoch, origin, nil)
}
func (d Directory) BeginForceRemoval(node, id string, expected, epoch uint64, origin json.RawMessage, probe lifecycle.RemovalProbe) (Directory, error) {
	return d.beginNode(node, id, lifecycle.ForceRemove, expected, epoch, origin, &probe)
}
func (d Directory) beginNode(node, id string, action lifecycle.Action, expected, epoch uint64, origin json.RawMessage, probe *lifecycle.RemovalProbe) (Directory, error) {
	if !d.writable() || len(origin) == 0 || len(origin) > 64<<10 || !json.Valid(origin) {
		return d, ErrMember
	}
	t, err := d.Topology()
	if err != nil {
		return d, err
	}
	e, exists := d.Entry(node)
	if !exists || !FullMember(e) || e.Job.Pending != nil {
		return d, ErrMember
	}
	if action == lifecycle.Remove || action == lifecycle.ForceRemove {
		plan, planErr := d.PlanNodeChange(node, true)
		if action == lifecycle.ForceRemove {
			plan, planErr = d.PlanForceRemoval(node)
		}
		if planErr != nil || len(plan.Blockers) != 0 {
			return d, ErrMember
		}
	}
	if action == lifecycle.ForceRemove {
		if probe == nil {
			return d, ErrMember
		}
		t, err = t.Retire(node, id, expected, epoch, *probe)
	} else {
		t, err = t.Begin(node, id, action, expected, epoch)
	}
	if err != nil {
		return d, err
	}
	n, err := d.keepTopology(t)
	if err != nil {
		return d, err
	}
	if action == lifecycle.ForceRemove {
		n = n.abandonIdentityRotations(node)
	}
	current, _ := t.Node(node)
	op := NodeOperation{Node: node, ID: id, Action: action, Generation: current.Generation, Epoch: epoch, Origin: bytes.Clone(origin)}
	if action == lifecycle.Remove || action == lifecycle.ForceRemove {
		body, _ := json.Marshal(struct {
			Node, Operation string
			Key             [32]byte
			Generation      uint64
		}{node, id, current.Member.Key, current.Generation})
		op.Job, err = reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: current.Revision, Resource: reconcile.Resource{Generation: current.Generation, Spec: string(body), Present: true}})
		if err == nil {
			op.Job, _, err = reconcile.Plan(op.Job)
		}
		if err != nil {
			return d, err
		}
	}
	n.Runtime.Operations = append(n.Runtime.Operations, op)
	slices.SortFunc(n.Runtime.Operations, func(a, b NodeOperation) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return n, nil
}
func (d Directory) ObserveNode(proof lifecycle.Proof) (Directory, error) {
	if !d.writable() {
		return d, ErrMember
	}
	t, err := d.Topology()
	if err == nil {
		t, err = t.Observe(proof)
	}
	if err != nil {
		return d, err
	}
	return d.keepTopology(t)
}
func (d Directory) DispatchRemoval(id string, expected, index uint64, source [32]byte) (Directory, error) {
	if !d.writable() || d.Revision != expected || !d.MemberKey(source) || d.runtimeDispatched() {
		return d, ErrMember
	}
	t, err := d.Topology()
	op, exists := d.NodeOperation(id)
	node, _ := t.Node(op.Node)
	if err != nil || !exists || node.Pending == nil || node.Pending.ID != id || !removalReady(node, index) || index != t.Configuration().Index || op.Job.Pending == nil || op.Job.Pending.Phase != reconcile.Prepared {
		return d, ErrMember
	}
	if len(t.Configuration().Members) <= 1 || node.Member.Voter && t.Configuration().Voters() <= 1 {
		return d, ErrMember
	}
	for _, e := range d.Entries {
		if e.Job.Pending != nil && e.Job.Pending.Phase != reconcile.Prepared {
			return d, ErrMember
		}
	}
	job, err := reconcile.Dispatch(op.Job, op.Job.Pending.ID)
	if err != nil {
		return d, err
	}
	n := clone(d)
	n.Revision++
	for i, saved := range n.Runtime.Operations {
		if saved.ID == id {
			n.Runtime.Operations[i].Job, n.Runtime.Operations[i].Source, n.Runtime.Operations[i].BaseIndex = job, source, index
		}
	}
	return n, nil
}
func (d Directory) UnknownRemoval(id string, expected uint64) (Directory, error) {
	if !d.writable() || d.Revision != expected {
		return d, ErrMember
	}
	op, exists := d.NodeOperation(id)
	if !exists || op.Job.Pending == nil {
		return d, ErrMember
	}
	job, err := reconcile.Settle(op.Job, op.Job.Pending.ID, reconcile.EffectUnknown)
	if err != nil {
		return d, err
	}
	n := clone(d)
	n.Revision++
	for i, saved := range n.Runtime.Operations {
		if saved.ID == id {
			n.Runtime.Operations[i].Job = job
		}
	}
	return n, nil
}

// ResumeNode changes only the explicit administrator authorization. The same
// lifecycle operation, native A2 request/target and unknown outcome remain.
func (d Directory) ResumeNode(node, id string, expected, epoch uint64, origin json.RawMessage) (Directory, error) {
	if !d.writable() || len(origin) == 0 || len(origin) > 64<<10 || !json.Valid(origin) {
		return d, ErrMember
	}
	t, err := d.Topology()
	v, exists := t.Node(node)
	if err != nil || !exists || v.Revision != expected || v.Pending == nil || v.Pending.ID != id || v.Pending.Epoch != epoch {
		return d, ErrMember
	}
	n := clone(d)
	n.Revision++
	for i, op := range n.Runtime.Operations {
		if op.ID == id {
			n.Runtime.Operations[i].Authorization = bytes.Clone(origin)
			return n, nil
		}
	}
	return d, ErrMember
}

func (d Directory) RotateNodeOperations(expected, epoch uint64) (Directory, error) {
	if !d.writable() {
		return d, ErrMember
	}
	t, err := d.Topology()
	if err == nil {
		t, err = t.RotateOperations(expected, epoch)
	}
	if err != nil {
		return d, err
	}
	n, err := d.keepTopology(t)
	if err != nil {
		return d, err
	}
	keep := map[string]bool{}
	for _, entry := range d.Entries {
		if node, exists := t.Node(entry.Peer.ID); exists {
			if node.Closure != nil {
				keep[node.Closure.Operation] = true
			}
			if node.Retirement != nil {
				keep[node.Retirement.Operation] = true
			}
		}
	}
	for _, op := range n.Runtime.Operations {
		if op.Job.Pending != nil {
			return d, ErrMember
		}
	}
	n.Runtime.Operations = slices.DeleteFunc(n.Runtime.Operations, func(op NodeOperation) bool { return !keep[op.ID] })
	return n, nil
}

func (d Directory) validateRuntime(joinDispatched int) error {
	if d.Runtime == nil {
		return nil
	}
	t, err := d.Topology()
	if err != nil || t.Cluster() != d.Cluster || len(d.Runtime.Operations) > 4096 {
		return ErrMember
	}
	operations := t.Operations()
	if len(operations) != len(d.Runtime.Operations) {
		return ErrMember
	}
	for _, member := range t.Configuration().Members {
		entry, found := d.Entry(member.ID)
		key, keyErr := identity.ParseKey(entry.CurrentPeer().Key)
		// The directory can observe a join/promotion before the adapter publishes
		// the next whole native configuration. Preserve that original prefix;
		// only InstallConfiguration may advance it.
		voterMatches := entry.Peer.Voter == member.Voter || (entry.Phase == Promoting || entry.Phase == Demoting) && entry.Job.Pending != nil && entry.Job.Pending.Phase != reconcile.Prepared && member.Voter == (entry.Phase == Promoting) || entry.NativeIndex > t.Configuration().Index
		if !found || keyErr != nil || key != member.Key || !voterMatches || entry.Phase == Invited && (entry.Job.Pending == nil || entry.Job.Pending.Phase == reconcile.Prepared) {
			return ErrMember
		}
	}
	active := joinDispatched
	for i, op := range d.Runtime.Operations {
		node, exists := t.Node(op.Node)
		if !exists || op.Generation != node.Generation || op.Epoch == 0 || op.Epoch > t.Epoch() || !lifecycle.ValidID(op.ID) || len(op.Origin) == 0 || len(op.Origin) > 64<<10 || !json.Valid(op.Origin) || i > 0 && d.Runtime.Operations[i-1].ID >= op.ID {
			return ErrMember
		}
		if len(op.Authorization) > 64<<10 || op.Authorization != nil && !json.Valid(op.Authorization) {
			return ErrMember
		}
		original := operations[i]
		if original.ID != op.ID || original.Action != op.Action || original.Generation != op.Generation || original.Epoch != op.Epoch {
			return ErrMember
		}
		if op.Action != lifecycle.Isolate && op.Action != lifecycle.Restore && op.Action != lifecycle.Remove && op.Action != lifecycle.ForceRemove {
			return ErrMember
		}
		if op.Action != lifecycle.Remove && op.Action != lifecycle.ForceRemove {
			if op.Job != (reconcile.State{}) || op.Source != ([32]byte{}) || op.BaseIndex != 0 || op.ObservedIndex != 0 {
				return ErrMember
			}
			continue
		}
		body, _ := json.Marshal(struct {
			Node, Operation string
			Key             [32]byte
			Generation      uint64
		}{op.Node, op.ID, node.Member.Key, op.Generation})
		if reconcile.Validate(op.Job) != nil || op.Job.LastID != 1 || op.Job.Desired.Revision != original.Revision || op.Job.Desired.Retiring != 0 || op.Job.Stopped || op.Job.Desired.Resource != (reconcile.Resource{Generation: op.Generation, Spec: string(body), Present: true}) {
			return ErrMember
		}
		if p := op.Job.Pending; p != nil {
			if p.Kind != reconcile.Apply || p.Target != op.Job.Desired.Resource || op.ObservedIndex != 0 {
				return ErrMember
			}
			if p.Phase == reconcile.Prepared {
				if op.Source != ([32]byte{}) || op.BaseIndex != 0 {
					return ErrMember
				}
			} else {
				active++
				if !d.HistoricalMemberKey(op.Source) || op.BaseIndex == 0 {
					return ErrMember
				}
			}
		} else if op.ObservedIndex <= op.BaseIndex || !d.HistoricalMemberKey(op.Source) || op.Job.Applied != op.Job.Desired.Resource || node.Phase != lifecycle.Removed && node.Phase != lifecycle.Retired {
			return ErrMember
		}
	}
	if active > 1 {
		return ErrMember
	}
	return nil
}

// Logical retirement carries no owner closure. Both variants consume only the
// exact installed configuration; the SDK effect stays the same A2 RemoveServer.
func removalReady(node lifecycle.Node, index uint64) bool {
	if node.Phase == lifecycle.Retiring {
		return node.Retirement != nil && !node.Retirement.Responding && node.Retirement.ConfigurationIndex <= index
	}
	return node.Phase == lifecycle.Removing && node.Closure != nil && node.Closure.Closed && node.Closure.ConfigurationIndex == index
}

// RecoverConfiguration installs the configuration a signed `sfcd recover`
// produced. Members it dropped become Retired at once (lifecycle Recover); a
// removal job still waiting on one of them is settled as applied, because
// the member is no longer in the actual configuration.
func (d Directory) RecoverConfiguration(r lifecycle.Recovery, c lifecycle.Configuration) (Directory, error) {
	if !d.writable() || d.Runtime == nil || c.Validate() != nil {
		return d, ErrMember
	}
	for _, member := range c.Members {
		e, exists := d.Entry(member.ID)
		key, err := identity.ParseKey(e.CurrentPeer().Key)
		if !exists || err != nil || key != member.Key {
			return d, ErrMember
		}
	}
	t, err := d.Topology()
	if err != nil {
		return d, err
	}
	if t, err = t.Recover(r, c); err != nil {
		return d, err
	}
	n, err := d.keepTopology(t)
	if err != nil {
		return d, err
	}
	if err = n.settleLostRemovals(c, r.Key, d.mustConfigurationIndex()); err != nil {
		return d, err
	}
	return n, n.Validate()
}

// Recovered reports whether a recovery with this request ID retired members.
func (d Directory) Recovered(requestID string) bool {
	t, err := d.Topology()
	if err != nil {
		return false
	}
	for _, m := range d.Entries {
		if n, ok := t.Node(m.Peer.ID); ok && n.Recovery != nil && n.Recovery.RequestID == requestID {
			return true
		}
	}
	return false
}

// settleLostRemovals ends every removal job that still waits on a member c
// no longer holds: the member is gone from the actual configuration, so the
// removal took effect. A job never dispatched is recorded as dispatched by
// source (the server that forced c) against the previous configuration.
func (d Directory) settleLostRemovals(c lifecycle.Configuration, source [32]byte, previous uint64) error {
	for i, op := range d.Runtime.Operations {
		if op.Action != lifecycle.Remove && op.Action != lifecycle.ForceRemove || op.Job.Pending == nil {
			continue
		}
		if _, exists := c.Member(op.Node); exists {
			continue
		}
		job := op.Job
		var err error
		if job.Pending.Phase == reconcile.Prepared {
			if job, err = reconcile.Dispatch(job, job.Pending.ID); err != nil {
				return err
			}
			d.Runtime.Operations[i].Source, d.Runtime.Operations[i].BaseIndex = source, previous
		}
		if job, err = reconcile.Settle(job, job.Pending.ID, reconcile.EffectApplied); err != nil {
			return err
		}
		d.Runtime.Operations[i].Job, d.Runtime.Operations[i].ObservedIndex = job, c.Index
	}
	return nil
}

func (d Directory) mustConfigurationIndex() uint64 {
	t, err := d.Topology()
	if err != nil {
		return 0
	}
	return t.Configuration().Index
}
