// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type VolumeMoveSelection struct {
	Scope volumes.Scope
	ID    string
}

type VolumeMoveCommit struct {
	Selection     VolumeMoveSelection
	OwnerRevision uint64
	Target        volumes.NativeReady
}

type VolumeMoveApp struct {
	CD        *AppCDMoveSource `json:",omitempty"`
	Operation string
	Revision  uint64
	Plan      [32]byte
	Target    *VolumeMoveTargetApp `json:",omitempty"`
}

// A move changes native placement, not the registered CD principal or source.
// These fields are part of the explicit signed move, never YAML authority.
type AppCDMoveSource struct {
	Registration                     [32]byte
	Principal                        string
	Requester                        [32]byte
	PolicyRevision, OverrideRevision uint64
	Intent, Input                    [32]byte
}

func (x AppCDMoveSource) Valid() bool {
	return x.Registration != ([32]byte{}) && lifecycle.ValidID(x.Principal) && x.Requester != ([32]byte{}) && x.PolicyRevision != 0 && x.Intent != ([32]byte{}) && x.Input != ([32]byte{})
}

// Artifacts stay in the existing bounded App upload store, not chunk permits.
type VolumeMoveTargetApp struct {
	Upload, Operation string
	Plan              [32]byte
}

// All effects use the original immutable move binding. ExpiresAt is the plan's
// fixed transfer deadline, not an automatically renewable lifetime.
type VolumeMoveBegin struct {
	App           *VolumeMoveApp `json:",omitempty"`
	Scope         volumes.Scope
	ID            string
	OwnerRevision uint64
	Target        volumes.NativeSpec
	Compatibility [32]byte
	MaxBytes      uint64
	MaxEntries    uint32
	CapacityBytes uint64
	ExpiresAt     int64
}

// The actual phase/evidence/reader remain in the existing volumes.State.
// This record adds only the accepted user/native recipe and reservations; it
// is not another ownership machine, work queue or consensus authority.
type VolumeMove struct {
	App            *VolumeMoveApp `json:",omitempty"`
	Schema         uint8
	Binding        volumes.Binding
	Source         volumes.NativeReady
	Target         volumes.NativeSpec
	MaxEntries     uint32
	CapacityBytes  uint64
	SourceCapacity uint64
	ExpiresAt      int64
	Origin         UserOperation
}

func (j VolumeMove) Digest() [32]byte { raw, _ := json.Marshal(j); return sha256.Sum256(raw) }
func (j VolumeMove) Verify() error {
	if !validMoveJob(j) {
		return ErrCatalog
	}
	return nil
}
func (j VolumeMove) Selection() VolumeMoveSelection {
	return VolumeMoveSelection{Scope: j.Binding.Scope, ID: j.Binding.ID}
}
func (j VolumeMove) Options() volumes.ArchiveOptions {
	return volumes.ArchiveOptions{MaxBytes: j.Binding.MaxBytes, MaxEntries: j.MaxEntries, MaxDepth: 64, UID: j.Source.Spec.UID, GID: j.Source.Spec.GID, RootMode: j.Source.Spec.Mode}
}

// StagingConsumer identifies cold native restore I/O only. It is not acquired
// in the logical Volume's shared A3 and cannot authorize a Task/Start. Current
// move/quorum admission and the native declaration lock guard every use.
func (j VolumeMove) StagingConsumer() volumes.Consumer {
	b := j.Binding
	return volumes.Consumer{ID: "m-" + b.ID, Generation: b.StartedRevision, Writable: true, Owner: b.Target, OwnerRevision: b.StartedRevision, Lease: reconcile.Lease{Generation: b.Scope.Generation, Token: 1}}
}
func moveKey(q VolumeMoveSelection) string { return volumeKey(q.Scope) + "/" + q.ID }
func ownMoveJob(j VolumeMove) VolumeMove {
	raw, _ := json.Marshal(j)
	var out VolumeMove
	_ = json.Unmarshal(raw, &out)
	return out
}
func (v Volumes) Move(q VolumeMoveSelection) (VolumeMove, volumes.Move, bool) {
	j, ok := v.moves[moveKey(q)]
	e, exists := v.entries[volumeKey(q.Scope)]
	m, found := e.State.Move(q.ID)
	return ownMoveJob(j), m, ok && exists && found && j.Binding.Scope == q.Scope && e.State.Scope() == q.Scope && m.Binding == j.Binding
}
func (v Volumes) Moves() []VolumeMove {
	var keys []string
	for key := range v.moves {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := make([]VolumeMove, 0, len(keys))
	for _, key := range keys {
		out = append(out, ownMoveJob(v.moves[key]))
	}
	return out
}
func movePending(m volumes.Move) bool {
	return m.Phase != volumes.Completed && m.Phase != volumes.Cancelled
}

func validMoveJob(j VolumeMove) bool {
	if j.App != nil && j.App.CD != nil && (!j.App.CD.Valid() || j.App.Target == nil) {
		return false
	}
	if j.App != nil && (!lifecycle.ValidID(j.App.Operation) || j.App.Plan == ([32]byte{}) || j.App.Revision == 0 || j.App.Revision == ^uint64(0)) {
		return false
	}
	if j.App != nil && j.App.Target != nil && (!lifecycle.ValidID(j.App.Target.Upload) || !lifecycle.ValidID(j.App.Target.Operation) || j.App.Target.Operation == j.App.Operation || j.App.Target.Plan == ([32]byte{})) {
		return false
	}
	b := j.Binding
	target, err := restoreTargetOwner(j.Target)
	if err != nil || b.Validate() != nil || j.Schema != 1 || j.Source.Verify() != nil || j.Source.Spec.Scope != b.Scope || j.Source.Owner != b.Source || target != b.Target || j.Target.Scope != b.Scope || j.Target.Materialization != "m-"+b.ID || len(b.ID) > 61 || j.Target.UID != j.Source.Spec.UID || j.Target.GID != j.Source.Spec.GID || j.Target.Mode != j.Source.Spec.Mode || j.MaxEntries == 0 || j.MaxEntries > 100_000 || b.MaxBytes < 1024 || b.MaxBytes > 1<<40 || j.CapacityBytes < b.MaxBytes || j.CapacityBytes > 1<<40 || j.SourceCapacity > j.CapacityBytes {
		return false
	}
	if j.Origin.VerifyOriginal(b.Scope.Cluster) != nil || j.Origin.Change.Action != "begin-volume-move" && j.Origin.Change.Action != "drain-node" || j.ExpiresAt <= j.Origin.At || j.ExpiresAt-j.Origin.At > 86400 {
		return false
	}
	var q VolumeMoveBegin
	return moveBeginForJob(j, &q) == nil && sameMoveApp(q.App, j.App) && q.Scope == b.Scope && q.ID == b.ID && q.OwnerRevision == b.SourceOwnerRevision && q.Target == j.Target && q.Compatibility == b.Compatibility && q.MaxBytes == b.MaxBytes && q.MaxEntries == j.MaxEntries && q.CapacityBytes == j.CapacityBytes && q.ExpiresAt == j.ExpiresAt
}

func (p Policy) validateMoves(v Volumes) error {
	if len(v.moves) > maxVolumes {
		return ErrCatalog
	}
	busy := map[string]VolumeMove{}
	for key, j := range v.moves {
		_, m, ok := v.Move(j.Selection())
		if !ok || key != moveKey(j.Selection()) || !validMoveJob(j) {
			return ErrCatalog
		}
		e := v.entries[volumeKey(j.Binding.Scope)]
		if movePending(m) {
			for _, node := range []string{j.Binding.Source.Node, j.Binding.Target.Node} {
				if prior, exists := busy[node]; exists && !sameDrainMoveGroup(prior, j) {
					return ErrCatalog
				}
				busy[node] = j
			}
			if m.CommitRevision == 0 && e.CapacityBytes != j.SourceCapacity {
				return ErrCatalog
			}
		}
	}
	for _, e := range v.entries {
		owner, _ := e.State.Owner()
		if e.Native.Verify() != nil || e.Native.Owner != owner || e.Native.Spec.Scope != e.State.Scope() {
			return ErrCatalog
		}
		var spec volumes.NativeSpec
		var generation uint64
		var physicalOwner volumes.Owner
		hasPrevious := false
		for _, m := range e.State.Moves() {
			j, ok := v.moves[moveKey(VolumeMoveSelection{Scope: e.State.Scope(), ID: m.Binding.ID})]
			if !ok || j.Binding != m.Binding {
				return ErrCatalog
			}
			// Historical targets stop being the CURRENT native after the next
			// committed move. Validate every original source against the prior
			// confirmed native, then compare only the final value with the registry.
			if hasPrevious && (j.Source.Spec != spec || j.Source.Generation != generation || j.Source.Owner != physicalOwner) {
				return ErrCatalog
			}
			spec, generation, physicalOwner = j.Source.Spec, j.Source.Generation, j.Source.Owner
			if m.CommitRevision != 0 {
				spec, generation, physicalOwner = j.Target, 1, j.Binding.Target
			}
			hasPrevious = true
		}
		if hasPrevious && (e.Native.Spec != spec || e.Native.Generation != generation || e.Native.Owner != physicalOwner) {
			return ErrCatalog
		}
	}
	return nil
}

func (p Policy) reduceVolumeMove(s state.State, c access.Catalog, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	if op.Change.Action == "commit-volume-move" {
		var q VolumeMoveCommit
		if canonical(op.Change.Payload, &q) != nil || q.Target.Verify() != nil {
			return nil, state.Invalid
		}
		j, _, ok := v.Move(q.Selection)
		e := v.entries[volumeKey(q.Selection.Scope)]
		if !ok || e.State.Revision() != op.Change.Expected || q.OwnerRevision != j.Binding.SourceOwnerRevision || q.Target.Spec != j.Target || q.Target.Owner != j.Binding.Target || q.Target.Generation != 1 {
			return nil, state.ConditionFailed
		}
		if _, err := p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Target.Node, j.Binding.Target.Key), VolumeMovePermitRequest{Selection: j.Selection(), Kind: "commit"}, op.At); err != nil {
			return nil, state.Forbidden
		}
		next, err := e.State.CommitOwner(c, op.Change.Principal, j.Binding.ID, op.Change.Expected, q.OwnerRevision)
		if err != nil {
			return nil, state.ConditionFailed
		}
		e.State, e.Native, e.CapacityBytes = next, q.Target, j.CapacityBytes
		v.entries[volumeKey(q.Selection.Scope)] = e
		return p.volumeCheckpoint(s, v)
	}
	if op.Change.Action == "cancel-volume-move" {
		var q VolumeMoveSelection
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		j, _, ok := v.Move(q)
		e := v.entries[volumeKey(q.Scope)]
		if !ok || e.State.Revision() != op.Change.Expected {
			return nil, state.ConditionFailed
		}
		next, err := e.State.Cancel(c, op.Change.Principal, j.Binding.ID, op.Change.Expected)
		if err != nil {
			return nil, state.ConditionFailed
		}
		e.State = next
		v.entries[volumeKey(q.Scope)] = e
		return p.volumeCheckpoint(s, v)
	}
	var q VolumeMoveBegin
	if op.Change.Action != "begin-volume-move" || canonical(op.Change.Payload, &q) != nil {
		return nil, state.Invalid
	}
	return p.beginVolumeMoveJob(s, c, v, op, q, op.Change.Expected)
}
func (p Policy) beginVolumeMoveJob(s state.State, c access.Catalog, v Volumes, op UserOperation, q VolumeMoveBegin, expected uint64) (map[string][]byte, state.Code) {
	if !lifecycle.ValidID(q.ID) || len(q.ID) > 61 || q.Target.Validate() != nil || q.Target.Scope != q.Scope || q.Target.Materialization != "m-"+q.ID || q.MaxEntries == 0 || q.MaxEntries > 100_000 || q.MaxBytes < 1024 || q.MaxBytes > 1<<40 || q.CapacityBytes < q.MaxBytes || q.CapacityBytes > 1<<40 || q.ExpiresAt <= op.At || q.ExpiresAt-op.At > 86400 {
		return nil, state.Invalid
	}
	e, ok := v.entries[volumeKey(q.Scope)]
	if !ok || e.State.Scope() != q.Scope || e.State.Revision() != expected || len(v.moves) >= maxVolumes || q.CapacityBytes < e.CapacityBytes {
		return nil, state.ConditionFailed
	}
	if _, exists := v.moves[moveKey(VolumeMoveSelection{q.Scope, q.ID})]; exists {
		return nil, state.ConditionFailed
	}
	if q.App != nil {
		for _, prior := range v.Moves() {
			_, move, ok := v.Move(prior.Selection())
			if ok && movePending(move) && prior.App != nil && prior.Binding.Scope.Tenant == q.Scope.Tenant && prior.Binding.Scope.App == q.Scope.App && !sameDrainGroupOrigin(prior.Origin, op, q.Scope.Tenant, q.Scope.App, prior.Binding.Scope.Tenant, prior.Binding.Scope.App) {
				return nil, state.ConditionFailed
			}
		}
	}
	if q.Target.UID != e.Native.Spec.UID || q.Target.GID != e.Native.Spec.GID || q.Target.Mode != e.Native.Spec.Mode {
		return nil, state.ConditionFailed
	}
	if err := p.validateMoveAppStart(s, c, op, q); err != nil {
		return nil, state.Forbidden
	}
	if current, err := p.workNodeOwner(s, q.Target.Node); err != nil || current != q.Target.NodeKey {
		return nil, state.Forbidden
	}
	for _, held := range e.State.Consumers() {
		// A pending backup must not be made invalid by freezing its activation.
		// The original writer may remain while the app controller retires it.
		if !held.Writable {
			return nil, state.ConditionFailed
		}
	}
	for _, owner := range []volumes.Owner{e.Native.Owner, {Node: q.Target.Node, Key: q.Target.NodeKey}} {
		current, err := p.nodeOwner(s, owner.Node)
		if err != nil || !p.ownsResource(s, current, owner.Key) || c.Authorize(op.Change.Principal, q.Scope.Tenant, access.ManageVolumes, owner.Node) != nil {
			return nil, state.Forbidden
		}
	}
	target, err := restoreTargetOwner(q.Target)
	if err != nil || !v.admitOriginal(q.Scope.Tenant, q.Target.Node, q.Target.NodeKey, q.CapacityBytes) {
		return nil, state.ConditionFailed
	}
	e.State, err = e.State.Prepare(c, op.Change.Principal, expected, q.OwnerRevision, q.ID, target, q.Compatibility, q.MaxBytes)
	if err != nil {
		return nil, state.ConditionFailed
	}
	m, _ := e.State.Move(q.ID)
	j := VolumeMove{Schema: 1, App: q.App, Binding: m.Binding, Source: e.Native, Target: q.Target, MaxEntries: q.MaxEntries, CapacityBytes: q.CapacityBytes, SourceCapacity: e.CapacityBytes, ExpiresAt: q.ExpiresAt, Origin: op}
	if !validMoveJob(j) {
		return nil, state.Invalid
	}
	v.entries[volumeKey(q.Scope)] = e
	v.moves[moveKey(j.Selection())] = j
	return p.volumeCheckpoint(s, v)
}

type VolumeMovePermitRequest struct {
	Selection VolumeMoveSelection
	Kind      string // fence, read, receive, commit, cleanup, receive-cleanup
}
type VolumeMovePermit struct {
	Job                 VolumeMove
	Move                volumes.Move
	Revision            uint64
	Reader              *volumes.Consumer `json:",omitempty"`
	Epoch, RootRevision uint64
	Inputs              *VolumeMoveInputs     `json:",omitempty"`
	ActiveTask          *VolumeMoveActiveTask `json:",omitempty"`
	ActiveIdle          bool                  `json:",omitempty"`
	SourceUnchanged     bool                  `json:",omitempty"`
}

// This pure check consumes a fresh authenticated adapter quorum view. The
// Runtime supplies the current time; neither a local DB nor session expiry is
// silently substituted for current accepted-operation authorization.
func (p Policy) VolumeMovePermit(s state.State, caller [32]byte, q VolumeMovePermitRequest, at int64) (VolumeMovePermit, error) {
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeMovePermit{}, err
	}
	j, m, ok := v.Move(q.Selection)
	if !ok {
		return VolumeMovePermit{}, access.ErrDenied
	}
	if q.Kind == "prepare-inputs" {
		base, err := p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Target.Node, j.Binding.Target.Key), VolumeMovePermitRequest{Selection: q.Selection, Kind: "prepare"}, at)
		if err != nil {
			return VolumeMovePermit{}, err
		}
		inputs, err := p.moveInputSet(s, j, at)
		if err != nil || inputs == nil || !p.ownsResource(s, caller, j.Binding.Target.Key) && !p.moveInputCaller(s, inputs, caller) {
			return VolumeMovePermit{}, access.ErrDenied
		}
		base.Inputs = inputs
		return base, nil
	}
	actor := j.Binding.Source
	if q.Kind == "receive" || q.Kind == "receive-cleanup" || q.Kind == "commit" || q.Kind == "prepare" || q.Kind == "activate-app" || q.Kind == "active" || q.Kind == "cleanup-target" || q.Kind == "cancel-target" {
		actor = j.Binding.Target
	}
	if !p.ownsResource(s, caller, actor.Key) {
		return VolumeMovePermit{}, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, actor.Node)
	if err != nil || owner != caller {
		return VolumeMovePermit{}, access.ErrDenied
	}
	e := v.entries[volumeKey(q.Selection.Scope)]
	out := VolumeMovePermit{Job: j, Move: m, Revision: e.State.Revision(), Epoch: s.ModuleEpoch(), RootRevision: s.Object(VolumesKey).Revision}
	if reader, ok := e.State.MoveReader(j.Binding); ok {
		out.Reader = &reader
	}
	if q.Kind == "active" {
		task, err := p.moveActiveTask(s, j)
		if err != nil {
			return VolumeMovePermit{}, err
		}
		if task.Task.Key == "" {
			out.ActiveIdle = true
		} else {
			out.ActiveTask = &task
		}
		return out, nil
	}
	if q.Kind == "cancel-source" || q.Kind == "cancel-target" || q.Kind == "cancel-fence" {
		if m.Phase != volumes.Cancelling || m.CommitRevision != 0 {
			return VolumeMovePermit{}, access.ErrDenied
		}
		if q.Kind == "cancel-target" {
			if m.CancelledTarget != nil {
				return VolumeMovePermit{}, access.ErrDenied
			}
			return out, nil
		}
		if m.SourceCleanup != nil {
			return VolumeMovePermit{}, access.ErrDenied
		}
		out.SourceUnchanged = p.moveSourceUnchanged(s, j, m, e.State)
		if q.Kind == "cancel-source" && out.SourceUnchanged {
			return out, nil
		}
		if len(e.State.Consumers()) != 0 || e.State.HadMoveReader(j.Binding) && m.ReaderClosed == nil {
			return VolumeMovePermit{}, access.ErrDenied
		}
		if j.App != nil {
			status, err := p.MoveAppQuiescence(s, j)
			if err != nil || status != "ready" {
				return VolumeMovePermit{}, access.ErrDenied
			}
		}
		if q.Kind == "cancel-source" && m.Fence == nil || q.Kind == "cancel-fence" && m.Fence != nil {
			return VolumeMovePermit{}, access.ErrDenied
		}
		return out, nil
	}
	if q.Kind == "cleanup-source" || q.Kind == "cleanup-target" {
		if m.Phase != volumes.Active || m.Activated == nil || m.Fence == nil || m.CommitRevision == 0 {
			return VolumeMovePermit{}, access.ErrDenied
		}
		if q.Kind == "cleanup-source" {
			if m.SourceCleanup != nil || m.ReaderClosed == nil || slices.ContainsFunc(e.State.Consumers(), func(c volumes.Consumer) bool { return c.Owner == j.Binding.Source }) {
				return VolumeMovePermit{}, access.ErrDenied
			}
		} else if m.TargetCleanup != nil {
			return VolumeMovePermit{}, access.ErrDenied
		}
		return out, nil
	}
	if q.Kind == "cleanup" || q.Kind == "receive-cleanup" {
		settledSource := q.Kind == "cleanup" && m.Phase == volumes.Verified && m.Verified != nil
		if (!settledSource && m.Phase != volumes.Cancelling) || m.CommitRevision != 0 {
			return VolumeMovePermit{}, access.ErrDenied
		}
		if q.Kind == "cleanup" && m.Phase == volumes.Cancelling {
			out.SourceUnchanged = p.moveSourceUnchanged(s, j, m, e.State)
		}
		return out, nil
	}
	// The plan's expiry bounds starting the copy. Once the copy is Verified
	// the app is already down and its data waits on the target, so starting
	// it there is not bounded by the plan: refusing would strand the app.
	verifiedActivate := q.Kind == "activate-app" && (m.Phase == volumes.Verified || m.Phase == volumes.OwnerCommitted)
	if at < j.Origin.At || at >= j.ExpiresAt && !verifiedActivate {
		return VolumeMovePermit{}, access.ErrDenied
	}
	if q.Kind == "prepare" || q.Kind == "receive" || q.Kind == "commit" || q.Kind == "activate-app" {
		if current, err := p.workNodeOwner(s, j.Binding.Target.Node); err != nil || !p.ownsResource(s, current, j.Binding.Target.Key) {
			return VolumeMovePermit{}, access.ErrDenied
		}
	}
	c, err := p.Catalog(s)
	if err != nil {
		return VolumeMovePermit{}, err
	}
	for _, o := range []volumes.Owner{j.Binding.Source, j.Binding.Target} {
		current, err := p.nodeOwner(s, o.Node)
		if err != nil || !p.ownsResource(s, current, o.Key) || c.AuthorizeAccepted(j.Origin.Session, p.Cluster, j.Origin.At, j.Binding.Scope.Tenant, access.ManageVolumes, o.Node) != nil {
			return VolumeMovePermit{}, access.ErrDenied
		}
	}
	switch q.Kind {
	case "activate-app":
		if j.App == nil || j.App.Target == nil || m.Phase != volumes.Verified && m.Phase != volumes.OwnerCommitted || m.Verified == nil || m.Manifest == nil || m.Preparation == nil || len(e.State.Consumers()) != 0 || p.moveAppSecretsReady(s, j, at) != nil {
			return VolumeMovePermit{}, access.ErrDenied
		}
	case "prepare":
		if m.Phase != volumes.Prepared || p.RevalidateMoveAppTarget(s, j) != nil {
			return VolumeMovePermit{}, access.ErrDenied
		}
	case "quiesce":
		status, err := p.MoveAppQuiescence(s, j)
		if err != nil || j.App == nil || m.Phase != volumes.Prepared || m.Preparation == nil || status != "pending" || p.RevalidateMoveAppTarget(s, j) != nil || p.moveInputsPrepared(s, j, m, at) != nil || c.AuthorizeAcceptedCleanup(j.Origin.Session, p.Cluster, j.Origin.At, j.Binding.Scope.Tenant, access.Deploy) != nil {
			return VolumeMovePermit{}, access.ErrDenied
		}
	case "commit":
		if m.Phase != volumes.Verified || m.Verified == nil || m.Manifest == nil || len(e.State.Consumers()) != 0 || e.State.HadMoveReader(j.Binding) && m.ReaderClosed == nil {
			return VolumeMovePermit{}, access.ErrDenied
		}
	case "receive":
		if m.Phase != volumes.Copying || m.Manifest == nil || out.Reader == nil {
			return VolumeMovePermit{}, access.ErrDenied
		}
	case "fence":
		if m.Phase != volumes.Prepared || len(e.State.Consumers()) != 0 {
			return VolumeMovePermit{}, access.ErrDenied
		}
		if j.App != nil {
			status, err := p.MoveAppQuiescence(s, j)
			if err != nil || status != "ready" || m.Preparation == nil {
				return VolumeMovePermit{}, access.ErrDenied
			}
		}
	case "read":
		if m.ReaderClosed != nil || m.Phase != volumes.SourceFenced && m.Phase != volumes.Copying {
			return VolumeMovePermit{}, access.ErrDenied
		}
		for _, reader := range e.State.Consumers() {
			if e.State.CheckMoveReader(j.Binding, reader) == nil {
				r := reader
				out.Reader = &r
			}
		}
	default:
		return VolumeMovePermit{}, access.ErrDenied
	}
	return out, nil
}

// Source archives share the existing backup budget; target staging shares
// restore budget. Both count toward the same node and tenant reservations.
func (v Volumes) copyBudgetsOK() bool { return v.copyBudgetFailure(nil) == "" }

// moveCharge is a move not yet accepted, charged like a pending one.
type moveCharge struct {
	tenant               string
	source, target       string
	sourceKey, targetKey [32]byte
	bytes                uint64
}

// copyBudgetFailure names the first copy budget that does not hold, with
// extra charged after every reservation already held. It is "" when all hold.
// The name is a bounded code a plan can return: SOURCE_BACKUP_LIMIT_* for
// the source archive or TARGET_STAGING_LIMIT_* for the target staging, ending
// in _CLUSTER or _TENANT for the limit that is missing or full.
func (v Volumes) copyBudgetFailure(extra *moveCharge) string {
	type usage struct {
		bytes uint64
		count uint32
	}
	archive, staging := map[string]usage{}, map[string]usage{}
	charge := func(dst map[string]usage, tenant, node string, key [32]byte, bytes uint64, stage bool) string {
		for _, t := range []string{"", tenant} {
			k := backupLimitKey(t, node)
			limit, ok := v.backupLimits[k]
			u := dst[k]
			maxBytes, maxCount := limit.Bytes, limit.Count
			if stage {
				maxBytes, maxCount = limit.StagingBytes, limit.StagingCount
			}
			if !ok || limit.Owner != key || bytes > maxBytes || u.bytes > maxBytes-bytes || u.count >= maxCount {
				code := "SOURCE_BACKUP_LIMIT"
				if stage {
					code = "TARGET_STAGING_LIMIT"
				}
				if t == "" {
					return code + "_CLUSTER"
				}
				return code + "_TENANT"
			}
			u.bytes += bytes
			u.count++
			dst[k] = u
		}
		return ""
	}
	for _, j := range v.backups {
		bytes, count := backupCharged(j)
		if count != 0 {
			if code := charge(archive, j.Binding.Scope.Tenant, j.Binding.Source.Owner.Node, j.Binding.Source.Owner.Key, bytes, false); code != "" {
				return code
			}
		}
	}
	for _, j := range v.restores {
		if v.restoreCharged(j) {
			if code := charge(staging, j.Binding.Target.Scope.Tenant, j.Binding.Target.Node, j.Binding.Target.NodeKey, j.Binding.MaxBytes, true); code != "" {
				return code
			}
		}
	}
	for _, j := range v.moves {
		_, m, ok := v.Move(j.Selection())
		if !ok {
			return "MOVE_RECORD_INVALID"
		}
		if !movePending(m) {
			continue
		}
		if code := charge(archive, j.Binding.Scope.Tenant, j.Binding.Source.Node, j.Binding.Source.Key, j.Binding.MaxBytes, false); code != "" {
			return code
		}
		if code := charge(staging, j.Binding.Scope.Tenant, j.Binding.Target.Node, j.Binding.Target.Key, j.Binding.MaxBytes, true); code != "" {
			return code
		}
	}
	if extra != nil {
		if code := charge(archive, extra.tenant, extra.source, extra.sourceKey, extra.bytes, false); code != "" {
			return code
		}
		return charge(staging, extra.tenant, extra.target, extra.targetKey, extra.bytes, true)
	}
	return ""
}

func isMoveAction(action string) bool { return strings.HasSuffix(action, "-volume-move") }
