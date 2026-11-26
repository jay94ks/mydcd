// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// VolumeCreate is a logical declaration, never a supplied native name/path.
// The local driver observes capacity and does not enforce filesystem quotas.
type VolumeCreate struct {
	Scope          volumes.Scope
	Node           string
	UID, GID, Mode uint32
	QuotaMode      string
	CapacityBytes  uint64 `json:",omitempty"`
}

type VolumeCreation struct {
	Spec        volumes.NativeSpec
	Origin      UserOperation
	Revision    uint64
	Capacity    int
	Phase       string
	Preparation *VolumeCreateReport         `json:",omitempty"`
	Ready       *volumes.NativeReady        `json:",omitempty"`
	Gone        *volumes.NativeRemoved      `json:",omitempty"`
	Fixed       *nodestorage.FixedSelection `json:",omitempty"`
	Unregister  *UserOperation              `json:",omitempty"`
}

type VolumeCreateWork struct {
	Spec     volumes.NativeSpec
	Revision uint64
	Capacity int
	Phase    string
	Prepared bool
	Fixed    *nodestorage.FixedSelection `json:",omitempty"`
}

type VolumeCreateReport struct {
	Operation           string
	Schema              uint8
	Scope               volumes.Scope
	Epoch, RootRevision uint64
	Revision            uint64
	At                  int64
	Prepared            bool `json:",omitempty"`
	Signature           []byte
	Ready               *volumes.NativeReady   `json:",omitempty"`
	Gone                *volumes.NativeRemoved `json:",omitempty"`
}

func creationKey(s volumes.Scope) string {
	return volumeKey(s) + "/" + strconv.FormatUint(s.Generation, 10)
}
func creationPending(phase string) bool {
	return phase == "Reserved" || phase == "Creating" || phase == "Cancelling"
}
func volumeCreateReportValue(raw []byte) bool {
	var q struct{ Operation string }
	return json.Unmarshal(raw, &q) == nil && q.Operation == "create"
}
func ownCreation(c VolumeCreation) VolumeCreation {
	raw, _ := json.Marshal(c)
	var owned VolumeCreation
	_ = json.Unmarshal(raw, &owned)
	return owned
}
func (v Volumes) Creation(scope volumes.Scope) (VolumeCreation, bool) {
	j, ok := v.creations[creationKey(scope)]
	return ownCreation(j), ok
}
func (v Volumes) Creations() []VolumeCreation {
	keys := make([]string, 0, len(v.creations))
	for key := range v.creations {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	rows := make([]VolumeCreation, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, ownCreation(v.creations[key]))
	}
	return rows
}

// Metadata names remain bounded even after native bytes/slots are returned.
// Terminal creation history must not make ordinary Volume pagination unbounded.
func (v Volumes) volumeMetadataSlots() int {
	keys := map[string]bool{}
	for key := range v.entries {
		keys[key] = true
	}
	for _, j := range v.creations {
		keys[volumeKey(j.Spec.Scope)] = true
	}
	for _, j := range v.restores {
		if restorePending(j.Phase) {
			keys[volumeKey(j.Binding.Target.Scope)] = true
		}
	}
	return len(keys)
}

func (v Volumes) creationTargetAvailable(scope volumes.Scope) bool {
	for _, j := range v.creations {
		terminal := j.Phase == "Cancelled" || j.Fixed != nil && j.Phase == "Unregistered"
		if volumeKey(j.Spec.Scope) == volumeKey(scope) && (!terminal || scope.Generation <= j.Spec.Scope.Generation) {
			return false
		}
	}
	return true
}

func createSpec(q VolumeCreate, op UserOperation, owner [32]byte) volumes.NativeSpec {
	raw, _ := json.Marshal(struct {
		Origin UserOperation
		Owner  [32]byte
	}{op, owner})
	digest := sha256.Sum256(append([]byte("mydc-volume-create-1\x00"), raw...))
	return volumes.NativeSpec{Schema: 1, Scope: q.Scope, Node: q.Node, NodeKey: owner, Materialization: "c-" + hex.EncodeToString(digest[:24]), UID: q.UID, GID: q.GID, Mode: q.Mode, Retain: true}
}
func (p Policy) createCapacity(s state.State, spec volumes.NativeSpec) (int, error) {
	n, err := p.bindingCapacity(s, deployment.Needs{Use: secrets.Use{Tenant: spec.Scope.Tenant, Node: spec.Node, NodeKey: spec.NodeKey}})
	if err != nil || n < 1 {
		return 0, access.ErrDenied
	}
	return min(n, 256), nil
}

func (p Policy) validateCreations(s state.State, c access.Catalog, v Volumes) error {
	if len(v.creations) > 256 || v.volumeMetadataSlots() > maxVolumes {
		return ErrCatalog
	}
	for key, j := range v.creations {
		if j.Fixed != nil {
			if err := p.validateFixedCreation(c, v, key, j); err != nil {
				return err
			}
			continue
		}
		if j.Unregister != nil {
			return ErrCatalog
		}
		var q VolumeCreate
		if key != creationKey(j.Spec.Scope) || j.Spec.Validate() != nil || j.Spec.Scope.Cluster != p.Cluster || j.Origin.VerifyOriginal(p.Cluster) != nil || j.Origin.Change.Action != "begin-volume-create" || j.Origin.Change.Expected != 0 || canonical(j.Origin.Change.Payload, &q) != nil || q.QuotaMode != "observe" || createSpec(q, j.Origin, j.Spec.NodeKey) != j.Spec || j.Capacity < 1 || j.Capacity > 256 {
			return ErrCatalog
		}
		_, exists := c.Tenant(j.Spec.Scope.Tenant)
		if !exists {
			return ErrCatalog
		}
		if prepared := j.Preparation; prepared != nil {
			if prepared.Operation != "create" || prepared.Schema != 1 || prepared.Scope != j.Spec.Scope || !prepared.Prepared || prepared.Revision != 1 || prepared.Epoch == 0 || prepared.At < 0 || prepared.Ready != nil || prepared.Gone != nil || !ed25519.Verify(j.Spec.NodeKey[:], VolumeCreateReportBytes(*prepared), prepared.Signature) {
				return ErrCatalog
			}
		}
		e, published := v.entries[volumeKey(j.Spec.Scope)]
		switch j.Phase {
		case "Reserved", "Creating", "Cancelling":
			expected := uint64(1)
			if j.Preparation != nil {
				expected++
			}
			if j.Phase == "Cancelling" {
				expected++
			}
			if j.Phase == "Reserved" && j.Preparation != nil || j.Phase == "Creating" && j.Preparation == nil || j.Revision != expected || j.Ready != nil || j.Gone != nil || published {
				return ErrCatalog
			}
		case "Ready":
			if j.Revision != 3 || j.Preparation == nil || j.Ready == nil || j.Ready.Verify() != nil || j.Ready.Spec != j.Spec || j.Ready.Generation != 1 || j.Gone != nil || !published || !sameVolumeNative(e.Native, *j.Ready) && !movedFrom(e.State, j.Ready.Owner) {
				return ErrCatalog
			}
		case "Cancelled":
			expected := uint64(3)
			if j.Preparation != nil {
				expected++
			}
			owner, err := restoreTargetOwner(j.Spec)
			if err != nil || j.Revision != expected || j.Ready != nil || j.Gone == nil || j.Gone.Verify() != nil || j.Gone.Scope != j.Spec.Scope || j.Gone.Owner != owner || j.Gone.Key != volumes.NativeKey(j.Spec) || j.Gone.Generation != 1 || j.Gone.DeleteRevision != j.Revision-1 || published && e.State.Scope().Generation <= j.Spec.Scope.Generation {
				return ErrCatalog
			}
		default:
			return ErrCatalog
		}
		for otherKey, other := range v.creations {
			if key < otherKey && creationPending(j.Phase) && creationPending(other.Phase) && volumeKey(j.Spec.Scope) == volumeKey(other.Spec.Scope) {
				return ErrCatalog
			}
		}
	}
	return nil
}

func (p Policy) reduceVolumeCreate(s state.State, c access.Catalog, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	if op.Change.Action == "register-fixed-volume" {
		return p.reduceFixedRegistration(s, c, v, op)
	}
	if op.Change.Action == "cancel-volume-create" {
		var scope volumes.Scope
		if canonical(op.Change.Payload, &scope) != nil {
			return nil, state.Invalid
		}
		j, ok := v.creations[creationKey(scope)]
		if !ok || (j.Phase != "Reserved" && j.Phase != "Creating") || j.Revision != op.Change.Expected {
			return nil, state.ConditionFailed
		}
		j.Phase, j.Revision = "Cancelling", j.Revision+1
		v.creations[creationKey(scope)] = j
		return p.volumeCheckpoint(s, v)
	}
	var q VolumeCreate
	if canonical(op.Change.Payload, &q) != nil || q.Scope.Cluster != p.Cluster || q.QuotaMode != "observe" || op.Change.Expected != 0 || len(v.creations) >= 256 {
		return nil, state.Invalid
	}
	owner, err := p.workNodeOwner(s, q.Node)
	if err != nil {
		return nil, state.Forbidden
	}
	spec := createSpec(q, op, owner)
	if spec.Validate() != nil {
		return nil, state.Invalid
	}
	appClaim := q.Scope.App != "" && s.Object(deployment.ResourceKey("volume", q.Scope.Tenant, q.Scope.App, q.Scope.ID)).Present
	if !v.restoreTargetAvailable(q.Scope) || v.volumeReservations() >= maxVolumes || v.volumeMetadataSlots() >= maxVolumes || len(v.entries) >= maxVolumes || appClaim {
		return nil, state.ConditionFailed
	}
	if _, exists := v.entries[volumeKey(q.Scope)]; exists {
		return nil, state.ConditionFailed
	}
	if !v.admitOriginal(q.Scope.Tenant, q.Node, owner, q.CapacityBytes) {
		return nil, state.ConditionFailed
	}
	capacity, err := p.createCapacity(s, spec)
	if err != nil {
		return nil, state.Forbidden
	}
	v.creations[creationKey(q.Scope)] = VolumeCreation{Spec: spec, Origin: op, Revision: 1, Capacity: capacity, Phase: "Reserved"}
	return p.volumeCheckpoint(s, v)
}

func (p Policy) VolumeCreatePermit(s state.State, caller [32]byte, scope volumes.Scope) (VolumeCreateWork, error) {
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeCreateWork{}, err
	}
	j, ok := v.Creation(scope)
	if !ok || !creationPending(j.Phase) || !p.ownsResource(s, caller, j.Spec.NodeKey) {
		return VolumeCreateWork{}, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, j.Spec.Node)
	if err != nil || owner != caller {
		return VolumeCreateWork{}, access.ErrDenied
	}
	capacity := j.Capacity
	if j.Phase == "Reserved" || j.Phase == "Creating" {
		if current, err := p.workNodeOwner(s, j.Spec.Node); err != nil || current != caller {
			return VolumeCreateWork{}, access.ErrDenied
		}
		c, err := p.Catalog(s)
		if err != nil || !p.acceptedIssuer(s, j.Origin.Session.Issuer) || c.AuthorizeAccepted(j.Origin.Session, p.Cluster, j.Origin.At, scope.Tenant, access.ManageVolumes, j.Spec.Node) != nil {
			return VolumeCreateWork{}, access.ErrDenied
		}
		currentCapacity, err := p.createCapacity(s, j.Spec)
		if err != nil {
			return VolumeCreateWork{}, err
		}
		capacity = min(capacity, currentCapacity)
		if j.Fixed != nil {
			roots, err := p.NodeStorage(s)
			if err != nil {
				return VolumeCreateWork{}, err
			}
			ref := j.Fixed.Root.Root
			root, err := roots.CanUse(c, j.Origin.Session.User, scope.Tenant, ref.Node, ref.ID, ref.Generation)
			if err != nil || root.Reference(p.Cluster) != ref {
				return VolumeCreateWork{}, access.ErrDenied
			}
		}
	}
	work := VolumeCreateWork{Spec: j.Spec, Revision: j.Revision, Capacity: capacity, Phase: j.Phase, Prepared: j.Preparation != nil}
	if j.Fixed != nil {
		fixed := j.Fixed.Clone()
		work.Fixed = &fixed
	}
	return work, nil
}

func VolumeCreateReportBytes(r VolumeCreateReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-volume-create-report-1\x00"), raw...)
}

func (p Policy) volumeCreateReport(s state.State, cmd state.Command) (VolumeCreateReport, error) {
	var r VolumeCreateReport
	if cmd.Kind != state.ModuleReport || cmd.Key != VolumesKey || canonical([]byte(cmd.Value), &r) != nil || r.Operation != "create" || r.Schema != 1 || r.Epoch != cmd.Epoch || r.RootRevision != cmd.Expected || r.At < 0 || cmd.RequestID != state.ReportRequestID(cmd) {
		return r, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return r, err
	}
	j, ok := v.Creation(r.Scope)
	if !ok || cmd.Actor != "node/"+hex.EncodeToString(j.Spec.NodeKey[:]) || !ed25519.Verify(j.Spec.NodeKey[:], VolumeCreateReportBytes(r), r.Signature) {
		return r, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, j.Spec.Node)
	if err != nil || !p.ownsResource(s, owner, j.Spec.NodeKey) {
		return r, access.ErrDenied
	}
	if r.Prepared {
		if r.Ready != nil || r.Gone != nil || r.Revision != 1 {
			return r, access.ErrDenied
		}
	} else if r.Ready != nil {
		if r.Gone != nil || r.Revision != 2 || r.Ready.Verify() != nil || r.Ready.Spec != j.Spec || r.Ready.Generation != creationNativeGeneration(j.Spec) {
			return r, access.ErrDenied
		}
	} else {
		expected, err := creationOwner(j.Spec)
		if err != nil || r.Revision < 2 || r.Revision > 3 || r.Gone == nil || r.Gone.Verify() != nil || r.Gone.Scope != j.Spec.Scope || r.Gone.Owner != expected || r.Gone.Key != volumes.NativeKey(j.Spec) || r.Gone.Generation != creationNativeGeneration(j.Spec) || r.Gone.DeleteRevision != r.Revision {
			return r, access.ErrDenied
		}
	}
	return r, nil
}
func (p Policy) ResolveVolumeCreateReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	r, err := schema.Decode[VolumeCreateReport](raw)
	if err != nil {
		return state.Command{}, err
	}
	v, e := p.Volumes(s)
	if e != nil {
		return state.Command{}, e
	}
	j, ok := v.Creation(r.Scope)
	if !ok || !p.ownsResource(s, caller, j.Spec.NodeKey) {
		return state.Command{}, access.ErrDenied
	}
	caller = j.Spec.NodeKey
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(caller[:]), Epoch: r.Epoch, Expected: r.RootRevision, Key: VolumesKey, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = p.volumeCreateReport(s, cmd)
	return cmd, err
}

func (p Policy) reduceVolumeCreateReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.volumeCreateReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	j := v.creations[creationKey(r.Scope)]
	if j.Revision != r.Revision || !creationPending(j.Phase) {
		return nil, state.ConditionFailed
	}
	if r.Prepared {
		if j.Phase != "Reserved" {
			return nil, state.ConditionFailed
		}
		if _, err := p.VolumeCreatePermit(s, p.resourceCallerForNode(s, j.Spec.Node, j.Spec.NodeKey), r.Scope); err != nil {
			return nil, state.Forbidden
		}
		j.Preparation, j.Phase, j.Revision = &r, "Creating", 2
	} else if r.Ready != nil {
		if j.Phase != "Creating" {
			return nil, state.ConditionFailed
		}
		work, err := p.VolumeCreatePermit(s, p.resourceCallerForNode(s, j.Spec.Node, j.Spec.NodeKey), r.Scope)
		if err != nil {
			return nil, state.Forbidden
		}
		c, err := p.Catalog(s)
		if err != nil {
			return nil, state.Invalid
		}
		constructor := volumes.New
		if j.Fixed != nil {
			constructor = volumes.NewFixed
		}
		core, err := constructor(c, j.Origin.Session.User, r.Scope, r.Ready.Owner, work.Capacity)
		if err != nil {
			return nil, state.Forbidden
		}
		if old, exists := v.entries[volumeKey(r.Scope)]; exists && (j.Fixed == nil || !old.State.Deleted() || old.State.Scope().Generation >= r.Scope.Generation) {
			return nil, state.ConditionFailed
		}
		bytes, err := creationBytes(j)
		if err != nil {
			return nil, state.Invalid
		}
		v.entries[volumeKey(r.Scope)] = registeredVolume{Native: *r.Ready, State: core, CapacityBytes: bytes}
		j.Ready, j.Phase, j.Revision = r.Ready, "Ready", 3
	} else {
		if j.Phase != "Cancelling" {
			return nil, state.ConditionFailed
		}
		j.Gone, j.Phase, j.Revision = r.Gone, "Cancelled", j.Revision+1
	}
	v.creations[creationKey(r.Scope)] = j
	return p.volumeCheckpoint(s, v)
}

// movedFrom says the first committed move took the volume away from owner.
// Its creation or restore record then names the native it was born with,
// which is no longer the current one. Cancelled moves never left owner.
func movedFrom(core volumes.State, owner volumes.Owner) bool {
	for _, m := range core.Moves() {
		if m.CommitRevision != 0 {
			return m.Binding.Source == owner
		}
	}
	return false
}
