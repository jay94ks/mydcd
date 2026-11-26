// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// VolumeDeleteWork is immutable public owner work, without the accepted user's
// session or a supplied host path/name. Native carries the original signed fact.
type VolumeDeleteWork struct {
	Native   volumes.NativeReady
	Revision uint64
	Retained string `json:",omitempty"`
}

type VolumeDeleteReport struct {
	Operation           string
	Schema              uint8
	Epoch, RootRevision uint64
	At                  int64
	Proof               volumes.NativeRemoved
	Retained            string `json:",omitempty"`
}

func volumeDeleteReportValue(raw []byte) bool {
	var value struct{ Operation string }
	return json.Unmarshal(raw, &value) == nil && value.Operation == "delete"
}

func (p Policy) validateVolumeDeletions(v Volumes) error {
	for _, entry := range v.entries {
		if p.validateRetainedDeletes(v, entry) != nil {
			return ErrCatalog
		}
		if entry.State.DeleteRevision() == 0 {
			if entry.DeleteIntent != nil {
				return ErrCatalog
			}
			continue
		}
		op := entry.DeleteIntent
		var scope volumes.Scope
		action := "delete-volume"
		if entry.State.Fixed() {
			action = "unregister-fixed-volume"
		}
		if op == nil || op.VerifyOriginal(p.Cluster) != nil || op.Change.Action != action || canonical(op.Change.Payload, &scope) != nil || scope != entry.State.Scope() || op.Change.Expected == ^uint64(0) || op.Change.Expected+1 != entry.State.DeleteRevision() {
			return ErrCatalog
		}
		if proof, ok := entry.State.Removal(); ok && (proof.Key != volumes.NativeKey(entry.Native.Spec) || proof.Generation != entry.Native.Generation) {
			return ErrCatalog
		}
	}
	return nil
}

func (p Policy) reduceVolumeDelete(s state.State, c access.Catalog, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	var scope volumes.Scope
	if canonical(op.Change.Payload, &scope) != nil || scope.Cluster != p.Cluster {
		return nil, state.Invalid
	}
	entry, ok := v.entries[volumeKey(scope)]
	if !ok || entry.State.Scope() != scope {
		return nil, state.ConditionFailed
	}
	if entry.State.Fixed() != (op.Change.Action == "unregister-fixed-volume") {
		return nil, state.ConditionFailed
	}
	if !p.closedAppVolume(s, entry) {
		return nil, state.ConditionFailed
	}
	var err error
	if entry.State.Fixed() {
		entry.State, err = entry.State.BeginUnregister(c, op.Session.User, op.Change.Expected)
	} else {
		entry.State, err = entry.State.BeginDelete(c, op.Session.User, op.Change.Expected)
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	entry.DeleteIntent = &op
	v.entries[volumeKey(scope)] = entry
	return p.volumeCheckpoint(s, v)
}

// Retained app volumes intentionally keep their original A1 goal; down does
// not publish a Drain mutation for them. The original signed RetainReceipt
// plus a settled Inventory is the actual producer/lifetime closure contract.
func (p Policy) closedAppVolume(s state.State, entry registeredVolume) bool {
	if entry.State.Fixed() {
		return len(entry.State.Consumers()) == 0
	}
	scope := entry.State.Scope()
	key := deployment.ResourceKey("volume", scope.Tenant, scope.App, scope.ID)
	object := s.Object(key)
	if !object.Present {
		return true
	}
	apps, err := p.Apps(s)
	app, ok := apps.entries[appKey(scope.Tenant, scope.App)]
	if err != nil || !ok {
		return false
	}
	if _, active := app.Inventory.Execution(); active {
		return false
	}
	if _, retiring := app.Inventory.Retirement(); retiring {
		return false
	}
	for _, claim := range app.Inventory.Claims() {
		if claim.Step.Key != key {
			continue
		}
		proof := claim.RetainProof
		return claim.Step.Kind == "volume" && claim.Step.Owner == entry.Native.Owner.Key && claim.Retained && !claim.Removed && claim.Result.Code == state.Applied && claim.Result.Generation == object.Generation && claim.Result.Revision == object.Revision && claim.Command.Value == object.Value && proof != nil && proof.Cluster == p.Cluster && proof.Key == key && proof.Owner == entry.Native.Owner.Key && proof.Native == entry.Native.Owner.Native && proof.Generation == object.Generation && proof.Revision == object.Revision && proof.Command == state.Digest(claim.Command) && proof.Fenced && proof.Stopped && proof.Released && proof.Retained && !proof.Gone && proof.Pins == 0 && ed25519.Verify(proof.Owner[:], deployment.RetainReceiptBytes(*proof), proof.Signature)
	}
	return false
}

func (p Policy) VolumeDeletePermit(s state.State, caller [32]byte, scope volumes.Scope) (VolumeDeleteWork, error) {
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeDeleteWork{}, err
	}
	e, ok := v.entries[volumeKey(scope)]
	if !ok || e.State.Scope() != scope || !e.State.Deleting() || e.DeleteIntent == nil || !p.ownsResource(s, caller, e.Native.Owner.Key) {
		return VolumeDeleteWork{}, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, e.Native.Owner.Node)
	if err != nil || owner != caller {
		return VolumeDeleteWork{}, access.ErrDenied
	}
	return VolumeDeleteWork{Native: e.Native, Revision: e.State.DeleteRevision()}, nil
}

func (p Policy) volumeDeleteReport(s state.State, cmd state.Command) (VolumeDeleteReport, error) {
	var r VolumeDeleteReport
	if cmd.Kind != state.ModuleReport || cmd.Key != VolumesKey || canonical([]byte(cmd.Value), &r) != nil || r.Operation != "delete" || r.Schema != 1 || r.Epoch != cmd.Epoch || r.RootRevision != cmd.Expected || r.At < 0 || r.Proof.Verify() != nil || cmd.Actor != "node/"+hex.EncodeToString(r.Proof.Owner.Key[:]) || cmd.RequestID != state.ReportRequestID(cmd) {
		return r, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return r, err
	}
	e, ok := v.entries[volumeKey(r.Proof.Scope)]
	if r.Retained != "" {
		return r, p.validateRetainedDeleteReport(s, v, r)
	}
	if !ok || e.State.Scope() != r.Proof.Scope || e.DeleteIntent == nil || e.State.DeleteRevision() != r.Proof.DeleteRevision || e.Native.Owner != r.Proof.Owner || volumes.NativeKey(e.Native.Spec) != r.Proof.Key || e.Native.Generation != r.Proof.Generation {
		return r, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, e.Native.Owner.Node)
	if err != nil || !p.ownsResource(s, owner, r.Proof.Owner.Key) {
		return r, access.ErrDenied
	}
	return r, nil
}

func (p Policy) ResolveVolumeDeleteReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	r, err := schema.Decode[VolumeDeleteReport](raw)
	if err != nil || !p.ownsResource(s, caller, r.Proof.Owner.Key) {
		return state.Command{}, access.ErrDenied
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Proof.Owner.Key[:]), Epoch: r.Epoch, Key: VolumesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = p.volumeDeleteReport(s, cmd)
	return cmd, err
}

func (p Policy) reduceVolumeDeleteReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.volumeDeleteReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	key := volumeKey(r.Proof.Scope)
	e := v.entries[key]
	if r.Retained == "" {
		e.State, err = e.State.CompleteDelete(r.Proof)
	} else {
		e.State, err = e.State.CompleteRetainedDelete(r.Retained, r.Proof)
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	v.entries[key] = e
	if e.State.Fixed() && e.State.Deleted() && r.Retained == "" {
		if job, ok := v.creations[creationKey(e.State.Scope())]; ok {
			if job.Fixed == nil || job.Phase != "Ready" || job.Revision != 3 || e.DeleteIntent == nil {
				return nil, state.ConditionFailed
			}
			proof := r.Proof
			job.Gone, job.Unregister, job.Phase, job.Revision = &proof, e.DeleteIntent, "Unregistered", 4
			v.creations[creationKey(e.State.Scope())] = job
		}
	}
	return p.volumeCheckpoint(s, v)
}

func (v Volumes) Deletions() []VolumeDeleteWork {
	var out []VolumeDeleteWork
	for _, e := range v.entries {
		if e.State.Deleting() {
			out = append(out, VolumeDeleteWork{Native: e.Native, Revision: e.State.DeleteRevision()})
		}
		for _, move := range e.State.Moves() {
			if d := move.SourceDeletion; d != nil && d.Gone == nil {
				job := v.moves[moveKey(VolumeMoveSelection{Scope: move.Binding.Scope, ID: move.Binding.ID})]
				out = append(out, VolumeDeleteWork{Native: job.Source, Revision: d.Revision, Retained: move.Binding.ID})
			}
		}
	}
	return out
}
