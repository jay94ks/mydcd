// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func (p Policy) validateRetainedDeletes(v Volumes, e registeredVolume) error {
	count := 0
	for _, m := range e.State.Moves() {
		d := m.SourceDeletion
		if d == nil {
			continue
		}
		count++
		q := VolumeMoveSelection{Scope: e.State.Scope(), ID: m.Binding.ID}
		j, _, ok := v.Move(q)
		op, exists := e.RetainedDeletes[q.ID]
		var selected VolumeMoveSelection
		if !ok || !exists || op.VerifyOriginal(p.Cluster) != nil || op.Change.Action != "delete-retained-volume" || canonical(op.Change.Payload, &selected) != nil || selected != q || op.Change.Expected == ^uint64(0) || op.Change.Expected+1 != d.Revision {
			return ErrCatalog
		}
		if d.Gone != nil && (d.Gone.Key != volumes.NativeKey(j.Source.Spec) || d.Gone.Generation != j.Source.Generation) {
			return ErrCatalog
		}
	}
	if count != len(e.RetainedDeletes) {
		return ErrCatalog
	}
	return nil
}

func (p Policy) reduceRetainedVolumeDelete(s state.State, c access.Catalog, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	var q VolumeMoveSelection
	if canonical(op.Change.Payload, &q) != nil || q.Scope.Cluster != p.Cluster {
		return nil, state.Invalid
	}
	j, m, ok := v.Move(q)
	if !ok || m.Phase != volumes.Completed || j.Source.Owner == j.Binding.Target {
		return nil, state.ConditionFailed
	}
	e := v.entries[volumeKey(q.Scope)]
	var err error
	e.State, err = e.State.BeginRetainedDelete(c, op.Session.User, q.ID, op.Change.Expected)
	if err != nil {
		return nil, state.ConditionFailed
	}
	if e.RetainedDeletes == nil {
		e.RetainedDeletes = map[string]UserOperation{}
	}
	e.RetainedDeletes[q.ID] = op
	v.entries[volumeKey(q.Scope)] = e
	return p.volumeCheckpoint(s, v)
}

func (p Policy) VolumeRetainedDeletePermit(s state.State, caller [32]byte, q VolumeMoveSelection) (VolumeDeleteWork, error) {
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeDeleteWork{}, err
	}
	j, m, ok := v.Move(q)
	if !ok || m.SourceDeletion == nil || m.SourceDeletion.Gone != nil || !p.ownsResource(s, caller, j.Source.Owner.Key) {
		return VolumeDeleteWork{}, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, j.Source.Owner.Node)
	if err != nil || owner != caller {
		return VolumeDeleteWork{}, access.ErrDenied
	}
	return VolumeDeleteWork{Native: j.Source, Revision: m.SourceDeletion.Revision, Retained: q.ID}, nil
}

func (p Policy) validateRetainedDeleteReport(s state.State, v Volumes, r VolumeDeleteReport) error {
	q := VolumeMoveSelection{Scope: r.Proof.Scope, ID: r.Retained}
	j, m, ok := v.Move(q)
	if !ok || m.SourceDeletion == nil || m.SourceDeletion.Revision != r.Proof.DeleteRevision || j.Source.Owner != r.Proof.Owner || volumes.NativeKey(j.Source.Spec) != r.Proof.Key || j.Source.Generation != r.Proof.Generation {
		return access.ErrDenied
	}
	owner, err := p.nodeOwner(s, j.Source.Owner.Node)
	if err != nil || !p.ownsResource(s, owner, r.Proof.Owner.Key) {
		return access.ErrDenied
	}
	return nil
}
