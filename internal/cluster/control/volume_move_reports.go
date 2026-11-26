// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

type VolumeMoveReport struct {
	Operation                     string // move, distinct from backup/restore in the same root
	Schema                        uint8
	Selection                     VolumeMoveSelection
	Binding                       [32]byte
	Epoch, RootRevision, Revision uint64
	At                            int64
	Kind                          string                     // source, preparation, copy, activation and cleanup facts
	Fence                         *volumes.FenceProof        `json:",omitempty"`
	Closed                        *volumes.Gone              `json:",omitempty"`
	Manifest                      *volumes.Manifest          `json:",omitempty"`
	Copy                          *volumes.CopyProof         `json:",omitempty"`
	Target                        *volumes.NativeReady       `json:",omitempty"`
	ArtifactReturned              bool                       `json:",omitempty"`
	Preparation                   *volumes.TargetPreparation `json:",omitempty"`
	Active                        *volumes.ActiveProof       `json:",omitempty"`
	Cleanup                       *volumes.CleanupProof      `json:",omitempty"`
	CancelledTarget               *volumes.CancelProof       `json:",omitempty"`
	Signature                     []byte
}

func VolumeMoveReportBytes(r VolumeMoveReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-volume-move-report-1\x00"), raw...)
}
func volumeMoveReportValue(raw []byte) bool {
	var tag struct{ Operation string }
	return json.Unmarshal(raw, &tag) == nil && tag.Operation == "move"
}
func (p Policy) volumeMoveReport(s state.State, cmd state.Command) (VolumeMoveReport, error) {
	r, err := schema.Decode[VolumeMoveReport]([]byte(cmd.Value))
	if err != nil || cmd.Kind != state.ModuleReport || cmd.Key != VolumesKey || r.Operation != "move" || r.Schema != 1 || r.Epoch != cmd.Epoch || r.RootRevision != cmd.Expected || r.Epoch == 0 || r.Revision == 0 || r.At < 0 || cmd.RequestID != state.ReportRequestID(cmd) {
		return r, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return r, err
	}
	j, _, ok := v.Move(r.Selection)
	owner := j.Binding.Source
	if r.Kind == "copied" || r.Kind == "prepared" || r.Kind == "activate-app" || r.Kind == "active" || r.Kind == "cleanup-target" || r.Kind == "cancel-target" {
		owner = j.Binding.Target
	}
	if !ok || r.Binding != j.Digest() || cmd.Actor != "node/"+hex.EncodeToString(owner.Key[:]) || !ed25519.Verify(owner.Key[:], VolumeMoveReportBytes(r), r.Signature) {
		return r, access.ErrDenied
	}
	key, err := p.nodeOwner(s, owner.Node)
	if err != nil || !p.ownsResource(s, key, owner.Key) {
		return r, access.ErrDenied
	}
	// Current membership authenticates the transport above. Native receipts
	// remain signed by this exact original resource owner after rotation.
	key = owner.Key
	if r.Kind != "copied" && (r.Copy != nil || r.Target != nil || r.ArtifactReturned) {
		return r, access.ErrDenied
	}
	if r.Kind != "prepared" && r.Preparation != nil {
		return r, access.ErrDenied
	}
	if r.Kind != "active" && r.Active != nil || r.Kind != "cleanup-source" && r.Kind != "cleanup-target" && r.Kind != "cancel-source" && r.Cleanup != nil || r.Kind != "cancel-target" && r.CancelledTarget != nil {
		return r, access.ErrDenied
	}
	switch r.Kind {
	case "cancel-target":
		if r.CancelledTarget == nil || r.CancelledTarget.Binding != j.Binding || !r.CancelledTarget.StagingGone || !r.CancelledTarget.StartsSettled || !r.CancelledTarget.MountsGone || !r.CancelledTarget.TransferClosed || r.Fence != nil || r.Closed != nil || r.Manifest != nil || !ed25519.Verify(key[:], volumes.CancelBytes(*r.CancelledTarget), r.CancelledTarget.Signature) {
			return r, access.ErrDenied
		}
	case "cancel-source":
		if r.Cleanup == nil || r.Cleanup.Binding != j.Binding || r.Cleanup.Owner != owner || !r.Cleanup.TransferClosed || r.Cleanup.RetainedFenced == r.Cleanup.Unchanged || r.Fence != nil || r.Closed != nil || r.Manifest != nil || !ed25519.Verify(key[:], volumes.CleanupBytes(*r.Cleanup), r.Cleanup.Signature) {
			return r, access.ErrDenied
		}
	case "active":
		if r.Active == nil || r.Active.Binding != j.Binding || r.Active.Idle && (r.Active.Running || r.Active.Consumer != (volumes.Consumer{})) || !r.Active.Idle && (r.Active.Consumer.Owner != j.Binding.Target || !r.Active.Running) || r.Fence != nil || r.Closed != nil || r.Manifest != nil || !ed25519.Verify(key[:], volumes.ActiveBytes(*r.Active), r.Active.Signature) {
			return r, access.ErrDenied
		}
	case "cleanup-source", "cleanup-target":
		if r.Cleanup == nil || r.Cleanup.Binding != j.Binding || r.Cleanup.Owner != owner || !r.Cleanup.TransferClosed || r.Cleanup.Unchanged || r.Cleanup.RetainedFenced != (r.Kind == "cleanup-source") || r.Fence != nil || r.Closed != nil || r.Manifest != nil || !ed25519.Verify(key[:], volumes.CleanupBytes(*r.Cleanup), r.Cleanup.Signature) {
			return r, access.ErrDenied
		}
	case "activate-app":
		if j.App == nil || j.App.Target == nil || r.Fence != nil || r.Closed != nil || r.Manifest != nil {
			return r, access.ErrDenied
		}
	case "prepared":
		if r.Preparation == nil || r.Fence != nil || r.Closed != nil || r.Manifest != nil || r.Preparation.Binding != j.Binding || r.Preparation.Target.Verify() != nil || r.Preparation.Target.Spec != j.Target || r.Preparation.Target.Owner != j.Binding.Target || !r.Preparation.Empty || !r.Preparation.NoWriters || !r.Preparation.SpaceChecked || !r.Preparation.ProtocolReady || !ed25519.Verify(key[:], volumes.TargetPreparationBytes(*r.Preparation), r.Preparation.Signature) {
			return r, access.ErrDenied
		}
	case "quiesce":
		if j.App == nil || r.Fence != nil || r.Closed != nil || r.Manifest != nil {
			return r, access.ErrDenied
		}
	case "copied":
		if r.Fence != nil || r.Closed != nil || r.Manifest != nil || r.Copy == nil || r.Target == nil || !r.ArtifactReturned || r.Target.Verify() != nil || r.Target.Spec != j.Target || r.Target.Owner != j.Binding.Target || r.Target.Generation != 1 || r.Copy.Binding != j.Binding || !r.Copy.DigestVerified || !r.Copy.Synced || !r.Copy.NoWriters || !ed25519.Verify(key[:], volumes.CopyBytes(*r.Copy), r.Copy.Signature) {
			return r, access.ErrDenied
		}
	case "fenced":
		if r.Fence == nil || r.Closed != nil || r.Manifest != nil || r.Fence.Binding != j.Binding || r.Fence.FenceThrough != j.Binding.SourceOwnerRevision || !r.Fence.Stopped || !r.Fence.MountsGone || !r.Fence.StartsSettled || !r.Fence.Synced || !ed25519.Verify(key[:], volumes.FenceBytes(*r.Fence), r.Fence.Signature) {
			return r, access.ErrDenied
		}
	case "reader":
		if r.Fence != nil || r.Closed != nil || r.Manifest != nil {
			return r, access.ErrDenied
		}
	case "reader-gone":
		if r.Fence != nil || r.Manifest != nil || r.Closed == nil || r.Closed.Scope != j.Binding.Scope || r.Closed.Consumer.Owner != j.Binding.Source || r.Closed.Consumer.Writable || !r.Closed.Stopped || !r.Closed.MountsGone || !ed25519.Verify(key[:], volumes.GoneBytes(*r.Closed), r.Closed.Signature) {
			return r, access.ErrDenied
		}
	case "manifest":
		if r.Fence != nil || r.Closed != nil || r.Manifest == nil || r.Manifest.Binding != j.Binding || !r.Manifest.ReadOnly || r.Manifest.ArchiveReceipt().Validate(j.Options()) != nil || !ed25519.Verify(key[:], volumes.ManifestBytes(*r.Manifest), r.Manifest.Signature) {
			return r, access.ErrDenied
		}
	default:
		return r, access.ErrDenied
	}
	return r, nil
}
func (p Policy) ResolveVolumeMoveReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	r, err := schema.Decode[VolumeMoveReport](raw)
	if err != nil {
		return state.Command{}, err
	}
	v, e := p.Volumes(s)
	if e != nil {
		return state.Command{}, e
	}
	j, _, ok := v.Move(r.Selection)
	owner := j.Binding.Source
	if r.Kind == "copied" || r.Kind == "prepared" || r.Kind == "activate-app" || r.Kind == "active" || r.Kind == "cleanup-target" || r.Kind == "cancel-target" {
		owner = j.Binding.Target
	}
	if !ok || !p.ownsResource(s, caller, owner.Key) {
		return state.Command{}, access.ErrDenied
	}
	caller = owner.Key
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(caller[:]), Epoch: r.Epoch, Key: VolumesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = p.volumeMoveReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceVolumeMoveReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.volumeMoveReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	j, _, _ := v.Move(r.Selection)
	e := v.entries[volumeKey(r.Selection.Scope)]
	if e.State.Revision() != r.Revision {
		return nil, state.ConditionFailed
	}
	switch r.Kind {
	case "cancel-source":
		permit, e2 := p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Source.Node, j.Binding.Source.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: "cancel-source"}, r.At)
		if e2 != nil || permit.SourceUnchanged != r.Cleanup.Unchanged {
			return nil, state.Forbidden
		}
		e.State, err = e.State.RecordCleanup(*r.Cleanup)
	case "cancel-target":
		if _, e2 := p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Target.Node, j.Binding.Target.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: "cancel-target"}, r.At); e2 != nil {
			return nil, state.Forbidden
		}
		e.State, err = e.State.RecordCancelTarget(*r.CancelledTarget)
	case "active":
		permit, e2 := p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Target.Node, j.Binding.Target.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: "active"}, r.At)
		if e2 != nil || permit.ActiveIdle != r.Active.Idle || permit.ActiveIdle && permit.ActiveTask != nil || !permit.ActiveIdle && (permit.ActiveTask == nil || permit.ActiveTask.Consumer != r.Active.Consumer) {
			return nil, state.Forbidden
		}
		e.State, err = e.State.RecordActive(*r.Active)
	case "cleanup-source", "cleanup-target":
		if _, e2 := p.VolumeMovePermit(s, p.resourceCallerForNode(s, r.Cleanup.Owner.Node, r.Cleanup.Owner.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: r.Kind}, r.At); e2 != nil {
			return nil, state.Forbidden
		}
		e.State, err = e.State.RecordCleanup(*r.Cleanup)
	case "activate-app":
		if _, err = p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Target.Node, j.Binding.Target.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: "activate-app"}, r.At); err != nil {
			return nil, state.Forbidden
		}
		return p.activateMoveApp(s, v, j)
	case "prepared":
		if _, err = p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Target.Node, j.Binding.Target.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: "prepare"}, r.At); err != nil {
			return nil, state.Forbidden
		}
		if j.App != nil && j.App.Target != nil {
			inputs, err := p.moveInputSet(s, j, r.At)
			if err != nil || inputs == nil || r.Preparation.Inputs == nil || *r.Preparation.Inputs != inputs.ReadSet || r.Preparation.InputsAt <= 0 || r.Preparation.InputsAt > r.At || r.At-r.Preparation.InputsAt > 30 {
				return nil, state.Forbidden
			}
		} else if r.Preparation.Inputs != nil {
			return nil, state.Forbidden
		}
		e.State, err = e.State.RecordTargetPreparation(*r.Preparation)
	case "quiesce":
		if _, err = p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Source.Node, j.Binding.Source.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: "quiesce"}, r.At); err != nil {
			return nil, state.Forbidden
		}
		appWrites, code := p.quiesceMoveApp(s, j)
		if code != state.Applied {
			return nil, code
		}
		// A1 binds the request receipt/CAS to its own Volume root. Publish
		// that root and the related original App retirement atomically.
		volumeWrites, code := p.volumeCheckpoint(s, v)
		if code != state.Applied {
			return nil, code
		}
		for key, value := range appWrites {
			volumeWrites[key] = value
		}
		return volumeWrites, state.Applied
	case "copied":
		if _, err = p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Target.Node, j.Binding.Target.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: "receive"}, r.At); err != nil {
			return nil, state.Forbidden
		}
		e.State, err = e.State.VerifyCopy(*r.Copy)
	case "fenced":
		kind := "fence"
		if m, _ := e.State.Move(j.Binding.ID); m.Phase == volumes.Cancelling {
			kind = "cancel-fence"
		}
		if _, err = p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Source.Node, j.Binding.Source.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: kind}, r.At); err != nil {
			return nil, state.Forbidden
		}
		e.State, err = e.State.RecordFence(*r.Fence)
	case "reader":
		if _, err = p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Source.Node, j.Binding.Source.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: "read"}, r.At); err != nil {
			return nil, state.Forbidden
		}
		var reader volumes.Consumer
		c, e2 := p.Catalog(s)
		if e2 != nil {
			return nil, state.Invalid
		}
		e.State, reader, err = e.State.AcquireMoveReader(c, j.Origin.Change.Principal, r.Revision, j.Binding)
		if err == nil && !slices.ContainsFunc(e.Grants, func(g volumeGrant) bool { return g.Consumer == reader }) {
			e.Grants = append(e.Grants, volumeGrant{Consumer: reader, Principal: j.Origin.Change.Principal})
		}
	case "reader-gone":
		reader, ok := e.State.MoveReader(j.Binding)
		if !ok || reader != r.Closed.Consumer {
			return nil, state.ConditionFailed
		}
		e.State, err = e.State.CloseMoveReader(j.Binding, *r.Closed)
		if err == nil {
			e.Grants = slices.DeleteFunc(e.Grants, func(g volumeGrant) bool { return g.Consumer == reader })
		}
	case "manifest":
		permit, e2 := p.VolumeMovePermit(s, p.resourceCallerForNode(s, j.Binding.Source.Node, j.Binding.Source.Key), VolumeMovePermitRequest{Selection: r.Selection, Kind: "read"}, r.At)
		if e2 != nil || permit.Reader == nil {
			return nil, state.Forbidden
		}
		e.State, err = e.State.BeginCopy(*r.Manifest)
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	if m, _ := e.State.Move(j.Binding.ID); m.Phase == volumes.Cancelling && m.SourceCleanup != nil && m.CancelledTarget != nil {
		e.State, err = e.State.SettleCancel(j.Binding, e.State.Revision())
		if err != nil {
			return nil, state.ConditionFailed
		}
	}
	v.entries[volumeKey(r.Selection.Scope)] = e
	return p.volumeCheckpoint(s, v)
}
