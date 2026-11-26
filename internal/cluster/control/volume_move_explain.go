// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// ExplainVolumeMovePrepare names, as a symbolic code, why the target's
// "prepare" permit is refused. Permit replies carry no reason, so a target
// retrying a refused prepare every pass logged only the stage. It replays
// VolumeMovePermit's prepare checks in order on a local view and never
// returns provider errors or input material. "" means the permit passes.
func (p Policy) ExplainVolumeMovePrepare(s state.State, caller [32]byte, selection VolumeMoveSelection, at int64) string {
	j, m, _, code := p.explainMoveTargetPermit(s, caller, selection, at, false)
	if code != "" {
		return code
	}
	if m.Phase != volumes.Prepared {
		return "MOVE_NOT_PREPARED"
	}
	if err := p.RevalidateMoveAppTarget(s, j); err != nil {
		var input *deployment.InputError
		if errors.As(err, &input) && symbolicCode(input.Code) {
			return "APP_TARGET_" + input.Code
		}
		return "APP_TARGET_CHANGED"
	}
	return ""
}

// ExplainVolumeMoveActivate does the same for the target's "activate-app"
// permit, which starts the app on the target once the copy is Verified.
func (p Policy) ExplainVolumeMoveActivate(s state.State, caller [32]byte, selection VolumeMoveSelection, at int64) string {
	j, m, e, code := p.explainMoveTargetPermit(s, caller, selection, at, true)
	switch {
	case code != "":
		return code
	case j.App == nil || j.App.Target == nil:
		return "NO_APP_TARGET"
	case m.Phase != volumes.Verified && m.Phase != volumes.OwnerCommitted:
		return "MOVE_NOT_VERIFIED"
	case m.Verified == nil || m.Manifest == nil:
		return "COPY_NOT_VERIFIED"
	case m.Preparation == nil:
		return "TARGET_NOT_PREPARED"
	case len(e.State.Consumers()) != 0:
		return "VOLUME_HAS_CONSUMERS"
	case p.moveAppSecretsReady(s, j, at) != nil:
		return "APP_SECRETS_NOT_READY"
	}
	// The permit passes: dry-run the report's reducer on this local view.
	v, err := p.Volumes(s)
	if err != nil {
		return "VOLUMES_UNREADABLE"
	}
	if _, code, reason := p.activateMoveAppReason(s, v, j); code != state.Applied {
		return "ACTIVATE_" + reason
	}
	return ""
}

// explainMoveTargetPermit replays the checks every target permit shares.
func (p Policy) explainMoveTargetPermit(s state.State, caller [32]byte, selection VolumeMoveSelection, at int64, activate bool) (VolumeMove, volumes.Move, registeredVolume, string) {
	var e registeredVolume
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeMove{}, volumes.Move{}, e, "VOLUMES_UNREADABLE"
	}
	j, m, ok := v.Move(selection)
	if !ok {
		return j, m, e, "MOVE_NOT_FOUND"
	}
	e = v.entries[volumeKey(selection.Scope)]
	code := func() string {
		if !p.ownsResource(s, caller, j.Binding.Target.Key) {
			return "TARGET_KEY_NOT_CALLER"
		}
		if owner, err := p.nodeOwner(s, j.Binding.Target.Node); err != nil || owner != caller {
			return "TARGET_NODE_OWNER_CHANGED"
		}
		if at < j.Origin.At {
			return "CLOCK_BEFORE_PLAN"
		}
		if at >= j.ExpiresAt && !(activate && (m.Phase == volumes.Verified || m.Phase == volumes.OwnerCommitted)) {
			return "MOVE_PLAN_EXPIRED"
		}
		if current, err := p.workNodeOwner(s, j.Binding.Target.Node); err != nil || !p.ownsResource(s, current, j.Binding.Target.Key) {
			return "TARGET_WORK_KEY_CHANGED"
		}
		c, err := p.Catalog(s)
		if err != nil {
			return "CATALOG_UNREADABLE"
		}
		for i, o := range []volumes.Owner{j.Binding.Source, j.Binding.Target} {
			side := [2]string{"SOURCE", "TARGET"}[i]
			current, err := p.nodeOwner(s, o.Node)
			if err != nil || !p.ownsResource(s, current, o.Key) {
				return side + "_OWNER_CHANGED"
			}
			if c.AuthorizeAccepted(j.Origin.Session, p.Cluster, j.Origin.At, j.Binding.Scope.Tenant, access.ManageVolumes, o.Node) != nil {
				return side + "_PERMISSION_REVOKED"
			}
		}
		return ""
	}()
	return j, m, e, code
}

// symbolicCode bounds a code before it reaches a log line: [A-Z0-9_], at most
// 48 bytes so the prefixed code stays within 64.
func symbolicCode(code string) bool {
	if code == "" || len(code) > 48 {
		return false
	}
	for _, ch := range code {
		if ch != '_' && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}
