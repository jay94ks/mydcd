// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// This is committed control evidence only. The source must ALSO inspect its
// actual native/gate and join local workers before signing Unchanged.
func (p Policy) moveSourceUnchanged(s state.State, j VolumeMove, m volumes.Move, core volumes.State) bool {
	if m.Fence != nil || m.Manifest != nil || m.Verified != nil || m.ReaderClosed != nil || core.HadMoveReader(j.Binding) {
		return false
	}
	if j.App != nil {
		status, err := p.MoveAppQuiescence(s, j)
		return err == nil && status == "pending" || p.moveAppSuperseded(s, j)
	}
	return true
}

// moveAppSuperseded reports that a user change replaced the move's app state:
// the app was taken down by another operation, deployed again, or removed.
// The move no longer owns any retirement of it, and with no fence, reader or
// manifest it never touched the source, so cancelling needs no quiescence.
// Without this a move planned, then overtaken by 'app down'/'deploy', stayed
// Cancelling forever (KVM: MOVE_PLAN_EXPIRED, then cancel never finished).
func (p Policy) moveAppSuperseded(s state.State, j VolumeMove) bool {
	if j.App == nil {
		return false
	}
	a, err := p.Apps(s)
	if err != nil {
		return false
	}
	e, ok := a.entries[appKey(j.Binding.Scope.Tenant, j.Binding.Scope.App)]
	if !ok {
		return true
	}
	if e.Down != nil {
		return !bytes.Equal(OperationBytes(*e.Down), OperationBytes(j.Origin)) || !bytes.Equal(e.Down.Signature, j.Origin.Signature)
	}
	active, ok := e.Inventory.Active()
	return ok && active.ID != j.App.Operation
}
