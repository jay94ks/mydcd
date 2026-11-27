// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// CurrentView obtains a quorum barrier without moving an installed native
// owner or credential issuer to the consensus leader. The only remote request
// is an authenticated Management status read; no user or credential data leaves
// the owner. The local durable FSM must consume both its command ordinal and
// Raft position before the view can be used for current policy checks.
//
// This establishes freshness, not user/native authority. Consumers still check
// current membership, session, epoch and the exact original target on this view.
func CurrentView(ctx context.Context, engine *Engine, mesh *sfcp.Transport, self *identity.Identity, cluster [32]byte) (View, error) {
	if engine == nil {
		return View{}, sfcp.ErrAdmission
	}
	if engine.IsLeader() {
		return engine.Read(ctx, true)
	}
	peer, ok := engine.LeaderPeer()
	if !ok || mesh == nil || self == nil || peer.Key == sfcp.Identity(self.Public) {
		return View{}, sfcp.ErrAdmission
	}
	barrier, err := CallManagement(ctx, mesh, self, cluster, peer, ManagementRequest{Method: "status", Latest: true})
	if err != nil {
		return View{}, err
	}
	if barrier.Local || barrier.Node != peer.ID || barrier.RaftIndex == 0 || barrier.AppliedTerm == 0 {
		return View{}, sfcp.ErrAdmission
	}
	for {
		// Subscribe before reading: configuration/barrier publication can
		// advance the Raft floor without another management command.
		changed := engine.Changes()
		view, err := engine.ReadAtLeast(ctx, barrier.CommandIndex)
		if err != nil {
			return View{}, err
		}
		if view.RaftIndex >= barrier.RaftIndex {
			view.Local = false
			return view, nil
		}
		select {
		case <-ctx.Done():
			return View{}, ctx.Err()
		case <-changed:
		}
	}
}
