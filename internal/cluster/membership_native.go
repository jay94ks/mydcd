// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"fmt"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/config"

	"github.com/hashicorp/raft"
)

// ChangeMember is the single native SDK effect. The caller must first commit
// the same A2 Dispatch. A future error/cancel never establishes non-execution.
// previous is the actual committed configuration index, not Future.Index().
func (e *Engine) ChangeMember(ctx context.Context, peer config.Peer, previous uint64) error {
	if !e.fsm.trackConfiguration || previous == 0 || !lifecycle.ValidID(peer.ID) || config.ValidateCanonicalEndpoint(peer.Endpoint) != nil {
		return fmt.Errorf("invalid native membership request")
	}
	if err := e.await(ctx, func() raft.Future {
		if peer.Voter {
			return e.raft.AddVoter(raft.ServerID(peer.ID), raft.ServerAddress(peer.Endpoint), previous, remaining(ctx))
		}
		return e.raft.AddNonvoter(raft.ServerID(peer.ID), raft.ServerAddress(peer.Endpoint), previous, remaining(ctx))
	}); err != nil {
		return fmt.Errorf("%w: native membership: %v", ErrUnknown, err)
	}
	return nil
}

// RemoveMember is called once only after the shared original A2 Dispatch.
// The old configuration quorum and the library's previous-index CAS apply.
func (e *Engine) RemoveMember(ctx context.Context, id string, previous uint64) error {
	if !e.fsm.trackConfiguration || previous == 0 || !lifecycle.ValidID(id) {
		return fmt.Errorf("invalid native member removal")
	}
	if err := e.await(ctx, func() raft.Future { return e.raft.RemoveServer(raft.ServerID(id), previous, remaining(ctx)) }); err != nil {
		return fmt.Errorf("%w: native member removal: %v", ErrUnknown, err)
	}
	return nil
}

// TransferLeadership is consensus scheduling before a self-removal. It grants
// no removal Dispatch and never changes the application's original operation.
func (e *Engine) TransferLeadership(ctx context.Context, id, address string) error {
	if !lifecycle.ValidID(id) || config.ValidateCanonicalEndpoint(address) != nil {
		return fmt.Errorf("invalid leadership target")
	}
	return e.await(ctx, func() raft.Future {
		return e.raft.LeadershipTransferToServer(raft.ServerID(id), raft.ServerAddress(address))
	})
}

// DemoteMember uses the adopted SDK suffrage operation once after the same A2
// dispatch. It does not remove the member's replication/key/native identity.
func (e *Engine) DemoteMember(ctx context.Context, id string, previous uint64) error {
	if !e.fsm.trackConfiguration || previous == 0 || !lifecycle.ValidID(id) {
		return fmt.Errorf("invalid native voter demotion")
	}
	if err := e.await(ctx, func() raft.Future { return e.raft.DemoteVoter(raft.ServerID(id), previous, remaining(ctx)) }); err != nil {
		return fmt.Errorf("%w: native voter demotion: %v", ErrUnknown, err)
	}
	return nil
}
