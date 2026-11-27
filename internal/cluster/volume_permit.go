// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// CallVolumePermit never falls back to a local/cached view. This authenticated
// read obtains one fresh request-bound permission; the native owner still has
// to sync and serialize its Gate.Accept with the actual Start and Fence.
func CallVolumePermit(ctx context.Context, mesh *sfcp.Transport, self *identity.Identity, cluster [32]byte, target sfcp.Peer, request volumes.StartRequest) (volumes.Permit, error) {
	if mesh == nil || self == nil || request.Scope.Cluster != cluster || request.Consumer.Owner.Key != self.Public {
		return volumes.Permit{}, sfcp.ErrAdmission
	}
	peer, ok := mesh.Peer(target.Key)
	if !ok || !peer.Member || !peer.Respond {
		return volumes.Permit{}, sfcp.ErrAdmission
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return volumes.Permit{}, err
	}
	reply, err := CallManagement(ctx, mesh, self, cluster, peer, ManagementRequest{Method: "volume-permit", Latest: true, Input: raw})
	if err != nil {
		return volumes.Permit{}, err
	}
	permit, err := schema.Decode[volumes.Permit](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || permit.Request != request || permit.AuthorityRevision < request.Consumer.OwnerRevision {
		return volumes.Permit{}, sfcp.ErrAdmission
	}
	return permit, nil
}
