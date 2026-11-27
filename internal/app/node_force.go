// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// nodeForceProbe performs a new authenticated request even if a transport
// connection is cached. A denied/error application reply is still a response;
// only failure to receive any authenticated reply can support logical eviction.
func (r *Runtime) nodeForceProbe(ctx context.Context, view cluster.View, plan control.NodeForcePlan) (lifecycle.RemovalProbe, error) {
	d, err := r.controlPolicy.Members(view.State)
	if err != nil {
		return lifecycle.RemovalProbe{}, err
	}
	entry, found := d.Entry(plan.Node)
	if !found {
		return lifecycle.RemovalProbe{}, control.ErrCatalog
	}
	key, err := identity.ParseKey(entry.CurrentPeer().Key)
	if err != nil {
		return lifecycle.RemovalProbe{}, err
	}
	probe := lifecycle.RemovalProbe{Schema: 1, Cluster: r.controlPolicy.Cluster, Node: plan.Node, Operation: plan.Operation, Target: key, Observer: r.Identity.Public, Epoch: plan.Epoch, Expected: plan.Expected, RootRevision: plan.RootRevision, ConfigurationIndex: plan.ConfigurationIndex, StartedAt: time.Now().Unix()}
	if _, err = rand.Read(probe.Challenge[:]); err != nil {
		return probe, err
	}
	if key == r.Identity.Public {
		probe.Responding = true
	} else {
		peer, approved := r.Mesh.Peer(sfcp.Identity(key))
		if !approved || peer.ID != plan.Node {
			return probe, sfcp.ErrAdmission
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		reply, callErr := cluster.CallManagement(probeCtx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "status", Input: probe.Challenge[:]})
		cancel()
		if ctx.Err() != nil {
			return probe, ctx.Err()
		}
		probe.Responding = callErr == nil
		var remote *cluster.ManagementError
		if errors.As(callErr, &remote) && remote.Code != "transport" {
			probe.Responding = true
		}
		if probe.Responding && reply.Node != plan.Node {
			return probe, sfcp.ErrAdmission
		}
	}
	probe.FinishedAt = time.Now().Unix()
	probe.Signature = ed25519.Sign(r.Identity.Private, lifecycle.RemovalProbeBytes(probe))
	if !probe.Valid() {
		return probe, control.ErrCatalog
	}
	return probe, nil
}
