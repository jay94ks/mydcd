// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"

	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// A lost activation reply or commit notification cannot be recovered with the
// revoked old TLS key. This finite read uses the already durable prepared key,
// asks only for its original activation, and closes before the daemon restarts.
func (r *Runtime) recoverIdentityActivation(ctx context.Context, row membership.IdentityRotation) error {
	if row.Phase != "Prepared" || row.Proof == nil || row.Proof.Old != r.Identity.Public || r.installation == nil {
		return sfcp.ErrAdmission
	}
	c := r.installation.config
	next, err := identity.Load(filepath.Join(c.Node.IdentityDir, "rotations", row.Operation))
	if err != nil {
		return err
	}
	defer clear(next.Private)
	if next.Public != row.Proof.New {
		return sfcp.ErrAdmission
	}
	mesh, err := sfcp.NewTransport(next, r.controlPolicy.Cluster, r.Mesh.Peer)
	if err != nil {
		return err
	}
	defer mesh.Close()
	_, directory, err := r.members(ctx, false)
	if err != nil {
		return err
	}
	_, leaderID := r.Engine().Leader()
	leader, found := directory.Entry(string(leaderID))
	if !found || leader.Peer.ID == row.Node {
		return sfcp.ErrAdmission
	}
	key, err := identity.ParseKey(leader.CurrentPeer().Key)
	if err != nil {
		return err
	}
	peer, found := r.Mesh.Peer(sfcp.Identity(key))
	if !found || !peer.Member || peer.ID != leader.Peer.ID {
		return sfcp.ErrAdmission
	}
	input, _ := json.Marshal(control.NodeIdentityChange{ID: row.Node, Operation: row.Operation})
	reply, err := cluster.CallManagement(ctx, mesh, next, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "node-identity-activation", Latest: true, Input: input})
	if err != nil {
		return err
	}
	activation, err := schema.Decode[control.NodeIdentityActivation](reply.Data)
	want, _ := json.Marshal(row.Proof)
	actual, _ := json.Marshal(activation.Proof)
	if err != nil || activation.Schema != 1 || activation.Index <= row.AcceptedIndex || activation.Index > reply.CommandIndex || reply.Local || !bytes.Equal(want, actual) {
		return sfcp.ErrAdmission
	}
	if _, err = bootstrap.ActivateIdentityRotation(c, activation.Proof, activation.Index); err != nil {
		return err
	}
	r.identityRestartOnce.Do(func() { close(r.identityRestart) })
	return nil
}
