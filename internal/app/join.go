// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jay94ks/mydcd/internal/bootstrap"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// Join persists an explicitly pinned intent before opening a non-bootstrapping
// runtime. The successful runtime remains live so callers can keep it serving.
func Join(ctx context.Context, c config.Node, inv membership.Invitation, cluster, source [32]byte) (*Runtime, bootstrap.Record, error) {
	record, err := bootstrap.PrepareJoin(c, inv, cluster, source)
	if err != nil {
		return nil, record, err
	}
	r, err := Open(c)
	if err != nil {
		return nil, record, err
	}
	record, err = r.finishJoin(ctx)
	if err != nil {
		return nil, record, errors.Join(err, r.Close())
	}
	return r, record, nil
}
func (r *Runtime) joinSource(ctx context.Context) (mydcp.Peer, error) {
	// Once installed, the pinned invitation source is historical provenance,
	// not a permanent dependency. Wait for the SDK's CURRENT leader rather than
	// dialing the old source merely because startup has not observed a leader.
	if r.installation.record.Root.Installed.Index != 0 {
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			if leader, ok := r.Engine().LeaderPeer(); ok {
				return leader, nil
			}
			select {
			case <-ctx.Done():
				return mydcp.Peer{}, ctx.Err()
			case <-r.ctx.Done():
				return mydcp.Peer{}, r.ctx.Err()
			case <-tick.C:
			}
		}
	}
	if leader, ok := r.Engine().LeaderPeer(); ok {
		return leader, nil
	}
	key, _ := identity.ParseKey(r.installation.record.Join.Source.Key)
	peer, ok := r.Mesh.Peer(mydcp.Identity(key))
	if !ok || !(peer.Member || peer.Replicate) {
		return peer, mydcp.ErrAdmission
	}
	return peer, nil
}
func (r *Runtime) finishJoin(ctx context.Context) (bootstrap.Record, error) {
	inv := r.installation.record.Join
	if r.installation.record.Root.Installed.Index != 0 && r.installation.record.Ack != nil {
		record, err := r.InstallConfiguration(ctx)
		if err != nil {
			return record, fmt.Errorf("local joined installation: %w", err)
		}
		_, directory, err := r.members(ctx, false)
		if err != nil {
			return record, err
		}
		entry, ok := directory.Entry(inv.Target.ID)
		if ok && membership.FullMember(entry) && entry.JoinID == inv.JoinID && entry.Peer.Key == inv.Target.Key && entry.Ack != nil && record.Ack != nil && bytes.Equal(membership.AckBytes(*entry.Ack), membership.AckBytes(*record.Ack)) && bytes.Equal(entry.Ack.Signature, record.Ack.Signature) {
			return record, nil
		}
	}
	target, err := r.joinSource(ctx)
	if err != nil {
		return bootstrap.Record{}, err
	}
	req := MemberRequest{Method: "join", Node: inv.Target.ID, JoinID: inv.JoinID}
	if _, err = CallMembership(ctx, r.Mesh, target, req); err != nil {
		return bootstrap.Record{}, fmt.Errorf("join request: %w", err)
	}
	record, err := r.InstallConfiguration(ctx)
	if err != nil {
		return record, fmt.Errorf("local join installation: %w", err)
	}
	record, err = bootstrap.PrepareAck(r.installation.config)
	if err != nil {
		return record, fmt.Errorf("durable join ACK: %w", err)
	}
	target, err = r.joinSource(ctx)
	if err != nil {
		return record, fmt.Errorf("join ACK target: %w", err)
	}
	reply, err := CallMembership(ctx, r.Mesh, target, MemberRequest{Method: "install", Node: inv.Target.ID, JoinID: inv.JoinID, Ack: record.Ack})
	if err != nil {
		return record, fmt.Errorf("publish join ACK: %w", err)
	}
	if reply.Entry == nil || !membership.FullMember(*reply.Entry) {
		return record, mydcp.ErrAdmission
	}
	return record, nil
}
func (r *Runtime) ResumeInstallation(ctx context.Context) (bootstrap.Record, error) {
	if r.installation == nil {
		return bootstrap.Record{}, bootstrap.ErrInstallation
	}
	if r.installation.record.Join != nil {
		return r.finishJoin(ctx)
	}
	return r.InstallConfiguration(ctx)
}
