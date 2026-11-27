// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
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
func (r *Runtime) joinSource(ctx context.Context) (sfcp.Peer, error) {
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
				return sfcp.Peer{}, ctx.Err()
			case <-r.ctx.Done():
				return sfcp.Peer{}, r.ctx.Err()
			case <-tick.C:
			}
		}
	}
	if leader, ok := r.Engine().LeaderPeer(); ok {
		return leader, nil
	}
	key, _ := identity.ParseKey(r.installation.record.Join.Source.Key)
	peer, ok := r.Mesh.Peer(sfcp.Identity(key))
	if !ok || !(peer.Member || peer.Replicate) {
		return peer, sfcp.ErrAdmission
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
	req := MemberRequest{Method: "join", Node: inv.Target.ID, JoinID: inv.JoinID}
	joinReply, err := r.callJoinSource(ctx, req)
	if err != nil {
		return bootstrap.Record{}, fmt.Errorf("join request: %w", err)
	}
	r.addJoinSeeds(joinReply.Members)
	record, err := r.InstallConfiguration(ctx)
	if err != nil {
		return record, fmt.Errorf("local join installation: %w", err)
	}
	record, err = bootstrap.PrepareAck(r.installation.config)
	if err != nil {
		return record, fmt.Errorf("durable join ACK: %w", err)
	}
	reply, err := r.callJoinSource(ctx, MemberRequest{Method: "install", Node: inv.Target.ID, JoinID: inv.JoinID, Ack: record.Ack})
	if err != nil {
		return record, fmt.Errorf("publish join ACK: %w", err)
	}
	if reply.Entry == nil || !membership.FullMember(*reply.Entry) {
		return record, sfcp.ErrAdmission
	}
	return record, nil
}

// callJoinSource sends a membership request to the leader, or before this
// node knows one, to the invitation source. "unavailable" means the member
// asked did nothing (it is not the leader and could not relay, or could not
// read the latest state), so the same request is sent again with backoff,
// to the leader that member named when this node knows that leader.
func (r *Runtime) callJoinSource(ctx context.Context, req MemberRequest) (MemberReply, error) {
	target, err := r.joinSource(ctx)
	if err != nil {
		return MemberReply{}, fmt.Errorf("membership target: %w", err)
	}
	wait := time.Second
	for {
		reply, err := CallMembership(ctx, r.Mesh, target, req)
		if err == nil || reply.Code != "unavailable" {
			return reply, err
		}
		if next, ok := r.memberLeader(reply.Leader); ok {
			target = next
		} else if next, e := r.joinSource(ctx); e == nil {
			target = next
		}
		select {
		case <-ctx.Done():
			return reply, err
		case <-r.ctx.Done():
			return reply, err
		case <-time.After(wait):
		}
		wait = min(2*wait, 8*time.Second)
	}
}

// addJoinSeeds admits the current members named in the source's join reply
// for replication, like the invitation's own genesis and source, until this
// node's replicated state takes over (the same window the runtime lookup
// gives invitation seeds).
func (r *Runtime) addJoinSeeds(members []config.Peer) {
	seeds := map[sfcp.Identity]sfcp.Peer{}
	for _, m := range members {
		key, err := identity.ParseKey(m.Key)
		if err != nil || key == r.Identity.Public || !lifecycle.ValidID(m.ID) || config.ValidateCanonicalEndpoint(m.Endpoint) != nil {
			continue
		}
		seeds[sfcp.Identity(key)] = sfcp.Peer{ID: m.ID, Endpoint: m.Endpoint, Policy: sfcp.Policy{Key: sfcp.Identity(key), Replicate: true, Snapshot: true, Respond: true}}
	}
	r.mu.Lock()
	if r.joinSeeds == nil {
		r.joinSeeds = map[sfcp.Identity]sfcp.Peer{}
	}
	for key, p := range seeds {
		r.joinSeeds[key] = p
	}
	r.mu.Unlock()
	for _, c := range r.lookupCaches {
		c.invalidate()
	}
}

// joinSeed finds a learned seed by key, or by ID when key is zero.
func (r *Runtime) joinSeed(key sfcp.Identity, id string) (sfcp.Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if key != (sfcp.Identity{}) {
		p, ok := r.joinSeeds[key]
		return p, ok
	}
	for _, p := range r.joinSeeds {
		if p.ID == id {
			return p, true
		}
	}
	return sfcp.Peer{}, false
}

// memberLeader resolves a leader hint to a peer. The hint came over the
// authenticated session with the pinned source, so it is admitted for
// replication like the members of a join reply (see addJoinSeeds).
func (r *Runtime) memberLeader(hint *MemberLeader) (sfcp.Peer, bool) {
	if hint == nil {
		return sfcp.Peer{}, false
	}
	key, err := identity.ParseKey(hint.Key)
	if err != nil || sfcp.Identity(key) == r.Mesh.LocalKey() {
		return sfcp.Peer{}, false
	}
	r.addJoinSeeds([]config.Peer{{ID: hint.ID, Key: hint.Key, Endpoint: hint.Endpoint}})
	peer, ok := r.Mesh.Peer(sfcp.Identity(key))
	return peer, ok && peer.ID == hint.ID && (peer.Member || peer.Replicate)
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
