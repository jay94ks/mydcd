// SPDX-License-Identifier: Apache-2.0

package app

import (
	"time"

	"github.com/jay94ks/seafield/internal/sfcp"
)

// leaderLink is this node's view of its connection to the current leader.
// Idle owners use it to skip a periodic ask when nothing changed: as long as
// the same leader in the same term has stayed connected, any change would
// have reached this node as a local FSM change, and anything this node
// changes is reported at once.
type leaderLink struct {
	ID    string
	Term  uint64
	Self  bool      // this node is the leader
	Since time.Time // unbroken SFCP connection to the leader since (not Self)
}

func (r *Runtime) leaderLink() (leaderLink, bool) {
	e := r.Engine()
	if e == nil {
		return leaderLink{}, false
	}
	_, id := e.Leader()
	if id == "" {
		return leaderLink{}, false
	}
	l := leaderLink{ID: string(id), Term: e.CurrentObservedTerm()}
	if e.IsLeader() {
		l.Self = true
		return l, true
	}
	peer, ok := e.LeaderPeer()
	if !ok || r.Mesh == nil {
		return l, false
	}
	l.Since, ok = r.Mesh.ConnectedSince(peer.Key)
	return l, ok
}

// heldSince reports whether l is the same leader and term as was and its
// connection has not broken since at.
func (l leaderLink) heldSince(was leaderLink, at time.Time) bool {
	return l.ID != "" && l.ID == was.ID && l.Term == was.Term && (l.Self || !l.Since.IsZero() && !l.Since.After(at))
}

// ownerLinkedSince reports whether the leader has stayed connected to the
// owner key since at; the leader's own observations are always linked.
func (r *Runtime) ownerLinkedSince(owner [32]byte, at time.Time) bool {
	if owner == r.Identity.Public {
		return true
	}
	if r.Mesh == nil {
		return false
	}
	since, ok := r.Mesh.ConnectedSince(sfcp.Identity(owner))
	return ok && !since.After(at)
}
