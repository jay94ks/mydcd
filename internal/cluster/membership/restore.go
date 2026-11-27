// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"net/netip"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/config"
)

// RestoreCluster applies a signed `sfcd restore` (design B4): every member
// of the backed-up state becomes Retired (lifecycle RestoreCluster), an
// invitation that never reached Raft is forgotten, and peer, the new server,
// is added as the only voter. A removal job still waiting on a retired member
// is settled, as in RecoverConfiguration. inUse are the tunnel addresses
// networks still use.
func (d Directory) RestoreCluster(r lifecycle.ClusterRestore, peer config.Peer, inUse map[netip.Addr]bool) (Directory, error) {
	if !d.writable() || d.Runtime == nil || !validPeer(peer) || !peer.Voter || peer.ID != r.Node || peer.Key != identityHex(r.Key) || peer.Endpoint != r.Endpoint || r.RequestID == "genesis" || len(d.Entries) >= 1024 {
		return d, ErrMember
	}
	if d.HistoricalMemberKey(r.Key) {
		return d, ErrMember
	}
	for _, e := range d.Entries {
		if e.Peer.ID == peer.ID || e.Peer.Key == peer.Key || e.JoinID == r.RequestID {
			return d, ErrMember
		}
		for _, row := range e.Keys {
			if row.Proof.Old == r.Key || row.Proof.New == r.Key {
				return d, ErrMember
			}
		}
	}
	t, err := d.Topology()
	if err != nil {
		return d, err
	}
	c := lifecycle.Configuration{Index: r.Index(), Members: []lifecycle.Member{{ID: r.Node, Key: r.Key, Voter: true}}}
	if t, err = t.RestoreCluster(r, c); err != nil {
		return d, err
	}
	n, err := d.keepTopology(t)
	if err != nil {
		return d, err
	}
	// An invitation that never reached Raft has no topology node: forget it.
	unjoined := map[string]bool{}
	for _, e := range n.Entries {
		if _, exists := t.Node(e.Peer.ID); !exists {
			unjoined[e.Peer.ID] = true
		}
	}
	n.Entries = slices.DeleteFunc(n.Entries, func(e Entry) bool { return unjoined[e.Peer.ID] })
	n.Cordons = slices.DeleteFunc(n.Cordons, func(c Cordon) bool { return unjoined[c.Node] })
	if err = n.settleLostRemovals(c, r.Key, d.mustConfigurationIndex()); err != nil {
		return d, err
	}
	address, ok := n.nextAddress(inUse)
	if !ok {
		return d, ErrMember
	}
	restore := r
	restore.Signature = slices.Clone(r.Signature)
	n = n.replace(Entry{Peer: peer, JoinID: r.RequestID, Phase: Active, Address: address, Restore: &restore})
	return n, n.Validate()
}

// Restored reports whether the restore with this request ID is recorded.
func (d Directory) Restored(requestID string) bool {
	t, err := d.Topology()
	if err != nil {
		return false
	}
	for _, r := range t.Restores() {
		if r.RequestID == requestID {
			return true
		}
	}
	return false
}
