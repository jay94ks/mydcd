// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
)

// Restore intent: a new server that rebuilds a cluster from a cluster backup
// (`sfcd restore`, design B4) after every voter was lost.
const RestoreIntent Intent = "restore"

// ClusterRestore is the node-root record of `sfcd restore`. The new server
// signs it with its identity key. It is applied once, as the first command
// after the backup's snapshot, before Raft starts: every member of the
// backup becomes Retired and the new server is the only voter.
//
// RaftIndex, Term and StateIndex are the backup snapshot's position. The new
// configuration and the record get index RaftIndex+1. Generation counts the
// restores of this cluster: two restores from one backup give two clusters
// with different voters, and neither admits the other's servers.
type ClusterRestore struct {
	Schema                      uint8
	Cluster                     [32]byte
	RequestID                   string
	Node                        string
	Key                         [32]byte
	Endpoint                    string
	Backup                      string // the cluster-backup operation of the file
	RaftIndex, Term, StateIndex uint64
	Generation                  uint64
	CreatedAt                   int64
	Signature                   []byte
}

func ClusterRestoreBytes(r ClusterRestore) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-cluster-restore-1\x00"), raw...)
}

// Index is the Raft index of the restored configuration.
func (r ClusterRestore) Index() uint64 { return r.RaftIndex + 1 }

func (r ClusterRestore) WellFormed() bool {
	return r.Schema == 1 && r.Cluster != ([32]byte{}) && validID(r.RequestID) && validID(r.Node) && r.Key != ([32]byte{}) && r.Endpoint != "" && len(r.Endpoint) <= 255 && r.Backup != "" && len(r.Backup) <= 64 && r.RaftIndex != 0 && r.RaftIndex != ^uint64(0) && r.Term != 0 && r.StateIndex != 0 && r.Generation != 0 && r.Generation <= maxRestores && r.CreatedAt > 0
}

func (r ClusterRestore) Valid() bool {
	return r.WellFormed() && ed25519.Verify(ed25519.PublicKey(r.Key[:]), ClusterRestoreBytes(r), r.Signature)
}

const maxRestores = 64

func ownRestore(r ClusterRestore) ClusterRestore {
	r.Signature = slices.Clone(r.Signature)
	return r
}

// Generation is the number of restores this cluster went through.
func (t Topology) Generation() uint64 { return uint64(len(t.restores)) }

// Restores returns the recorded restores, oldest first.
func (t Topology) Restores() []ClusterRestore {
	out := make([]ClusterRestore, len(t.restores))
	for i, r := range t.restores {
		out[i] = ownRestore(r)
	}
	return out
}

// RestoreCluster installs the configuration of a restore: c is exactly the
// new server as the only voter. Every member that is not already gone
// becomes Retired by this generation, the same end state as a force removal.
func (t Topology) RestoreCluster(r ClusterRestore, c Configuration) (Topology, error) {
	self := Member{ID: r.Node, Key: r.Key, Voter: true}
	if !r.Valid() || r.Cluster != t.cluster || r.Generation != t.Generation()+1 || c.Validate() != nil || c.Index != r.Index() || c.Index <= t.configuration.Index || len(c.Members) != 1 || c.Members[0] != self {
		return t, ErrLifecycle
	}
	if _, exists := t.nodes[r.Node]; exists {
		return t, ErrLifecycle
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	for id, v := range n.nodes {
		if v.Phase == Removed || v.Phase == Retired {
			continue
		}
		v.Phase, v.Pending, v.Closure, v.Retirement = Retired, nil, nil, nil
		v.Restored = r.Generation
		v.Revision = n.revision
		n.nodes[id] = v
	}
	n.nodes[r.Node] = Node{Member: self, Generation: c.Index, Revision: n.revision, Phase: Active}
	n.configuration = ownConfig(c)
	n.restores = append(n.restores, ownRestore(r))
	return n, nil
}
