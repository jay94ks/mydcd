// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
)

// Recovery is the node-root plan of `sfcd recover`: after the cluster lost a
// voter majority for good, the surviving voters force a voting configuration
// of only themselves. The node that ran it signs the plan with its identity
// key, so the cluster keeps a record of who recovered with which list.
//
// Previous is the Raft configuration index the plan was made against and
// LastIndex the last Raft log index at that time. The recovered configuration
// is installed at LastIndex+1.
type Recovery struct {
	Schema                         uint8
	Cluster                        [32]byte
	RequestID                      string
	Node                           string
	Key                            [32]byte
	Voters                         []string
	PreviousIndex, LastIndex, Term uint64
	CreatedAt                      int64
	Signature                      []byte
}

func RecoveryBytes(r Recovery) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-cluster-recovery-1\x00"), raw...)
}

// Index is the Raft configuration index the recovered configuration gets.
func (r Recovery) Index() uint64 { return r.LastIndex + 1 }

// WellFormed checks the plan's own fields, not its signature.
func (r Recovery) WellFormed() bool {
	if r.Schema != 1 || r.Cluster == ([32]byte{}) || !validID(r.RequestID) || !validID(r.Node) || r.Key == ([32]byte{}) || len(r.Voters) == 0 || len(r.Voters) > 1024 || r.PreviousIndex == 0 || r.LastIndex < r.PreviousIndex || r.LastIndex == ^uint64(0) || r.Term == 0 || r.CreatedAt <= 0 {
		return false
	}
	for i, id := range r.Voters {
		if !validID(id) || i > 0 && id <= r.Voters[i-1] {
			return false
		}
	}
	return slices.Contains(r.Voters, r.Node)
}

func (r Recovery) Valid() bool {
	return r.WellFormed() && ed25519.Verify(ed25519.PublicKey(r.Key[:]), RecoveryBytes(r), r.Signature)
}

func ownRecovery(r *Recovery) *Recovery {
	if r == nil {
		return nil
	}
	v := *r
	v.Voters = slices.Clone(r.Voters)
	v.Signature = slices.Clone(r.Signature)
	return &v
}

// Recover installs the configuration a signed recovery produced. Every member
// of the old configuration that is not in c becomes Retired at once, the same
// end state as a force removal: the cluster no longer admits it and frees its
// name and address. c must keep every survivor with its key and suffrage, and
// its voters must be exactly the plan's voters.
func (t Topology) Recover(r Recovery, c Configuration) (Topology, error) {
	if !r.Valid() || r.Cluster != t.cluster || c.Validate() != nil || c.Index != r.Index() || c.Index <= t.configuration.Index {
		return t, ErrLifecycle
	}
	self, ok := c.Member(r.Node)
	if !ok || !self.Voter || self.Key != r.Key {
		return t, ErrLifecycle
	}
	var voters []string
	for _, m := range c.Members {
		old, exists := t.configuration.Member(m.ID)
		if !exists || old != m {
			return t, ErrLifecycle
		}
		if m.Voter {
			voters = append(voters, m.ID)
		}
	}
	if !slices.Equal(voters, r.Voters) {
		return t, ErrLifecycle
	}
	lost := 0
	for _, m := range t.configuration.Members {
		if _, kept := c.Member(m.ID); !kept {
			lost++
		}
	}
	if lost == 0 {
		return t, ErrLifecycle
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	for _, m := range t.configuration.Members {
		if _, kept := c.Member(m.ID); kept {
			continue
		}
		v := n.nodes[m.ID]
		v.Phase, v.Pending, v.Closure, v.Retirement = Retired, nil, nil, nil
		v.Recovery = ownRecovery(&r)
		v.Revision = n.revision
		n.nodes[m.ID] = v
	}
	n.configuration = ownConfig(c)
	return n, nil
}
