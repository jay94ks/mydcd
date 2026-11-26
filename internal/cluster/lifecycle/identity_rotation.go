// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
)

// IdentityProof binds possession of BOTH private keys to one retained admin
// operation and durable local preparation. It grants no task/Volume closure.
type IdentityProof struct {
	Schema                     uint8
	Cluster                    [32]byte
	Node, Operation            string
	Old, New                   [32]byte
	Prepared                   [32]byte
	OldSignature, NewSignature []byte
}

func IdentityProofBytes(p IdentityProof) []byte {
	p.OldSignature = nil
	p.NewSignature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("mydc-node-identity-1\x00"), raw...)
}
func (p IdentityProof) Valid() bool {
	return p.Schema == 1 && p.Cluster != ([32]byte{}) && ValidID(p.Node) && ValidID(p.Operation) && p.Old != ([32]byte{}) && p.New != ([32]byte{}) && p.Old != p.New && p.Prepared != ([32]byte{}) && ed25519.Verify(ed25519.PublicKey(p.Old[:]), IdentityProofBytes(p), p.OldSignature) && ed25519.Verify(ed25519.PublicKey(p.New[:]), IdentityProofBytes(p), p.NewSignature)
}

type IdentityTransition struct {
	Proof           IdentityProof
	Index, Revision uint64
}

func OwnIdentityTransitions(rows []IdentityTransition) []IdentityTransition {
	out := slices.Clone(rows)
	for i := range out {
		out[i].Proof.OldSignature = slices.Clone(out[i].Proof.OldSignature)
		out[i].Proof.NewSignature = slices.Clone(out[i].Proof.NewSignature)
	}
	return out
}
func ValidIdentityTransitions(cluster [32]byte, node string, original [32]byte, rows []IdentityTransition) ([32]byte, bool) {
	key := original
	last := uint64(0)
	lastRevision := uint64(0)
	seen := map[[32]byte]bool{key: true}
	if len(rows) > 32 {
		return key, false
	}
	for _, row := range rows {
		p := row.Proof
		if !p.Valid() || p.Cluster != cluster || p.Node != node || p.Old != key || seen[p.New] || row.Index <= last || row.Revision <= lastRevision {
			return key, false
		}
		seen[p.New] = true
		key = p.New
		last = row.Index
		lastRevision = row.Revision
	}
	return key, true
}
func (t Topology) RotateIdentity(proof IdentityProof, index uint64) (Topology, error) {
	node, exists := t.Node(proof.Node)
	observerCurrent := node.Member.Key
	if !exists || !proof.Valid() || proof.Cluster != t.cluster || proof.Old != observerCurrent || index == 0 || node.Pending != nil || node.Phase != Active && node.Phase != Isolated {
		return t, ErrLifecycle
	}
	for _, other := range t.nodes {
		if other.Member.Key == proof.New {
			return t, ErrLifecycle
		}
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	node.Member.Key = proof.New
	node.Revision = n.revision
	node.Keys = append(OwnIdentityTransitions(node.Keys), IdentityTransition{Proof: proof, Index: index, Revision: node.Revision})
	n.nodes[proof.Node] = node
	for i, member := range n.configuration.Members {
		if member.ID == proof.Node {
			n.configuration.Members[i].Key = proof.New
		}
	}
	return n, nil
}
func (n Node) proofKey(revision uint64) [32]byte {
	key := n.Member.Key
	for i := len(n.Keys) - 1; i >= 0; i-- {
		if revision < n.Keys[i].Revision {
			key = n.Keys[i].Proof.Old
		}
	}
	return key
}
func (r Root) OriginalKey() [32]byte {
	if len(r.Keys) > 0 {
		return r.Keys[0].Proof.Old
	}
	return r.Self.Key
}
func (r Root) RotateIdentity(proof IdentityProof, index uint64) (Root, error) {
	if r.Validate() != nil || r.Installed.Index == 0 || !proof.Valid() || proof.Cluster != r.Cluster || proof.Node != r.Self.ID || proof.Old != r.Self.Key || index == 0 {
		return r, ErrLifecycle
	}
	r.Self.Key = proof.New
	// index is the management FSM command ordinal. AppliedIndex/Installed.Index
	// are Raft positions, which include barriers/configuration and are unrelated.
	// Keep their original installation evidence instead of comparing/replacing it.
	r.Keys = append(OwnIdentityTransitions(r.Keys), IdentityTransition{Proof: proof, Index: index, Revision: index})
	for i, member := range r.Installed.Members {
		if member.ID == r.Self.ID {
			r.Installed.Members[i].Key = proof.New
		}
	}
	if r.Validate() != nil {
		return Root{}, ErrLifecycle
	}
	return r, nil
}

func verifyNodeProof(n Node, p Proof) bool {
	key := n.proofKey(p.Revision)
	return ed25519.Verify(ed25519.PublicKey(key[:]), ProofBytes(p), p.Signature)
}
