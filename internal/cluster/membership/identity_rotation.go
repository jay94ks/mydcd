// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
)

type IdentityRotation struct {
	Node, Operation, Phase, Failure                         string
	Origin                                                  json.RawMessage
	Expected, AcceptedIndex, ActivatedIndex, InstalledIndex uint64
	Proof                                                   *lifecycle.IdentityProof `json:",omitempty"`
}

func (e Entry) CurrentPeer() config.Peer {
	peer := e.Peer
	if len(e.Keys) > 0 {
		peer.Key = identityHex(e.Keys[len(e.Keys)-1].Proof.New)
	}
	return peer
}
func (d Directory) IdentityRotation(node, operation string) (IdentityRotation, bool) {
	for _, row := range d.Rotations {
		if row.Node == node && row.Operation == operation {
			raw, _ := json.Marshal(row)
			var copy IdentityRotation
			_ = json.Unmarshal(raw, &copy)
			return copy, true
		}
	}
	return IdentityRotation{}, false
}
func (d Directory) BeginIdentityRotation(node, operation string, expected, index uint64, origin json.RawMessage) (Directory, error) {
	e, found := d.Entry(node)
	if !d.writable() || !found || !FullMember(e) || e.Revision != expected || !lifecycle.ValidID(operation) || index == 0 || len(origin) == 0 || len(origin) > 64<<10 || !json.Valid(origin) || len(d.Rotations) >= 128 || e.Job.Pending != nil {
		return d, ErrMember
	}
	t, err := d.Topology()
	n, present := t.Node(node)
	if err != nil || !present || n.Pending != nil || !t.AdmitWork(node) {
		return d, ErrMember
	}
	for _, row := range d.Rotations {
		if row.Operation == operation || row.Node == node && row.Phase != "Installed" {
			return d, ErrMember
		}
	}
	next := clone(d)
	next.Revision++
	next.Rotations = append(next.Rotations, IdentityRotation{Node: node, Operation: operation, Phase: "Preparing", Origin: bytes.Clone(origin), Expected: expected, AcceptedIndex: index})
	return next, next.Validate()
}
func (d Directory) PrepareIdentityRotation(node, operation string, proof lifecycle.IdentityProof) (Directory, error) {
	row, found := d.IdentityRotation(node, operation)
	e, exists := d.Entry(node)
	key, _ := identity.ParseKey(e.CurrentPeer().Key)
	if !d.writable() || !found || !exists || row.Phase != "Preparing" || !proof.Valid() || proof.Cluster != d.Cluster || proof.Node != node || proof.Operation != operation || proof.Old != key {
		return d, ErrMember
	}
	if d.HistoricalMemberKey(proof.New) {
		return d, ErrMember
	}
	next := clone(d)
	next.Revision++
	for i := range next.Rotations {
		if next.Rotations[i].Operation == operation {
			copy := proof
			copy.OldSignature = bytes.Clone(proof.OldSignature)
			copy.NewSignature = bytes.Clone(proof.NewSignature)
			next.Rotations[i].Proof = &copy
			next.Rotations[i].Phase = "Prepared"
			next.Rotations[i].Failure = ""
		}
	}
	return next, next.Validate()
}
func (d Directory) ActivateIdentityRotation(node, operation string, index uint64) (Directory, error) {
	row, found := d.IdentityRotation(node, operation)
	if !d.writable() || !found || row.Phase != "Prepared" || row.Proof == nil || index <= row.AcceptedIndex {
		return d, ErrMember
	}
	topology, err := d.Topology()
	if err != nil {
		return d, err
	}
	topology, err = topology.RotateIdentity(*row.Proof, index)
	if err != nil {
		return d, err
	}
	next, err := d.keepTopology(topology)
	if err != nil {
		return d, err
	}
	entry, _ := next.Entry(node)
	view, _ := topology.Node(node)
	entry.Keys = append(lifecycle.OwnIdentityTransitions(entry.Keys), lifecycle.IdentityTransition{Proof: *row.Proof, Index: index, Revision: view.Revision})
	next = next.replace(entry)
	for i := range next.Rotations {
		if next.Rotations[i].Operation == operation {
			next.Rotations[i].Phase = "Activated"
			next.Rotations[i].Failure = ""
			next.Rotations[i].ActivatedIndex = index
		}
	}
	return next, next.Validate()
}
func (d Directory) InstalledIdentityRotation(node, operation string, index uint64) (Directory, error) {
	row, found := d.IdentityRotation(node, operation)
	if !d.writable() || !found || row.Phase != "Activated" || index < row.ActivatedIndex {
		return d, ErrMember
	}
	next := clone(d)
	next.Revision++
	for i := range next.Rotations {
		if next.Rotations[i].Operation == operation {
			next.Rotations[i].Phase = "Installed"
			next.Rotations[i].Failure = ""
			next.Rotations[i].InstalledIndex = index
		}
	}
	return next, next.Validate()
}
func (d Directory) validateIdentityRotations() error {
	if len(d.Rotations) > 128 {
		return ErrMember
	}
	seen := map[string]bool{}
	hasKeys := false
	for _, entry := range d.Entries {
		hasKeys = hasKeys || len(entry.Keys) > 0
	}
	if len(d.Rotations) == 0 && !hasKeys {
		return nil
	}
	topology, err := d.Topology()
	if err != nil {
		return err
	}
	for _, entry := range d.Entries {
		node, found := topology.Node(entry.Peer.ID)
		if !found && len(entry.Keys) > 0 {
			return ErrMember
		}
		left, _ := json.Marshal(entry.Keys)
		right, _ := json.Marshal(node.Keys)
		if len(entry.Keys) > 0 && !bytes.Equal(left, right) {
			return ErrMember
		}
		for _, transition := range entry.Keys {
			matched := false
			proof, _ := json.Marshal(transition.Proof)
			for _, row := range d.Rotations {
				other, _ := json.Marshal(row.Proof)
				if row.Node == entry.Peer.ID && row.Operation == transition.Proof.Operation && (row.Phase == "Activated" || row.Phase == "Installed") && row.ActivatedIndex == transition.Index && bytes.Equal(proof, other) {
					matched = true
					break
				}
			}
			if !matched {
				return ErrMember
			}
		}
	}
	for _, row := range d.Rotations {
		if row.Failure != "" && row.Failure != "IDENTITY_PREPARE_FAILED" && row.Failure != "IDENTITY_ACTIVATE_FAILED" {
			return ErrMember
		}
		if !lifecycle.ValidID(row.Node) || !lifecycle.ValidID(row.Operation) || seen[row.Operation] || row.Expected == 0 || row.AcceptedIndex == 0 || len(row.Origin) == 0 || len(row.Origin) > 64<<10 || !json.Valid(row.Origin) {
			return ErrMember
		}
		seen[row.Operation] = true
		switch row.Phase {
		case "Preparing":
			if row.Proof != nil || row.ActivatedIndex != 0 || row.InstalledIndex != 0 {
				return ErrMember
			}
		case "Prepared", "Activated", "Installed":
			if row.Proof == nil || !row.Proof.Valid() || row.Proof.Cluster != d.Cluster || row.Proof.Node != row.Node || row.Proof.Operation != row.Operation {
				return ErrMember
			}
			if row.Phase == "Prepared" && (row.ActivatedIndex != 0 || row.InstalledIndex != 0) || row.Phase != "Prepared" && row.ActivatedIndex <= row.AcceptedIndex || row.Phase == "Installed" && row.InstalledIndex < row.ActivatedIndex {
				return ErrMember
			}
			entry, exists := d.Entry(row.Node)
			if !exists {
				return ErrMember
			}
			if row.Phase == "Prepared" {
				if row.Proof.Old != mustPeerKey(entry.CurrentPeer()) {
					return ErrMember
				}
			} else {
				matched := false
				for _, transition := range entry.Keys {
					if transition.Proof.Operation == row.Operation && transition.Index == row.ActivatedIndex {
						matched = true
						break
					}
				}
				if !matched {
					return ErrMember
				}
			}
		default:
			return ErrMember
		}
	}
	return nil
}

// ResourceKeyActive is for retained resource recipes only. Current TLS,
// replication, user issuers and report authentication always use MemberKey/
// WorkKey. A compiler chooses CurrentPeer; it cannot allocate a new old owner.
func (d Directory) ResourceKeyActive(key [32]byte) bool {
	for _, entry := range d.Entries {
		if !d.WorkKey(mustPeerKey(entry.CurrentPeer())) {
			continue
		}
		if mustPeerKey(entry.Peer) == key {
			return true
		}
		for _, transition := range entry.Keys {
			if transition.Proof.Old == key || transition.Proof.New == key {
				return true
			}
		}
	}
	return false
}
func (d Directory) OwnsResource(current, original [32]byte) bool {
	if !d.MemberKey(current) {
		return false
	}
	for _, entry := range d.Entries {
		if mustPeerKey(entry.CurrentPeer()) != current {
			continue
		}
		if mustPeerKey(entry.Peer) == original {
			return true
		}
		for _, transition := range entry.Keys {
			if transition.Proof.Old == original || transition.Proof.New == original {
				return true
			}
		}
	}
	return false
}
func mustPeerKey(peer config.Peer) [32]byte { key, _ := identity.ParseKey(peer.Key); return key }

func (d Directory) FailIdentityRotation(node, operation, code string) (Directory, error) {
	row, ok := d.IdentityRotation(node, operation)
	if !ok || row.Phase == "Installed" || row.Phase == "Activated" || code != "IDENTITY_PREPARE_FAILED" && code != "IDENTITY_ACTIVATE_FAILED" || !d.writable() {
		return d, ErrMember
	}
	if row.Failure == code {
		return d, nil
	}
	n := clone(d)
	n.Revision++
	for i := range n.Rotations {
		if n.Rotations[i].Operation == operation {
			n.Rotations[i].Failure = code
		}
	}
	return n, n.Validate()
}

// ResourceKeyForNode validates a retained owner reference, including retired
// nodes. It grants no current authentication or native permission.
func (d Directory) ResourceKeyForNode(node string, key [32]byte) bool {
	entry, ok := d.Entry(node)
	if !ok {
		return false
	}
	if mustPeerKey(entry.Peer) == key {
		return true
	}
	for _, row := range entry.Keys {
		if row.Proof.Old == key || row.Proof.New == key {
			return true
		}
	}
	return false
}
