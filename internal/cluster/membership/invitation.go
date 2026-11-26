// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
)

// Invitation is verified against EXPLICIT external cluster/control pins before
// the target writes a local Join intent. Genesis alone is not signer approval.
// MinimumIndex bounds the initial source-only replication seed: after that
// prefix is installed, only the committed directory can authorize peers.
type Invitation struct {
	Schema                         uint8
	Cluster, Admin                 [32]byte
	Genesis, Source, Target        config.Peer
	JoinID                         string
	ApprovalRevision, MinimumIndex uint64
	Signature                      []byte
}

func InvitationBytes(i Invitation) []byte {
	i.Signature = nil
	b, _ := json.Marshal(i)
	return append([]byte("mydc-member-invitation-1\x00"), b...)
}
func (i Invitation) Verify(cluster, source [32]byte) error {
	key, err := identity.ParseKey(i.Source.Key)
	if i.Schema != 1 || cluster == ([32]byte{}) || i.Cluster != cluster || i.Admin == ([32]byte{}) || err != nil || source == ([32]byte{}) || key != source || !validPeer(i.Genesis) || !i.Genesis.Voter || !validPeer(i.Source) || !i.Source.Voter || !validPeer(i.Target) || i.Target.Voter || !lifecycle.ValidID(i.JoinID) || i.JoinID == "genesis" || i.ApprovalRevision < 2 || i.MinimumIndex == 0 || !ed25519.Verify(ed25519.PublicKey(source[:]), InvitationBytes(i), i.Signature) {
		return ErrMember
	}
	for _, peer := range []config.Peer{i.Genesis, i.Source} {
		if i.Target.ID == peer.ID || i.Target.Key == peer.Key || i.Target.Endpoint == peer.Endpoint {
			return ErrMember
		}
	}
	if i.Source.ID == i.Genesis.ID || i.Source.Key == i.Genesis.Key || i.Source.Endpoint == i.Genesis.Endpoint {
		if i.Source != i.Genesis {
			return ErrMember
		}
	}
	return nil
}
func (i Invitation) Encode() ([]byte, error) {
	key, _ := identity.ParseKey(i.Source.Key)
	if i.Verify(i.Cluster, key) != nil {
		return nil, ErrMember
	}
	return json.Marshal(i)
}
func DecodeInvitation(raw []byte) (Invitation, error) {
	var i Invitation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 16<<10 || d.Decode(&i) != nil {
		return i, ErrMember
	}
	b, err := i.Encode()
	if err != nil || !bytes.Equal(raw, b) {
		return i, ErrMember
	}
	return i, nil
}
