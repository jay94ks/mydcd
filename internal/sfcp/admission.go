// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"crypto/ed25519"
	"errors"

	"github.com/jay94ks/seafield/internal/buildinfo"
)

var ErrAdmission = errors.New("SFCP identity or purpose denied")

type Identity [32]byte
type Binding struct {
	Key, TLSKey        Identity
	Cluster, Challenge [32]byte
	Signature          []byte
}
type Policy struct {
	Key                                                     Identity
	Manage, Read, Respond, Member, Snapshot, Report, Tunnel bool
	UserAuth                                                bool
	// Replicate admits an approved joining key only to Raft/Snapshot. It is
	// distinct from installed membership and never grants relay/data rights.
	Replicate bool
}
type Gate struct {
	cluster, challenge [32]byte
	key                Identity
	authenticated      bool
	// features are what the peer announced in its handshake hello; frames
	// whose purpose/kind needs more are refused.
	features buildinfo.Features
	// own is this node's announced feature set.
	own buildinfo.Features
	// version is the build version the peer announced (tag 128), "" when
	// none.
	version string
	// common is features ∩ own, computed once at the handshake
	// (setPeerFeatures) so frames are checked without decoding sets.
	common buildinfo.Features
}

// setPeerFeatures records what the peer announced and the common set.
func (g *Gate) setPeerFeatures(f buildinfo.Features) {
	g.features, g.common = f, f.And(g.own)
}

func NewGate(cluster, challenge [32]byte) (*Gate, error) {
	if cluster == [32]byte{} || challenge == [32]byte{} {
		return nil, ErrAdmission
	}
	return &Gate{cluster: cluster, challenge: challenge}, nil
}
func ProofBytes(key Identity, cluster, challenge [32]byte) []byte {
	b := append([]byte("sfc-go-auth-1"), key[:]...)
	b = append(b, cluster[:]...)
	return append(b, challenge[:]...)
}

// TLS binding and current public-key approval come from real adapters. This
// verifies the application proof only; it does not establish TLS or quorum.
func (g *Gate) Authenticate(b Binding, approved bool) error {
	if g.authenticated || !approved || b.Key == (Identity{}) || b.Key != b.TLSKey || b.Cluster != g.cluster || b.Challenge != g.challenge || !ed25519.Verify(ed25519.PublicKey(b.Key[:]), ProofBytes(b.Key, b.Cluster, b.Challenge), b.Signature) {
		return ErrAdmission
	}
	g.key = b.Key
	g.authenticated = true
	return nil
}

// Admit takes CURRENT policy each time; a prior grant is never cached forever.
// The caller also binds one purpose to each stream and enforces queue/deadline.
func (g *Gate) Admit(f Frame, p Policy, earlyData, datagram bool) error {
	k, known := kindOf(f.Purpose, f.Kind)
	if !known {
		return ErrAdmission
	}
	if earlyData || datagram != (f.Purpose == Packet) {
		return ErrAdmission
	}
	if f.Purpose == Handshake {
		if g.authenticated {
			return ErrAdmission
		}
		return nil
	}
	if !g.authenticated || p.Key != g.key {
		return ErrAdmission
	}
	if k.allow == nil || !k.allow(p) {
		return ErrAdmission
	}
	if needs := needsOf(f.Purpose, f.Kind); len(needs) > 0 && !g.common.Meets(needs...) {
		return ErrAdmission
	}
	return nil
}
func (g *Gate) AdmitOn(stream Purpose, f Frame, p Policy, earlyData, datagram bool) error {
	if f.Purpose != stream {
		return ErrAdmission
	}
	return g.Admit(f, p, earlyData, datagram)
}
