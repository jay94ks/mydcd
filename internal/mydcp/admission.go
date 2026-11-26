// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"crypto/ed25519"
	"errors"
)

var ErrAdmission = errors.New("MYDCP identity or purpose denied")

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
}

func NewGate(cluster, challenge [32]byte) (*Gate, error) {
	if cluster == [32]byte{} || challenge == [32]byte{} {
		return nil, ErrAdmission
	}
	return &Gate{cluster: cluster, challenge: challenge}, nil
}
func ProofBytes(key Identity, cluster, challenge [32]byte) []byte {
	b := append([]byte("mydc-go-auth-1"), key[:]...)
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
	if _, limit := fieldRule(f.Purpose, f.Kind); limit == 0 {
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
	allow := false
	switch f.Purpose {
	case SecretFetch, VolumeTransfer, CheckerArtifact, CheckerProbe, CertificateMaterial:
		allow = p.Member
	case SecretInput:
		allow = p.UserAuth
		if f.Kind == 2 {
			allow = p.Respond
		}
	case User:
		allow = p.UserAuth
		if f.Kind == 2 {
			allow = p.Respond
		}
		if f.Kind == 3 {
			allow = p.Member
		}
		if f.Kind == 4 {
			allow = p.UserAuth || p.Member
		}
	case VolumeFile:
		switch f.Kind {
		case 1:
			allow = p.UserAuth
		case 3:
			allow = p.Member
		case 2:
			allow = p.Respond
		case 4:
			allow = p.UserAuth || p.Member || p.Respond
		}
	case ImageContent:
		switch f.Kind {
		case 1:
			allow = p.UserAuth
		case 2, 4:
			allow = p.Respond
		case 3, 5:
			allow = p.Member
		}
	case NodeShell, ContainerSession:
		switch f.Kind {
		case 1:
			allow = p.UserAuth
		case 2:
			allow = p.Respond
		case 3:
			allow = p.Member
		case 5:
			allow = p.UserAuth || p.Member || p.Respond
		}
	case Membership:
		allow = p.Member || p.Replicate
		if f.Kind == 2 {
			allow = allow && p.Respond
		}
	case Management:
		allow = p.Manage
		if f.Kind == 2 {
			allow = p.Respond
		}
		if f.Kind == 3 {
			allow = p.Read
		}
		if f.Kind == 4 {
			// A member relays an original signed request. Relay permission does
			// not authorize the original actor's management command.
			allow = p.Member
		}
	case Raft:
		// Non-voters also exchange replication RPCs. The Raft library alone
		// decides voting/leadership; admission proves current membership only.
		allow = p.Member || p.Replicate
	case Snapshot:
		allow = (p.Member || p.Replicate) && p.Snapshot
	case Observation:
		allow = p.Report
		if f.Kind == 2 {
			allow = p.Respond
		}
	case Packet:
		allow = p.Tunnel
	case PathControl:
		allow = p.Member && p.Tunnel
	}
	if !allow {
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
